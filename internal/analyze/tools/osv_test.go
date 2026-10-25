package tools_test

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mrdhira/galahad/internal/analyze/tools"
)

// osvRelay is a relay in front of backend. It answers CONNECT with 200 and then passes bytes both ways, or
// with 403 and the body in refuse when refuse is not empty. hosts returns the CONNECT targets it saw.
func osvRelay(t *testing.T, backend *httptest.Server, refuse string) (addr string, hosts func() []string) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	var mu sync.Mutex
	var seen []string
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				br := bufio.NewReader(c)
				line, err := br.ReadString('\n')
				if err != nil {
					return
				}
				for { // the headers
					h, err := br.ReadString('\n')
					if err != nil || h == "\r\n" {
						break
					}
				}
				fields := strings.Fields(line)
				if len(fields) < 2 || fields[0] != "CONNECT" {
					return
				}
				mu.Lock()
				seen = append(seen, fields[1])
				mu.Unlock()
				if refuse != "" {
					_, _ = fmt.Fprintf(c, "HTTP/1.1 403 Forbidden\r\nContent-Length: %d\r\n\r\n%s", len(refuse), refuse)
					return
				}
				up, err := net.Dial("tcp", backend.Listener.Addr().String())
				if err != nil {
					return
				}
				defer func() { _ = up.Close() }()
				_, _ = io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n")
				done := make(chan struct{})
				go func() { _, _ = io.Copy(up, br); close(done) }()
				_, _ = io.Copy(c, up)
				<-done
			}()
		}
	}()
	return l.Addr().String(), func() []string {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(seen)
	}
}

// osvResults renders a querybatch response for n queries, with the IDs in hits for the queries it names.
func osvResults(n int, hits map[int][]string) string {
	results := make([]string, n)
	for i := range results {
		results[i] = "{}"
		if ids := hits[i]; len(ids) > 0 {
			var vulns []string
			for _, id := range ids {
				vulns = append(vulns, fmt.Sprintf(`{"id":%q,"modified":"2025-01-01T00:00:00Z"}`, id))
			}
			results[i] = `{"vulns":[` + strings.Join(vulns, ",") + `]}`
		}
	}
	return `{"results":[` + strings.Join(results, ",") + `]}`
}

// manyPins is a requirements file that pins n packages.
func manyPins(n int) map[string][]byte {
	var b strings.Builder
	for i := range n {
		fmt.Fprintf(&b, "pkg%05d==1.0.%d\n", i, i)
	}
	return map[string][]byte{"requirements.txt": []byte(b.String())}
}

// withFile is files and one more file.
func withFile(files map[string][]byte, name, content string) map[string][]byte {
	out := maps.Clone(files)
	out[name] = []byte(content)
	return out
}

func TestOSV(t *testing.T) {
	lock := `{"name":"demo","lockfileVersion":3,"packages":{"":{"name":"demo","version":"1.0.0"},
"node_modules/evil-pkg":{"version":"1.0.1"},"node_modules/left-pad":{"version":"1.3.0"}}}`
	const reqs = "flask==2.0.0\nrequests>=2\n"
	both := map[string][]byte{"package-lock.json": []byte(lock), "requirements.txt": []byte(reqs)}
	ok := func(_, n int) (int, string) { return http.StatusOK, osvResults(n, nil) }

	tests := []struct {
		name string
		// inputs
		files   map[string][]byte
		relay   string // "refuse" refuses the tunnel, "dns" and "dial" refuse it as the host proxy does when it has no network, "down" has no relay listening, "none" gives no address
		base    string // the API address; the test server through api.osv.dev:443 when empty; "none" for no address
		respond func(call, n int) (status int, body string)
		// expectations
		wantFinds    []string
		wantQueries  []string // of the first request
		wantRequests []int    // queries in each request
		wantHosts    []string // CONNECT targets
		wantPartial  bool
		wantNote     string
		wantErr      string
	}{
		{
			name:  "a MAL entry becomes a critical finding on the file that pins the package, and other advisories do not",
			files: both,
			respond: func(_, n int) (int, string) {
				return http.StatusOK, osvResults(n, map[int][]string{0: {"GHSA-xxxx-yyyy-zzzz", "MAL-2024-1234"}, 1: {"CVE-2024-1"}, 2: {"PYSEC-2021-1"}})
			},
			wantFinds:    []string{"GAL-DEPS-005 package-lock.json: npm evil-pkg@1.0.1: MAL-2024-1234"},
			wantQueries:  []string{"npm:evil-pkg@1.0.1", "npm:left-pad@1.3.0", "PyPI:flask@2.0.0"},
			wantRequests: []int{3},
			wantHosts:    []string{"api.osv.dev:443"},
		},
		{
			name:         "a PyPI pin in a requirements file is looked up",
			files:        map[string][]byte{"app/requirements.txt": []byte("Flask_Login[ext]==0.6.3 --hash=sha256:abcd\n")},
			respond:      func(_, n int) (int, string) { return http.StatusOK, osvResults(n, map[int][]string{0: {"MAL-2025-1"}}) },
			wantFinds:    []string{"GAL-DEPS-005 app/requirements.txt: PyPI flask-login@0.6.3: MAL-2025-1"},
			wantQueries:  []string{"PyPI:flask-login@0.6.3"},
			wantRequests: []int{1},
			wantHosts:    []string{"api.osv.dev:443"},
		},
		{
			name:         "a package without a MAL entry is clean",
			files:        both,
			respond:      ok,
			wantQueries:  []string{"npm:evil-pkg@1.0.1", "npm:left-pad@1.3.0", "PyPI:flask@2.0.0"},
			wantRequests: []int{3},
			wantHosts:    []string{"api.osv.dev:443"},
		},
		{
			name:  "input that pins nothing makes no request, even without a network",
			files: map[string][]byte{"package.json": []byte(`{"dependencies":{"a":"^1.0.0"}}`), "notes.txt": []byte("hello")},
			relay: "none",
		},
		{
			name:         "the same package in two files is looked up once",
			files:        map[string][]byte{"a/requirements.txt": []byte("flask==2.0.0\n"), "b/requirements.txt": []byte("flask==2.0.0\n")},
			respond:      ok,
			wantQueries:  []string{"PyPI:flask@2.0.0"},
			wantRequests: []int{1},
			wantHosts:    []string{"api.osv.dev:443"},
		},
		{
			name:         "a big text file that is not a requirements file does not make the lookup partial",
			files:        withFile(both, "notes.txt", strings.Repeat("just words\n", 200000)),
			respond:      ok,
			wantQueries:  []string{"npm:evil-pkg@1.0.1", "npm:left-pad@1.3.0", "PyPI:flask@2.0.0"},
			wantRequests: []int{3},
			wantHosts:    []string{"api.osv.dev:443"},
		},
		{
			name:         "a requirements file over 1 MiB is skipped and makes the lookup partial",
			files:        withFile(both, "requirements-big.txt", strings.Repeat("# padding\n", 200000)),
			respond:      ok,
			wantRequests: []int{3},
			wantHosts:    []string{"api.osv.dev:443"},
			wantPartial:  true,
		},
		{
			name:         "more than 1000 packages are sent in batches",
			files:        manyPins(2500),
			respond:      ok,
			wantRequests: []int{1000, 1000, 500},
			wantHosts:    []string{"api.osv.dev:443", "api.osv.dev:443", "api.osv.dev:443"},
			wantQueries:  nil,
		},
		{
			name:         "at most 3 requests are made",
			files:        manyPins(3200),
			respond:      ok,
			wantRequests: []int{1000, 1000, 1000},
			wantHosts:    []string{"api.osv.dev:443", "api.osv.dev:443", "api.osv.dev:443"},
			wantPartial:  true,
		},
		{
			name:  "a later request that fails keeps the findings of the first and is partial",
			files: manyPins(1500),
			respond: func(call, n int) (int, string) {
				if call == 2 {
					return http.StatusInternalServerError, "oops"
				}
				return http.StatusOK, osvResults(n, map[int][]string{3: {"MAL-2024-9"}})
			},
			wantFinds:    []string{"GAL-DEPS-005 requirements.txt: PyPI pkg00003@1.0.3: MAL-2024-9"},
			wantRequests: []int{1000, 500},
			wantHosts:    []string{"api.osv.dev:443", "api.osv.dev:443"},
			wantPartial:  true,
			wantNote:     "the lookup stopped after 1000 packages",
		},
		{
			name:    "no network leaves the tool out",
			files:   both,
			relay:   "none",
			wantErr: "no network",
		},
		{
			name:      "a failed DNS lookup of the host proxy is no network",
			files:     both,
			relay:     "dns",
			wantHosts: []string{"api.osv.dev:443"},
			wantErr:   "no network: the computer that runs Galahad could not reach api.osv.dev",
		},
		{
			name:      "a failed dial of the host proxy is no network",
			files:     both,
			relay:     "dial",
			wantHosts: []string{"api.osv.dev:443"},
			wantErr:   "no network: the computer that runs Galahad could not reach api.osv.dev",
		},
		{
			name:    "no API address leaves the tool out",
			files:   both,
			base:    "none",
			wantErr: "no OSV server",
		},
		{
			name:      "a refusal of the host proxy leaves the tool out and says why",
			files:     both,
			relay:     "refuse",
			wantHosts: []string{"api.osv.dev:443"},
			wantErr:   "host proxy refused the OSV lookup; if it names a private address, the DNS of the computer that runs Galahad resolves api.osv.dev to one",
		},
		{
			name:      "the reason of the refusal is in the error",
			files:     both,
			relay:     "refuse",
			wantHosts: []string{"api.osv.dev:443"},
			wantErr:   "api.osv.dev:443 denied: benchmarking",
		},
		{
			name:    "a relay that is not there leaves the tool out as offline",
			files:   both,
			relay:   "down",
			wantErr: "possibly because the computer is offline",
		},
		{
			name:         "a status other than 200 leaves the tool out",
			files:        both,
			respond:      func(_, _ int) (int, string) { return http.StatusTooManyRequests, "slow down" },
			wantRequests: []int{3},
			wantHosts:    []string{"api.osv.dev:443"},
			wantErr:      "status 429",
		},
		{
			name:         "a redirect is not followed",
			files:        both,
			respond:      func(_, _ int) (int, string) { return http.StatusFound, "" },
			wantRequests: []int{3},
			wantHosts:    []string{"api.osv.dev:443"},
			wantErr:      "status 302",
		},
		{
			name:         "a response that is not JSON leaves the tool out",
			files:        both,
			respond:      func(_, _ int) (int, string) { return http.StatusOK, "<html>" },
			wantRequests: []int{3},
			wantHosts:    []string{"api.osv.dev:443"},
			wantErr:      "not OSV JSON",
		},
		{
			name:         "data after the document leaves the tool out",
			files:        both,
			respond:      func(_, n int) (int, string) { return http.StatusOK, osvResults(n, nil) + `{}` },
			wantRequests: []int{3},
			wantHosts:    []string{"api.osv.dev:443"},
			wantErr:      "data after the JSON document",
		},
		{
			name:         "a response with the wrong number of results leaves the tool out",
			files:        both,
			respond:      func(_, n int) (int, string) { return http.StatusOK, osvResults(n-1, nil) },
			wantRequests: []int{3},
			wantHosts:    []string{"api.osv.dev:443"},
			wantErr:      "2 results for 3 queries",
		},
		{
			name:  "a malformed ID leaves the tool out",
			files: both,
			respond: func(_, n int) (int, string) {
				return http.StatusOK, osvResults(n, map[int][]string{0: {"MAL-1\n"}})
			},
			wantRequests: []int{3},
			wantHosts:    []string{"api.osv.dev:443"},
			wantErr:      "malformed ID",
		},
		{
			name:         "a response over the size cap leaves the tool out",
			files:        both,
			respond:      func(_, _ int) (int, string) { return http.StatusOK, strings.Repeat(" ", 9<<20) },
			wantRequests: []int{3},
			wantHosts:    []string{"api.osv.dev:443"},
			wantErr:      "over 8388608 bytes",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given an API behind a relay
			var mu sync.Mutex
			var requests []int
			var firstQueries []string
			calls := 0
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var body struct {
					Queries []struct {
						Package struct{ Name, Ecosystem string } `json:"package"`
						Version string                           `json:"version"`
					} `json:"queries"`
				}
				if r.Method != http.MethodPost || r.URL.Path != "/v1/querybatch" || json.NewDecoder(r.Body).Decode(&body) != nil {
					http.Error(w, "bad request", http.StatusBadRequest)
					return
				}
				mu.Lock()
				calls++
				call := calls
				requests = append(requests, len(body.Queries))
				if call == 1 {
					for _, q := range body.Queries {
						firstQueries = append(firstQueries, q.Package.Ecosystem+":"+q.Package.Name+"@"+q.Version)
					}
				}
				mu.Unlock()
				status, text := http.StatusOK, osvResults(len(body.Queries), nil)
				if tt.respond != nil {
					status, text = tt.respond(call, len(body.Queries))
				}
				w.WriteHeader(status)
				_, _ = io.WriteString(w, text)
			}))
			defer backend.Close()
			refuse := map[string]string{
				"refuse": "denied: benchmarking\n",
				"dns":    "denied: dns lookup failed\n",
				"dial":   "denied: dial failed\n",
			}[tt.relay]
			relay, hosts := osvRelay(t, backend, refuse)
			switch tt.relay {
			case "down":
				relay = "127.0.0.1:1" // nothing listens on port 1
			case "none":
				relay = ""
			}
			base := "http://api.osv.dev:443"
			switch tt.base {
			case "none":
				base = ""
			case "":
			default:
				base = tt.base
			}
			dir := t.TempDir()
			writeTree(t, dir, tt.files)
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()

			// When the tool runs
			res, err := tools.NewOSV(relay, base).Run(ctx, dir)

			// Then the findings, the requests and the outcome are as expected
			if (err != nil) != (tt.wantErr != "") || (err != nil && !strings.Contains(err.Error(), tt.wantErr)) {
				t.Fatalf("error = %v, want %q", err, tt.wantErr)
			}
			if got := evidence(res.Findings); !slices.Equal(got, tt.wantFinds) {
				t.Errorf("findings = %q, want %q", got, tt.wantFinds)
			}
			for _, f := range res.Findings {
				if f.Severity != "critical" || f.Attack != "T1195.001" {
					t.Errorf("finding %s has severity %q and attack %q, want critical and T1195.001", f.RuleID, f.Severity, f.Attack)
				}
			}
			mu.Lock()
			defer mu.Unlock()
			if !slices.Equal(requests, tt.wantRequests) {
				t.Errorf("queries per request = %v, want %v", requests, tt.wantRequests)
			}
			if tt.wantQueries != nil && !slices.Equal(firstQueries, tt.wantQueries) {
				t.Errorf("queries of the first request = %q, want %q", firstQueries, tt.wantQueries)
			}
			if got := hosts(); !slices.Equal(got, tt.wantHosts) {
				t.Errorf("CONNECT targets = %q, want %q", got, tt.wantHosts)
			}
			if res.Partial != tt.wantPartial {
				t.Errorf("partial = %v, want %v", res.Partial, tt.wantPartial)
			}
			if !strings.Contains(res.Note, tt.wantNote) {
				t.Errorf("note = %q, want it to contain %q", res.Note, tt.wantNote)
			}
		})
	}
}
