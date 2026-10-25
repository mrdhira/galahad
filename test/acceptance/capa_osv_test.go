package acceptance_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
)

// toolReport mirrors the parts of report.json that the guest tool tests read.
type toolReport struct {
	Verdict  string        `json:"verdict"`
	Findings []toolFinding `json:"findings"`
	Coverage struct {
		Analyzers []string `json:"analyzers"`
		Truncated bool     `json:"truncated"`
		LeftOut   []struct {
			Tool  string `json:"tool"`
			Cause string `json:"cause"`
		} `json:"left_out"`
	} `json:"coverage"`
	Reasons []string `json:"reasons"`
	Network *struct {
		Events []struct {
			Host    string `json:"host"`
			Blocked bool   `json:"blocked"`
			Reason  string `json:"reason"`
		} `json:"events"`
	} `json:"network"`
}

type toolFinding struct {
	RuleID   string `json:"rule_id"`
	Severity string `json:"severity"`
	Analyzer string `json:"analyzer"`
	Evidence []struct {
		Path    string `json:"path"`
		Snippet string `json:"snippet"`
	} `json:"evidence"`
}

func readToolReport(t *testing.T, dir string) toolReport {
	t.Helper()
	var rep toolReport
	if err := json.Unmarshal([]byte(readFile(t, filepath.Join(dir, "report.json"))), &rep); err != nil {
		t.Fatal(err)
	}
	return rep
}

// toolsLog returns tools.log of the job.
func toolsLog(t *testing.T, dir string) string {
	t.Helper()
	return readFile(t, filepath.Join(dir, "artifacts", "tools.log"))
}

// fromTools returns the findings of the guest tools capa and osv.
func (r toolReport) fromTools() []toolFinding {
	var out []toolFinding
	for _, f := range r.Findings {
		if f.Analyzer == "capa" || f.Analyzer == "osv" {
			out = append(out, f)
		}
	}
	return out
}

// stubCapa puts a capa on PATH that prints doc, a capa JSON document, whatever it is given. The real capa
// lives in the re image only, so these tests run without it.
func stubCapa(t *testing.T, doc string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the capa stub is a shell script, and capa runs in the Linux guest only")
	}
	dir := t.TempDir()
	script := "#!/bin/sh\ncat <<'JSON'\n" + doc + "\nJSON\n"
	if err := os.WriteFile(filepath.Join(dir, "capa"), []byte(script), 0o700); err != nil { // #nosec G306 -- the stub must be executable
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func capaDoc(rules ...[2]string) string {
	var parts []string
	for _, r := range rules {
		parts = append(parts, fmt.Sprintf(`%q:{"meta":{"name":%q,"namespace":%q}}`, r[0], r[0], r[1]))
	}
	return `{"meta":{"version":"10.0.0"},"rules":{` + strings.Join(parts, ",") + `}}`
}

// P7: an executable in the re image is examined by capa. The stub prints what capa would.
func TestScanCapa(t *testing.T) {
	exe := filesRepo(map[string]string{"bin/app.exe": string(sfxStub()), "README.md": "# app\n"})
	vmOnly := capaDoc([2]string{"check for VMware I/O port", "anti-analysis/anti-vm/vm-detection"})
	tests := []struct {
		name string
		// inputs
		args   []string
		target func(t *testing.T) string
		stub   string // the capa JSON; no capa on PATH when empty
		noCapa bool   // PATH holds no capa at all
		// expectations
		wantCode     int
		wantRules    []string
		wantEvidence string // path of the GAL-CAPA-001 evidence
		wantSnippet  string // substring of its snippet
		wantAnalyzer bool   // capa is in coverage.analyzers
		wantTruncate bool
		wantLog      string
		wantNoLog    string
	}{
		{
			name: "the re image with an executable that only has vm-detection stays clean", args: []string{"--image", "re"}, target: exe, stub: vmOnly,
			wantCode: 0, wantAnalyzer: true, wantLog: "capa: ok, 0 findings",
		},
		{
			name: "the re image without an executable needs no capa", args: []string{"--image", "re"}, target: func(t *testing.T) string { return corpus(t, "benign-go-cli") }, noCapa: true,
			wantCode: 0, wantAnalyzer: true, wantLog: "capa: ok, 0 findings",
		},
		{
			name: "injection and keylogging in an executable are one medium finding", args: []string{"--image", "re"}, target: exe,
			stub:     capaDoc([2]string{"inject thread", "host-interaction/process/inject"}, [2]string{"log keystrokes via polling", "collection/keylog"}, [2]string{"check for VMware I/O port", "anti-analysis/anti-vm/vm-detection"}),
			wantCode: 10, wantRules: []string{"GAL-CAPA-001"}, wantEvidence: "bin/app.exe", wantSnippet: "injection: inject thread", wantAnalyzer: true,
		},
		{
			name: "the core image does not run capa", target: exe, stub: capaDoc([2]string{"inject thread", "host-interaction/process/inject"}),
			wantCode: 0, wantNoLog: "capa:",
		},
		{
			name: "the re image without capa on PATH leaves the tool out", args: []string{"--image", "re"}, target: exe, noCapa: true,
			wantCode: 0, wantTruncate: true, wantLog: "capa: left out: capa is not installed",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given a capa stub on PATH, or none
			if tt.stub != "" {
				stubCapa(t, tt.stub)
			}
			if tt.noCapa {
				t.Setenv("PATH", t.TempDir())
			}
			home := t.TempDir()

			// When the input is scanned
			stdout, stderr, code := scan(t, home, append(tt.args, tt.target(t))...)

			// Then the exit code, the report and tools.log are as expected
			if code != tt.wantCode {
				t.Fatalf("exit = %d, want %d\nstdout: %s\nstderr: %s", code, tt.wantCode, stdout, stderr)
			}
			dir := onlyJob(t, home)
			rep := readToolReport(t, dir)
			var rules []string
			for _, f := range rep.fromTools() {
				rules = append(rules, f.RuleID)
			}
			if !slices.Equal(rules, tt.wantRules) {
				t.Errorf("rules = %v, want %v", rules, tt.wantRules)
			}
			for _, f := range rep.fromTools() {
				if f.Severity != "medium" || f.Analyzer != "capa" || f.Evidence[0].Path != tt.wantEvidence || !strings.Contains(f.Evidence[0].Snippet, tt.wantSnippet) {
					t.Errorf("finding = %+v, want medium, analyzer capa, path %q, snippet with %q", f, tt.wantEvidence, tt.wantSnippet)
				}
			}
			if got := slices.Contains(rep.Coverage.Analyzers, "capa"); got != tt.wantAnalyzer {
				t.Errorf("capa in coverage.analyzers = %v, want %v (%v)", got, tt.wantAnalyzer, rep.Coverage.Analyzers)
			}
			log := toolsLog(t, dir)
			if !strings.Contains(log, tt.wantLog) {
				t.Errorf("tools.log = %q, want it to contain %q", log, tt.wantLog)
			}
			if tt.wantNoLog != "" && strings.Contains(log, tt.wantNoLog) {
				t.Errorf("tools.log = %q, want no %q", log, tt.wantNoLog)
			}
		})
	}
}

// osvServer serves /v1/querybatch with a MAL entry for the first query when mal is set, and counts the requests.
func osvServer(t *testing.T, mal bool) (port string, requests *atomic.Int32) {
	t.Helper()
	requests = new(atomic.Int32)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		var body struct {
			Queries []json.RawMessage `json:"queries"`
		}
		data, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if r.URL.Path != "/v1/querybatch" || json.Unmarshal(data, &body) != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		results := make([]string, len(body.Queries))
		for i := range results {
			results[i] = "{}"
		}
		if mal && len(results) > 0 {
			results[0] = `{"vulns":[{"id":"GHSA-aaaa-bbbb-cccc"},{"id":"MAL-2024-1234"}]}`
		}
		_, _ = io.WriteString(w, `{"results":[`+strings.Join(results, ",")+`]}`)
	}))
	t.Cleanup(srv.Close)
	_, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return port, requests
}

// P2: a dependency that OSV lists as malicious is critical. The OSV API is a local server that api.osv.dev
// resolves to, over plain HTTP on port 443; the host proxy applies its policy as it does for the real API.
func TestScanOSV(t *testing.T) {
	lock := filesRepo(map[string]string{
		"package-lock.json": `{"name":"demo","lockfileVersion":3,"packages":{"":{"name":"demo","version":"1.0.0"},"node_modules/evil-pkg":{"version":"1.0.1"}}}`,
		"README.md":         "# demo\n",
	})
	tests := []struct {
		name string
		// inputs
		mal     bool   // the server lists a MAL entry for the package
		resolve string // GALAHAD_TEST_RESOLVE; the server through the sinkhole when empty
		// expectations
		wantCode     int
		wantVerdict  string
		wantRules    []string
		wantSnippet  string
		wantAnalyzer bool // osv is in coverage.analyzers
		wantRequests int32
		wantBlocked  bool   // api.osv.dev is a blocked event
		wantReason   string // substring of a reason of the report
		wantLog      string
		wantCause    string // why osv is left out, in coverage.left_out; none when empty
		wantSummary  string // substring of summary.md
		wantNoText   string // substring that summary.md must not have
	}{
		{
			name: "a MAL entry for a pinned package is malicious", mal: true,
			wantCode: 20, wantVerdict: "malicious", wantRules: []string{"GAL-DEPS-005"}, wantSnippet: "npm evil-pkg@1.0.1: MAL-2024-1234",
			wantAnalyzer: true, wantRequests: 1, wantLog: "osv: ok, 1 findings",
		},
		{
			name:     "a package that OSV does not list as malicious stays clean",
			wantCode: 0, wantVerdict: "clean", wantAnalyzer: true, wantRequests: 1, wantLog: "osv: ok, 0 findings",
		},
		{
			name: "OSV that resolves to a fake-IP address is left out and the scan stays clean", mal: true, resolve: "api.osv.dev=198.18.0.5",
			wantCode: 0, wantVerdict: "clean", wantBlocked: true, wantReason: "the OSV lookup was blocked: api.osv.dev resolved to an address that is not public (benchmarking)",
			wantLog: "osv: left out: the host proxy refused the OSV lookup", wantCause: "failed",
			wantSummary: "Galahad's own OSV lookup", wantNoText: "| BLOCKED | api[.]osv[.]dev",
		},
		{
			name: "OSV without a network is left out for no network and the scan stays clean", mal: true, resolve: "api.osv.dev=fail",
			wantCode: 0, wantVerdict: "clean", wantReason: "osv was left out: no network",
			wantLog: "osv: left out: no network: the computer that runs Galahad could not reach api.osv.dev", wantCause: "no_network",
			wantSummary: "| Galahad's own OSV lookup | api[.]osv[.]dev | 443 | 1 | dns lookup failed |", wantNoText: "| denied | api[.]osv[.]dev",
		},
		{
			name: "OSV that a Pi-hole answers with 0.0.0.0 is left out and the scan stays clean", mal: true, resolve: "api.osv.dev=0.0.0.0",
			wantCode: 0, wantVerdict: "clean", wantBlocked: true, wantReason: "(this network)",
			wantLog: "api.osv.dev:443 denied: this network", wantCause: "failed",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given an OSV server that api.osv.dev resolves to, or an address that is not public
			port, requests := osvServer(t, tt.mal)
			t.Setenv("GALAHAD_TEST_OSV_BASE", "http://api.osv.dev:443")
			if tt.resolve != "" {
				t.Setenv("GALAHAD_TEST_RESOLVE", tt.resolve)
			} else {
				t.Setenv("GALAHAD_TEST_RESOLVE", "api.osv.dev=127.0.0.1")
				t.Setenv("GALAHAD_TEST_SINKHOLE", "127.0.0.1:"+port)
			}
			home := t.TempDir()

			// When the project is scanned
			stdout, stderr, code := scan(t, home, lock(t))

			// Then the verdict, the findings and the coverage are as expected
			if code != tt.wantCode {
				t.Fatalf("exit = %d, want %d\nstdout: %s\nstderr: %s", code, tt.wantCode, stdout, stderr)
			}
			dir := onlyJob(t, home)
			rep := readToolReport(t, dir)
			if rep.Verdict != tt.wantVerdict {
				t.Errorf("verdict = %q, want %q", rep.Verdict, tt.wantVerdict)
			}
			var rules []string
			for _, f := range rep.fromTools() {
				rules = append(rules, f.RuleID)
			}
			if !slices.Equal(rules, tt.wantRules) {
				t.Errorf("rules = %v, want %v", rules, tt.wantRules)
			}
			for _, f := range rep.fromTools() {
				if f.Severity != "critical" || f.Analyzer != "osv" || f.Evidence[0].Path != "package-lock.json" || f.Evidence[0].Snippet != tt.wantSnippet {
					t.Errorf("finding = %+v, want critical, analyzer osv, package-lock.json: %q", f, tt.wantSnippet)
				}
			}
			if got := slices.Contains(rep.Coverage.Analyzers, "osv"); got != tt.wantAnalyzer {
				t.Errorf("osv in coverage.analyzers = %v, want %v (%v)", got, tt.wantAnalyzer, rep.Coverage.Analyzers)
			}
			if !tt.wantAnalyzer && !rep.Coverage.Truncated {
				t.Error("coverage.truncated = false, want true for a tool that was left out")
			}
			cause := ""
			for _, l := range rep.Coverage.LeftOut {
				if l.Tool == "osv" {
					cause = l.Cause
				}
			}
			if cause != tt.wantCause {
				t.Errorf("cause of osv in coverage.left_out = %q, want %q", cause, tt.wantCause)
			}
			md := readFile(t, filepath.Join(dir, "summary.md"))
			if !strings.Contains(md, tt.wantSummary) {
				t.Errorf("summary.md lacks %q:\n%s", tt.wantSummary, md)
			}
			if tt.wantNoText != "" && strings.Contains(md, tt.wantNoText) {
				t.Errorf("summary.md has %q, want none:\n%s", tt.wantNoText, md)
			}
			if got := requests.Load(); got != tt.wantRequests {
				t.Errorf("requests to the OSV server = %d, want %d", got, tt.wantRequests)
			}
			blocked := rep.Network != nil && slices.ContainsFunc(rep.Network.Events, func(e struct {
				Host    string `json:"host"`
				Blocked bool   `json:"blocked"`
				Reason  string `json:"reason"`
			}) bool {
				return e.Host == "api.osv.dev" && e.Blocked
			})
			if blocked != tt.wantBlocked {
				t.Errorf("api.osv.dev blocked in the report = %v, want %v", blocked, tt.wantBlocked)
			}
			if tt.wantReason != "" && !slices.ContainsFunc(rep.Reasons, func(r string) bool { return strings.Contains(r, tt.wantReason) }) {
				t.Errorf("reasons = %q, want one containing %q", rep.Reasons, tt.wantReason)
			}
			if log := toolsLog(t, dir); !strings.Contains(log, tt.wantLog) {
				t.Errorf("tools.log = %q, want it to contain %q", log, tt.wantLog)
			}
			if j := readJob(t, dir); j.Blocked {
				t.Error("job.json says blocked, want false: the OSV block is not a request of the input")
			}
		})
	}
}
