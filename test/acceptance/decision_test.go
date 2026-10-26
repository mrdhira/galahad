package acceptance_test

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// decisionKey is a fake key, built from pieces so no full literal sits in the source.
const decisionKey = "fake-key-" + "t34b-" + "5d1e8b07"

// decisionRecord is the part of report.json that the decision tests read.
type decisionRecord struct {
	Verdict string   `json:"verdict"`
	Score   int      `json:"score"`
	Reasons []string `json:"reasons"`
	Target  struct {
		SHA256 string `json:"sha256"`
	} `json:"target"`
	Files []struct {
		SHA256 string `json:"sha256"`
	} `json:"files"`
	// Decision is nil when the scan asked no provider.
	Decision *struct {
		Provider string `json:"provider"`
		Status   string `json:"status"`
		Reason   string `json:"reason"`
		Error    *struct {
			Code       string `json:"code"`
			HTTPStatus int    `json:"http_status"`
		} `json:"error"`
		Sent       json.RawMessage `json:"sent"`
		Redactions map[string]int  `json:"redactions"`
		RequestID  string          `json:"request_id"`
		Attempts   int             `json:"attempts"`
	} `json:"decision"`
}

// decisionAnswer is a valid answer of the provider with the given verdict probabilities.
func decisionAnswer(clean, suspicious, malicious float64) string {
	return fmt.Sprintf(`{"object": "decisions", "model": "test/model-1", "prompt_format_version": 1, "answers": {
  "verdict": {"type": "choice", "probabilities": {"clean": %g, "suspicious": %g, "malicious": %g}, "label_mass": 0.6},
  "risk": {"type": "score", "probabilities": {"0": 0.25, "1": 0.25, "2": 0.25, "3": 0.25}, "label_mass": 0.4, "score": 1.5},
  "steals_secrets": {"type": "yes_no", "probabilities": {"yes": 0.5, "no": 0.5}, "label_mass": 0.5}},
  "usage": {"prompt_tokens": 100, "completion_tokens": 0, "total_tokens": 100}}`, clean, suspicious, malicious)
}

// mockProvider is an httptest server that records the body and the Authorization header of each request.
type mockProvider struct {
	srv    *httptest.Server
	mu     sync.Mutex
	bodies [][]byte
	auths  []string
	first  chan struct{} // closed at the first request
}

func newMockProvider(t *testing.T, handler func(w http.ResponseWriter, r *http.Request, n int)) *mockProvider {
	t.Helper()
	m := &mockProvider{first: make(chan struct{})}
	m.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := new(bytes.Buffer)
		_, _ = body.ReadFrom(r.Body)
		m.mu.Lock()
		m.bodies = append(m.bodies, body.Bytes())
		m.auths = append(m.auths, r.Header.Get("Authorization"))
		n := len(m.bodies)
		m.mu.Unlock()
		if n == 1 {
			close(m.first)
		}
		handler(w, r, n)
	}))
	t.Cleanup(m.srv.Close)
	return m
}

func (m *mockProvider) requests() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.bodies)
}

// answers replies to every request with body.
func answers(body string) func(w http.ResponseWriter, r *http.Request, n int) {
	return func(w http.ResponseWriter, _ *http.Request, _ int) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Request-Id", "req_t34b")
		_, _ = w.Write([]byte(body))
	}
}

func status(code int) func(w http.ResponseWriter, r *http.Request, n int) {
	return func(w http.ResponseWriter, _ *http.Request, _ int) { w.WriteHeader(code) }
}

// unescapeHTML turns the three characters that report.json escapes back, so that the request in the
// report reads as it went on the wire.
var unescapeHTML = strings.NewReplacer(`\u003c`, "<", `\u003e`, ">", `\u0026`, "&")

// TestScanDecision runs "scan --decision" through the built binary and the fake sandbox against a mock
// provider over loopback http (P9). Every case that makes a request checks that the mock got what the
// report says was sent, and that the key is in no file and no output.
func TestScanDecision(t *testing.T) {
	var second atomic.Int32
	secondSrv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { second.Add(1) }))
	defer secondSrv.Close()
	closedPort := func() string {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = l.Close() }() // only to find a port nobody listens on
		return "http://" + l.Addr().String()
	}()
	tests := []struct {
		name string
		// inputs
		target    string // a fixture in testdata/corpus, or a link when link is set
		link      bool
		copyAs    string // the target is copied under this name first, to give it a revealing name
		handler   func(w http.ResponseWriter, r *http.Request, n int)
		url       string // the provider URL instead of the mock's
		timeout   int    // seconds of the provider; 30 when zero
		interrupt bool   // Ctrl-C after the first request
		// expectations
		wantCode       int
		wantState      string
		wantVerdict    string
		wantScore      int
		wantSame       bool   // the verdict, score and exit code are those of the scan without --decision
		wantStatus     string // status of the decision; empty means the scan has no report
		wantReason     string // the reason of a skipped decision
		wantErrCode    string
		wantHTTP       int
		wantRequests   int
		wantLine       string   // in stdout, and in the output of "galahad report"
		wantReasons    []string // substrings of reasons
		wantExtra      time.Duration
		wantSecond     int      // requests of the second server
		wantRedacted   []string // kinds the report counts
		wantBodyHas    []string // substrings of the body the mock received
		wantBodyAbsent []string // substrings that must not be in it
	}{
		{
			name: "a benign opinion on the P1 repo changes nothing", target: "fake-interview-repo", handler: answers(decisionAnswer(0.99, 0.005, 0.005)),
			wantCode: 20, wantState: "done", wantSame: true, wantStatus: "ok", wantRequests: 1, wantLine: "AI opinion (mock): malicious 1%, no change",
		},
		{
			name: "a strong opinion raises a clean scan to suspicious", target: "benign-husky-lint", handler: answers(decisionAnswer(0.03, 0.02, 0.95)),
			wantCode: 10, wantState: "done", wantVerdict: "suspicious", wantScore: 20, wantStatus: "ok", wantRequests: 1,
			wantLine: "AI opinion (mock): malicious 95%, raised to suspicious", wantReasons: []string{"AI opinion (mock): malicious 95%"},
		},
		{
			name: "a strong opinion on a suspicious scan stays suspicious", target: "p2-typosquat", handler: answers(decisionAnswer(0.03, 0.02, 0.95)),
			wantCode: 10, wantState: "done", wantVerdict: "suspicious", wantScore: 65, wantStatus: "ok", wantRequests: 1,
			wantLine: "AI opinion (mock): malicious 95%, raised to suspicious",
		},
		{
			name: "a strong opinion gives the exact reason line and never makes a verdict malicious", target: "benign-husky-lint", handler: answers(decisionAnswer(0.05, 0.03, 0.92)),
			wantCode: 10, wantState: "done", wantVerdict: "suspicious", wantScore: 20, wantStatus: "ok", wantRequests: 1,
			wantLine:    "AI opinion (mock): malicious 92%, raised to suspicious",
			wantReasons: []string{"AI opinion (mock): malicious 92%, raised to suspicious; an AI opinion never makes a verdict malicious"},
		},
		{
			name: "a clean answer to a prompt injection cannot lower a malicious verdict", target: "p9-prompt-injection-repo",
			handler: func(w http.ResponseWriter, r *http.Request, _ int) {
				body, _ := io.ReadAll(r.Body)
				if bytes.Contains(bytes.ToLower(body), []byte("ignore all previous instructions")) {
					answers(decisionAnswer(0.99, 0.005, 0.005))(w, r, 0)
					return
				}
				answers(decisionAnswer(0.005, 0.005, 0.99))(w, r, 0)
			},
			wantCode: 20, wantState: "done", wantSame: true, wantStatus: "ok", wantRequests: 1, wantLine: "AI opinion (mock): malicious ",
			wantBodyHas: []string{"ignore all previous instructions", "GAL-INJECT-001", "GAL-AUTOEXEC-010"},
		},
		{
			name: "a folder with a revealing name is sent as the target, without hashes or the IOCs of no snippet", target: "fake-interview-repo", copyAs: "Acme-layoffs-2026",
			handler:  answers(decisionAnswer(0.1, 0.1, 0.8)),
			wantCode: 20, wantState: "done", wantSame: true, wantStatus: "ok", wantRequests: 1, wantLine: "AI opinion (mock): malicious 80%, no change",
			wantBodyHas:    []string{"GAL-AUTOEXEC-"},
			wantBodyAbsent: []string{"Acme", "layoffs", "2026"},
		},
		{
			name: "a file with a revealing name is sent as (target), without hashes or the IOCs of no snippet", target: "p6-eml-lure/lure.eml", copyAs: "Acme-layoffs-2026.eml",
			handler:  answers(decisionAnswer(0.1, 0.1, 0.8)),
			wantCode: 20, wantState: "done", wantSame: true, wantStatus: "ok", wantRequests: 1, wantLine: "AI opinion (mock): malicious 80%, no change",
			wantBodyHas:    []string{"(target)!/setup.js", "login.sinkhole.test"},
			wantBodyAbsent: []string{"Acme", "layoffs", "2026", "bounce@recruit-sinkhole.test", "candidate@example.test"},
		},
		{
			name: "the example keys are redacted before they leave the machine", target: "p9-prompt-injection-repo", handler: answers(decisionAnswer(1, 0, 0)),
			wantCode: 20, wantState: "done", wantSame: true, wantStatus: "ok", wantRequests: 1, wantLine: "AI opinion (mock): malicious 0%, no change",
			wantRedacted: []string{"aws-access-key", "aws-secret"},
		},
		{
			name: "nothing to judge is skipped and nothing is sent", target: "benign-go-cli", handler: answers(decisionAnswer(0, 0, 1)),
			wantCode: 0, wantState: "done", wantSame: true, wantStatus: "skipped", wantReason: "no_findings", wantLine: "AI opinion (mock): skipped: no findings to send",
		},
		{
			name: "a link that was never downloaded is skipped", target: "http://files.test/to-metadata", link: true, handler: answers(decisionAnswer(0, 0, 1)),
			wantCode: 10, wantState: "done", wantSame: true, wantStatus: "skipped", wantReason: "no_findings", wantLine: "AI opinion (mock): skipped: no findings to send",
			wantReasons: []string{"could not be downloaded"},
		},
		{
			name: "a provider that is down leaves the static verdict", target: "fake-interview-repo", url: closedPort, timeout: 2,
			wantCode: 20, wantState: "done", wantSame: true, wantStatus: "failed", wantErrCode: "network", wantLine: "AI opinion (mock): unavailable (network",
			wantExtra: 4 * time.Second,
		},
		{
			name: "four 503 answers leave the static verdict", target: "fake-interview-repo", handler: status(503),
			wantCode: 20, wantState: "done", wantSame: true, wantStatus: "failed", wantErrCode: "status", wantHTTP: 503, wantRequests: 3,
			wantLine: "AI opinion (mock): unavailable (status 503: scoring unavailable)",
		},
		{
			name: "a 402 leaves the static verdict", target: "benign-husky-lint", handler: status(402),
			wantCode: 0, wantState: "done", wantSame: true, wantStatus: "failed", wantErrCode: "status", wantHTTP: 402, wantRequests: 1,
			wantLine: "AI opinion (mock): unavailable (status 402: insufficient credit)",
		},
		{
			name: "a provider that hangs times out within the limit plus two seconds", target: "fake-interview-repo", timeout: 2,
			handler:  func(_ http.ResponseWriter, r *http.Request, _ int) { <-r.Context().Done() },
			wantCode: 20, wantState: "done", wantSame: true, wantStatus: "failed", wantErrCode: "timeout", wantRequests: 1,
			wantLine: "AI opinion (mock): unavailable (timeout", wantExtra: 4 * time.Second,
		},
		{
			name: "an answer that is not JSON is invalid", target: "fake-interview-repo",
			handler: func(w http.ResponseWriter, _ *http.Request, _ int) {
				w.Header().Set("Content-Type", "text/html")
				_, _ = w.Write([]byte(decisionAnswer(0, 0, 1)))
			},
			wantCode: 20, wantState: "done", wantSame: true, wantStatus: "failed", wantErrCode: "invalid", wantRequests: 1,
			wantLine: "AI opinion (mock): unavailable (invalid",
		},
		{
			name: "an answer whose model is the key is invalid and the key stays out of the files", target: "benign-husky-lint",
			handler: func(w http.ResponseWriter, r *http.Request, _ int) {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("X-Request-Id", r.Header.Get("Authorization"))
				_, _ = w.Write([]byte(strings.Replace(decisionAnswer(0, 0, 1), `"model": "test/model-1"`, `"model": "`+r.Header.Get("Authorization")+`"`, 1)))
			},
			wantCode: 0, wantState: "done", wantSame: true, wantStatus: "failed", wantErrCode: "invalid", wantRequests: 1,
			wantLine: "AI opinion (mock): unavailable (invalid",
		},
		{
			name: "an error body that echoes the key keeps the key out of the files and the output", target: "fake-interview-repo",
			handler: func(w http.ResponseWriter, r *http.Request, _ int) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error": {"message": "bad key ` + r.Header.Get("Authorization") + ` ` + strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ") + `"}}`))
			},
			wantCode: 20, wantState: "done", wantSame: true, wantStatus: "failed", wantErrCode: "status", wantHTTP: 400, wantRequests: 1,
			wantLine: "AI opinion (mock): unavailable (status 400",
		},
		{
			name: "a redirect is not followed", target: "fake-interview-repo",
			handler: func(w http.ResponseWriter, r *http.Request, _ int) {
				http.Redirect(w, r, secondSrv.URL+"/v1/decisions", http.StatusFound)
			},
			wantCode: 20, wantState: "done", wantSame: true, wantStatus: "failed", wantErrCode: "status", wantHTTP: 302, wantRequests: 1,
			wantLine: "AI opinion (mock): unavailable (status 302",
		},
		{
			name: "Ctrl-C during the call cancels the job", target: "benign-husky-lint", interrupt: true,
			handler:  func(_ http.ResponseWriter, r *http.Request, _ int) { <-r.Context().Done() },
			wantCode: 1, wantState: "canceled", wantRequests: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.interrupt && runtime.GOOS == "windows" {
				t.Skip("a console program cannot be sent Ctrl-C from a test on Windows")
			}
			// Given the scan without a provider, for what the static verdict is and how long a scan takes
			target := corpus(t, tt.target)
			if tt.copyAs != "" {
				copied := filepath.Join(t.TempDir(), tt.copyAs)
				if info, err := os.Stat(target); err != nil {
					t.Fatal(err)
				} else if info.IsDir() {
					copyTree(t, target, copied)
				} else {
					writeText(t, copied, readFile(t, target))
				}
				target = copied
			}
			if tt.link {
				target = tt.target
				files := linkServer(t, []byte("x"), []byte("x"))
				_, port, err := net.SplitHostPort(files.Listener.Addr().String())
				if err != nil {
					t.Fatal(err)
				}
				t.Setenv("GALAHAD_TEST_RESOLVE", "files.test=127.0.0.1")
				t.Setenv("GALAHAD_TEST_SINKHOLE", "127.0.0.1:"+port)
			}
			staticHome := t.TempDir()
			start := time.Now()
			_, _, staticCode := scan(t, staticHome, target)
			base := time.Since(start)

			// And a mock provider that is in the config, with the key in the environment
			var mock *mockProvider
			url := tt.url
			if tt.handler != nil {
				mock = newMockProvider(t, tt.handler)
				url = mock.srv.URL
			}
			home := t.TempDir()
			t.Setenv("GALAHAD_HOME", home)
			t.Setenv("QA_DECISION_KEY", decisionKey)
			add := []string{"provider", "add", "mock", "--url", url, "--model", "test/model-1", "--key-env", "QA_DECISION_KEY", "--timeout", fmt.Sprintf("%ds", cmp.Or(tt.timeout, 30))}
			if stdout, stderr, code := run(t, add...); code != 0 {
				t.Fatalf("%v = %d\n%s%s", add, code, stdout, stderr)
			}

			// When it is scanned with --decision
			var stdout, stderr string
			var code int
			start = time.Now()
			if tt.interrupt {
				stdout, stderr, code = scanInterrupted(t, home, mock, append([]string{"--decision", "mock"}, target)...)
			} else {
				stdout, stderr, code = scan(t, home, append([]string{"--decision", "mock"}, target)...)
			}
			elapsed := time.Since(start)

			// Then the exit code and the job are as expected, and the key went nowhere
			if code != tt.wantCode {
				t.Fatalf("exit = %d, want %d\nstdout: %s\nstderr: %s", code, tt.wantCode, stdout, stderr)
			}
			if tt.wantExtra > 0 && elapsed > base+tt.wantExtra {
				t.Errorf("the scan took %v, want at most %v more than the %v without a provider", elapsed, tt.wantExtra, base)
			}
			for _, out := range []string{stdout, stderr} {
				if strings.Contains(out, decisionKey) {
					t.Errorf("the key is in the output:\n%s", out)
				}
			}
			dir := onlyJob(t, home)
			keyFree(t, home, decisionKey)
			if j := readJob(t, dir); j.State != tt.wantState || j.ExitCode != tt.wantCode {
				t.Errorf("job.json = %+v, want state %s, exit code %d", j, tt.wantState, tt.wantCode)
			}
			if mock != nil && mock.requests() != tt.wantRequests {
				t.Errorf("the mock got %d requests, want %d", mock.requests(), tt.wantRequests)
			}
			if got := int(second.Swap(0)); got != tt.wantSecond {
				t.Errorf("the second server got %d requests, want %d", got, tt.wantSecond)
			}
			if tt.wantStatus == "" {
				if _, err := os.Stat(filepath.Join(dir, "report.json")); err == nil {
					t.Error("report.json exists, want none")
				}
				return
			}
			if !strings.Contains(stdout, tt.wantLine) {
				t.Errorf("stdout lacks %q:\n%s", tt.wantLine, stdout)
			}
			rep := readDecisionRecord(t, dir)
			d := rep.Decision
			if d == nil || d.Provider != "mock" || d.Status != tt.wantStatus || d.Reason != tt.wantReason {
				t.Fatalf("decision = %+v, want provider mock, status %s, reason %q", d, tt.wantStatus, tt.wantReason)
			}
			if (d.Error == nil) != (tt.wantErrCode == "") || d.Error != nil && (d.Error.Code != tt.wantErrCode || d.Error.HTTPStatus != tt.wantHTTP) {
				t.Errorf("decision error = %+v, want code %q, status %d", d.Error, tt.wantErrCode, tt.wantHTTP)
			}
			if tt.wantSame {
				static := readDecisionRecord(t, onlyJob(t, staticHome))
				if rep.Verdict != static.Verdict || rep.Score != static.Score || code != staticCode {
					t.Errorf("verdict %s score %d exit %d, want those of the scan without --decision: %s %d %d", rep.Verdict, rep.Score, code, static.Verdict, static.Score, staticCode)
				}
			} else if rep.Verdict != tt.wantVerdict || rep.Score != tt.wantScore {
				t.Errorf("verdict %s score %d, want %s %d", rep.Verdict, rep.Score, tt.wantVerdict, tt.wantScore)
			}
			for _, want := range tt.wantReasons {
				if !slices.ContainsFunc(rep.Reasons, func(r string) bool { return strings.Contains(r, want) }) {
					t.Errorf("reasons = %q, want one containing %q", rep.Reasons, want)
				}
			}
			for _, kind := range tt.wantRedacted {
				if d.Redactions[kind] < 1 {
					t.Errorf("redactions = %v, want %s counted", d.Redactions, kind)
				}
			}
			if d.Sent != nil && mock != nil {
				checkSent(t, mock, d.Sent, d.Redactions)
				hashes := []string{rep.Target.SHA256}
				for _, f := range rep.Files {
					hashes = append(hashes, f.SHA256)
				}
				mock.mu.Lock()
				body := string(mock.bodies[0])
				mock.mu.Unlock()
				for _, h := range hashes {
					if h != "" && strings.Contains(body, h) {
						t.Errorf("the mock received the hash %s", h)
					}
				}
				for _, want := range tt.wantBodyHas {
					if !strings.Contains(body, want) {
						t.Errorf("the mock received no %q:\n%s", want, body)
					}
				}
				for _, absent := range tt.wantBodyAbsent {
					if strings.Contains(body, absent) {
						t.Errorf("the mock received %q:\n%s", absent, body)
					}
				}
			}

			// And "galahad report" shows the same decision
			jobID := filepath.Base(dir)
			rStdout, rStderr, rCode := run(t, "report", jobID)
			if rCode != tt.wantCode || !strings.Contains(rStdout, tt.wantLine) {
				t.Errorf("report = %d, want %d with %q\n%s%s", rCode, tt.wantCode, tt.wantLine, rStdout, rStderr)
			}
			jStdout, _, jCode := run(t, "report", jobID, "--json")
			var asJSON decisionRecord
			if err := json.Unmarshal([]byte(jStdout), &asJSON); err != nil || jCode != tt.wantCode || asJSON.Decision == nil || asJSON.Decision.Status != tt.wantStatus {
				t.Errorf("report --json = %d, %v, want a decision of status %s\n%s", jCode, err, tt.wantStatus, jStdout)
			}
			if strings.Contains(rStdout+rStderr+jStdout, decisionKey) {
				t.Error("the key is in the output of galahad report")
			}
		})
	}
}

func readDecisionRecord(t *testing.T, dir string) decisionRecord {
	t.Helper()
	var rep decisionRecord
	if err := json.Unmarshal([]byte(readFile(t, filepath.Join(dir, "report.json"))), &rep); err != nil {
		t.Fatal(err)
	}
	return rep
}

// checkSent checks that the first body the mock received is decision.sent of the report, encoded
// again, that it holds the key header, and that the redaction counts match its markers.
func checkSent(t *testing.T, mock *mockProvider, sent json.RawMessage, redactions map[string]int) {
	t.Helper()
	mock.mu.Lock()
	body, auth := mock.bodies[0], mock.auths[0]
	mock.mu.Unlock()
	var compact bytes.Buffer
	if err := json.Compact(&compact, sent); err != nil {
		t.Fatal(err)
	}
	if got := unescapeHTML.Replace(compact.String()); got != string(body) {
		t.Errorf("decision.sent encodes to\n%s\nthe mock received\n%s", got, body)
	}
	if auth != "Bearer "+decisionKey {
		t.Errorf("the mock got the Authorization header %q, want the bearer key", auth)
	}
	for _, secret := range []string{"AKIA" + "IOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/" + "bPxRfiCYEXAMPLEKEY"} {
		if bytes.Contains(body, []byte(secret)) {
			t.Errorf("the mock received %q", secret)
		}
	}
	for kind, n := range redactions {
		if got := bytes.Count(body, []byte("[REDACTED:"+kind+"]")); got != n {
			t.Errorf("redactions[%s] = %d, the body holds %d markers", kind, n, got)
		}
	}
}

// scanInterrupted starts "galahad scan", sends it Ctrl-C when the mock has its first request, and
// waits for it to end.
func scanInterrupted(t *testing.T, home string, mock *mockProvider, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	t.Setenv("GALAHAD_HOME", home)
	t.Setenv("GALAHAD_SANDBOX", "fake")
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, binPath, append([]string{"scan"}, args...)...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-mock.first:
	case <-ctx.Done():
		t.Fatal("the mock got no request")
	}
	if err := cmd.Process.Signal(os.Interrupt); err != nil {
		t.Fatal(err)
	}
	err := cmd.Wait()
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return out.String(), errb.String(), code
}

// TestScanDecisionPreBoot checks that "scan --decision" refuses before anything boots (P9, Q4, Q7): exit 2,
// a message on stderr, no job directory, and no request to the provider.
func TestScanDecisionPreBoot(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		args   []string // after "scan"; the target follows
		keyEnv string   // the variable the provider reads
		setKey bool     // the variable is set to the fake key
		// expectations
		wantCode   int
		wantStderr string
	}{
		{
			name: "--no-network with a provider", args: []string{"--decision", "mock", "--no-network"}, keyEnv: "QA_DECISION_KEY", setKey: true,
			wantCode: 2, wantStderr: "--no-network",
		},
		{
			name: "a name that is not a provider", args: []string{"--decision", "nobody"}, keyEnv: "QA_DECISION_KEY", setKey: true,
			wantCode: 2, wantStderr: "no provider nobody",
		},
		{
			name: "a key variable that is not set", args: []string{"--decision", "mock"}, keyEnv: "QA_DECISION_KEY_UNSET",
			wantCode: 2, wantStderr: "$QA_DECISION_KEY_UNSET",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given a provider in the config, a mock that counts requests, and a key variable that is set or not
			mock := newMockProvider(t, answers(decisionAnswer(0, 0, 1)))
			home := t.TempDir()
			t.Setenv("GALAHAD_HOME", home)
			t.Setenv("QA_DECISION_KEY_UNSET", "")
			if tt.setKey {
				t.Setenv(tt.keyEnv, decisionKey)
			}
			add := []string{"provider", "add", "mock", "--url", mock.srv.URL, "--model", "test/model-1", "--key-env", tt.keyEnv}
			if stdout, stderr, code := run(t, add...); code != 0 {
				t.Fatalf("%v = %d\n%s%s", add, code, stdout, stderr)
			}

			// When it is scanned with --decision
			stdout, stderr, code := scan(t, home, append(tt.args, corpus(t, "fake-interview-repo"))...)

			// Then it exits 2 before the boot, with no job and no request
			if code != tt.wantCode || !strings.Contains(stderr, tt.wantStderr) {
				t.Errorf("scan = %d, want %d with %q on stderr\nstdout: %s\nstderr: %s", code, tt.wantCode, tt.wantStderr, stdout, stderr)
			}
			if entries, err := os.ReadDir(filepath.Join(home, "jobs")); err == nil && len(entries) > 0 {
				t.Errorf("jobs = %d entries, want none", len(entries))
			}
			if n := mock.requests(); n != 0 {
				t.Errorf("the mock got %d requests, want 0", n)
			}
			if strings.Contains(stdout+stderr, decisionKey) {
				t.Errorf("the key is in the output:\n%s%s", stdout, stderr)
			}
			keyFree(t, home, decisionKey)
		})
	}
}
