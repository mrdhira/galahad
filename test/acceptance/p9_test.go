package acceptance_test

import (
	"bytes"
	"encoding/json"
	"html"
	"net/http"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// P9 asks: "when an AI opinion is wanted, does it help without ever being able to hurt?". The scenarios are
// in docs/milestones/M3.md section 4, and run through the built binary, the fake sandbox and a mock provider
// over loopback http (vm_p9_test.go runs scenarios 1 and 2 again in a real VM). Where an earlier test already
// has the row of a scenario exactly, the scenario points at it instead of copying it:
//   - 5, the raise: TestScanDecision, rows "a strong opinion raises a clean scan to suspicious" (benign-husky-lint:
//     exit 10, score 20, with the AI reason) and "a strong opinion on a suspicious scan stays suspicious"
//     (p2-typosquat: exit 10, score 65). TestP9NeverMalicious adds the rule that holds for every fixture.
//   - 6, nothing to judge: TestScanDecision, row "nothing to judge is skipped and nothing is sent" (benign-go-cli).
//   - 9, usage: TestScanDecisionPreBoot (an unknown name, an unset key variable, --no-network), and
//     TestProviderTest (provider test: exit 0 against a working mock, 1 against a closed port).
//   - 10, no redirect: TestScanDecision, row "a redirect is not followed" (the second server gets no request).

// p9Key is a fake key, built from pieces so no full literal sits in the source.
const p9Key = "fake-key-" + "p9-" + "7c3e91d4"

// sentInHTML matches the request that report.html shows under "What was sent".
var sentInHTML = regexp.MustCompile(`(?s)<summary>What was sent</summary>.*?<pre>(.*?)</pre>`)

// addMockProvider puts the mock at url in the config of home as "mock", with the key in QA_DECISION_KEY.
func addMockProvider(t *testing.T, home, url string, timeoutSeconds int) {
	t.Helper()
	t.Setenv("GALAHAD_HOME", home)
	t.Setenv("QA_DECISION_KEY", decisionKey)
	add := []string{"provider", "add", "mock", "--url", url, "--model", "test/model-1", "--key-env", "QA_DECISION_KEY", "--timeout", strconv.Itoa(timeoutSeconds) + "s"}
	if stdout, stderr, code := run(t, add...); code != 0 {
		t.Fatalf("%v = %d\n%s%s", add, code, stdout, stderr)
	}
}

// staticScan scans target without a provider, and returns its report, its exit code and how long it took.
func staticScan(t *testing.T, target string) (decisionRecord, int, time.Duration) {
	t.Helper()
	home := t.TempDir()
	start := time.Now()
	_, _, code := scan(t, home, target)
	elapsed := time.Since(start)
	return readDecisionRecord(t, onlyJob(t, home)), code, elapsed
}

// lineOf returns the number of the first line of the file that holds want.
func lineOf(t *testing.T, path, want string) int {
	t.Helper()
	for i, line := range strings.Split(readFile(t, path), "\n") {
		if strings.Contains(line, want) {
			return i + 1
		}
	}
	t.Fatalf("%s has no line with %q", path, want)
	return 0
}

// TestP9MaliciousStands covers scenarios 1, 3 and 4: an AI opinion that says "clean" never lowers a malicious
// verdict, a prompt injection in the input is found and reported, and the request holds no secret.
func TestP9MaliciousStands(t *testing.T) {
	injection := "README.md:" + strconv.Itoa(lineOf(t, filepath.Join(corpus(t, "p9-prompt-injection-repo"), "README.md"), "ignore all previous instructions"))
	awsKey, awsSecret := "AKIA"+"IOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/"+"bPxRfiCYEXAMPLEKEY"
	tests := []struct {
		name string
		// inputs
		target  string // a fixture in testdata/corpus
		handler func(w http.ResponseWriter, r *http.Request, n int)
		// expectations
		wantCode       int
		wantEvidence   []string // "RULE path:line" in report.json
		wantClean      float64  // the clean probability of the verdict answer that came back
		wantReports    []string // in summary.md and report.html
		wantBodyHas    []string // in the body the mock received
		wantBodyAbsent []string
		wantSentInHTML bool // report.html shows the body the mock received
	}{
		{
			name: "scenario 1: a benign opinion on the P1 repo changes nothing", target: "fake-interview-repo", handler: answers(decisionAnswer(0.99, 0.005, 0.005)),
			wantCode: 20, wantEvidence: []string{"GAL-AUTOEXEC-010 .vscode/tasks.json:7", "GAL-EXFIL-001 scripts/setup.js:3"}, wantClean: 0.99,
			wantReports: []string{"AI opinions", "no change: an AI opinion never lowers a verdict"},
		},
		{
			name: "scenario 3: a clean answer to a prompt injection leaves the repo malicious, with the injection reported", target: "p9-prompt-injection-repo", handler: injectionAnswer,
			wantCode: 20, wantEvidence: []string{"GAL-INJECT-001 " + injection, "GAL-AUTOEXEC-010 .vscode/tasks.json:7"}, wantClean: 1,
			wantReports: []string{"GAL-INJECT-001", "tries to steer an AI reviewer", "no change: an AI opinion never lowers a verdict"},
			wantBodyHas: []string{"ignore all previous instructions"},
		},
		{
			name: "scenario 4: the example keys are redacted and the report shows the same request", target: "p9-prompt-injection-repo", handler: injectionAnswer,
			wantCode: 20, wantClean: 1,
			wantBodyHas:    []string{"[REDACTED:aws-access-key]", "[REDACTED:aws-secret]"},
			wantBodyAbsent: []string{awsKey, awsSecret},
			wantSentInHTML: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given the scan without a provider, and a mock provider in the config
			target := corpus(t, tt.target)
			static, staticCode, _ := staticScan(t, target)
			mock := newMockProvider(t, tt.handler)
			home := t.TempDir()
			addMockProvider(t, home, mock.srv.URL, 30)

			// When it is scanned with --decision
			stdout, stderr, code := scan(t, home, "--decision", "mock", target)

			// Then the verdict and the score are those of the scan without it
			if code != tt.wantCode || code != staticCode {
				t.Fatalf("exit = %d, want %d (without --decision: %d)\nstdout: %s\nstderr: %s", code, tt.wantCode, staticCode, stdout, stderr)
			}
			dir := onlyJob(t, home)
			rep := readDecisionRecord(t, dir)
			if rep.Verdict != "malicious" || rep.Verdict != static.Verdict || rep.Score != static.Score {
				t.Errorf("verdict %s score %d, want malicious with the score of the scan without --decision: %s %d", rep.Verdict, rep.Score, static.Verdict, static.Score)
			}
			if j := readJob(t, dir); j.State != "done" || j.ExitCode != tt.wantCode {
				t.Errorf("job.json = %+v, want state done and exit code %d", j, tt.wantCode)
			}
			d := rep.Decision
			if d == nil || d.Status != "ok" || d.Answers == nil || d.Answers.Questions["verdict"].Probabilities["clean"] != tt.wantClean {
				t.Fatalf("decision = %+v, want status ok with clean %g", d, tt.wantClean)
			}
			agent, err := readReport(filepath.Join(dir, "report.json"))
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range tt.wantEvidence {
				rule, at, _ := strings.Cut(want, " ")
				if !hasFinding(agent, rule, at) {
					t.Errorf("no %s at %s in %+v", rule, at, agent.Findings)
				}
			}
			for _, name := range []string{"summary.md", "report.html"} {
				page := readFile(t, filepath.Join(dir, name))
				for _, want := range tt.wantReports {
					if !strings.Contains(page, want) {
						t.Errorf("%s lacks %q", name, want)
					}
				}
			}

			// And the request the mock got is what the report says was sent, with the secrets redacted
			if mock.requests() != 1 {
				t.Fatalf("the mock got %d requests, want 1", mock.requests())
			}
			checkSent(t, mock, d.Sent, d.Redactions)
			mock.mu.Lock()
			body := string(mock.bodies[0])
			mock.mu.Unlock()
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
			if tt.wantSentInHTML {
				page := readFile(t, filepath.Join(dir, "report.html"))
				m := sentInHTML.FindStringSubmatch(page)
				if m == nil {
					t.Fatalf("report.html has no \"What was sent\" block")
				}
				var compact bytes.Buffer
				if err := json.Compact(&compact, []byte(html.UnescapeString(m[1]))); err != nil {
					t.Fatalf("\"What was sent\" is not JSON: %v\n%s", err, m[1])
				}
				if got := unescapeHTML.Replace(compact.String()); got != body {
					t.Errorf("\"What was sent\" in report.html is\n%s\nthe mock received\n%s", got, body)
				}
				kinds := make([]string, 0, len(d.Redactions))
				for kind, n := range d.Redactions {
					kinds = append(kinds, kind+" "+strconv.Itoa(n))
				}
				sort.Strings(kinds)
				if want := "Redactions: " + strings.Join(kinds, ", "); len(kinds) == 0 || !strings.Contains(page, want) {
					t.Errorf("report.html lacks %q", want)
				}
			}
			keyFree(t, home, decisionKey)
		})
	}
}

// TestP9ProviderDown covers scenario 2: a provider that is down, refuses, hangs or answers wrongly never fails a
// scan. Each scan ends in state done with the static verdict, the report gives the error code, and the scan takes
// at most the provider timeout plus 2 s longer than without --decision. TestScanDecision has the rows of
// fake-interview-repo for a closed port, four 503 answers, a hang and text/html, and the row of benign-husky-lint
// for a 402. The rows here are the other half of each pair, and the answers that TestScanDecision does not make.
func TestP9ProviderDown(t *testing.T) {
	const timeout = 2 * time.Second // the provider timeout of every case
	closed := closedPort(t)
	missingID := strings.Replace(decisionAnswer(0.1, 0.1, 0.8), `"steals_secrets"`, `"unasked"`, 1)
	tests := []struct {
		name string
		// inputs
		target  string
		handler func(w http.ResponseWriter, r *http.Request, n int) // nil: nobody listens at url
		url     string
		// expectations
		wantCode     int
		wantEffect   string // in summary.md, with "; the verdict comes from the analysis alone"
		wantErrCode  string
		wantHTTP     int
		wantRequests int
	}{
		{
			name: "a missing question ID is invalid on the P1 repo", target: "fake-interview-repo", handler: answers(missingID),
			wantCode: 20, wantEffect: "unavailable (invalid", wantErrCode: "invalid", wantRequests: 1,
		},
		{
			name: "a missing question ID is invalid on a clean scan", target: "benign-husky-lint", handler: answers(missingID),
			wantCode: 0, wantEffect: "unavailable (invalid", wantErrCode: "invalid", wantRequests: 1,
		},
		{
			name: "a probability of 1.7 is invalid on the P1 repo", target: "fake-interview-repo", handler: answers(decisionAnswer(0, 0, 1.7)),
			wantCode: 20, wantEffect: "unavailable (invalid", wantErrCode: "invalid", wantRequests: 1,
		},
		{
			name: "a probability of 1.7 is invalid on a clean scan", target: "benign-husky-lint", handler: answers(decisionAnswer(0, 0, 1.7)),
			wantCode: 0, wantEffect: "unavailable (invalid", wantErrCode: "invalid", wantRequests: 1,
		},
		{
			name: "a body of 2 MiB is too large on the P1 repo", target: "fake-interview-repo",
			handler:  func(w http.ResponseWriter, r *http.Request, n int) { answers(strings.Repeat(" ", 2<<20))(w, r, n) },
			wantCode: 20, wantEffect: "unavailable (too_large", wantErrCode: "too_large", wantRequests: 1,
		},
		{
			name: "a body of 2 MiB is too large on a clean scan", target: "benign-husky-lint",
			handler:  func(w http.ResponseWriter, r *http.Request, n int) { answers(strings.Repeat(" ", 2<<20))(w, r, n) },
			wantCode: 0, wantEffect: "unavailable (too_large", wantErrCode: "too_large", wantRequests: 1,
		},
		{
			name: "a closed port is a network error on a clean scan", target: "benign-husky-lint", url: closed,
			wantCode: 0, wantEffect: "unavailable (network", wantErrCode: "network",
		},
		{
			name: "four 503 answers are a status error on a clean scan", target: "benign-husky-lint", handler: status(503),
			wantCode: 0, wantEffect: "unavailable (status 503", wantErrCode: "status", wantHTTP: 503, wantRequests: 3,
		},
		{
			name: "a 402 is a status error on the P1 repo", target: "fake-interview-repo", handler: status(402),
			wantCode: 20, wantEffect: "unavailable (status 402: insufficient credit", wantErrCode: "status", wantHTTP: 402, wantRequests: 1,
		},
		{
			name: "a hang past the timeout is a timeout on a clean scan", target: "benign-husky-lint",
			handler:  func(_ http.ResponseWriter, r *http.Request, _ int) { <-r.Context().Done() },
			wantCode: 0, wantEffect: "unavailable (timeout", wantErrCode: "timeout", wantRequests: 1,
		},
		{
			name: "text/html is invalid on a clean scan", target: "benign-husky-lint",
			handler: func(w http.ResponseWriter, _ *http.Request, _ int) {
				w.Header().Set("Content-Type", "text/html")
				_, _ = w.Write([]byte(decisionAnswer(0, 0, 1)))
			},
			wantCode: 0, wantEffect: "unavailable (invalid", wantErrCode: "invalid", wantRequests: 1,
		},
	}
	// Given the scans without a provider, for the static verdicts and how long a scan takes
	type baseline struct {
		rep     decisionRecord
		code    int
		elapsed time.Duration
	}
	base := map[string]baseline{}
	for _, tt := range tests {
		if _, ok := base[tt.target]; !ok {
			rep, code, elapsed := staticScan(t, corpus(t, tt.target))
			base[tt.target] = baseline{rep, code, elapsed}
		}
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// And a provider in the config that fails the way the case says
			var mock *mockProvider
			url := tt.url
			if tt.handler != nil {
				mock = newMockProvider(t, tt.handler)
				url = mock.srv.URL
			}
			home := t.TempDir()
			addMockProvider(t, home, url, int(timeout/time.Second))

			// When it is scanned with --decision
			start := time.Now()
			stdout, stderr, code := scan(t, home, "--decision", "mock", corpus(t, tt.target))
			elapsed := time.Since(start)

			// Then the job is done with the static verdict, and the report gives the error code
			static := base[tt.target]
			if code != tt.wantCode || code != static.code {
				t.Fatalf("exit = %d, want %d (without --decision: %d)\nstdout: %s\nstderr: %s", code, tt.wantCode, static.code, stdout, stderr)
			}
			if limit := static.elapsed + timeout + 2*time.Second; elapsed > limit {
				t.Errorf("the scan took %v, want at most %v (%v without --decision, plus the timeout and 2 s)", elapsed, limit, static.elapsed)
			}
			dir := onlyJob(t, home)
			if j := readJob(t, dir); j.State != "done" || j.ExitCode != tt.wantCode {
				t.Errorf("job.json = %+v, want state done and exit code %d", j, tt.wantCode)
			}
			rep := readDecisionRecord(t, dir)
			if rep.Verdict != static.rep.Verdict || rep.Score != static.rep.Score {
				t.Errorf("verdict %s score %d, want those of the scan without --decision: %s %d", rep.Verdict, rep.Score, static.rep.Verdict, static.rep.Score)
			}
			d := rep.Decision
			if d == nil || d.Status != "failed" || d.Error == nil || d.Error.Code != tt.wantErrCode || d.Error.HTTPStatus != tt.wantHTTP {
				t.Fatalf("decision = %+v, want status failed with code %q and HTTP status %d", d, tt.wantErrCode, tt.wantHTTP)
			}
			if !strings.Contains(stdout, "AI opinion (mock): "+tt.wantEffect) {
				t.Errorf("stdout lacks the AI line with %q:\n%s", tt.wantEffect, stdout)
			}
			for _, name := range []string{"summary.md", "report.html"} {
				// summary.md escapes Markdown punctuation with a backslash
				if page := strings.ReplaceAll(readFile(t, filepath.Join(dir, name)), `\`, ""); !strings.Contains(page, tt.wantEffect) || !strings.Contains(page, "the verdict comes from the analysis alone") {
					t.Errorf("%s lacks %q and the note that the verdict comes from the analysis alone", name, tt.wantEffect)
				}
			}
			if mock != nil && mock.requests() != tt.wantRequests {
				t.Errorf("the mock got %d requests, want %d", mock.requests(), tt.wantRequests)
			}
			keyFree(t, home, decisionKey)
		})
	}
}

// TestP9NeverMalicious covers the last rule of scenario 5: whatever the corpus fixture, a mock that answers
// "malicious" 0.99 makes no scan exit 20 that does not exit 20 without --decision, lowers nothing, and adds at
// most 15 points (69 at most when it raises).
func TestP9NeverMalicious(t *testing.T) {
	mock := newMockProvider(t, answers(decisionAnswer(0.005, 0.005, 0.99)))
	for _, tt := range corpusCases() {
		t.Run(tt.name, func(t *testing.T) {
			// Given a fixture, scanned without a provider
			target := tt.target(t)
			static, staticCode, _ := staticScan(t, target)
			home := t.TempDir()
			addMockProvider(t, home, mock.srv.URL, 30)

			// When it is scanned with --decision
			stdout, stderr, code := scan(t, home, "--decision", "mock", target)

			// Then the verdict is at most one step higher, and only from clean to suspicious
			if code == 20 && staticCode != 20 {
				t.Errorf("exit = 20, want %d as without --decision", staticCode)
			}
			if code != staticCode && (staticCode != 0 || code != 10) {
				t.Fatalf("exit = %d, want %d as without --decision, or 10 when that is 0\nstdout: %s\nstderr: %s", code, staticCode, stdout, stderr)
			}
			rep := readDecisionRecord(t, onlyJob(t, home))
			if rep.Score < static.Score || rep.Score > static.Score+15 || code != staticCode && rep.Score > 69 {
				t.Errorf("score = %d, want %d to %d (69 at most when raised)", rep.Score, static.Score, static.Score+15)
			}
			if rep.Decision == nil || rep.Decision.Status == "failed" {
				t.Errorf("decision = %+v, want the mock to have answered or the scan to have skipped it", rep.Decision)
			}
		})
	}
}

// TestP9NoOptIn covers scenario 7: with a provider in the config and no --decision, nothing is sent and
// nothing changes. The mock gets no request, report.json has no decision, and every case of the M1 and M2
// corpus table gives what TestScanCorpus expects.
func TestP9NoOptIn(t *testing.T) {
	mock := newMockProvider(t, answers(decisionAnswer(0, 0, 1)))
	for _, tt := range corpusCases() {
		t.Run(tt.name, func(t *testing.T) {
			// Given a fixture and a provider in the config, with its key variable set
			target := tt.target(t)
			home := t.TempDir()
			addMockProvider(t, home, mock.srv.URL, 30)

			// When it is scanned without --decision
			stdout, stderr, code := scan(t, home, target)

			// Then the result is the one of the corpus table, with no AI line and no decision
			if code != tt.wantCode {
				t.Fatalf("exit = %d, want %d\nstdout: %s\nstderr: %s", code, tt.wantCode, stdout, stderr)
			}
			dir := onlyJob(t, home)
			rep, err := readReport(filepath.Join(dir, "report.json"))
			if err != nil {
				t.Fatal(err)
			}
			checkCorpus(t, tt, rep, dir)
			if j := readJob(t, dir); j.State != "done" || j.ExitCode != tt.wantCode || j.Verdict != rep.Verdict {
				t.Errorf("job.json = %+v, want state done, exit code %d, verdict %q", j, tt.wantCode, rep.Verdict)
			}
			var raw map[string]json.RawMessage
			if err := json.Unmarshal([]byte(readFile(t, filepath.Join(dir, "report.json"))), &raw); err != nil {
				t.Fatal(err)
			}
			if _, ok := raw["decision"]; ok {
				t.Error("report.json has a decision, want none")
			}
			for _, page := range []string{stdout, readFile(t, filepath.Join(dir, "summary.md")), readFile(t, filepath.Join(dir, "report.html"))} {
				if strings.Contains(page, "AI opinion") {
					t.Errorf("a report mentions an AI opinion:\n%s", page)
				}
			}
			if n := mock.requests(); n != 0 {
				t.Errorf("the mock got %d requests, want 0", n)
			}
		})
	}
}

// TestP9Keys covers scenario 8: NETRA_API_KEY holds a fake value, and the mock checks the header. The steps are
// provider add, list and test, two scans (the second against a mock that echoes the key), report and jobs. The
// value is in no output of a step and in no file under GALAHAD_HOME afterwards.
func TestP9Keys(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		args []string // "{mock}" is the URL of the mock, "{id}" the ID of the first scan, "{corpus}" testdata/corpus
		// expectations
		wantCode   int
		wantStdout []string
		wantStderr []string
	}{
		{
			name: "provider add netra with the URL of the mock keeps the preset key variable", args: []string{"provider", "add", "netra", "--url", "{mock}"},
			wantCode: 0, wantStdout: []string{"added provider netra"},
		},
		{
			name: "provider list shows that the key is set", args: []string{"provider", "list"},
			wantCode: 0, wantStdout: []string{"NETRA_API_KEY  yes"},
		},
		{
			name: "provider test gets the answers", args: []string{"provider", "test", "netra"},
			wantCode: 0, wantStdout: []string{"provider netra: ok", "request id: req_t34b"},
		},
		{
			name: "a scan gets an opinion", args: []string{"scan", "--decision", "netra", "{corpus}/fake-interview-repo"},
			wantCode: 20, wantStdout: []string{"AI opinion (netra): malicious 80%, no change"},
		},
		{
			name: "a scan against a mock that echoes the key is a failed call and no more", args: []string{"scan", "--decision", "netra", "{corpus}/benign-husky-lint"},
			wantCode: 0, wantStdout: []string{"AI opinion (netra): unavailable (status 400"},
		},
		{
			name: "report shows the first scan again", args: []string{"report", "{id}"},
			wantCode: 20, wantStdout: []string{"AI opinion (netra): malicious 80%, no change"},
		},
		{
			name: "jobs lists both scans", args: []string{"jobs"},
			wantCode: 0, wantStdout: []string{"{id}", "fake-interview-repo", "benign-husky-lint"},
		},
	}
	// Given a fake key in the environment, and a mock that checks it: it answers the test, answers the first
	// scan, and echoes the key in the body and in a header for the second scan
	mock := newMockProvider(t, func(w http.ResponseWriter, r *http.Request, n int) {
		switch n {
		case 1:
			answers(providerTestAnswer)(w, r, n)
		case 2:
			answers(decisionAnswer(0.1, 0.1, 0.8))(w, r, n)
		default:
			w.Header().Set("X-Request-Id", r.Header.Get("Authorization"))
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error": "bad key ` + r.Header.Get("Authorization") + ` ` + strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ") + `"}`))
		}
	})
	home := t.TempDir()
	t.Setenv("GALAHAD_HOME", home)
	t.Setenv("GALAHAD_SANDBOX", "fake")
	t.Setenv("NETRA_API_KEY", p9Key)
	var seen []string // the job directories of the scans so far
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// When the step runs
			id := ""
			if len(seen) > 0 {
				id = seen[0]
			}
			args := make([]string, len(tt.args))
			for i, a := range tt.args {
				a = strings.ReplaceAll(a, "{mock}", mock.srv.URL)
				a = strings.ReplaceAll(a, "{id}", id)
				args[i] = strings.ReplaceAll(a, "{corpus}", corpus(t, "."))
			}
			stdout, stderr, code := run(t, args...)

			// Then the exit code and the output are as expected, and the key is not in the output
			if code != tt.wantCode {
				t.Fatalf("exit = %d, want %d\nstdout: %s\nstderr: %s", code, tt.wantCode, stdout, stderr)
			}
			for _, w := range tt.wantStdout {
				if w = strings.ReplaceAll(w, "{id}", id); !strings.Contains(stdout, w) {
					t.Errorf("stdout lacks %q:\n%s", w, stdout)
				}
			}
			for _, w := range tt.wantStderr {
				if !strings.Contains(stderr, w) {
					t.Errorf("stderr lacks %q:\n%s", w, stderr)
				}
			}
			if strings.Contains(stdout+stderr, p9Key) {
				t.Errorf("the key is in the output:\n%s%s", stdout, stderr)
			}
			if args[0] == "scan" {
				seen = append(seen, filepath.Base(newJob(t, home, seen)))
			}
		})
	}

	// Then every request carried the key, and the key is in no file under GALAHAD_HOME
	mock.mu.Lock()
	auths := slices.Clone(mock.auths)
	mock.mu.Unlock()
	if want := []string{"Bearer " + p9Key, "Bearer " + p9Key, "Bearer " + p9Key}; !slices.Equal(auths, want) {
		t.Errorf("the mock got the Authorization headers %q, want the bearer key three times", auths)
	}
	keyFree(t, home, p9Key)
}
