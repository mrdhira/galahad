//go:build vm

package acceptance_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestVMP9 runs scenario 1 and the closed-port case of scenario 2 of P9 (docs/milestones/M3.md section 4) through
// the real Firecracker backend. The decision step runs on the host after the VM is gone, so the mock is a loopback
// server of the test (the galahadtest build accepts http on loopback), as in p9_test.go. The state directory of the
// job is the one that holds the images, so the provider is taken out of its config afterwards.
func TestVMP9(t *testing.T) {
	closed := closedPort(t)
	mock := newMockProvider(t, answers(decisionAnswer(0.99, 0.005, 0.005)))
	tests := []struct {
		name string
		// inputs
		target string // a fixture in testdata/corpus
		url    string
		// expectations
		wantCode     int
		wantEvidence []string // "RULE path:line" in report.json
		wantStatus   string
		wantErrCode  string
		wantEffect   string // in summary.md
		wantRequests int
	}{
		{
			name: "scenario 1: a benign opinion on the P1 repo changes nothing", target: "fake-interview-repo", url: mock.srv.URL,
			wantCode: 20, wantEvidence: []string{"GAL-AUTOEXEC-010 .vscode/tasks.json:7", "GAL-EXFIL-001 scripts/setup.js:3"},
			wantStatus: "ok", wantEffect: "no change: an AI opinion never lowers a verdict", wantRequests: 1,
		},
		{
			name: "scenario 2: a closed port leaves the P1 repo malicious", target: "fake-interview-repo", url: closed,
			wantCode: 20, wantEvidence: []string{"GAL-AUTOEXEC-010 .vscode/tasks.json:7", "GAL-EXFIL-001 scripts/setup.js:3"},
			wantStatus: "failed", wantErrCode: "network", wantEffect: "unavailable (network",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given a provider in the config of the state directory, and its key in the environment
			home := vmHome(t)
			t.Cleanup(func() { _ = os.Remove(filepath.Join(home, "config.json")) })
			addMockProvider(t, home, tt.url, 30)
			before := mock.requests()

			// When the fixture is scanned in a VM with --decision
			dir := scanInVM(t, home, tt.wantCode, "--decision", "mock", corpus(t, tt.target))

			// Then the job is done, the report has the evidence, and the opinion is as the mock made it
			if j := readJob(t, dir); j.State != "done" || j.ExitCode != tt.wantCode {
				t.Errorf("job.json = %+v, want state done and exit code %d", j, tt.wantCode)
			}
			rep, err := readReport(filepath.Join(dir, "report.json"))
			if err != nil {
				t.Fatal(err)
			}
			if rep.Verdict != "malicious" {
				t.Errorf("verdict = %q, want malicious", rep.Verdict)
			}
			for _, want := range tt.wantEvidence {
				rule, at, _ := strings.Cut(want, " ")
				if !hasFinding(rep, rule, at) {
					t.Errorf("no %s at %s in %+v", rule, at, rep.Findings)
				}
			}
			d := readDecisionRecord(t, dir).Decision
			if d == nil || d.Status != tt.wantStatus || (d.Error == nil) != (tt.wantErrCode == "") || d.Error != nil && d.Error.Code != tt.wantErrCode {
				t.Fatalf("decision = %+v, want status %s with error code %q", d, tt.wantStatus, tt.wantErrCode)
			}
			if got := mock.requests() - before; got != tt.wantRequests {
				t.Errorf("the mock got %d requests, want %d", got, tt.wantRequests)
			}
			// summary.md escapes Markdown punctuation with a backslash
			if page := strings.ReplaceAll(readFile(t, filepath.Join(dir, "summary.md")), `\`, ""); !strings.Contains(page, tt.wantEffect) {
				t.Errorf("summary.md lacks %q", tt.wantEffect)
			}
			keyFree(t, dir, decisionKey)
		})
	}
}
