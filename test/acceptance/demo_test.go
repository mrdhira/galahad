package acceptance_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDemo runs the M1 demo from docs/milestones/M1.md section 5, step by step, with the
// same arguments. "{out}" stands for the output directory and "{corpus}" for testdata/corpus.
// The analyze steps pass --unsafe-host because the demo runs on the host until M2 moves it into a VM.
func TestDemo(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		args []string
		// expectations
		wantCode     int
		wantStdout   []string // each must be in stdout
		wantEvidence []string // "RULE path:line" that must be in report.json
		wantFiles    []string // files that must exist in the output directory
		wantSummary  []string // each must be in summary.md, which the demo has the reader open
		wantVerdict  string   // empty means the step writes no report
	}{
		{
			name:       "galahad-agent version prints the build",
			args:       []string{"version"},
			wantCode:   0,
			wantStdout: []string{"galahad-agent " + stampedVersion},
		},
		{
			name:         "fake-interview-repo is malicious with tasks.json:7 and setup.js:3 as evidence",
			args:         []string{"analyze", "--unsafe-host", "-o", "{out}", "{corpus}/fake-interview-repo"},
			wantCode:     20,
			wantStdout:   []string{"Verdict: MALICIOUS", "report.html"},
			wantEvidence: []string{"GAL-AUTOEXEC-010 .vscode/tasks.json:7", "GAL-EXFIL-001 scripts/setup.js:3"},
			wantSummary:  []string{".vscode/tasks.json:7", "scripts/setup.js:3"},
			wantFiles:    []string{"summary.md", "report.html", "report.json"},
			wantVerdict:  "malicious",
		},
		{
			name:        "benign-express-app is clean",
			args:        []string{"analyze", "--unsafe-host", "-o", "{out}", "{corpus}/benign-express-app"},
			wantCode:    0,
			wantStdout:  []string{"Verdict: CLEAN"},
			wantFiles:   []string{"summary.md", "report.html", "report.json"},
			wantVerdict: "clean",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given the built agent and the demo fixtures
			out := filepath.Join(t.TempDir(), "demo")
			args := make([]string, len(tt.args))
			for i, a := range tt.args {
				a = strings.ReplaceAll(a, "{out}", out)
				args[i] = strings.ReplaceAll(a, "{corpus}", corpus(t, "."))
			}
			// When the demo step runs
			stdout, stderr, code := runAgent(t, args...)
			// Then the exit code, terminal summary and report files match
			if code != tt.wantCode {
				t.Fatalf("exit = %d, want %d\nstdout: %s\nstderr: %s", code, tt.wantCode, stdout, stderr)
			}
			for _, want := range tt.wantStdout {
				if !strings.Contains(stdout, want) {
					t.Errorf("stdout lacks %q:\n%s", want, stdout)
				}
			}
			for _, name := range tt.wantFiles {
				if st, err := os.Stat(filepath.Join(out, name)); err != nil || st.Size() == 0 {
					t.Errorf("%s missing or empty: %v", name, err)
				}
			}
			if tt.wantVerdict == "" {
				return
			}
			rep, err := readReport(filepath.Join(out, "report.json"))
			if err != nil {
				t.Fatal(err)
			}
			if rep.Verdict != tt.wantVerdict {
				t.Errorf("verdict = %q, want %q", rep.Verdict, tt.wantVerdict)
			}
			for _, want := range tt.wantEvidence {
				rule, at, _ := strings.Cut(want, " ")
				if !hasFinding(rep, rule, at) {
					t.Errorf("no %s at %s in %+v", rule, at, rep.Findings)
				}
			}
			for _, want := range tt.wantSummary {
				if md := readFile(t, filepath.Join(out, "summary.md")); !strings.Contains(md, want) {
					t.Errorf("summary.md lacks %q:\n%s", want, md)
				}
			}
			// And the summary the reader opens has no live link: every URL is defanged
			for _, name := range []string{"summary.md", "report.html"} {
				if m := liveLink.FindString(readFile(t, filepath.Join(out, name))); m != "" {
					t.Errorf("%s has a live link %q", name, m)
				}
			}
		})
	}
}
