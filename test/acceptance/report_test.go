package acceptance_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestAgentAnalyzeReports(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		eicar   bool
		content string // notes.txt
		// expectations
		wantCode         int
		wantMD           []string
		wantHTMLAbsent   []string
		wantStdout       []string
		wantStdoutAbsent []string
	}{
		{
			name:             "eicar and a sinkhole url produce three defanged reports",
			eicar:            true,
			content:          "beacon: https://collect.sinkhole.test/k\n",
			wantCode:         20,
			wantMD:           []string{"GAL-SIG-001", "hxxps://collect[.]sinkhole[.]test/k"},
			wantHTMLAbsent:   []string{"<script", "href=", "https://collect.sinkhole.test"},
			wantStdout:       []string{"Verdict: MALICIOUS", "CRITICAL GAL-SIG-001", "report.html", "summary.md", "report.json"},
			wantStdoutAbsent: []string{"https://collect.sinkhole.test", "\x1b["},
		},
		{
			name:             "benign twin is clean and still writes the reports",
			content:          "hello world\n",
			wantCode:         0,
			wantMD:           []string{"Verdict: CLEAN"},
			wantHTMLAbsent:   []string{"<script", "href="},
			wantStdout:       []string{"Verdict: CLEAN", "report.html"},
			wantStdoutAbsent: []string{"\x1b["},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given a target directory built at test time
			dir := t.TempDir()
			if tt.eicar {
				writeEICAR(t, dir)
			}
			if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte(tt.content), 0o600); err != nil {
				t.Fatal(err)
			}
			out := filepath.Join(t.TempDir(), "out")

			// When the agent analyzes it
			stdout, stderr, code := runAgent(t, "analyze", "-o", out, dir)

			// Then the exit code, the three files and the terminal summary match
			if code != tt.wantCode {
				t.Fatalf("exit = %d, want %d\nstdout: %s\nstderr: %s", code, tt.wantCode, stdout, stderr)
			}
			for _, name := range []string{"report.json", "summary.md", "report.html"} {
				st, err := os.Stat(filepath.Join(out, name))
				if err != nil {
					t.Fatal(err)
				}
				if runtime.GOOS != "windows" && st.Mode().Perm() != 0o600 {
					t.Errorf("%s mode = %v, want 0600", name, st.Mode().Perm())
				}
			}
			md, html := readFile(t, filepath.Join(out, "summary.md")), readFile(t, filepath.Join(out, "report.html"))
			for _, w := range tt.wantMD {
				if !strings.Contains(md, w) {
					t.Errorf("summary.md lacks %q:\n%s", w, md)
				}
			}
			for _, a := range tt.wantHTMLAbsent {
				if strings.Contains(html, a) {
					t.Errorf("report.html contains %q", a)
				}
			}
			for _, w := range tt.wantStdout {
				if !strings.Contains(stdout, w) {
					t.Errorf("stdout lacks %q:\n%s", w, stdout)
				}
			}
			for _, a := range tt.wantStdoutAbsent {
				if strings.Contains(stdout, a) {
					t.Errorf("stdout contains %q:\n%s", a, stdout)
				}
			}
		})
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
