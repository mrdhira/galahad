package tools_test

import (
	"cmp"
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mrdhira/galahad/internal/analyze/tools"
)

func TestYARA(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		fake      fakeRun
		noRules   bool
		noBinary  bool
		fileScan  bool          // the target is a file and not a directory
		budget    time.Duration // time the job has left; a generous one when zero
		wantFlags []string      // arguments the scanner must get; "RULES" and "ROOT" stand for the rules file and the target
		// expectations
		wantFindings []string
		wantErr      string
	}{
		{
			name:         "a match becomes a finding with a path relative to the target",
			fake:         fakeRun{out: "Suspicious_Script %ROOT%/scripts/setup.js\n"},
			wantFlags:    []string{"-C", "-N", "-r", "-f", "RULES", "ROOT"},
			wantFindings: []string{"GAL-YARA-001 scripts/setup.js Suspicious_Script"},
		},
		{name: "no match is a clean scan", fake: fakeRun{}},
		{name: "missing rules", noRules: true, wantErr: "no rules at"},
		{name: "missing binary", noBinary: true, wantErr: "yara is not installed"},
		{name: "output over the cap kills the tool", fake: fakeRun{mode: "flood"}, wantErr: "output is over"},
		{name: "a hang ends at the time limit", fake: fakeRun{mode: "hang"}, budget: 300 * time.Millisecond, wantErr: "timed out"},
		{name: "a crash", fake: fakeRun{exit: 1, err: "error: rules file is corrupt\nmore"}, wantErr: "exited with code 1: error: rules file is corrupt"},
		{name: "a match is not trusted when the exit code says error", fake: fakeRun{out: "Rule_A %ROOT%/a\n", exit: 1}, wantErr: "exited with code 1"},
		{
			name:         "two rules on one file and a file with spaces",
			fake:         fakeRun{out: "Rule_A %ROOT%/a b.exe\nRule_B %ROOT%/a b.exe\nRule_A %ROOT%/c/d.dll\n"},
			wantFindings: []string{"GAL-YARA-001 a b.exe Rule_A", "GAL-YARA-001 a b.exe Rule_B", "GAL-YARA-001 c/d.dll Rule_A"},
		},
		{
			name:         "a file name with a colon",
			fake:         fakeRun{out: "Rule_A %ROOT%/x: y.txt\n"},
			wantFindings: []string{"GAL-YARA-001 x: y.txt Rule_A"},
		},
		{
			name:         "a file name with a newline",
			fake:         fakeRun{out: "Rule_A %ROOT%/line1\nline2.txt\nRule_B %ROOT%/b\n"},
			wantFindings: []string{`GAL-YARA-001 line1\u000aline2.txt Rule_A`, "GAL-YARA-001 b Rule_B"},
		},
		{
			name:         "a file name with escape codes is cleaned",
			fake:         fakeRun{out: "Rule_A %ROOT%/\x1b[2J.txt\n"},
			wantFindings: []string{`GAL-YARA-001 \u001b[2J.txt Rule_A`},
		},
		{
			name:         "a file target gives its own name",
			fake:         fakeRun{out: "Rule_A %ROOT%\n"},
			fileScan:     true,
			wantFindings: []string{"GAL-YARA-001 payload.bin Rule_A"},
		},
		{name: "output that does not end in a newline", fake: fakeRun{out: "Rule_A %ROOT%/a"}, wantErr: "does not end in a newline"},
		{name: "a first line that is not a match", fake: fakeRun{out: "warning: odd\nRule_A %ROOT%/a\n"}, wantErr: "not a match"},
		{name: "a path outside the target", fake: fakeRun{out: "Rule_A /etc/passwd\n"}, wantErr: "not a match"},
		{name: "a rule name that is not an identifier", fake: fakeRun{out: "bad-rule %ROOT%/a\n"}, wantErr: "not a match"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			argsFile := useFake(t, tt.fake)
			rules := filepath.Join(t.TempDir(), "core.yarc")
			if !tt.noRules {
				if err := os.WriteFile(rules, nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if tt.noBinary {
				t.Setenv("PATH", t.TempDir())
			}
			target := t.TempDir()
			if tt.fileScan {
				target = filepath.Join(target, "payload.bin")
				if err := os.WriteFile(target, []byte("harmless"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), cmp.Or(tt.budget, time.Minute))
			defer cancel()

			fs, err := tools.NewYARA(rules).Run(ctx, target)

			if (err != nil) != (tt.wantErr != "") || (err != nil && !strings.Contains(err.Error(), tt.wantErr)) {
				t.Fatalf("error = %v, want %q", err, tt.wantErr)
			}
			if got := format(fs); !slices.Equal(got, tt.wantFindings) {
				t.Errorf("findings = %q, want %q", got, tt.wantFindings)
			}
			if tt.wantFlags != nil {
				args, err := os.ReadFile(argsFile)
				if err != nil {
					t.Fatal(err)
				}
				want := make([]string, len(tt.wantFlags))
				for i, f := range tt.wantFlags {
					want[i] = strings.NewReplacer("RULES", rules, "ROOT", target).Replace(f)
				}
				if got := strings.Split(string(args), "\n"); !slices.Equal(got, want) {
					t.Errorf("arguments = %q, want %q", got, want)
				}
			}
		})
	}
}
