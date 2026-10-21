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

func TestClamAV(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		fake      fakeRun
		noSigs    bool
		noBinary  bool
		fileScan  bool          // the target is a file and not a directory
		budget    time.Duration // time the job has left; a generous one when zero
		wantFlags []string      // arguments the scanner must get; "ROOT" stands for the target
		// expectations
		wantFindings []string // "%ROOTNAME%" stands for the name of the target
		wantNote     string
		wantErr      string
	}{
		{
			name:         "a hit becomes a finding with a path relative to the target",
			fake:         fakeRun{out: "%ROOT%/scripts/setup.js: Win.Test.Sample-1 FOUND\n", exit: 1},
			wantFlags:    []string{"-r", "--database=DB", "--infected", "--no-summary", "--heuristic-alerts=no", "--max-filesize=32M", "--max-scansize=256M", "--max-recursion=6", "ROOT"},
			wantFindings: []string{"GAL-AV-001 scripts/setup.js Win.Test.Sample-1"},
		},
		{name: "no hit is a clean scan", fake: fakeRun{}},
		{name: "a lot of stderr does not break a clean scan", fake: fakeRun{err: strings.Repeat("LibClamAV Warning: odd\n", 400)}},
		{
			name:         "a lot of stderr does not break a hit",
			fake:         fakeRun{out: "%ROOT%/a: Sig.One-1 FOUND\n", exit: 1, err: strings.Repeat("LibClamAV Warning: odd\n", 400)},
			wantFindings: []string{"GAL-AV-001 a Sig.One-1"},
		},
		{name: "missing signatures", noSigs: true, wantErr: "no signatures in"},
		{name: "missing binary", noBinary: true, wantErr: "clamscan is not installed"},
		{name: "output over the cap kills the tool", fake: fakeRun{mode: "flood"}, wantErr: "output is over"},
		{name: "a hang ends at the time limit", fake: fakeRun{mode: "hang"}, budget: 300 * time.Millisecond, wantErr: "timed out"},
		{name: "exit 0 with output is not trusted", fake: fakeRun{out: "%ROOT%/a: Sig FOUND\n"}, wantErr: "exit 0 with output"},
		{
			name:         "exit 1 without a hit still reports the hit on the target",
			fake:         fakeRun{exit: 1},
			wantFindings: []string{"GAL-AV-001 %ROOTNAME% unparsed clamscan hit"},
			wantNote:     "exit 1 without a hit",
		},
		{
			name:         "two hits and a file with spaces",
			fake:         fakeRun{out: "%ROOT%/a b.exe: Sig.One-1 FOUND\n%ROOT%/c/d.dll: Sig.Two-2 FOUND\n", exit: 1},
			wantFindings: []string{"GAL-AV-001 a b.exe Sig.One-1", "GAL-AV-001 c/d.dll Sig.Two-2"},
		},
		{
			name:         "a file name with a colon and a space",
			fake:         fakeRun{out: "%ROOT%/x: y: z.txt: Sig.One-1 FOUND\n", exit: 1},
			wantFindings: []string{"GAL-AV-001 x: y: z.txt Sig.One-1"},
		},
		{
			name:         "a file name with a newline",
			fake:         fakeRun{out: "%ROOT%/line1\nline2.txt: Sig.One-1 FOUND\n%ROOT%/b: Sig.Two-2 FOUND\n", exit: 1},
			wantFindings: []string{`GAL-AV-001 line1\u000aline2.txt Sig.One-1`, "GAL-AV-001 b Sig.Two-2"},
		},
		{
			name:         "a file name with a newline and a FOUND line inside",
			fake:         fakeRun{out: "%ROOT%/a FOUND\nb.txt: Sig.One-1 FOUND\n", exit: 1},
			wantFindings: []string{`GAL-AV-001 a FOUND\u000ab.txt Sig.One-1`},
		},
		{
			name:         "a file name with escape codes is cleaned",
			fake:         fakeRun{out: "%ROOT%/\x1b[2J.txt: Sig.One-1 FOUND\n", exit: 1},
			wantFindings: []string{`GAL-AV-001 \u001b[2J.txt Sig.One-1`},
		},
		{
			name:         "a file target gives its own name",
			fake:         fakeRun{out: "%ROOT%: Sig.One-1 FOUND\n", exit: 1},
			fileScan:     true,
			wantFindings: []string{"GAL-AV-001 payload.bin Sig.One-1"},
		},
		{
			name:         "a path outside the target",
			fake:         fakeRun{out: "/etc/passwd: Sig.One-1 FOUND\n", exit: 1},
			wantFindings: []string{"GAL-AV-001 %ROOTNAME% unparsed clamscan hit"},
			wantNote:     "not a hit",
		},
		{
			name:         "a line that is not a hit keeps the hits before it",
			fake:         fakeRun{out: "%ROOT%/a: Sig.One-1 FOUND\nWARNING: odd\n", exit: 1},
			wantFindings: []string{"GAL-AV-001 a Sig.One-1", "GAL-AV-001 %ROOTNAME% unparsed clamscan hit"},
			wantNote:     "does not end in FOUND",
		},
		{
			name:         "a signature with a space",
			fake:         fakeRun{out: "%ROOT%/a: Sig One FOUND\n", exit: 1},
			wantFindings: []string{"GAL-AV-001 %ROOTNAME% unparsed clamscan hit"},
			wantNote:     "not a hit",
		},
		{
			name:         "a directory named to look like a hit does not hide the real one",
			fake:         fakeRun{out: "%ROOT%/d: X FOUND\nz/m: Real.Sig FOUND\n", exit: 1},
			wantFindings: []string{"GAL-AV-001 d X", "GAL-AV-001 %ROOTNAME% unparsed clamscan hit"},
			wantNote:     "not a hit",
		},
		{
			name:         "a file named to look like a hit does not hide the real one",
			fake:         fakeRun{out: "%ROOT%/a: X FOUND\nb: Real.Sig FOUND\n", exit: 1},
			wantFindings: []string{"GAL-AV-001 a X", "GAL-AV-001 %ROOTNAME% unparsed clamscan hit"},
			wantNote:     "not a hit",
		},
		{name: "a crash", fake: fakeRun{exit: 2, err: "ERROR: Can't open database\nmore"}, wantErr: "exited with code 2: ERROR: Can't open database"},
		{
			name:         "a hit that comes with file errors is reported",
			fake:         fakeRun{out: "%ROOT%/a: Sig.One-1 FOUND\n", exit: 2, err: "ERROR: Can't open file\n"},
			wantFindings: []string{"GAL-AV-001 a Sig.One-1"},
			wantNote:     "exit 2: some files could not be scanned",
		},
		{
			name:         "a hit that comes with file errors keeps its note when other output does not parse",
			fake:         fakeRun{out: "%ROOT%/a: Sig.One-1 FOUND\nWARNING: odd\n", exit: 2},
			wantFindings: []string{"GAL-AV-001 a Sig.One-1"},
			wantNote:     "does not end in FOUND",
		},
		{name: "exit 2 with output that is not a hit is an error", fake: fakeRun{out: "WARNING: odd\n", exit: 2}, wantErr: "exited with code 2"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			argsFile := useFake(t, tt.fake)
			db := t.TempDir()
			if tt.noSigs {
				db = filepath.Join(db, "missing")
			} else if err := os.WriteFile(filepath.Join(db, "main.cvd"), nil, 0o600); err != nil {
				t.Fatal(err)
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

			res, err := tools.NewClamAV(db).Run(ctx, target)

			if (err != nil) != (tt.wantErr != "") || (err != nil && !strings.Contains(err.Error(), tt.wantErr)) {
				t.Fatalf("error = %v, want %q", err, tt.wantErr)
			}
			want := slices.Clone(tt.wantFindings)
			for i := range want {
				want[i] = strings.ReplaceAll(want[i], "%ROOTNAME%", filepath.Base(target))
			}
			if got := format(res.Findings); !slices.Equal(got, want) {
				t.Errorf("findings = %q, want %q", got, want)
			}
			if !strings.Contains(res.Note, tt.wantNote) || (tt.wantNote == "" && res.Note != "") {
				t.Errorf("note = %q, want %q", res.Note, tt.wantNote)
			}
			if tt.wantFlags != nil {
				args, err := os.ReadFile(argsFile)
				if err != nil {
					t.Fatal(err)
				}
				want := make([]string, len(tt.wantFlags))
				for i, f := range tt.wantFlags {
					want[i] = strings.NewReplacer("DB", db, "ROOT", target).Replace(f)
				}
				if got := strings.Split(string(args), "\n"); !slices.Equal(got, want) {
					t.Errorf("arguments = %q, want %q", got, want)
				}
			}
		})
	}
}
