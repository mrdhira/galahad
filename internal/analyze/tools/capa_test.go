package tools_test

import (
	"cmp"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mrdhira/galahad/internal/analyze/tools"
	"github.com/mrdhira/galahad/internal/protocol"
)

// Harmless headers: they only identify a file as a PE, ELF or Mach-O file.
var (
	peFile    = peHeader()
	elfFile   = append([]byte("\x7fELF"), make([]byte, 60)...)
	machoFile = append([]byte{0xcf, 0xfa, 0xed, 0xfe}, make([]byte, 60)...)
)

// peHeader is a DOS header whose PE offset points at the PE signature.
func peHeader() []byte {
	b := make([]byte, 0x80)
	copy(b, "MZ")
	b[0x3c] = 0x40
	copy(b[0x40:], "PE\x00\x00")
	return b
}

// writeTree writes the files, named relative to dir with slashes, and creates their directories.
func writeTree(t *testing.T, dir string, files map[string][]byte) {
	t.Helper()
	for name, data := range files {
		path := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// capaJSON renders the part of the capa document the tool reads: each rule is a name and a namespace,
// and an empty namespace is JSON null.
func capaJSON(rules ...[2]string) string {
	var parts []string
	for _, r := range rules {
		ns := "null"
		if r[1] != "" {
			ns = fmt.Sprintf("%q", r[1])
		}
		parts = append(parts, fmt.Sprintf(`%q:{"meta":{"name":%q,"namespace":%s,"scopes":{"static":"function"}},"source":"x","matches":[[{"type":"absolute","value":4096},{"success":true,"children":[]}]]}`, r[0], r[0], ns))
	}
	return `{"meta":{"version":"10.0.0","analysis":{"format":"pe"}},"rules":{` + strings.Join(parts, ",") + `}}` + "\n"
}

// evidence renders findings as "rule path: snippet; snippet".
func evidence(fs []protocol.Finding) []string {
	var out []string
	for _, f := range fs {
		var snippets []string
		for _, e := range f.Evidence {
			snippets = append(snippets, e.Snippet)
		}
		out = append(out, fmt.Sprintf("%s %s: %s", f.RuleID, f.Evidence[0].Path, strings.Join(snippets, "; ")))
	}
	return out
}

func TestCapa(t *testing.T) {
	allFour := capaJSON(
		[2]string{"inject thread", "host-interaction/process/inject"},
		[2]string{"log keystrokes via polling", "collection/keylog"},
		[2]string{"gather chrome based browser login information", "collection/browser"},
		[2]string{"steal keepass passwords", "collection/password-manager/keepass"},
		[2]string{"check for debugger via API", "anti-analysis/anti-debugging/debugger-detection"},
		[2]string{"check for VMware I/O port", "anti-analysis/anti-vm/vm-detection"},
		[2]string{"connect to URL", "communication/http/client"},
	)
	manyELF := map[string][]byte{}
	for i := range 21 {
		manyELF[fmt.Sprintf("bins/b%02d", i)] = elfFile
	}
	bigELF := t.TempDir()
	bigPath := filepath.Join(bigELF, "huge.bin")
	if err := os.WriteFile(bigPath, elfFile, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(bigPath, 33<<20); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		// inputs
		files       map[string][]byte
		target      string // a file below the tree to scan instead of the tree
		existing    string // a directory to scan as it is, instead of a tree
		fake        fakeRun
		noBinary    bool
		budget      time.Duration
		wantErr     string
		wantFlags   []string // ROOT stands for the target; not checked when nil
		wantFinds   []string
		wantNote    string
		wantPartial bool // Partial
	}{
		{
			name:      "capabilities of the four namespaces become one finding for the file, and vm-detection and other rules are left out",
			files:     map[string][]byte{"bin/app.exe": peFile, "notes.txt": []byte("hello")},
			fake:      fakeRun{out: allFour},
			wantFlags: []string{"-j", "-q", filepath.Join("ROOT", "bin", "app.exe")},
			wantFinds: []string{"GAL-CAPA-001 bin/app.exe: anti-debugging: check for debugger via API; credential theft: gather chrome based browser login information; credential theft: steal keepass passwords; injection: inject thread; keylogging: log keystrokes via polling"},
		},
		{
			name:      "a file target gives its own name",
			files:     map[string][]byte{"payload.dll": peFile},
			target:    "payload.dll",
			fake:      fakeRun{out: capaJSON([2]string{"inject thread", "host-interaction/process/inject"})},
			wantFinds: []string{"GAL-CAPA-001 payload.dll: injection: inject thread"},
		},
		{
			name:  "PE, ELF and Mach-O files are examined and other files are not",
			files: map[string][]byte{"a.exe": peFile, "b": elfFile, "c.dylib": machoFile, "d.txt": []byte("hello"), "e.zip": []byte("PK\x03\x04abcdefgh")},
			fake:  fakeRun{out: capaJSON([2]string{"inject thread", "host-interaction/process/inject"})},
			wantFinds: []string{
				"GAL-CAPA-001 a.exe: injection: inject thread",
				"GAL-CAPA-001 b: injection: inject thread",
				"GAL-CAPA-001 c.dylib: injection: inject thread",
			},
		},
		{
			name:  "rules that fire on ordinary software are not findings, and the others of their namespaces are",
			files: map[string][]byte{"a.exe": peFile},
			fake: fakeRun{out: capaJSON(
				[2]string{"allocate or change RWX memory", "host-interaction/process/inject"},
				[2]string{"free user process memory", "host-interaction/process/inject"},
				[2]string{"attach user process memory", "host-interaction/process/inject"},
				[2]string{"add value to global atom table", "host-interaction/process/inject"},
				[2]string{"check for time delay via QueryPerformanceCounter", "anti-analysis/anti-debugging/debugger-evasion"},
				[2]string{"check for time delay via GetTickCount", "anti-analysis/anti-debugging/debugger-evasion"},
				[2]string{"inject APC", "host-interaction/process/inject"},
			)},
			wantFinds: []string{"GAL-CAPA-001 a.exe: injection: inject APC"},
		},
		{
			name:  "vm-detection alone is not a finding",
			files: map[string][]byte{"a.exe": peFile},
			fake:  fakeRun{out: capaJSON([2]string{"check for VMware I/O port", "anti-analysis/anti-vm/vm-detection"}, [2]string{"check for VirtualBox", "anti-analysis/anti-vm"})},
		},
		{
			name:  "a namespace matches on its path segments",
			files: map[string][]byte{"a.exe": peFile},
			fake: fakeRun{out: capaJSON(
				[2]string{"x", "host-interaction/process/injection-helper"},
				[2]string{"y", "collection/keylogger"},
				[2]string{"z", "host-interaction/process"},
			)},
		},
		{
			name:  "a rule without a namespace is ignored",
			files: map[string][]byte{"a.exe": peFile},
			fake:  fakeRun{out: `{"rules":{"a":{"meta":{"name":"a","namespace":null}},"b":{"meta":{"name":"b"}}}}`},
		},
		{
			name:  "input without an executable needs no capa",
			files: map[string][]byte{"readme.txt": []byte("hello"), "script.sh": []byte("echo hi\n")}, noBinary: true,
		},
		{
			name:  "more than 20 executables are not all examined",
			files: manyELF,
			fake:  fakeRun{out: capaJSON([2]string{"inject thread", "host-interaction/process/inject"})},
			wantFinds: func() []string {
				var out []string
				for i := range 20 {
					out = append(out, fmt.Sprintf("GAL-CAPA-001 bins/b%02d: injection: inject thread", i))
				}
				return out
			}(),
			wantNote:    "not every executable was examined",
			wantPartial: true,
		},
		{
			name:     "an executable over 32 MiB is not examined",
			existing: bigELF, noBinary: true,
			wantNote: "not every executable was examined", wantPartial: true,
		},
		{
			name:  "the temporary files of a capa that ends are removed",
			files: map[string][]byte{"a.exe": peFile},
			fake:  fakeRun{out: capaJSON(), leak: true},
		},
		{
			name:  "capa that is not installed leaves the tool out",
			files: map[string][]byte{"a.exe": peFile}, noBinary: true,
			wantErr: "capa is not installed",
		},
		{
			name:    "output that is not JSON leaves the tool out",
			files:   map[string][]byte{"a.exe": peFile},
			fake:    fakeRun{out: "this is not json"},
			wantErr: "a.exe: output is not capa JSON",
		},
		{
			name:    "data after the document leaves the tool out",
			files:   map[string][]byte{"a.exe": peFile},
			fake:    fakeRun{out: capaJSON() + `{"rules":{}}`},
			wantErr: "data after the JSON document",
		},
		{
			name:    "a document without rules leaves the tool out",
			files:   map[string][]byte{"a.exe": peFile},
			fake:    fakeRun{out: `{"meta":{}}`},
			wantErr: "no rules member",
		},
		{
			name:    "a rule of the wrong type leaves the tool out",
			files:   map[string][]byte{"a.exe": peFile},
			fake:    fakeRun{out: `{"rules":{"a":{"meta":{"name":7}}}}`},
			wantErr: "not capa JSON",
		},
		{
			name:    "a rule without a name leaves the tool out",
			files:   map[string][]byte{"a.exe": peFile},
			fake:    fakeRun{out: `{"rules":{"a":{"meta":{"namespace":"collection/keylog"}}}}`},
			wantErr: "without a usable name",
		},
		{
			name:    "a failing capa leaves the tool out",
			files:   map[string][]byte{"a.exe": peFile},
			fake:    fakeRun{out: "", exit: 1, err: "ERROR: unsupported format\n"},
			wantErr: "exited with code 1: ERROR: unsupported format",
		},
		{
			name:    "a capa that runs out of time leaves the tool out",
			files:   map[string][]byte{"a.exe": peFile},
			fake:    fakeRun{mode: "hang"},
			budget:  300 * time.Millisecond,
			wantErr: "timed out",
		},
		{
			name:    "the temporary files of a capa that is killed are removed",
			files:   map[string][]byte{"a.exe": peFile},
			fake:    fakeRun{mode: "hang", leak: true},
			budget:  300 * time.Millisecond,
			wantErr: "timed out",
		},
		{
			name:    "after a timeout the other executables are not examined",
			files:   map[string][]byte{"a.exe": peFile, "b.exe": peFile},
			fake:    fakeRun{mode: "hang"},
			budget:  300 * time.Millisecond,
			wantErr: "stopped after a.exe timed out; 1 more executable was not examined",
		},
		{
			name:    "the stop note counts the executables that were not examined",
			files:   map[string][]byte{"a.exe": peFile, "b.exe": peFile, "c.exe": peFile, "d.exe": peFile},
			fake:    fakeRun{mode: "hang"},
			budget:  300 * time.Millisecond,
			wantErr: "stopped after a.exe timed out; 3 more executables were not examined",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			argsFile := useFake(t, tt.fake)
			if tt.noBinary {
				t.Setenv("PATH", t.TempDir())
			}
			dir := cmp.Or(tt.existing, t.TempDir())
			writeTree(t, dir, tt.files)
			target := dir
			if tt.target != "" {
				target = filepath.Join(dir, tt.target)
			}
			ctx, cancel := context.WithTimeout(context.Background(), cmp.Or(tt.budget, time.Minute))
			defer cancel()

			scratch := t.TempDir()

			res, err := tools.NewCapa(scratch).Run(ctx, target)

			if left, rerr := os.ReadDir(scratch); rerr != nil || len(left) != 0 {
				t.Errorf("scratch directory holds %v (%v), want it empty", left, rerr)
			}

			if (err != nil) != (tt.wantErr != "") || (err != nil && !strings.Contains(err.Error(), tt.wantErr)) {
				t.Fatalf("error = %v, want %q", err, tt.wantErr)
			}
			if got := evidence(res.Findings); !slices.Equal(got, tt.wantFinds) {
				t.Errorf("findings = %q, want %q", got, tt.wantFinds)
			}
			if !strings.Contains(res.Note, tt.wantNote) {
				t.Errorf("note = %q, want it to contain %q", res.Note, tt.wantNote)
			}
			if res.Partial != tt.wantPartial {
				t.Errorf("partial = %v, want %v", res.Partial, tt.wantPartial)
			}
			if tt.wantFlags != nil {
				args, err := os.ReadFile(argsFile)
				if err != nil {
					t.Fatal(err)
				}
				want := make([]string, len(tt.wantFlags))
				for i, f := range tt.wantFlags {
					want[i] = strings.Replace(f, "ROOT", dir, 1)
				}
				if got := strings.Split(string(args), "\n"); !slices.Equal(got, want) {
					t.Errorf("arguments = %q, want %q", got, want)
				}
			}
		})
	}
}
