package ingest_test

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/mrdhira/galahad/internal/ingest"
	"github.com/mrdhira/galahad/internal/protocol"
)

// entry is one tar entry. A nil body for a regular file means an empty file.
type entry struct {
	hdr  tar.Header
	body string
}

func file(name, body string) entry {
	return entry{hdr: tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(body))}, body: body}
}

func dir(name string) entry {
	return entry{hdr: tar.Header{Name: name, Typeflag: tar.TypeDir, Mode: 0o755}}
}

func link(name, target string) entry {
	return entry{hdr: tar.Header{Name: name, Typeflag: tar.TypeSymlink, Linkname: target, Mode: 0o777}}
}

func build(t *testing.T, entries ...entry) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		if err := tw.WriteHeader(&e.hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(e.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestExtract(t *testing.T) {
	huge := entry{hdr: tar.Header{Name: "big", Typeflag: tar.TypeReg, Mode: 0o644, Size: protocol.MaxInputBytes + 1}}
	tests := []struct {
		name string
		// input builds the tar stream; outside is a directory next to the extraction directory.
		input func(t *testing.T, outside string) []byte
		// want*
		wantFiles  map[string]string // path to content
		wantLinks  map[string]string // path to link target
		wantAbsent []string
		wantErr    string // substring; empty means success
		wantIs     error  // sentinel the error wraps
	}{
		{
			name: "files, directories and links",
			input: func(t *testing.T, _ string) []byte {
				fifo := entry{hdr: tar.Header{Name: "pipe", Typeflag: tar.TypeFifo, Mode: 0o644}}
				hard := entry{hdr: tar.Header{Name: "hard", Typeflag: tar.TypeLink, Linkname: "top.txt"}}
				return build(t, dir("./"), dir("d/"), file("d/a.txt", "alpha"), file("top.txt", "top"),
					file("x/y/z.txt", "deep"), link("d/link", "a.txt"), fifo, hard)
			},
			wantFiles:  map[string]string{"d/a.txt": "alpha", "top.txt": "top", "x/y/z.txt": "deep"},
			wantLinks:  map[string]string{"d/link": "a.txt"},
			wantAbsent: []string{"pipe", "hard"},
		},
		{
			name:    "garbage is not a tar stream",
			input:   func(*testing.T, string) []byte { return bytes.Repeat([]byte("not a tar header"), 100) },
			wantErr: "read tar",
		},
		{
			name:    "absolute path",
			input:   func(t *testing.T, _ string) []byte { return build(t, file("/etc/passwd", "x")) },
			wantErr: "unsafe path", wantIs: ingest.ErrUnsafePath,
		},
		{
			name:    "dot dot leaves the directory",
			input:   func(t *testing.T, _ string) []byte { return build(t, file("../escape", "x")) },
			wantErr: "unsafe path", wantIs: ingest.ErrUnsafePath,
		},
		{
			name:    "dot dot inside a name",
			input:   func(t *testing.T, _ string) []byte { return build(t, dir("a/"), file("a/../b", "x")) },
			wantErr: "unsafe path", wantIs: ingest.ErrUnsafePath,
		},
		{
			name:    "a file named dot",
			input:   func(t *testing.T, _ string) []byte { return build(t, file(".", "x")) },
			wantErr: "unsafe path", wantIs: ingest.ErrUnsafePath,
		},
		{
			name: "write through a symlink to an absolute path",
			input: func(t *testing.T, outside string) []byte {
				return build(t, link("out", outside), file("out/pwned", "x"))
			},
			wantLinks:  map[string]string{"out": ""}, // the link itself is made; the target is checked in the test
			wantAbsent: []string{"out/pwned"},
			wantErr:    "pwned",
		},
		{
			name: "write through a symlink to the parent",
			input: func(t *testing.T, _ string) []byte {
				return build(t, link("up", ".."), file("up/pwned", "x"))
			},
			wantAbsent: []string{"up/pwned"},
			wantErr:    "pwned",
		},
		{
			name: "directory through a symlink",
			input: func(t *testing.T, outside string) []byte {
				return build(t, link("out", outside), dir("out/sub/"))
			},
			wantErr: "sub",
		},
		{
			name: "file over a symlink",
			input: func(t *testing.T, _ string) []byte {
				return build(t, file("f", "x"), link("l", "f"), file("l", "y"))
			},
			wantFiles: map[string]string{"f": "x"},
			wantErr:   "extract",
		},
		{
			name: "file larger than the byte cap",
			input: func(t *testing.T, _ string) []byte {
				var buf bytes.Buffer
				if err := tar.NewWriter(&buf).WriteHeader(&huge.hdr); err != nil {
					t.Fatal(err)
				}
				return buf.Bytes()
			},
			wantAbsent: []string{"big"},
			wantErr:    "bytes of files", wantIs: ingest.ErrTooLarge,
		},
		{
			name: "more entries than the cap",
			input: func(t *testing.T, _ string) []byte {
				// A FIFO header is skipped, so the entries cost no disk. One header block, repeated.
				var buf bytes.Buffer
				if err := tar.NewWriter(&buf).WriteHeader(&tar.Header{Name: "p", Typeflag: tar.TypeFifo}); err != nil {
					t.Fatal(err)
				}
				return bytes.Repeat(buf.Bytes(), protocol.MaxInputEntries+1)
			},
			wantErr: "entries", wantIs: ingest.ErrTooLarge,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if runtime.GOOS == "windows" && (len(tt.wantLinks) > 0 || strings.Contains(tt.name, "symlink")) {
				t.Skip("creating symlinks needs a privilege on Windows, and the guest is Linux")
			}
			base := t.TempDir()
			dst, outside := filepath.Join(base, "dst"), filepath.Join(base, "outside")
			for _, d := range []string{dst, outside} {
				if err := os.Mkdir(d, 0o750); err != nil {
					t.Fatal(err)
				}
			}
			data := tt.input(t, outside)

			stream, err := ingest.Extract(bytes.NewReader(data), dst)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Extract: %v", err)
				}
				sum := sha256.Sum256(data)
				end := protocol.End{Bytes: int64(len(data)), SHA256: hex.EncodeToString(sum[:])}
				if err := stream.Verify(end); err != nil {
					t.Errorf("Verify: %v", err)
				}
			} else {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want one containing %q", err, tt.wantErr)
				}
				if tt.wantIs != nil && !errors.Is(err, tt.wantIs) {
					t.Errorf("error = %v, want it to wrap %v", err, tt.wantIs)
				}
			}
			for p, want := range tt.wantFiles {
				got, err := os.ReadFile(filepath.Join(dst, filepath.FromSlash(p)))
				if err != nil || string(got) != want {
					t.Errorf("%s = %q, %v; want %q", p, got, err, want)
				}
			}
			for p, want := range tt.wantLinks {
				got, err := os.Readlink(filepath.Join(dst, filepath.FromSlash(p)))
				if err != nil || (want != "" && got != want) {
					t.Errorf("link %s = %q, %v; want %q", p, got, err, want)
				}
			}
			for _, p := range tt.wantAbsent {
				if _, err := os.Lstat(filepath.Join(dst, filepath.FromSlash(p))); err == nil {
					t.Errorf("%s exists, want it absent", p)
				}
			}
			if left, _ := os.ReadDir(outside); len(left) != 0 {
				t.Errorf("a write reached outside the directory: %v", left)
			}
		})
	}
}

func TestStreamVerify(t *testing.T) {
	good := strings.Repeat("a", 64)
	tests := []struct {
		name    string
		stream  ingest.Stream
		end     protocol.End
		wantErr string
	}{
		{name: "match", stream: ingest.Stream{Bytes: 10, SHA256: good}, end: protocol.End{Bytes: 10, SHA256: good}},
		{name: "byte count differs", stream: ingest.Stream{Bytes: 10, SHA256: good}, end: protocol.End{Bytes: 11, SHA256: good}, wantErr: "read 10 bytes"},
		{name: "hash differs", stream: ingest.Stream{Bytes: 10, SHA256: good}, end: protocol.End{Bytes: 10, SHA256: strings.Repeat("b", 64)}, wantErr: "sha256 is"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.stream.Verify(tt.end)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Verify: %v", err)
				}
				return
			}
			if !errors.Is(err, ingest.ErrMismatch) || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want ErrMismatch containing %q", err, tt.wantErr)
			}
		})
	}
}
