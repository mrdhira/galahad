package ingest_test

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

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

// zeros is an endless stream of zero bytes: a tar stream that ends at once, then padding.
type zeros struct{}

func (zeros) Read(p []byte) (int, error) { clear(p); return len(p), nil }

func TestExtract(t *testing.T) {
	huge := entry{hdr: tar.Header{Name: "big", Typeflag: tar.TypeReg, Mode: 0o644, Size: protocol.MaxInputBytes + 1}}
	deepDir := strings.Repeat("d/", 63) // 63 elements
	expired, cancelExpired := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancelExpired()
	tests := []struct {
		name string
		// inputs
		ctx context.Context //nolint:containedctx // a test input
		// input builds the tar stream; outside is a directory next to the extraction directory.
		input func(t *testing.T, outside string) io.Reader
		// want*
		wantFiles      map[string]string // path to content
		wantLinks      map[string]string // path to link target
		wantAbsent     []string
		wantTooDeep    int    // Stream.TooDeep
		wantShallowest string // Stream.Shallowest
		wantErr        string // substring; empty means success
		wantIs         error  // sentinel the error wraps
	}{
		{
			name: "files, directories and links",
			input: func(t *testing.T, _ string) io.Reader {
				fifo := entry{hdr: tar.Header{Name: "pipe", Typeflag: tar.TypeFifo, Mode: 0o644}}
				hard := entry{hdr: tar.Header{Name: "hard", Typeflag: tar.TypeLink, Linkname: "top.txt"}}
				return bytes.NewReader(build(t, dir("./"), dir("d/"), file("d/a.txt", "alpha"), file("top.txt", "top"),
					file("x/y/z.txt", "deep"), link("d/link", "a.txt"), fifo, hard))
			},
			wantFiles:  map[string]string{"d/a.txt": "alpha", "top.txt": "top", "x/y/z.txt": "deep"},
			wantLinks:  map[string]string{"d/link": "a.txt"},
			wantAbsent: []string{"pipe", "hard"},
		},
		{
			name: "garbage is not a tar stream",
			input: func(*testing.T, string) io.Reader {
				return bytes.NewReader(bytes.Repeat([]byte("not a tar header"), 100))
			},
			wantErr: "read tar",
		},
		{
			name: "deadline passed",
			ctx:  expired,
			input: func(t *testing.T, _ string) io.Reader {
				return bytes.NewReader(build(t, file("a.txt", "x")))
			},
			wantAbsent: []string{"a.txt"},
			wantErr:    "extract", wantIs: context.DeadlineExceeded,
		},
		{
			name: "more entries than the cap",
			input: func(t *testing.T, _ string) io.Reader {
				// A FIFO header is skipped, so the entries cost no disk. One header block, repeated.
				var buf bytes.Buffer
				if err := tar.NewWriter(&buf).WriteHeader(&tar.Header{Name: "p", Typeflag: tar.TypeFifo}); err != nil {
					t.Fatal(err)
				}
				return bytes.NewReader(bytes.Repeat(buf.Bytes(), protocol.MaxInputEntries+1))
			},
			wantErr: "entries", wantIs: ingest.ErrTooLarge,
		},
		{
			name: "file larger than the byte cap",
			input: func(t *testing.T, _ string) io.Reader {
				var buf bytes.Buffer
				if err := tar.NewWriter(&buf).WriteHeader(&huge.hdr); err != nil {
					t.Fatal(err)
				}
				return &buf
			},
			wantAbsent: []string{"big"},
			wantErr:    "bytes of files", wantIs: ingest.ErrTooLarge,
		},
		{
			name:    "stream larger than the byte cap",
			input:   func(*testing.T, string) io.Reader { return io.LimitReader(zeros{}, protocol.MaxInputBytes+1) },
			wantErr: "bytes of stream", wantIs: ingest.ErrTooLarge,
		},
		{
			name:    "absolute path",
			input:   func(t *testing.T, _ string) io.Reader { return bytes.NewReader(build(t, file("/etc/passwd", "x"))) },
			wantErr: "unsafe path", wantIs: ingest.ErrUnsafePath,
		},
		{
			name:    "dot dot leaves the directory",
			input:   func(t *testing.T, _ string) io.Reader { return bytes.NewReader(build(t, file("../escape", "x"))) },
			wantErr: "unsafe path", wantIs: ingest.ErrUnsafePath,
		},
		{
			name: "dot dot inside a name",
			input: func(t *testing.T, _ string) io.Reader {
				return bytes.NewReader(build(t, dir("a/"), file("a/../b", "x")))
			},
			wantErr: "unsafe path", wantIs: ingest.ErrUnsafePath,
		},
		{
			name: "path 64 elements deep",
			input: func(t *testing.T, _ string) io.Reader {
				return bytes.NewReader(build(t, file(deepDir+"f.txt", "x")))
			},
			wantFiles: map[string]string{deepDir + "f.txt": "x"},
		},
		{
			name: "path 65 elements deep",
			input: func(t *testing.T, _ string) io.Reader {
				return bytes.NewReader(build(t, file("ok.txt", "fine"), file("e/"+deepDir+"f.txt", "x")))
			},
			wantFiles:   map[string]string{"ok.txt": "fine"},
			wantAbsent:  []string{"e"},
			wantTooDeep: 1, wantShallowest: "e/" + deepDir + "f.txt",
		},
		{
			name: "deep entries of every type are skipped and the shallowest is reported",
			input: func(t *testing.T, _ string) io.Reader {
				return bytes.NewReader(build(t, file("ok.txt", "fine"), file("q/r/"+deepDir+"f.txt", "x"),
					file("x/"+deepDir+"f.txt", "x"), dir("y/"+deepDir+"e"), link("z/"+deepDir+"l", "f.txt")))
			},
			wantFiles:   map[string]string{"ok.txt": "fine"},
			wantAbsent:  []string{"q", "x", "y", "z"},
			wantTooDeep: 4, wantShallowest: "x/" + deepDir + "f.txt", // ties keep the first
		},
		{
			name: "a path that is both too deep and unsafe is refused",
			input: func(t *testing.T, _ string) io.Reader {
				return bytes.NewReader(build(t, file("e/"+deepDir+"../f.txt", "x")))
			},
			wantErr: "unsafe path", wantIs: ingest.ErrUnsafePath,
		},
		{
			name: "directory through a symlink",
			input: func(t *testing.T, outside string) io.Reader {
				return bytes.NewReader(build(t, link("out", outside), dir("out/sub/")))
			},
			wantErr: "sub",
		},
		{
			name:    "a file named dot",
			input:   func(t *testing.T, _ string) io.Reader { return bytes.NewReader(build(t, file(".", "x"))) },
			wantErr: "unsafe path", wantIs: ingest.ErrUnsafePath,
		},
		{
			name: "write through a symlink to an absolute path",
			input: func(t *testing.T, outside string) io.Reader {
				return bytes.NewReader(build(t, link("out", outside), file("out/pwned", "x")))
			},
			wantLinks:  map[string]string{"out": ""}, // the link itself is made; the target is checked in the test
			wantAbsent: []string{"out/pwned"},
			wantErr:    "pwned",
		},
		{
			name: "write through a symlink to the parent",
			input: func(t *testing.T, _ string) io.Reader {
				return bytes.NewReader(build(t, link("up", ".."), file("up/pwned", "x")))
			},
			wantAbsent: []string{"up/pwned"},
			wantErr:    "pwned",
		},
		{
			name: "file over a symlink",
			input: func(t *testing.T, _ string) io.Reader {
				return bytes.NewReader(build(t, file("f", "x"), link("l", "f"), file("l", "y")))
			},
			wantFiles: map[string]string{"f": "x"},
			wantErr:   "extract",
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
			ctx := tt.ctx
			if ctx == nil {
				ctx = context.Background()
			}
			stream, err := ingest.Extract(ctx, tt.input(t, outside), dst)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Extract: %v", err)
				}
				if stream.Bytes == 0 || len(stream.SHA256) != 64 {
					t.Errorf("stream = %+v, want the byte count and hash of the input", stream)
				}
			} else {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want one containing %q", err, tt.wantErr)
				}
				if tt.wantIs != nil && !errors.Is(err, tt.wantIs) {
					t.Errorf("error = %v, want it to wrap %v", err, tt.wantIs)
				}
			}
			if stream.TooDeep != tt.wantTooDeep || stream.Shallowest != tt.wantShallowest {
				t.Errorf("TooDeep, Shallowest = %d, %q; want %d, %q", stream.TooDeep, stream.Shallowest, tt.wantTooDeep, tt.wantShallowest)
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
