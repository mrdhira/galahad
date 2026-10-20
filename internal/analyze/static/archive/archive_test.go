package archive_test

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/hex"
	"fmt"
	"io/fs"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"

	"github.com/mrdhira/galahad/internal/analyze"
	"github.com/mrdhira/galahad/internal/analyze/ident"
	"github.com/mrdhira/galahad/internal/analyze/static/archive"
)

type entry struct {
	name string
	data string
	mode fs.FileMode
	flag uint16
	raw  []byte // when set, written instead of data, with the stored method
}

func zipOf(t *testing.T, entries ...entry) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range entries {
		h := &zip.FileHeader{Name: e.name, Method: zip.Deflate, Flags: e.flag}
		if e.mode != 0 {
			h.SetMode(e.mode)
		}
		if e.raw != nil {
			h.Method = zip.Store
		}
		w, err := zw.CreateHeader(h)
		if err != nil {
			t.Fatal(err)
		}
		if e.raw != nil {
			_, err = w.Write(e.raw)
		} else {
			_, err = w.Write([]byte(e.data))
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

type tarEntry struct {
	name, data, link string
	typeflag         byte
}

func tarOf(t *testing.T, entries ...tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		h := &tar.Header{Name: e.name, Typeflag: e.typeflag, Linkname: e.link, Mode: 0o644}
		if e.typeflag == tar.TypeReg {
			h.Size = int64(len(e.data))
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if e.typeflag == tar.TypeReg {
			if _, err := tw.Write([]byte(e.data)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func gzipOf(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func fromHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// helloBz2 is "hello\n" compressed with bzip2; the standard library only decompresses.
const helloBz2 = "425a6839314159265359c1c080e2000001410000100244a00030cd00c3462997177245385090c1c080e2"

func TestAnalyze(t *testing.T) {
	random := make([]byte, analyze.MaxFileSize+1)
	_, _ = rand.NewChaCha8([32]byte{1}).Read(random) // never fails
	var many []entry
	for i := range archive.MaxEntries + 1 {
		many = append(many, entry{name: fmt.Sprintf("f%d", i)})
	}
	iso := make([]byte, 0x8100)
	copy(iso[0x8001:], "CD001")

	tests := []struct {
		name string
		// inputs
		file string
		data []byte
		// expectations
		wantChildren []string // member names, in order
		wantFindings []string // "rule path"
		wantSkips    []string // "path reason"
		wantErr      bool
	}{
		{name: "zip members become children and directories are ignored", file: "in.zip",
			data:         zipOf(t, entry{name: "d/", mode: fs.ModeDir | 0o755}, entry{name: "a.txt", data: "a"}, entry{name: "d/b.txt", data: "b"}),
			wantChildren: []string{"a.txt", "d/b.txt"}},
		{name: "zip that cannot be read", file: "in.zip", data: []byte("PK\x03\x04 truncated"), wantErr: true},
		{name: "parent segment", file: "in.zip", data: zipOf(t, entry{name: "../../evil.sh", data: "x"}),
			wantFindings: []string{"GAL-ARCHIVE-001 in.zip!/../../evil.sh"}},
		{name: "absolute path", file: "in.zip", data: zipOf(t, entry{name: "/etc/cron.d/x", data: "x"}),
			wantFindings: []string{"GAL-ARCHIVE-001 in.zip!//etc/cron.d/x"}},
		{name: "drive letter", file: "in.zip", data: zipOf(t, entry{name: "C:/Windows/x.dll", data: "x"}),
			wantFindings: []string{"GAL-ARCHIVE-001 in.zip!/C:/Windows/x.dll"}},
		{name: "UNC path", file: "in.zip", data: zipOf(t, entry{name: `\\srv\share\x`, data: "x"}),
			wantFindings: []string{`GAL-ARCHIVE-001 in.zip!/\\srv\share\x`}},
		{name: "backslash traversal", file: "in.zip", data: zipOf(t, entry{name: `a\..\..\x`, data: "x"}),
			wantFindings: []string{`GAL-ARCHIVE-001 in.zip!/a\..\..\x`}},
		{name: "dots inside a name are fine", file: "in.zip", data: zipOf(t, entry{name: "a..b/c..d", data: "x"}),
			wantChildren: []string{"a..b/c..d"}},
		{name: "zip symlink entry", file: "in.zip", data: zipOf(t, entry{name: "link", data: "/etc/passwd", mode: fs.ModeSymlink | 0o777}),
			wantFindings: []string{"GAL-ARCHIVE-002 in.zip!/link"}},
		{name: "encrypted zip entry", file: "in.zip", data: zipOf(t, entry{name: "secret.txt", data: "x", flag: 1}),
			wantFindings: []string{"GAL-ARCHIVE-004 in.zip!/secret.txt"}, wantSkips: []string{"in.zip!/secret.txt encrypted"}},
		{name: "zip bomb by ratio", file: "in.zip", data: zipOf(t, entry{name: "zeros", data: strings.Repeat("\x00", 20<<20)}),
			wantFindings: []string{"GAL-ARCHIVE-003 in.zip"}, wantSkips: []string{"in.zip!/zeros budget"}},
		{name: "entry above the file size limit", file: "in.zip", data: zipOf(t, entry{name: "big", raw: random}),
			wantSkips: []string{"in.zip!/big too_large"}},
		{name: "more entries than the limit", file: "in.zip", data: zipOf(t, many...),
			wantChildren: func() []string {
				var names []string
				for i := range archive.MaxEntries {
					names = append(names, fmt.Sprintf("f%d", i))
				}
				return names
			}(),
			wantSkips: []string{"in.zip budget"}},
		{name: "tar members become children", file: "in.tar", data: tarOf(t, tarEntry{name: "d/", typeflag: tar.TypeDir}, tarEntry{name: "a.txt", data: "a", typeflag: tar.TypeReg}),
			wantChildren: []string{"a.txt"}},
		{name: "tar that cannot be read", file: "in.tar", data: bytes.Repeat([]byte("x"), 1024),
			wantSkips: []string{"in.tar parse_error"}},
		{name: "tar entry that escapes", file: "in.tar", data: tarOf(t, tarEntry{name: "../x", data: "x", typeflag: tar.TypeReg}),
			wantFindings: []string{"GAL-ARCHIVE-001 in.tar!/../x"}},
		{name: "tar symlink", file: "in.tar", data: tarOf(t, tarEntry{name: "link", link: "/etc/passwd", typeflag: tar.TypeSymlink}),
			wantFindings: []string{"GAL-ARCHIVE-002 in.tar!/link"}},
		{name: "tar hardlink", file: "in.tar", data: tarOf(t, tarEntry{name: "link", link: "a.txt", typeflag: tar.TypeLink}),
			wantFindings: []string{"GAL-ARCHIVE-002 in.tar!/link"}},
		{name: "tar fifo is ignored", file: "in.tar", data: tarOf(t, tarEntry{name: "pipe", typeflag: tar.TypeFifo}, tarEntry{name: "a", data: "a", typeflag: tar.TypeReg}),
			wantChildren: []string{"a"}},
		{name: "tgz expands its tar", file: "in.tgz", data: gzipOf(t, tarOf(t, tarEntry{name: "a.txt", data: "a", typeflag: tar.TypeReg})),
			wantChildren: []string{"a.txt"}},
		{name: "tar.gz expands its tar", file: "in.tar.gz", data: gzipOf(t, tarOf(t, tarEntry{name: "a.txt", data: "a", typeflag: tar.TypeReg})),
			wantChildren: []string{"a.txt"}},
		{name: "gz becomes one child without its suffix", file: "notes.txt.gz", data: gzipOf(t, []byte("hello\n")),
			wantChildren: []string{"notes.txt"}},
		{name: "gz without a suffix", file: "notes", data: gzipOf(t, []byte("hello\n")),
			wantChildren: []string{"notes.out"}},
		{name: "gz bomb", file: "in.gz", data: gzipOf(t, bytes.Repeat([]byte{0}, 20<<20)),
			wantFindings: []string{"GAL-ARCHIVE-003 in.gz"}, wantSkips: []string{"in.gz!/in budget"}},
		{name: "gz entry above the file size limit", file: "in.gz", data: gzipOf(t, random),
			wantSkips: []string{"in.gz!/in too_large"}},
		{name: "tar.gz bomb", file: "in.tar.gz", data: gzipOf(t, tarOf(t, tarEntry{name: "z", data: strings.Repeat("\x00", 20<<20), typeflag: tar.TypeReg})),
			wantFindings: []string{"GAL-ARCHIVE-003 in.tar.gz"}, wantSkips: []string{"in.tar.gz!/z budget"}},
		{name: "gz that cannot be read", file: "in.gz", data: []byte{0x1f, 0x8b, 8, 0}, wantErr: true},
		{name: "bz2 becomes one child", file: "hello.txt.bz2", data: fromHex(helloBz2),
			wantChildren: []string{"hello.txt"}},
		{name: "tbz2 name", file: "hello.tbz2", data: fromHex(helloBz2),
			wantChildren: []string{"hello.tar"}},
		{name: "bz2 that cannot be read", file: "in.bz2", data: []byte("BZh9 not bzip2"), wantErr: true},
		{name: "7z is unsupported", file: "in.7z", data: []byte("7z\xbc\xaf\x27\x1c\x00\x04"),
			wantSkips: []string{"in.7z unsupported"}},
		{name: "rar is unsupported", file: "in.rar", data: []byte("Rar!\x1a\x07\x00"),
			wantSkips: []string{"in.rar unsupported"}},
		{name: "iso is unsupported", file: "in.iso", data: iso,
			wantSkips: []string{"in.iso unsupported"}},
		{name: "plain text is left alone", file: "a.txt", data: []byte("hello\n")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := analyze.File{Path: tt.file, Name: tt.file, Kind: ident.Identify(tt.file, tt.data), Data: tt.data}

			out, err := archive.New().Analyze(context.Background(), f)

			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, want error %v", err, tt.wantErr)
			}
			var children, findings, skips []string
			for _, c := range out.Children {
				children = append(children, c.Name)
			}
			for _, fd := range out.Findings {
				findings = append(findings, fd.RuleID+" "+fd.Evidence[0].Path)
			}
			for _, s := range out.Skips {
				skips = append(skips, s.Path+" "+s.Reason)
			}
			if !slices.Equal(children, tt.wantChildren) {
				t.Errorf("children = %v, want %v", children, tt.wantChildren)
			}
			if !slices.Equal(findings, tt.wantFindings) {
				t.Errorf("findings = %v, want %v", findings, tt.wantFindings)
			}
			if !slices.Equal(skips, tt.wantSkips) {
				t.Errorf("skips = %v, want %v", skips, tt.wantSkips)
			}
		})
	}
}

func TestAnalyzeRuleMetadata(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		data []byte
		// expectations
		wantRule     string
		wantSeverity string
		wantAttack   string
		wantSnippet  string
	}{
		{name: "zip slip", data: zipOf(t, entry{name: "../x"}), wantRule: "GAL-ARCHIVE-001", wantSeverity: "high", wantSnippet: "../x"},
		{name: "encrypted entry", data: zipOf(t, entry{name: "s", flag: 1}), wantRule: "GAL-ARCHIVE-004", wantSeverity: "medium", wantAttack: "T1027.013", wantSnippet: "encrypted entry"},
		{name: "link target is shown", data: tarOf(t, tarEntry{name: "l", link: "/etc/passwd", typeflag: tar.TypeSymlink}), wantRule: "GAL-ARCHIVE-002", wantSeverity: "medium", wantSnippet: "l -> /etc/passwd"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := analyze.File{Path: "in", Name: "in", Kind: ident.Identify("in.tar", tt.data), Data: tt.data}

			out, err := archive.New().Analyze(context.Background(), f)

			if err != nil || len(out.Findings) != 1 {
				t.Fatalf("err = %v, findings = %+v, want one finding", err, out.Findings)
			}
			got := out.Findings[0]
			if got.RuleID != tt.wantRule || string(got.Severity) != tt.wantSeverity || got.Attack != tt.wantAttack || got.Evidence[0].Snippet != tt.wantSnippet {
				t.Errorf("finding = %s %s %q %q, want %s %s %q %q", got.RuleID, got.Severity, got.Attack, got.Evidence[0].Snippet, tt.wantRule, tt.wantSeverity, tt.wantAttack, tt.wantSnippet)
			}
		})
	}
}

func TestAnalyzeCancelled(t *testing.T) {
	tests := []struct {
		name string
		file string
		data []byte
	}{
		{name: "zip", file: "in.zip", data: zipOf(t, entry{name: "a", data: "a"})},
		{name: "tar", file: "in.tar", data: tarOf(t, tarEntry{name: "a", data: "a", typeflag: tar.TypeReg})},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			f := analyze.File{Path: tt.file, Name: tt.file, Kind: ident.Identify(tt.file, tt.data), Data: tt.data}

			out, err := archive.New().Analyze(ctx, f)

			if err == nil || len(out.Children) != 0 {
				t.Errorf("err = %v, children = %d, want an error and no children", err, len(out.Children))
			}
		})
	}
}

func TestName(t *testing.T) {
	tests := []struct {
		name     string
		wantName string
	}{
		{name: "analyzer name", wantName: "archive"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := archive.New().Name(); got != tt.wantName {
				t.Errorf("Name() = %q, want %q", got, tt.wantName)
			}
		})
	}
}
