package ident_test

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"math"
	"testing"

	"github.com/mrdhira/galahad/internal/analyze/ident"
)

func pe() []byte {
	b := make([]byte, 0x80)
	copy(b, "MZ")
	binary.LittleEndian.PutUint32(b[0x3c:], 0x40)
	copy(b[0x40:], "PE\x00\x00")
	return b
}

func macho(magic uint32, second uint32) []byte {
	b := make([]byte, 16)
	binary.BigEndian.PutUint32(b, magic)
	binary.BigEndian.PutUint32(b[4:], second)
	return b
}

func tarHeader() []byte {
	b := make([]byte, 512)
	copy(b[257:], "ustar")
	return b
}

func zipOf(t *testing.T, names ...string) []byte {
	t.Helper()
	return zipWith(t, func(name string) string { return "<x/>" }, names...)
}

func zipWith(t *testing.T, content func(name string) string, names ...string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, name := range names {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(content(name))); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestIdentify(t *testing.T) {
	docx := zipOf(t, "[Content_Types].xml", "word/document.xml")

	longText := append(bytes.Repeat([]byte("a"), 8191), []byte("é")...) // multi-byte rune cut by the window
	peBadOffset := pe()
	binary.LittleEndian.PutUint32(peBadOffset[0x3c:], 0xffffff)
	tests := []struct {
		name     string
		file     string
		data     []byte
		wantKind ident.Kind
	}{
		{name: "text", file: "a.txt", data: []byte("hello\nworld\n"), wantKind: ident.Text},
		{name: "empty file is text", file: "a", data: nil, wantKind: ident.Text},
		{name: "pdf", file: "a.pdf", data: []byte("%PDF-1.7\n"), wantKind: ident.PDF},
		{name: "zip", file: "a.zip", data: []byte("PK\x03\x04rest"), wantKind: ident.Zip},
		{name: "empty zip", file: "a.zip", data: []byte("PK\x05\x06rest"), wantKind: ident.Zip},
		{name: "ooxml", file: "a.docx", data: docx, wantKind: ident.OOXML},
		{name: "ooxml with a content types name in other case", file: "a.docx", data: zipOf(t, "[content_types].XML", "word/document.xml"), wantKind: ident.OOXML},
		{name: "content types file below a folder is a plain zip", file: "a.zip", data: zipOf(t, "p/run.js", "sub/[Content_Types].xml"), wantKind: ident.Zip},
		{name: "content types text inside a member is a plain zip", file: "a.zip",
			data:     zipWith(t, func(string) string { return "see [Content_Types].xml" }, "notes.txt"),
			wantKind: ident.Zip},
		{name: "truncated zip that names a content types file is a plain zip", file: "a.docx", data: docx[:len(docx)-10], wantKind: ident.Zip},
		{name: "garbage after the zip magic that names a content types file is a plain zip", file: "a.docx", data: []byte("PK\x03\x04...[Content_Types].xml..."), wantKind: ident.Zip},
		{name: "gzip", file: "a.gz", data: []byte{0x1f, 0x8b, 8}, wantKind: ident.Gzip},
		{name: "bzip2", file: "a.bz2", data: []byte("BZh91AY"), wantKind: ident.Bzip2},
		{name: "ole", file: "a.doc", data: []byte{0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1, 0}, wantKind: ident.OLE},
		{name: "elf", file: "a", data: []byte("\x7fELF\x02\x01"), wantKind: ident.ELF},
		{name: "lnk", file: "a.lnk", data: []byte{0x4c, 0, 0, 0, 0x01, 0x14, 0x02, 0, 0, 0}, wantKind: ident.LNK},
		{name: "pe", file: "a.exe", data: pe(), wantKind: ident.PE},
		{name: "mz without PE header is unknown", file: "a.exe", data: append([]byte("MZ"), make([]byte, 0x80)...), wantKind: ident.Unknown},
		{name: "pe with out-of-range header offset is unknown", file: "a.exe", data: peBadOffset, wantKind: ident.Unknown},
		{name: "macho 64-bit", file: "a", data: macho(0xfeedfacf, 7), wantKind: ident.MachO},
		{name: "macho little endian", file: "a", data: macho(0xcffaedfe, 7), wantKind: ident.MachO},
		{name: "macho universal", file: "a", data: macho(0xcafebabe, 2), wantKind: ident.MachO},
		{name: "java class is not macho", file: "A.class", data: macho(0xcafebabe, 52), wantKind: ident.Unknown},
		{name: "short data is not macho", file: "a", data: []byte{0xfe, 0xed}, wantKind: ident.Unknown},
		{name: "tar with ustar magic", file: "a", data: tarHeader(), wantKind: ident.Tar},
		{name: "tar by name", file: "A.TAR", data: bytes.Repeat([]byte("a"), 512), wantKind: ident.Tar},
		{name: "short .tar is text", file: "a.tar", data: []byte("abc"), wantKind: ident.Text},
		{name: "long text cut inside a character", file: "a.txt", data: longText, wantKind: ident.Text},
		{name: "nul byte is unknown", file: "a.bin", data: []byte("ab\x00cd"), wantKind: ident.Unknown},
		{name: "invalid utf-8 is unknown", file: "a.bin", data: []byte{0xff, 0xfe, 0xfd}, wantKind: ident.Unknown},
		{name: "long invalid utf-8 is unknown", file: "a.bin", data: bytes.Repeat([]byte{0xff}, 9000), wantKind: ident.Unknown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ident.Identify(tt.file, tt.data); got != tt.wantKind {
				t.Errorf("Identify(%q) = %q, want %q", tt.file, got, tt.wantKind)
			}
		})
	}
}

func TestEntropy(t *testing.T) {
	random := make([]byte, 1<<16)
	if _, err := rand.Read(random); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		data    []byte
		wantMin float64
		wantMax float64
	}{
		{name: "random data is near 8", data: random, wantMin: 7.9, wantMax: 8},
		{name: "empty data", data: nil, wantMin: 0, wantMax: 0},
		{name: "constant data", data: bytes.Repeat([]byte("a"), 1000), wantMin: 0, wantMax: 0},
		{name: "two equal symbols", data: []byte("abababab"), wantMin: 1 - 1e-9, wantMax: 1 + 1e-9},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ident.Entropy(tt.data)
			if got < tt.wantMin || got > tt.wantMax || math.IsNaN(got) {
				t.Errorf("Entropy = %v, want in [%v, %v]", got, tt.wantMin, tt.wantMax)
			}
		})
	}
}
