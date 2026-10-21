package archive_test

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash/crc32"
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
	// extra is written as the extra field of the local header and the central directory record
	extra []byte
}

func zipOf(t *testing.T, entries ...entry) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range entries {
		h := &zip.FileHeader{Name: e.name, Method: zip.Deflate, Flags: e.flag, Extra: e.extra}
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
	raw              byte // when set, a regular entry whose type flag is patched to this value
}

func tarOf(t *testing.T, entries ...tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		typeflag := e.typeflag
		if e.raw != 0 {
			typeflag = tar.TypeReg
		}
		h := &tar.Header{Name: e.name, Typeflag: typeflag, Linkname: e.link, Mode: 0o644}
		if typeflag == tar.TypeReg {
			h.Size = int64(len(e.data))
		}
		start := buf.Len()
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if e.raw != 0 {
			// The writer refuses these types, so patch the type flag and the checksum.
			hdr := buf.Bytes()[start : start+512]
			hdr[156] = e.raw
			if e.raw == 'S' {
				// One sparse region after a one byte hole, in the old GNU layout.
				copy(hdr[257:265], "ustar  \x00")
				copy(hdr[386:398], "00000000001\x00")
				copy(hdr[398:410], fmt.Sprintf("%011o\x00", len(e.data)))
				copy(hdr[483:495], fmt.Sprintf("%011o\x00", len(e.data)+1))
			}
			copy(hdr[148:156], "        ")
			sum := 0
			for _, b := range hdr {
				sum += int(b)
			}
			copy(hdr[148:156], fmt.Sprintf("%06o\x00 ", sum))
		}
		if typeflag == tar.TypeReg {
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

// sfx is a stub with a valid PE header followed by tail, like the start of a self-extracting archive.
func sfx(t *testing.T, tail ...byte) []byte {
	t.Helper()
	stub := make([]byte, 0x80)
	copy(stub, "MZ")
	stub[0x3c] = 0x40
	copy(stub[0x40:], "PE\x00\x00")
	return append(stub, tail...)
}

// mismatched renames the entry in its local file header only, so the central directory keeps the old name.
func mismatched(t *testing.T, from, to string) []byte {
	t.Helper()
	if len(from) != len(to) {
		t.Fatalf("names %q and %q differ in length", from, to)
	}
	return bytes.Replace(zipOf(t, entry{name: from, data: "payload"}), []byte(from), []byte(to), 1)
}

// fakeHeader is an extra field block that holds a well-formed local file header for name.
func fakeHeader(name string) []byte {
	h := make([]byte, 30)
	copy(h, "PK\x03\x04")
	h[26] = byte(len(name))
	h = append(h, name...)
	return append([]byte{0x66, 0x66, byte(len(h)), 0}, h...)
}

// rawZip assembles a stored zip by hand: n central directory records that all point at one local
// header named "a" with the data "x" and the given local extra field. With zip64 the records
// keep their offset in a zip64 extra field and the directory ends with the zip64 records.
func rawZip(n int, extra []byte, zip64 bool) []byte {
	le := binary.LittleEndian
	crc := crc32.ChecksumIEEE([]byte("x"))
	b := []byte("PK\x03\x04")
	b = le.AppendUint16(b, 20)
	b = le.AppendUint16(b, 0)
	b = le.AppendUint16(b, 0)
	b = le.AppendUint32(b, 0)
	b = le.AppendUint32(b, crc)
	b = le.AppendUint32(b, 1)
	b = le.AppendUint32(b, 1)
	b = le.AppendUint16(b, 1)
	b = le.AppendUint16(b, uint16(len(extra)))
	b = append(b, 'a')
	b = append(b, extra...)
	b = append(b, 'x')
	dirAt := len(b)
	for range n {
		b = append(b, "PK\x01\x02"...)
		b = le.AppendUint16(b, 20)
		b = le.AppendUint16(b, 20)
		b = le.AppendUint16(b, 0)
		b = le.AppendUint16(b, 0)
		b = le.AppendUint32(b, 0)
		b = le.AppendUint32(b, crc)
		b = le.AppendUint32(b, 1)
		b = le.AppendUint32(b, 1)
		b = le.AppendUint16(b, 1)
		offset := uint32(0)
		if zip64 {
			b = le.AppendUint16(b, 12)
			offset = 1<<32 - 1
		} else {
			b = le.AppendUint16(b, 0)
		}
		b = le.AppendUint16(b, 0)
		b = le.AppendUint16(b, 0)
		b = le.AppendUint16(b, 0)
		b = le.AppendUint32(b, 0)
		b = le.AppendUint32(b, offset)
		b = append(b, 'a')
		if zip64 {
			b = le.AppendUint16(b, 1)
			b = le.AppendUint16(b, 8)
			b = le.AppendUint64(b, 0)
		}
	}
	dirSize, dirOff := uint32(len(b)-dirAt), uint32(dirAt)
	if zip64 {
		end := len(b)
		b = append(b, "PK\x06\x06"...)
		b = le.AppendUint64(b, 44)
		b = le.AppendUint16(b, 45)
		b = le.AppendUint16(b, 45)
		b = le.AppendUint32(b, 0)
		b = le.AppendUint32(b, 0)
		b = le.AppendUint64(b, uint64(n))
		b = le.AppendUint64(b, uint64(n))
		b = le.AppendUint64(b, uint64(dirSize))
		b = le.AppendUint64(b, uint64(dirAt))
		b = append(b, "PK\x06\x07"...)
		b = le.AppendUint32(b, 0)
		b = le.AppendUint64(b, uint64(end))
		b = le.AppendUint32(b, 1)
		dirOff = 1<<32 - 1
	}
	b = append(b, "PK\x05\x06"...)
	b = le.AppendUint16(b, 0)
	b = le.AppendUint16(b, 0)
	b = le.AppendUint16(b, uint16(n))
	b = le.AppendUint16(b, uint16(n))
	b = le.AppendUint32(b, dirSize)
	b = le.AppendUint32(b, dirOff)
	return le.AppendUint16(b, 0)
}

const oleMagic = "\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"

func TestAnalyze(t *testing.T) {
	random := make([]byte, analyze.MaxFileSize+1)
	_, _ = rand.NewChaCha8([32]byte{1}).Read(random) // never fails
	var many []entry
	for i := range archive.MaxEntries + 1 {
		many = append(many, entry{name: fmt.Sprintf("f%d", i)})
	}
	crowded := make([]string, archive.MaxEntries)
	for i := range crowded {
		crowded[i] = "a"
	}
	// A 64 KiB extra field full of local header signatures, which a scan for the header would trip over.
	decoys := bytes.Repeat([]byte("PK\x03\x04"), 1<<14-1)
	withGap := func() []byte {
		z := zipOf(t, entry{name: "a.txt", data: "a"})
		end := bytes.LastIndex(z, []byte("PK\x05\x06"))
		return slices.Concat(z[:end], []byte("junk!"), z[end:])
	}()
	// The second local header loses the last byte of its signature.
	badLocal := zipOf(t, entry{name: "a.txt", data: "a"}, entry{name: "b.txt", data: "b"})
	badLocal[bytes.LastIndex(badLocal[:bytes.Index(badLocal, []byte("PK\x01\x02"))], []byte("PK\x03\x04"))+3] = 5
	iso := make([]byte, 0x8100)
	copy(iso[0x8001:], "CD001")
	// A stub, then a zip whose end record implies a shift by the stub. patch edits a record planted
	// in the stub at the offset where the unshifted directory would start.
	planted := func(patch func(rec []byte)) []byte {
		z := zipOf(t, entry{name: strings.Repeat("n", 40), data: "a"})
		stub := sfx(t, make([]byte, 64)...) // room for a record
		rec := stub[bytes.Index(z, []byte("PK\x01\x02")):]
		copy(rec, "PK\x01\x02")
		patch(rec)
		return append(stub, z...)
	}

	tests := []struct {
		name string
		// inputs
		file  string
		data  []byte
		depth int
		// expectations
		wantChildren []string // member names, in order
		wantFindings []string // "rule path"
		wantSkips    []string // "path reason"
		wantErr      bool
	}{
		{name: "zip members become children and directories are ignored", file: "in.zip",
			data:         zipOf(t, entry{name: "d/", mode: fs.ModeDir | 0o755}, entry{name: "a.txt", data: "a"}, entry{name: "d/b.txt", data: "b"}),
			wantChildren: []string{"a.txt", "d/b.txt"}},
		{name: "zip with a nested content types file is not ooxml and keeps all members", file: "in.zip",
			data:         zipOf(t, entry{name: "p/.vscode/tasks.json", data: "{}"}, entry{name: "sub/[Content_Types].xml", data: "<Types/>"}),
			wantChildren: []string{"p/.vscode/tasks.json", "sub/[Content_Types].xml"}},
		{name: "zip at the nesting limit is not decompressed", file: "in.zip", depth: analyze.MaxNesting,
			data:      zipOf(t, entry{name: "a.txt", data: "a"}),
			wantSkips: []string{"in.zip depth"}},
		{name: "zip just above the nesting limit is expanded", file: "in.zip", depth: analyze.MaxNesting - 1,
			data:         zipOf(t, entry{name: "a.txt", data: "a"}),
			wantChildren: []string{"a.txt"}},
		{name: "executable with an appended zip is expanded", file: "in.exe",
			data:         sfx(t, zipOf(t, entry{name: "p/.vscode/tasks.json", data: "{}"})...),
			wantChildren: []string{"p/.vscode/tasks.json"},
			wantFindings: []string{"GAL-ARCHIVE-006 in.exe"}},
		{name: "executable with a zip written after an offset shift is expanded", file: "in.exe",
			data: func() []byte {
				stub := sfx(t)
				buf := bytes.NewBuffer(stub)
				zw := zip.NewWriter(buf)
				zw.SetOffset(int64(len(stub)))
				w, err := zw.Create("a.txt")
				if err != nil {
					t.Fatal(err)
				}
				_, _ = w.Write([]byte("a"))
				if err := zw.Close(); err != nil {
					t.Fatal(err)
				}
				return buf.Bytes()
			}(),
			wantChildren: []string{"a.txt"},
			wantFindings: []string{"GAL-ARCHIVE-006 in.exe"}},
		{name: "planted record whose name runs past the file does not undo the shift", file: "in.exe",
			data:         planted(func(rec []byte) { binary.LittleEndian.PutUint16(rec[28:], 0xffff) }),
			wantChildren: []string{strings.Repeat("n", 40)},
			wantFindings: []string{"GAL-ARCHIVE-006 in.exe"}},
		{name: "planted record with a zip64 field too short for its full size does not undo the shift", file: "in.exe",
			data: planted(func(rec []byte) {
				binary.LittleEndian.PutUint32(rec[20:], 1<<32-1)
				binary.LittleEndian.PutUint16(rec[30:], 8)
				copy(rec[46:], []byte{1, 0, 4, 0})
			}),
			wantChildren: []string{strings.Repeat("n", 40)},
			wantFindings: []string{"GAL-ARCHIVE-006 in.exe"}},
		{name: "executable with an appended zip at the nesting limit is not expanded", file: "in.exe", depth: analyze.MaxNesting,
			data:      sfx(t, zipOf(t, entry{name: "a.txt", data: "a"})...),
			wantSkips: []string{"in.exe depth"}},
		{name: "executable with a stray zip signature is left alone", file: "in.exe",
			data: sfx(t, []byte("text PK\x05\x06 text")...)},
		{name: "executable without a zip is left alone", file: "in.exe", data: sfx(t)},
		{name: "zip that cannot be read", file: "in.zip", data: []byte("PK\x03\x04 truncated"), wantErr: true},
		{name: "more entries than the limit", file: "in.zip", data: zipOf(t, many...),
			wantChildren: func() []string {
				var names []string
				for i := range archive.MaxEntries {
					names = append(names, fmt.Sprintf("f%d", i))
				}
				return names
			}(),
			wantSkips: []string{"in.zip budget"}},
		{name: "many backslash names give one finding for the first", file: "in.zip",
			data:         zipOf(t, entry{name: `a\1`}, entry{name: `a\2`}, entry{name: `a\3`}),
			wantChildren: []string{`a\1`, `a\2`, `a\3`},
			wantFindings: []string{`GAL-ARCHIVE-005 in.zip!/a\1`}},
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
		{name: "backslash name is unpacked and reported", file: "in.zip", data: zipOf(t, entry{name: `a\.vscode\tasks.json`, data: "{}"}),
			wantChildren: []string{`a\.vscode\tasks.json`},
			wantFindings: []string{`GAL-ARCHIVE-005 in.zip!/a\.vscode\tasks.json`}},
		{name: "tar backslash name is unpacked and reported", file: "in.tar", data: tarOf(t, tarEntry{name: `a\b`, data: "x", typeflag: tar.TypeReg}),
			wantChildren: []string{`a\b`},
			wantFindings: []string{`GAL-ARCHIVE-005 in.tar!/a\b`}},
		{name: "dots inside a name are fine", file: "in.zip", data: zipOf(t, entry{name: "a..b/c..d", data: "x"}),
			wantChildren: []string{"a..b/c..d"}},
		{name: "local name differs from the central name", file: "in.zip", data: mismatched(t, "a.txt", "b.txt"),
			wantChildren: []string{"a.txt", "b.txt"},
			wantFindings: []string{"GAL-ARCHIVE-007 in.zip!/a.txt"}},
		{name: "many local names that differ give one finding for the first", file: "in.zip",
			data: bytes.Replace(
				bytes.Replace(zipOf(t, entry{name: "a.txt", data: "a"}, entry{name: "c.txt", data: "c"}), []byte("a.txt"), []byte("b.txt"), 1),
				[]byte("c.txt"), []byte("d.txt"), 1),
			wantChildren: []string{"a.txt", "b.txt", "c.txt", "d.txt"},
			wantFindings: []string{"GAL-ARCHIVE-007 in.zip!/a.txt"}},
		{name: "local name that escapes is reported and not unpacked", file: "in.zip", data: mismatched(t, "abcdefg", "../evil"),
			wantChildren: []string{"abcdefg"},
			wantFindings: []string{"GAL-ARCHIVE-001 in.zip!/../evil", "GAL-ARCHIVE-007 in.zip!/abcdefg"}},
		{name: "fake local header in the extra field does not hide the real local name", file: "in.zip",
			data: bytes.Replace(zipOf(t, entry{name: "_vscode/tasks.json", data: "{}", extra: fakeHeader("_vscode/tasks.json")}),
				[]byte("_vscode/tasks.json"), []byte(".vscode/tasks.json"), 1),
			wantChildren: []string{"_vscode/tasks.json", ".vscode/tasks.json"},
			wantFindings: []string{"GAL-ARCHIVE-007 in.zip!/_vscode/tasks.json"}},
		{name: "local header that is not where the directory says is reported", file: "in.zip",
			data:         badLocal,
			wantChildren: []string{"a.txt"},
			wantFindings: []string{"GAL-ARCHIVE-007 in.zip"}, wantSkips: []string{"in.zip!/b.txt unreadable"}},
		{name: "many entries sharing one local header with decoy signatures", file: "in.zip",
			data: rawZip(archive.MaxEntries, decoys, false), wantChildren: crowded},
		{name: "zip64 central directory records are followed", file: "in.zip",
			data: rawZip(2, nil, true), wantChildren: []string{"a", "a"}},
		{name: "gap before the end record does not shift the offsets", file: "in.zip",
			data: withGap, wantChildren: []string{"a.txt"}},
		{name: "local name that only differs by separator is reported once", file: "in.zip", data: mismatched(t, "a/b.txt", `a\b.txt`),
			wantChildren: []string{"a/b.txt"},
			wantFindings: []string{"GAL-ARCHIVE-007 in.zip!/a/b.txt"}},
		{name: "zip symlink entry", file: "in.zip", data: zipOf(t, entry{name: "link", data: "/etc/passwd", mode: fs.ModeSymlink | 0o777}),
			wantFindings: []string{"GAL-ARCHIVE-002 in.zip!/link"}},
		{name: "ooxml leaves package markup and macro projects to the office analyzer", file: "in.docm",
			data: zipOf(t,
				entry{name: "[Content_Types].xml", data: "<Types/>"}, entry{name: "[CONTENT_TYPES].XML", data: "<Types/>"},
				entry{name: "_rels/.rels", data: "<r/>"}, entry{name: "docProps/app.xml", data: "<a/>"},
				entry{name: "customXml/item1.xml", data: "<c/>"}, entry{name: "word/document.xml", data: "<d/>"},
				entry{name: "word/_rels/document.xml.rels", data: "<r/>"}, entry{name: "Word/Theme/theme1.XML", data: "<t/>"},
				entry{name: "xl/sharedStrings.xml", data: "<s/>"}, entry{name: "ppt/slides/slide1.xml", data: "<s/>"},
				entry{name: "word/vbaProject.bin", data: oleMagic}, entry{name: "macros/VBAPROJECT.BIN", data: oleMagic},
				entry{name: "docProps/empty.xml"}, entry{name: "word/utf8.xml", data: "<a>\u00e9</a>"},
				entry{name: "word/_rels/.rels", data: "<r/>"}, entry{name: "ppt/.a.rels", data: "<a/>"}, entry{name: "x/y/z.rels", data: "<a/>"})},
		{name: "ooxml unpacks every other member", file: "in.docx",
			data: zipOf(t,
				entry{name: "[Content_Types].xml", data: "<Types/>"}, entry{name: "word/document.xml", data: "<d/>"},
				entry{name: "extra/.vscode/tasks.json", data: "{}"}, entry{name: "run.js", data: "x"},
				entry{name: "[Content_Types].xml.bak", data: "x"}, entry{name: "wordy/run.xml", data: "x"}, entry{name: "word", data: "x"},
				entry{name: `word\theme.xml`, data: "<t/>"}, entry{name: `word\vbaProject.bin`, data: "x"}),
			wantChildren: []string{"extra/.vscode/tasks.json", "run.js", "[Content_Types].xml.bak", "wordy/run.xml", "word", `word\theme.xml`, `word\vbaProject.bin`},
			wantFindings: []string{`GAL-ARCHIVE-005 in.docx!/word\theme.xml`}},
		{name: "ooxml unpacks payloads below the package folders", file: "in.docx",
			data: zipOf(t,
				entry{name: "[Content_Types].xml", data: "<Types/>"}, entry{name: "word/.vscode/tasks.json", data: "{}"},
				entry{name: "xl/.vscode/tasks.json", data: "{}"}, entry{name: "word/embeddings/x.bin", data: "x"},
				entry{name: "word/run.js", data: "x"}, entry{name: "Word/media/image1.png", data: "x"},
				entry{name: "word/.hidden/a.xml", data: "<a/>"}),
			wantChildren: []string{"word/.vscode/tasks.json", "xl/.vscode/tasks.json", "word/embeddings/x.bin", "word/run.js", "Word/media/image1.png", "word/.hidden/a.xml"}},
		{name: "ooxml part holding a zip, an executable or binary data is unpacked", file: "in.docx",
			data: zipOf(t,
				entry{name: "[Content_Types].xml", data: "<Types/>"},
				entry{name: "word/styles.xml", data: "PK\x03\x04 zip"}, entry{name: "word/theme/theme1.xml", data: "MZ stub"},
				entry{name: "docProps/core.xml", data: "<a/>\x00\x01"}, entry{name: "word/_rels/document.xml.rels", data: "PK\x05\x06"},
				entry{name: "word/gz.xml", data: string(gzipOf(t, []byte("x")))}),
			wantChildren: []string{"word/styles.xml", "word/theme/theme1.xml", "docProps/core.xml", "word/_rels/document.xml.rels", "word/gz.xml"}},
		{name: "ooxml vba project that is not OLE is unpacked", file: "in.docm",
			data:         zipOf(t, entry{name: "[Content_Types].xml", data: "<Types/>"}, entry{name: "word/vbaProject.bin", data: "PK\x03\x04 zip"}, entry{name: "empty/vbaProject.bin"}),
			wantChildren: []string{"word/vbaProject.bin", "empty/vbaProject.bin"}},
		{name: "ooxml part with a different local name is unpacked under both names", file: "in.docx",
			data:         bytes.Replace(zipOf(t, entry{name: "[Content_Types].xml", data: "<Types/>"}, entry{name: "word/a.xml", data: "<a/>"}), []byte("word/a.xml"), []byte("word/b.xml"), 1),
			wantChildren: []string{"word/a.xml", "word/b.xml"},
			wantFindings: []string{"GAL-ARCHIVE-007 in.docx!/word/a.xml"}},
		{name: "ooxml part name that escapes is still reported", file: "in.docx",
			data:         zipOf(t, entry{name: "[Content_Types].xml", data: "<Types/>"}, entry{name: "word/../../evil.sh", data: "x"}),
			wantFindings: []string{"GAL-ARCHIVE-001 in.docx!/word/../../evil.sh"}},
		{name: "ooxml symlink under a package folder is still reported", file: "in.docx",
			data:         zipOf(t, entry{name: "[Content_Types].xml", data: "<Types/>"}, entry{name: "word/link", data: "/etc/passwd", mode: fs.ModeSymlink | 0o777}),
			wantFindings: []string{"GAL-ARCHIVE-002 in.docx!/word/link"}},
		{name: "ooxml encrypted part is left to the office analyzer", file: "in.docx",
			data: zipOf(t, entry{name: "[Content_Types].xml", data: "<Types/>"}, entry{name: "word/styles.xml", data: "x", flag: 1})},
		{name: "encrypted zip entry", file: "in.zip", data: zipOf(t, entry{name: "secret.txt", data: "x", flag: 1}),
			wantFindings: []string{"GAL-ARCHIVE-004 in.zip!/secret.txt"}, wantSkips: []string{"in.zip!/secret.txt encrypted"}},
		{name: "zip bomb by ratio", file: "in.zip", data: zipOf(t, entry{name: "zeros", data: strings.Repeat("\x00", 20<<20)}),
			wantFindings: []string{"GAL-ARCHIVE-003 in.zip"}, wantSkips: []string{"in.zip!/zeros budget"}},
		{name: "entry above the file size limit", file: "in.zip", data: zipOf(t, entry{name: "big", raw: random}),
			wantSkips: []string{"in.zip!/big too_large"}},
		{name: "tar at the nesting limit is not decompressed", file: "in.tar", depth: analyze.MaxNesting,
			data:      tarOf(t, tarEntry{name: "a.txt", data: "a", typeflag: tar.TypeReg}),
			wantSkips: []string{"in.tar depth"}},
		{name: "tar members become children", file: "in.tar", data: tarOf(t, tarEntry{name: "d/", typeflag: tar.TypeDir}, tarEntry{name: "a.txt", data: "a", typeflag: tar.TypeReg}),
			wantChildren: []string{"a.txt"}},
		{name: "tar that cannot be read", file: "in.tar", data: bytes.Repeat([]byte("x"), 1024),
			wantSkips: []string{"in.tar unreadable"}},
		{name: "tar with a bad header after a member keeps the member and reports the rest unreadable", file: "in.tar",
			data: func() []byte {
				b := tarOf(t, tarEntry{name: "a.txt", data: "a", typeflag: tar.TypeReg}, tarEntry{name: ".vscode/tasks.json", data: "{}", typeflag: tar.TypeReg})
				copy(b[1024+148:], "9999999\x00") // the checksum of the second header
				return b
			}(),
			wantChildren: []string{"a.txt"}, wantSkips: []string{"in.tar unreadable"}},
		{name: "tar entry that escapes", file: "in.tar", data: tarOf(t, tarEntry{name: "../x", data: "x", typeflag: tar.TypeReg}),
			wantFindings: []string{"GAL-ARCHIVE-001 in.tar!/../x"}},
		{name: "tar symlink", file: "in.tar", data: tarOf(t, tarEntry{name: "link", link: "/etc/passwd", typeflag: tar.TypeSymlink}),
			wantFindings: []string{"GAL-ARCHIVE-002 in.tar!/link"}},
		{name: "tar hardlink", file: "in.tar", data: tarOf(t, tarEntry{name: "link", link: "a.txt", typeflag: tar.TypeLink}),
			wantFindings: []string{"GAL-ARCHIVE-002 in.tar!/link"}},
		{name: "tar contiguous file is read", file: "in.tar", data: tarOf(t, tarEntry{name: "c", data: "payload", raw: '7'}),
			wantChildren: []string{"c"}},
		{name: "tar sparse file is read", file: "in.tar", data: tarOf(t, tarEntry{name: "s", data: "payload", raw: 'S'}),
			wantChildren: []string{"s"}},
		{name: "tar entry of unknown type is read", file: "in.tar", data: tarOf(t, tarEntry{name: "z", data: "payload", raw: 'Z'}),
			wantChildren: []string{"z"}},
		{name: "tar fifo is ignored", file: "in.tar", data: tarOf(t, tarEntry{name: "pipe", typeflag: tar.TypeFifo}, tarEntry{name: "a", data: "a", typeflag: tar.TypeReg}),
			wantChildren: []string{"a"}},
		{name: "tgz expands its tar", file: "in.tgz", data: gzipOf(t, tarOf(t, tarEntry{name: "a.txt", data: "a", typeflag: tar.TypeReg})),
			wantChildren: []string{"a.txt"}},
		{name: "tar.gz expands its tar", file: "in.tar.gz", data: gzipOf(t, tarOf(t, tarEntry{name: "a.txt", data: "a", typeflag: tar.TypeReg})),
			wantChildren: []string{"a.txt"}},
		{name: "gz at the nesting limit is not decompressed", file: "in.gz", depth: analyze.MaxNesting,
			data:      gzipOf(t, []byte("hello\n")),
			wantSkips: []string{"in.gz depth"}},
		{name: "gz becomes one child without its suffix", file: "notes.txt.gz", data: gzipOf(t, []byte("hello\n")),
			wantChildren: []string{"notes.txt"}},
		{name: "gz suffix in capitals", file: "NOTES.GZ", data: gzipOf(t, []byte("hello\n")),
			wantChildren: []string{"NOTES"}},
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
			f := analyze.File{Path: tt.file, Name: tt.file, Kind: ident.Identify(tt.file, tt.data), Data: tt.data, Depth: tt.depth}

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

func TestAnalyzeBrokenZip64(t *testing.T) {
	le := binary.LittleEndian
	good := rawZip(1, nil, true)
	locator := bytes.LastIndex(good, []byte("PK\x06\x07"))
	end := bytes.LastIndex(good, []byte("PK\x05\x06"))
	// The locator loses its last four bytes, so it no longer ends at the end record.
	truncatedLocator := slices.Concat(good[:end-4], good[end:])
	// The locator points past the end of the file.
	farLocator := slices.Clone(good)
	le.PutUint64(farLocator[locator+8:], uint64(len(good))+100)
	// The zip64 extra field of the record holds four bytes where the offset needs eight.
	shortExtra := func() []byte {
		z := slices.Clone(good)
		field := bytes.Index(z, []byte{1, 0, 8, 0})
		z = slices.Concat(z[:field], []byte{1, 0, 4, 0, 0, 0, 0, 0}, z[field+12:])
		z[bytes.Index(z, []byte("PK\x01\x02"))+30] = 8
		z64 := bytes.Index(z, []byte("PK\x06\x06"))
		le.PutUint64(z[z64+40:], le.Uint64(z[z64+40:])-4)
		le.PutUint64(z[bytes.Index(z, []byte("PK\x06\x07"))+8:], uint64(z64))
		e := bytes.LastIndex(z, []byte("PK\x05\x06"))
		le.PutUint32(z[e+12:], le.Uint32(z[e+12:])-4)
		return z
	}()
	tests := []struct {
		name string
		// inputs
		data []byte
		// expectations
		wantChildren []string
		wantErr      bool
	}{
		{name: "intact zip64 zip is expanded", data: good, wantChildren: []string{"a"}},
		{name: "truncated zip64 locator", data: truncatedLocator, wantErr: true},
		{name: "zip64 locator that points past the end", data: farLocator, wantErr: true},
		{name: "zip64 extra field too short for the offset", data: shortExtra, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := analyze.File{Path: "in.zip", Name: "in.zip", Kind: ident.Zip, Data: tt.data}

			out, err := archive.New().Analyze(context.Background(), f)

			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, want error %v", err, tt.wantErr)
			}
			var children []string
			for _, c := range out.Children {
				children = append(children, c.Name)
			}
			if !slices.Equal(children, tt.wantChildren) {
				t.Errorf("children = %v, want %v", children, tt.wantChildren)
			}
			if len(out.Findings) != 0 {
				t.Errorf("findings = %+v, want none", out.Findings)
			}
		})
	}
}

func TestAnalyzeBudget(t *testing.T) {
	small := zipOf(t, entry{name: "a.txt", data: strings.Repeat("a", 600<<10)})
	bomb := zipOf(t, entry{name: "a.txt", data: strings.Repeat("a", 3<<20)})
	tests := []struct {
		name string
		// inputs
		data   []byte
		budget int64 // negative means the context carries none
		// expectations
		wantChildren []string
		wantFindings []string
		wantSkips    []string
	}{
		{name: "a member that fits in the budget is expanded", data: small, budget: 1 << 20, wantChildren: []string{"a.txt"}},
		{name: "no budget leaves the archive limits alone", data: small, budget: -1, wantChildren: []string{"a.txt"}},
		{name: "a bomb is still a bomb when the budget is larger than the archive limit", data: bomb, budget: 1 << 30,
			wantFindings: []string{"GAL-ARCHIVE-003 in.zip"}, wantSkips: []string{"in.zip!/a.txt budget"}},
		{name: "a member over the budget is a budget skip and not a bomb", data: small, budget: 1 << 10,
			wantSkips: []string{"in.zip!/a.txt budget"}},
		{name: "a spent budget expands nothing", data: small, budget: 0,
			wantSkips: []string{"in.zip!/a.txt budget"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			if tt.budget >= 0 {
				ctx = analyze.WithBudget(ctx, tt.budget)
			}
			f := analyze.File{Path: "in.zip", Name: "in.zip", Kind: ident.Zip, Data: tt.data}

			out, err := archive.New().Analyze(ctx, f)

			if err != nil {
				t.Fatal(err)
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
			if !slices.Equal(children, tt.wantChildren) || !slices.Equal(findings, tt.wantFindings) || !slices.Equal(skips, tt.wantSkips) {
				t.Errorf("children %v findings %v skips %v, want %v %v %v", children, findings, skips, tt.wantChildren, tt.wantFindings, tt.wantSkips)
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
		{name: "backslash name", data: zipOf(t, entry{name: `a\b`}), wantRule: "GAL-ARCHIVE-005", wantSeverity: "low", wantSnippet: `1 in this archive, first: a\b`},
		{name: "appended zip", data: sfx(t, zipOf(t, entry{name: "a"})...), wantRule: "GAL-ARCHIVE-006", wantSeverity: "low", wantSnippet: "1 zip entries after the executable"},
		{name: "name mismatch", data: mismatched(t, "a.txt", "b.txt"), wantRule: "GAL-ARCHIVE-007", wantSeverity: "medium", wantSnippet: "1 in this archive, first: central: a.txt, local: b.txt"},
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
