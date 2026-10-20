package office_test

import (
	"archive/zip"
	"bytes"
	"cmp"
	"context"
	"encoding/binary"
	"fmt"
	"math/bits"
	"slices"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/mrdhira/galahad/internal/analyze"
	"github.com/mrdhira/galahad/internal/analyze/ident"
	"github.com/mrdhira/galahad/internal/analyze/static/office"
)

// ---- fixture builders ----

type part struct {
	name  string
	data  []byte
	flags uint16
}

func zipOf(t *testing.T, parts ...part) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, p := range parts {
		method := zip.Deflate
		if len(p.data) == 0 {
			method = zip.Store
		}
		w, err := zw.CreateHeader(&zip.FileHeader{Name: p.name, Method: method, Flags: p.flags})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(p.data); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// zipUnsupported builds a zip whose only member uses a compression method Go cannot open.
func zipUnsupported(t *testing.T, name string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.CreateRaw(&zip.FileHeader{Name: name, Method: 99, CompressedSize64: 3, UncompressedSize64: 3})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("abc")); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func rels(rs ...string) []byte {
	return []byte("<?xml version=\"1.0\"?>\n<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\">\n" +
		strings.Join(rs, "\n") + "\n</Relationships>\n")
}

const relType = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/"

func rel(kind, target string, external bool) string {
	mode := ""
	if external {
		mode = ` TargetMode="External"`
	}
	return fmt.Sprintf(`<Relationship Id="rId1" Type="%s%s" Target="%s"%s/>`, relType, kind, target, mode)
}

// lz compresses data as MS-OVBA chunks, using copy tokens for repeated text.
func lz(data []byte) []byte {
	out := []byte{1}
	for len(data) > 0 {
		n := min(len(data), 4096)
		body := lzChunk(data[:n])
		data = data[n:]
		hdr := uint16(len(body)-1) | 0x3000 | 0x8000
		out = append(out, byte(hdr), byte(hdr>>8))
		out = append(out, body...)
	}
	return out
}

func lzChunk(c []byte) []byte {
	var body []byte
	for i := 0; i < len(c); {
		flagAt := len(body)
		body = append(body, 0)
		for bit := 0; bit < 8 && i < len(c); bit++ {
			bestLen, bestOff, bitCount := 0, 0, 4
			if i > 0 {
				bitCount = max(bits.Len(uint(i-1)), 4)
				for off := 1; off <= i; off++ {
					l := 0
					for l < 0xFFFF>>bitCount+3 && i+l < len(c) && c[i+l-off] == c[i+l] {
						l++
					}
					if l > bestLen {
						bestLen, bestOff = l, off
					}
				}
			}
			if bestLen < 3 {
				body = append(body, c[i])
				i++
				continue
			}
			tok := (bestOff-1)<<(16-bitCount) | (bestLen - 3)
			body = append(body, byte(tok), byte(tok>>8))
			body[flagAt] |= 1 << bit
			i += bestLen
		}
	}
	return body
}

// raw stores data as uncompressed MS-OVBA chunks.
func raw(data []byte) []byte {
	out := []byte{1}
	for len(data) > 0 {
		n := min(len(data), 4096)
		chunk := append(append([]byte{}, data[:n]...), make([]byte, 4096-n)...)
		data = data[n:]
		out = append(out, 0xFF, 0x3F)
		out = append(out, chunk...)
	}
	return out
}

type vbaModule struct {
	name, source string
	uncompressed bool   // stored in uncompressed chunks, which makes the stream large
	body         []byte // when set, used as the compressed container
	hasBody      bool
	offset       uint32 // TextOffset in the dir stream; 0 means 4, the size of the junk prefix
	noStream     bool   // the dir stream names the module but its stream does not exist
}

func rec(id uint16, data []byte) []byte {
	b := binary.LittleEndian.AppendUint16(nil, id)
	b = binary.LittleEndian.AppendUint32(b, uint32(len(data)))
	return append(b, data...)
}

// vbaStreams returns the dir stream and module streams of a VBA project. Each
// module stream starts with 4 junk bytes that the dir stream's offset skips.
func vbaStreams(mods []vbaModule) []cfbStream {
	// The size field of PROJECTVERSION is the constant 4, and 6 bytes of version follow it.
	dir := []byte{9, 0, 4, 0, 0, 0, 1, 0, 0, 0, 2, 0}
	dir = append(dir, rec(0x000F, []byte{byte(len(mods)), 0})...)
	var streams []cfbStream
	for _, m := range mods {
		dir = append(dir, rec(0x0019, []byte(m.name))...)
		dir = append(dir, rec(0x001A, []byte(m.name))...)
		off := cmp.Or(m.offset, 4)
		dir = append(dir, rec(0x0031, binary.LittleEndian.AppendUint32(nil, off))...)
		dir = append(dir, rec(0x002B, nil)...)
		body := lz([]byte(m.source))
		if m.uncompressed {
			body = raw([]byte(m.source))
		}
		if m.hasBody {
			body = m.body
		}
		if !m.noStream {
			streams = append(streams, cfbStream{m.name, append([]byte("junk"), body...)})
		}
	}
	dir = append(dir, rec(0x0010, nil)...)
	return append([]cfbStream{{"dir", lz(dir)}, {"_VBA_PROJECT", []byte{0xcc, 0x61, 0xff, 0xff, 0, 0, 0}}}, streams...)
}

type cfbStream struct {
	name string
	data []byte
}

const free, endOfChain = 0xFFFFFFFF, 0xFFFFFFFE

// buildCFB writes a version 3 compound file: a root entry, nested storages and
// the streams in the innermost storage. Streams under 4096 bytes go in the mini
// stream. mutate may change the FAT before it is written.
func buildCFB(storages []string, streams []cfbStream, mutate func(fat []uint32)) []byte {
	type ent struct {
		name             string
		typ              byte
		left, right, kid uint32
		start            uint32
		size             uint32
	}
	ents := []ent{{name: "Root Entry", typ: 5, left: free, right: free, kid: free}}
	for i, s := range storages {
		ents = append(ents, ent{name: s, typ: 1, left: free, right: free, kid: free})
		ents[i].kid = uint32(i + 1)
	}
	parent := len(ents) - 1
	for i, s := range streams {
		if i == 0 {
			ents[parent].kid = uint32(len(ents))
		} else {
			ents[len(ents)-1].right = uint32(len(ents))
		}
		ents = append(ents, ent{name: s.name, typ: 2, left: free, right: free, kid: free, size: uint32(len(s.data))})
	}

	var mini []byte
	var miniFAT []uint32
	big := map[int][]byte{}
	for i, s := range streams {
		e := &ents[len(ents)-len(streams)+i]
		if len(s.data) >= 4096 {
			big[len(ents)-len(streams)+i] = s.data
			continue
		}
		e.start = uint32(len(mini) / 64)
		n := (len(s.data) + 63) / 64
		for j := range n {
			next := uint32(len(miniFAT) + 1)
			if j == n-1 {
				next = endOfChain
			}
			miniFAT = append(miniFAT, next)
		}
		mini = append(mini, s.data...)
		mini = append(mini, make([]byte, n*64-len(s.data))...)
	}

	ceil := func(n, d int) int { return (n + d - 1) / d }
	nDir, nMiniFAT, nMini := ceil(len(ents)*128, 512), ceil(len(miniFAT)*4, 512), ceil(len(mini), 512)
	fat := make([]uint32, 128)
	for i := range fat {
		fat[i] = free
	}
	fat[0] = 0xFFFFFFFD
	next := 1
	alloc := func(n int) uint32 {
		if n == 0 {
			return endOfChain
		}
		start := next
		for i := range n {
			fat[next+i] = uint32(next + i + 1)
		}
		fat[next+n-1] = endOfChain
		next += n
		return uint32(start)
	}
	dirStart := alloc(nDir)
	miniFATStart := alloc(nMiniFAT)
	ents[0].start = alloc(nMini)
	ents[0].size = uint32(len(mini))
	var bigIdx []int
	for i := range big {
		bigIdx = append(bigIdx, i)
	}
	slices.Sort(bigIdx)
	bigStart := map[int]int{}
	for _, i := range bigIdx {
		bigStart[i] = next
		ents[i].start = alloc(ceil(len(big[i]), 512))
	}
	if mutate != nil {
		mutate(fat)
	}

	le := binary.LittleEndian
	hdr := make([]byte, 512)
	copy(hdr, []byte{0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1})
	le.PutUint16(hdr[24:], 0x3e)
	le.PutUint16(hdr[26:], 3)
	le.PutUint16(hdr[28:], 0xFFFE)
	le.PutUint16(hdr[30:], 9)
	le.PutUint16(hdr[32:], 6)
	le.PutUint32(hdr[44:], 1)
	le.PutUint32(hdr[48:], dirStart)
	le.PutUint32(hdr[56:], 4096)
	le.PutUint32(hdr[60:], miniFATStart)
	le.PutUint32(hdr[64:], uint32(nMiniFAT))
	le.PutUint32(hdr[68:], endOfChain)
	for i := range 109 {
		le.PutUint32(hdr[76+4*i:], free)
	}
	le.PutUint32(hdr[76:], 0)

	out := hdr
	sector := func(n int, b []byte) {
		for len(out) < (n+2)*512 {
			out = append(out, 0)
		}
		copy(out[(n+1)*512:], b)
	}
	fatBytes := make([]byte, 512)
	for i, v := range fat {
		le.PutUint32(fatBytes[4*i:], v)
	}
	sector(0, fatBytes)
	dirBytes := make([]byte, nDir*512)
	for i, e := range ents {
		b := dirBytes[i*128 : (i+1)*128]
		name := utf16.Encode([]rune(e.name))
		for j, u := range name {
			le.PutUint16(b[2*j:], u)
		}
		le.PutUint16(b[64:], uint16(2*len(name)+2))
		b[66], b[67] = e.typ, 1
		le.PutUint32(b[68:], e.left)
		le.PutUint32(b[72:], e.right)
		le.PutUint32(b[76:], e.kid)
		le.PutUint32(b[116:], e.start)
		le.PutUint32(b[120:], e.size)
	}
	put := func(start uint32, b []byte) {
		for i := 0; i*512 < len(b); i++ {
			sector(int(start)+i, b[i*512:min((i+1)*512, len(b))])
		}
	}
	put(dirStart, dirBytes)
	miniFATBytes := make([]byte, nMiniFAT*512)
	for i := range miniFATBytes {
		miniFATBytes[i] = 0xFF
	}
	for i, v := range miniFAT {
		le.PutUint32(miniFATBytes[4*i:], v)
	}
	if nMiniFAT > 0 {
		put(miniFATStart, miniFATBytes)
	}
	if nMini > 0 {
		put(ents[0].start, mini)
	}
	for _, i := range bigIdx {
		put(uint32(bigStart[i]), big[i])
	}
	return out
}

var macroModules = []vbaModule{
	{name: "ThisDocument", source: "Option Explicit\r\nSub Document_Open()\r\n  Call Run\r\nEnd Sub\r\n"},
	{name: "Module1", source: "Sub Run()\r\n  Dim s\r\n  Set s = CreateObject(\"WScript.Shell\")\r\nEnd Sub\r\n' Sub Run() ' Sub Run()\r\n"},
	{name: "Big", source: "Private Function Auto_Open()\r\nx = Shell(\"calc\")\r\nEnd Function\r\n", uncompressed: true},
}

func patched(b []byte, f func(b []byte)) []byte {
	f(b)
	return b
}

func vbaProject(mods []vbaModule, mutate func(fat []uint32)) []byte {
	return buildCFB([]string{"VBA"}, vbaStreams(mods), mutate)
}

// ---- tests ----

func TestAnalyze(t *testing.T) {
	const word = "offer.docx"
	const relsPath = word + "!/word/_rels/settings.xml.rels"
	const binPath = word + "!/word/vbaProject.bin"
	attached := rel("attachedTemplate", "http://templates.sinkhole.test/t.dotm", true)
	manyParts := make([]part, 5)
	for i := range manyParts {
		manyParts[i] = part{name: fmt.Sprintf("d%d/vbaProject.bin", i), data: make([]byte, 16<<20)}
	}
	manyNames := make([]part, 5001)
	for i := range manyNames {
		manyNames[i] = part{name: fmt.Sprintf("f%d.txt", i)}
	}

	tests := []struct {
		name string
		// inputs
		kind  ident.Kind
		path  string
		data  func(t *testing.T) []byte
		abort bool // cancel the context before the call
		// expectations
		wantErr      bool
		wantFindings []string // "RULE path:line"
		wantIOCs     []string // "value path:line"
		wantSkips    []string // "path:reason"
	}{
		{
			name: "remote template in settings.xml.rels is flagged with its line and URL",
			kind: ident.OOXML, path: word,
			data: func(t *testing.T) []byte {
				return zipOf(t, part{name: "[Content_Types].xml", data: []byte("<Types/>")}, part{name: "word/_rels/settings.xml.rels", data: rels(attached)})
			},
			wantFindings: []string{"GAL-OFFICE-001 " + relsPath + ":3"},
			wantIOCs:     []string{"http://templates.sinkhole.test/t.dotm " + relsPath + ":3"},
		},
		{
			name: "file that is not a zip fails",
			kind: ident.OOXML, path: word,
			data:    func(t *testing.T) []byte { return []byte("PK\x03\x04 not really a zip") },
			wantErr: true,
		},
		{
			name: "cancelled context stops the scan",
			kind: ident.OOXML, path: word, abort: true,
			data: func(t *testing.T) []byte {
				return zipOf(t, part{name: "word/_rels/settings.xml.rels", data: rels(attached)})
			},
			wantErr: true,
		},
		{
			name: "more than the entry limit stops the scan",
			kind: ident.OOXML, path: word,
			data:      func(t *testing.T) []byte { return zipOf(t, manyNames...) },
			wantSkips: []string{word + ":budget"},
		},
		{
			name: "encrypted part is skipped",
			kind: ident.OOXML, path: word,
			data: func(t *testing.T) []byte {
				return zipOf(t, part{name: "word/_rels/a.rels", data: []byte("x"), flags: 1})
			},
			wantSkips: []string{word + "!/word/_rels/a.rels:encrypted"},
		},
		{
			name: "part larger than its limit is skipped",
			kind: ident.OOXML, path: word,
			data:      func(t *testing.T) []byte { return zipOf(t, part{name: "a.rels", data: make([]byte, 2<<20)}) },
			wantSkips: []string{word + "!/a.rels:too_large"},
		},
		{
			name: "part that cannot be opened is skipped",
			kind: ident.OOXML, path: word,
			data:      func(t *testing.T) []byte { return zipUnsupported(t, "a.rels") },
			wantSkips: []string{word + "!/a.rels:parse_error"},
		},
		{
			name: "parts beyond the package budget stop the scan",
			kind: ident.OOXML, path: word,
			data: func(t *testing.T) []byte { return zipOf(t, manyParts...) },
			wantFindings: []string{
				"GAL-OFFICE-002 " + word + "!/d0/vbaProject.bin:0", "GAL-OFFICE-002 " + word + "!/d1/vbaProject.bin:0",
				"GAL-OFFICE-002 " + word + "!/d2/vbaProject.bin:0", "GAL-OFFICE-002 " + word + "!/d3/vbaProject.bin:0",
			},
			wantSkips: []string{
				word + "!/d0/vbaProject.bin:parse_error", word + "!/d1/vbaProject.bin:parse_error",
				word + "!/d2/vbaProject.bin:parse_error", word + "!/d3/vbaProject.bin:parse_error",
				word + "!/d4/vbaProject.bin:budget",
			},
		},
		{
			name: "vbaProject.bin with auto-exec and shell calls is flagged per module",
			kind: ident.OOXML, path: word,
			data: func(t *testing.T) []byte {
				return zipOf(t, part{name: "word/vbaProject.bin", data: vbaProject(macroModules, nil)})
			},
			wantFindings: []string{
				"GAL-OFFICE-002 " + binPath + ":0",
				"GAL-OFFICE-003 " + binPath + "!/VBA/ThisDocument:2",
				"GAL-OFFICE-003 " + binPath + "!/VBA/Big:1",
				"GAL-OFFICE-004 " + binPath + "!/VBA/Module1:3",
				"GAL-OFFICE-004 " + binPath + "!/VBA/Big:2",
			},
		},
		{
			name: "vbaProject.bin with a harmless macro only reports the macro",
			kind: ident.OOXML, path: word,
			data: func(t *testing.T) []byte {
				mods := []vbaModule{{name: "Module1", source: "' AutoOpen is not called here\r\nSub Hello()\r\n  MsgBox \"hi\"\r\nEnd Sub\r\n"}}
				return zipOf(t, part{name: "word/vbaProject.bin", data: vbaProject(mods, nil)})
			},
			wantFindings: []string{"GAL-OFFICE-002 " + binPath + ":0"},
		},
		{
			name: "vbaProject.bin that is not a compound file is still reported",
			kind: ident.OOXML, path: word,
			data:         func(t *testing.T) []byte { return zipOf(t, part{name: "word/vbaProject.bin", data: []byte("junk")}) },
			wantFindings: []string{"GAL-OFFICE-002 " + binPath + ":0"},
			wantSkips:    []string{binPath + ":parse_error"},
		},
		{
			name: "document.xml with a DDEAUTO field is flagged",
			kind: ident.OOXML, path: word,
			data: func(t *testing.T) []byte {
				doc := "<w:document><w:r><w:instrText xml:space=\"preserve\"> DDEAUTO c:\\\\windows\\\\system32\\\\cmd.exe \"/k calc.exe\" </w:instrText></w:r></w:document>"
				return zipOf(t, part{name: "word/document.xml", data: []byte("<?xml version=\"1.0\"?>\n" + doc)})
			},
			wantFindings: []string{"GAL-OFFICE-005 " + word + "!/word/document.xml:2"},
		},
		{
			name: "document.xml that only mentions DDE in text is clean",
			kind: ident.OOXML, path: word,
			data: func(t *testing.T) []byte {
				return zipOf(t, part{name: "word/document.xml", data: []byte("<w:document><w:t>DDE is old</w:t></w:document>")})
			},
		},
		{
			name: "sharedStrings.xml with a DDE formula is flagged",
			kind: ident.OOXML, path: "sheet.xlsx",
			data: func(t *testing.T) []byte {
				return zipOf(t, part{name: "xl/sharedStrings.xml", data: []byte("<sst>\n<si><t>DDE 'cmd /c calc'!A1</t></si></sst>")})
			},
			wantFindings: []string{"GAL-OFFICE-005 sheet.xlsx!/xl/sharedStrings.xml:2"},
		},
		{
			name: "relationships file that is not XML is skipped",
			kind: ident.OOXML, path: word,
			data: func(t *testing.T) []byte {
				return zipOf(t, part{name: "_rels/.rels", data: []byte("<Relationships><Relationship ")})
			},
			wantSkips: []string{word + "!/_rels/.rels:parse_error"},
		},
		{
			name: "external hyperlink is an indicator only",
			kind: ident.OOXML, path: word,
			data: func(t *testing.T) []byte {
				return zipOf(t, part{name: "word/_rels/document.xml.rels", data: rels(rel("hyperlink", "https://docs.sinkhole.test/a", true))})
			},
			wantIOCs: []string{"https://docs.sinkhole.test/a " + word + "!/word/_rels/document.xml.rels:3"},
		},
		{
			name: "internal links and other external types give nothing",
			kind: ident.OOXML, path: word,
			data: func(t *testing.T) []byte {
				return zipOf(t, part{name: "word/_rels/document.xml.rels", data: rels(
					rel("hyperlink", "#bookmark", false), rel("attachedTemplate", "t.dotm", false), rel("image", "http://img.sinkhole.test/p.png", true))})
			},
		},
		{
			name: "remote template over SMB is flagged without an indicator",
			kind: ident.OOXML, path: word,
			data: func(t *testing.T) []byte {
				return zipOf(t, part{name: "word/_rels/settings.xml.rels", data: rels(rel("attachedTemplate", `\\192.0.2.10\share\t.dotm`, true))})
			},
			wantFindings: []string{"GAL-OFFICE-001 " + relsPath + ":3"},
		},
		{
			name: "OLE document with auto-exec macro is flagged",
			kind: ident.OLE, path: "memo.doc",
			data: func(t *testing.T) []byte {
				return buildCFB([]string{"Macros", "VBA"}, vbaStreams(macroModules[:2]), nil)
			},
			wantFindings: []string{
				"GAL-OFFICE-002 memo.doc:0",
				"GAL-OFFICE-003 memo.doc!/Macros/VBA/ThisDocument:2",
				"GAL-OFFICE-004 memo.doc!/Macros/VBA/Module1:3",
			},
		},
		{
			name: "OLE document without macros is clean",
			kind: ident.OLE, path: "memo.doc",
			data: func(t *testing.T) []byte {
				return buildCFB(nil, []cfbStream{{"WordDocument", []byte("hello")}, {"BigStream", make([]byte, 5000)}}, nil)
			},
		},
		{
			name: "OLE file with a bad header is skipped",
			kind: ident.OLE, path: "memo.doc",
			data: func(t *testing.T) []byte {
				return append([]byte{0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1}, make([]byte, 600)...)
			},
			wantSkips: []string{"memo.doc:parse_error"},
		},
		{
			name: "OLE file whose sector chain loops is skipped",
			kind: ident.OLE, path: "memo.doc",
			data: func(t *testing.T) []byte {
				return vbaProject(macroModules, func(fat []uint32) { fat[1] = 1 })
			},
			wantSkips: []string{"memo.doc:parse_error"},
		},
		{
			name: "OLE file with a corrupt dir stream is still a macro document",
			kind: ident.OLE, path: "memo.doc",
			data: func(t *testing.T) []byte {
				return buildCFB([]string{"VBA"}, []cfbStream{{"dir", []byte("\x00not compressed")}}, nil)
			},
			wantFindings: []string{"GAL-OFFICE-002 memo.doc:0"},
			wantSkips:    []string{"memo.doc:parse_error"},
		},
		{
			name: "OLE file with too many FAT sectors is skipped",
			kind: ident.OLE, path: "memo.doc",
			data: func(t *testing.T) []byte {
				return patched(vbaProject(macroModules, nil), func(b []byte) { binary.LittleEndian.PutUint32(b[44:], 1000) })
			},
			wantSkips: []string{"memo.doc:parse_error"},
		},
		{
			name: "OLE file whose DIFAT points outside the file is skipped",
			kind: ident.OLE, path: "memo.doc",
			data: func(t *testing.T) []byte {
				return patched(vbaProject(macroModules, nil), func(b []byte) {
					binary.LittleEndian.PutUint32(b[44:], 2)
					binary.LittleEndian.PutUint32(b[68:], 9999)
					binary.LittleEndian.PutUint32(b[72:], 1)
				})
			},
			wantSkips: []string{"memo.doc:parse_error"},
		},
		{
			name: "OLE file whose FAT sector is outside the file is skipped",
			kind: ident.OLE, path: "memo.doc",
			data: func(t *testing.T) []byte {
				return patched(vbaProject(macroModules, nil), func(b []byte) { binary.LittleEndian.PutUint32(b[76:], 9999) })
			},
			wantSkips: []string{"memo.doc:parse_error"},
		},
		{
			name: "OLE file whose mini FAT starts outside the FAT is skipped",
			kind: ident.OLE, path: "memo.doc",
			data: func(t *testing.T) []byte {
				return patched(vbaProject(macroModules, nil), func(b []byte) { binary.LittleEndian.PutUint32(b[60:], 9999) })
			},
			wantSkips: []string{"memo.doc:parse_error"},
		},
		{
			name: "truncated OLE file keeps the modules read before the cut",
			kind: ident.OLE, path: "memo.doc",
			data: func(t *testing.T) []byte {
				b := vbaProject(macroModules, nil)
				return b[:len(b)-3000]
			},
			wantFindings: []string{
				"GAL-OFFICE-002 memo.doc:0", "GAL-OFFICE-003 memo.doc!/VBA/ThisDocument:2", "GAL-OFFICE-004 memo.doc!/VBA/Module1:3",
			},
			wantSkips: []string{"memo.doc:parse_error"},
		},
		{
			name: "OLE file with an oversized mini stream is still a macro document",
			kind: ident.OLE, path: "memo.doc",
			data: func(t *testing.T) []byte {
				// the root entry is the first entry of the directory, which starts at sector 1
				return patched(vbaProject(macroModules, nil), func(b []byte) { binary.LittleEndian.PutUint32(b[512*2+120:], 0xFFFFFFFF) })
			},
			wantFindings: []string{"GAL-OFFICE-002 memo.doc:0"},
			wantSkips:    []string{"memo.doc:parse_error"},
		},
		{
			name: "dir stream with an oversized record yields no modules",
			kind: ident.OLE, path: "memo.doc",
			data: func(t *testing.T) []byte {
				dir := append(rec(0x0019, []byte("M")), 0x1A, 0, 0xF0, 0xFF, 0xFF, 0xFF)
				return buildCFB([]string{"VBA"}, []cfbStream{{"dir", lz(dir)}}, nil)
			},
			wantFindings: []string{"GAL-OFFICE-002 memo.doc:0"},
		},
		{
			name: "module named in the dir stream but missing is ignored",
			kind: ident.OLE, path: "memo.doc",
			data:         func(t *testing.T) []byte { return vbaProject([]vbaModule{{name: "Ghost", noStream: true}}, nil) },
			wantFindings: []string{"GAL-OFFICE-002 memo.doc:0"},
		},
		{
			name: "module whose text offset is beyond its stream is skipped",
			kind: ident.OLE, path: "memo.doc",
			data:         func(t *testing.T) []byte { return vbaProject([]vbaModule{{name: "M", source: "x", offset: 1000}}, nil) },
			wantFindings: []string{"GAL-OFFICE-002 memo.doc:0"},
			wantSkips:    []string{"memo.doc:parse_error"},
		},
		{
			name: "module without compressed data is skipped",
			kind: ident.OLE, path: "memo.doc",
			data: func(t *testing.T) []byte {
				return vbaProject([]vbaModule{{name: "M", body: []byte{}, hasBody: true}}, nil)
			},
			wantFindings: []string{"GAL-OFFICE-002 memo.doc:0"},
			wantSkips:    []string{"memo.doc:parse_error"},
		},
		{
			name: "module with a bad container signature is skipped",
			kind: ident.OLE, path: "memo.doc",
			data: func(t *testing.T) []byte {
				return vbaProject([]vbaModule{{name: "M", body: []byte{2}, hasBody: true}}, nil)
			},
			wantFindings: []string{"GAL-OFFICE-002 memo.doc:0"},
			wantSkips:    []string{"memo.doc:parse_error"},
		},
		{
			name: "module with a bad chunk header is skipped",
			kind: ident.OLE, path: "memo.doc",
			data: func(t *testing.T) []byte {
				return vbaProject([]vbaModule{{name: "M", body: []byte{1, 0, 0}, hasBody: true}}, nil)
			},
			wantFindings: []string{"GAL-OFFICE-002 memo.doc:0"},
			wantSkips:    []string{"memo.doc:parse_error"},
		},
		{
			name: "module with a chunk longer than the stream is skipped",
			kind: ident.OLE, path: "memo.doc",
			data: func(t *testing.T) []byte {
				return vbaProject([]vbaModule{{name: "M", body: []byte{1, 0xFF, 0x3F}, hasBody: true}}, nil)
			},
			wantFindings: []string{"GAL-OFFICE-002 memo.doc:0"},
			wantSkips:    []string{"memo.doc:parse_error"},
		},
		{
			name: "module with a truncated copy token is skipped",
			kind: ident.OLE, path: "memo.doc",
			data: func(t *testing.T) []byte {
				return vbaProject([]vbaModule{{name: "M", body: []byte{1, 1, 0xB0, 1, 0}, hasBody: true}}, nil)
			},
			wantFindings: []string{"GAL-OFFICE-002 memo.doc:0"},
			wantSkips:    []string{"memo.doc:parse_error"},
		},
		{
			name: "module with a copy token at the start of a chunk is skipped",
			kind: ident.OLE, path: "memo.doc",
			data: func(t *testing.T) []byte {
				return vbaProject([]vbaModule{{name: "M", body: []byte{1, 2, 0xB0, 1, 0, 0}, hasBody: true}}, nil)
			},
			wantFindings: []string{"GAL-OFFICE-002 memo.doc:0"},
			wantSkips:    []string{"memo.doc:parse_error"},
		},
		{
			name: "module with a copy token reaching before the chunk is skipped",
			kind: ident.OLE, path: "memo.doc",
			data: func(t *testing.T) []byte {
				return vbaProject([]vbaModule{{name: "M", body: []byte{1, 3, 0xB0, 2, 'a', 0, 0x40}, hasBody: true}}, nil)
			},
			wantFindings: []string{"GAL-OFFICE-002 memo.doc:0"},
			wantSkips:    []string{"memo.doc:parse_error"},
		},
		{
			name: "storages nested beyond the depth limit are not entered",
			kind: ident.OLE, path: "memo.doc",
			data: func(t *testing.T) []byte {
				var names []string
				for i := range 40 {
					names = append(names, fmt.Sprintf("S%d", i))
				}
				return buildCFB(names, []cfbStream{{"dir", []byte("x")}}, nil)
			},
			wantSkips: []string{"memo.doc:depth"},
		},
		{
			name: "cancelled context stops the OLE scan",
			kind: ident.OLE, path: "memo.doc", abort: true,
			data:    func(t *testing.T) []byte { return vbaProject(macroModules, nil) },
			wantErr: true,
		},
		{
			name: "more module records than the limit stop the scan",
			kind: ident.OLE, path: "memo.doc",
			data: func(t *testing.T) []byte {
				var dir []byte
				for range 1001 {
					dir = append(dir, rec(0x001A, []byte("Ghost"))...)
					dir = append(dir, rec(0x002B, nil)...)
				}
				return buildCFB([]string{"VBA"}, []cfbStream{{"dir", lz(dir)}}, nil)
			},
			wantFindings: []string{"GAL-OFFICE-002 memo.doc:0"},
			wantSkips:    []string{"memo.doc:parse_error"},
		},
		{
			name: "VBA storage name is matched without case",
			kind: ident.OLE, path: "memo.doc",
			data: func(t *testing.T) []byte {
				return buildCFB([]string{"MACROS", "vba"}, vbaStreams(macroModules[:1]), nil)
			},
			wantFindings: []string{"GAL-OFFICE-002 memo.doc:0", "GAL-OFFICE-003 memo.doc!/MACROS/vba/ThisDocument:2"},
		},
		{
			name: "benign CreateObject in Workbook_Open is auto-exec only",
			kind: ident.OLE, path: "book.xls",
			data: func(t *testing.T) []byte {
				mods := []vbaModule{{name: "ThisWorkbook", source: "Sub Workbook_Open()\r\n  Set d = CreateObject(\"Scripting.Dictionary\")\r\nEnd Sub\r\n"}}
				return buildCFB([]string{"_VBA_PROJECT_CUR", "VBA"}, vbaStreams(mods), nil)
			},
			wantFindings: []string{"GAL-OFFICE-002 book.xls:0", "GAL-OFFICE-003 book.xls!/_VBA_PROJECT_CUR/VBA/ThisWorkbook:1"},
		},
		{
			name: "shell calls inside comments are ignored",
			kind: ident.OLE, path: "memo.doc",
			data: func(t *testing.T) []byte {
				mods := []vbaModule{{name: "M", source: "Sub Hello()\r\n  ' x = Shell(\"calc\")\r\n  Rem powershell -enc\r\n  y = \"a'b\" & Shell(\"calc\")\r\nEnd Sub\r\n"}}
				return buildCFB([]string{"VBA"}, vbaStreams(mods), nil)
			},
			wantFindings: []string{"GAL-OFFICE-002 memo.doc:0", "GAL-OFFICE-004 memo.doc!/VBA/M:4"},
		},
		{
			name: "DDE field split over runs is flagged at its first run",
			kind: ident.OOXML, path: word,
			data: func(t *testing.T) []byte {
				doc := "<w:document>\n<w:r><w:instrText>DD</w:instrText></w:r><w:r><w:instrText>EAUTO c:\\x</w:instrText></w:r></w:document>"
				return zipOf(t, part{name: "word/document.xml", data: []byte(doc)})
			},
			wantFindings: []string{"GAL-OFFICE-005 " + word + "!/word/document.xml:2"},
		},
		{
			name: "DDE field via fldSimple is flagged",
			kind: ident.OOXML, path: word,
			data: func(t *testing.T) []byte {
				return zipOf(t, part{name: "word/document.xml", data: []byte(`<w:fldSimple w:instr=" DDE cmd x ">`)})
			},
			wantFindings: []string{"GAL-OFFICE-005 " + word + "!/word/document.xml:1"},
		},
		{
			name: "instruction pieces separated by text are not joined",
			kind: ident.OOXML, path: word,
			data: func(t *testing.T) []byte {
				doc := "<w:instrText>DD</w:instrText><w:t>x</w:t><w:instrText>E</w:instrText>"
				return zipOf(t, part{name: "word/document.xml", data: []byte(doc)})
			},
		},
		{
			name: "whitespace around an external target is trimmed from the indicator",
			kind: ident.OOXML, path: word,
			data: func(t *testing.T) []byte {
				return zipOf(t, part{name: "word/_rels/document.xml.rels", data: rels(rel("hyperlink", " https://docs.sinkhole.test/a ", true))})
			},
			wantIOCs: []string{"https://docs.sinkhole.test/a " + word + "!/word/_rels/document.xml.rels:3"},
		},
		{
			name: "other kinds are ignored",
			kind: ident.Text, path: "notes.txt",
			data: func(t *testing.T) []byte { return []byte("Sub AutoOpen()") },
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given a file of the case's kind
			f := analyze.File{Path: tt.path, Name: tt.path, Kind: tt.kind, Data: tt.data(t)}
			ctx := context.Background()
			if tt.abort {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			// When the office analyzer runs
			out, err := office.New().Analyze(ctx, f)
			// Then findings, indicators and skips match
			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tt.wantErr)
			}
			var findings, iocs, skips []string
			for _, fd := range out.Findings {
				findings = append(findings, fmt.Sprintf("%s %s:%d", fd.RuleID, fd.Evidence[0].Path, fd.Evidence[0].Line))
			}
			for _, i := range out.IOCs {
				iocs = append(iocs, fmt.Sprintf("%s %s:%d", i.Value, i.Path, i.Line))
				if i.Type != "url" {
					t.Errorf("ioc type = %q, want url", i.Type)
				}
			}
			for _, s := range out.Skips {
				skips = append(skips, s.Path+":"+s.Reason)
			}
			for name, got := range map[string][]string{"findings": findings, "iocs": iocs, "skips": skips} {
				want := map[string][]string{"findings": tt.wantFindings, "iocs": tt.wantIOCs, "skips": tt.wantSkips}[name]
				slices.Sort(got)
				slices.Sort(want)
				if !slices.Equal(got, want) {
					t.Errorf("%s = %q, want %q", name, got, want)
				}
			}
			if len(out.Children) != 0 {
				t.Errorf("children = %d, want none", len(out.Children))
			}
		})
	}
}

func TestName(t *testing.T) {
	tests := []struct {
		name     string
		wantName string
	}{{name: "analyzer name", wantName: "office"}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := office.New().Name(); got != tt.wantName {
				t.Errorf("Name() = %q, want %q", got, tt.wantName)
			}
		})
	}
}
