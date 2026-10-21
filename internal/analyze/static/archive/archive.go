// Package archive expands zip, tar, gzip and bzip2 files into in-memory
// children. Nothing is ever written to disk and links are never followed.
// Every read is capped by the real number of bytes decompressed, never by the
// sizes an archive header claims.
package archive

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"slices"
	"strings"

	"github.com/mrdhira/galahad/internal/analyze"
	"github.com/mrdhira/galahad/internal/analyze/ident"
	"github.com/mrdhira/galahad/internal/protocol"
)

// Limits of one archive.
const (
	MaxEntries      = 10000
	MaxRatio        = 100       // decompressed bytes per compressed byte
	MaxArchiveBytes = 256 << 20 // decompressed bytes per archive
	minRatioBytes   = 1 << 20   // the ratio check applies only above this size
	tarHeadLen      = 512
	partHeadLen     = 512         // bytes of an OOXML part checked against its name
	eocdWindow      = 64<<10 + 22 // where the end of central directory record of a zip may start
	eocdLen         = 22          // fixed part of the end of central directory record
	dirHeadLen      = 46          // fixed part of a central directory record
	localHeadLen    = 30          // fixed part of a zip local file header
	max32           = 1<<32 - 1   // a 32-bit zip field that is too small, so the zip64 field holds the value
)

var (
	ruleSlip      = protocol.Rule{ID: "GAL-ARCHIVE-001", Severity: protocol.SeverityHigh, Title: "Archive entry path escapes the archive"}
	ruleLink      = protocol.Rule{ID: "GAL-ARCHIVE-002", Severity: protocol.SeverityMedium, Title: "Link entry in archive"}
	ruleBomb      = protocol.Rule{ID: "GAL-ARCHIVE-003", Severity: protocol.SeverityHigh, Title: "Decompression bomb"}
	ruleEncrypted = protocol.Rule{ID: "GAL-ARCHIVE-004", Severity: protocol.SeverityMedium, Title: "Encrypted archive entries could not be inspected", Attack: "T1027.013"}
	// Legitimate archives use "/". The members are still analyzed under the "/" name,
	// so this is only a hint, not enough to be suspicious alone.
	ruleBackslash = protocol.Rule{ID: "GAL-ARCHIVE-005", Severity: protocol.SeverityLow, Title: "Archive entry name uses backslash separators"}
	ruleAppended  = protocol.Rule{ID: "GAL-ARCHIVE-006", Severity: protocol.SeverityLow, Title: "Executable with an appended zip archive"}
	ruleNames     = protocol.Rule{ID: "GAL-ARCHIVE-007", Severity: protocol.SeverityMedium, Title: "Zip entry names disagree"}
)

var (
	localSig = []byte("PK\x03\x04")
	dirSig   = []byte("PK\x01\x02")
	eocdSig  = []byte("PK\x05\x06")
)

var errBomb = errors.New("archive expands beyond its limits")

type analyzer struct{}

// New returns the archive analyzer.
func New() analyze.Analyzer { return analyzer{} }

func (analyzer) Name() string { return "archive" }

func (analyzer) Analyze(ctx context.Context, f analyze.File) (analyze.Output, error) {
	left, byJob := allowance(ctx, len(f.Data))
	u := &unpack{ctx: ctx, f: f, left: left, byJob: byJob}

	var err error
	switch f.Kind {
	case ident.Zip, ident.OOXML, ident.Tar, ident.Gzip, ident.Bzip2:
		if f.Depth >= analyze.MaxNesting {
			// The engine would drop the members, so do not decompress them.
			u.skip(f.Path, protocol.SkipDepth)
			return u.out, nil
		}
	}
	switch f.Kind {
	case ident.Zip, ident.OOXML:
		err = u.zip()
	case ident.PE, ident.ELF, ident.MachO:
		err = u.appended()
	case ident.Tar:
		err = u.tar(u.cap(bytes.NewReader(f.Data)))
	case ident.Gzip:
		err = u.compressed(".gz", ".tgz", func(r io.Reader) (io.Reader, error) { return gzip.NewReader(r) })
	case ident.Bzip2:
		err = u.compressed(".bz2", ".tbz2", func(r io.Reader) (io.Reader, error) { return bzip2.NewReader(r), nil })
	default:
		if unsupported(f.Data) {
			u.skip(f.Path, protocol.SkipUnsupported)
		}
	}
	u.flush()
	return u.out, err
}

// allowance is how many bytes an archive of n compressed bytes may expand to,
// and never more than the job budget that is left. byJob says the job budget is
// the smaller limit.
func allowance(ctx context.Context, n int) (left int64, byJob bool) {
	left = min(MaxArchiveBytes, max(minRatioBytes, int64(n)*MaxRatio))
	if b, ok := analyze.Budget(ctx); ok && b < left {
		return b, true
	}
	return left, false
}

// unsupported reports a 7z, rar or iso image, which are not expanded.
func unsupported(data []byte) bool {
	return bytes.HasPrefix(data, []byte("7z\xbc\xaf\x27\x1c")) ||
		bytes.HasPrefix(data, []byte("Rar!\x1a\x07")) ||
		(len(data) > 0x8006 && bytes.Equal(data[0x8001:0x8006], []byte("CD001")))
}

type unpack struct {
	ctx     context.Context
	f       analyze.File
	out     analyze.Output
	left    int64 // decompressed bytes still allowed
	byJob   bool  // the job budget, not the archive, sets left
	entries int
	bombed  bool

	// Findings that every entry of a bad archive would raise are kept as one each.
	backslash, names tally
}

// tally groups the entries of one archive that raise the same finding, so that a
// flood of them cannot fill the findings cap before the members are analyzed.
type tally struct {
	n      int
	path   string // evidence path of the first
	detail string // what the first looked like
}

func (t *tally) add(path, detail string) {
	if t.n == 0 {
		t.path, t.detail = path, detail
	}
	t.n++
}

// flush reports the grouped findings, once the entries are all seen.
func (u *unpack) flush() {
	for _, g := range []struct {
		rule protocol.Rule
		t    *tally
	}{{ruleBackslash, &u.backslash}, {ruleNames, &u.names}} {
		if g.t.n > 0 {
			u.out.Findings = append(u.out.Findings, g.rule.Finding(protocol.Evidence{
				Path: g.t.path, Snippet: protocol.Snippet(fmt.Sprintf("%d in this archive, first: %s", g.t.n, g.t.detail)),
			}))
		}
	}
}

func (u *unpack) member(name string) string { return u.f.Path + "!/" + protocol.CleanPath(name) }

func (u *unpack) skip(path, reason string) {
	u.out.Skips = append(u.out.Skips, protocol.Skip{Path: path, Reason: reason})
}

// cap limits the bytes read from r to what the archive may still expand to.
func (u *unpack) cap(r io.Reader) io.Reader { return &capReader{r: r, left: &u.left} }

type capReader struct {
	r    io.Reader
	left *int64
}

func (c *capReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	*c.left -= int64(n)
	if *c.left < 0 {
		return n, errBomb
	}
	return n, err
}

// admit counts an entry and decides whether to read it. stop says to ignore the
// rest of the archive.
func (u *unpack) admit(name string) (ok, stop bool) {
	u.entries++
	if u.entries > MaxEntries {
		u.skip(u.f.Path, protocol.SkipBudget)
		return false, true
	}
	if escapes(name) {
		u.out.Findings = append(u.out.Findings, ruleSlip.Finding(protocol.Evidence{
			Path: u.member(name), Snippet: protocol.Snippet(name),
		}))
		return false, false
	}
	if strings.Contains(name, `\`) {
		// The engine turns the backslash into a slash, so keep the raw name here.
		u.backslash.add(u.member(name), name)
	}
	return true, false
}

// escapes reports names that would leave the extraction directory: parent
// segments, absolute paths, drive letters and UNC paths, with either separator.
func escapes(name string) bool {
	n := fsName(name)
	if strings.HasPrefix(n, "/") {
		return true
	}
	if len(n) >= 2 && n[1] == ':' && n[0]|0x20 >= 'a' && n[0]|0x20 <= 'z' {
		return true
	}
	return slices.Contains(strings.Split(n, "/"), "..")
}

// fsName is the name as a Windows extractor reads it, with "/" as the only separator.
func fsName(name string) string { return strings.ReplaceAll(name, `\`, "/") }

func (u *unpack) link(name, target string) {
	snip := name
	if target != "" {
		snip += " -> " + target
	}
	u.out.Findings = append(u.out.Findings, ruleLink.Finding(protocol.Evidence{
		Path: u.member(name), Snippet: protocol.Snippet(snip),
	}))
}

// read reads one member into a child. It returns errBomb when the archive hit
// its limits and any other error when the member could not be read.
func (u *unpack) read(r io.Reader, name string) error {
	data, err := io.ReadAll(io.LimitReader(r, analyze.MaxFileSize+1))
	switch {
	case errors.Is(err, errBomb):
		u.bomb(name)
		return err
	case err != nil:
		u.skip(u.member(name), protocol.SkipParseError)
		return err
	case len(data) > analyze.MaxFileSize:
		u.skip(u.member(name), protocol.SkipTooLarge)
		return nil
	}
	u.out.Children = append(u.out.Children, analyze.File{Name: name, Data: data})
	return nil
}

func (u *unpack) bomb(name string) {
	if u.bombed {
		return
	}
	u.bombed = true
	if !u.byJob {
		// Running out of the job budget says nothing about this archive, but the skip still hides content.
		u.out.Findings = append(u.out.Findings, ruleBomb.Finding(protocol.Evidence{
			Path: u.f.Path, Snippet: "expands beyond 100:1 or 256 MiB at " + protocol.Snippet(name),
		}))
	}
	u.skip(u.member(name), protocol.SkipBudget)
}

// ooxmlPart reports a member the office analyzer already reads, or that is
// plain package markup it has nothing to find in: the root [Content_Types].xml
// (any case), a vbaProject.bin or .rels file anywhere (office scans them on the
// parent), and .xml files below the standard package folders when no path segment
// is hidden. Everything else, such as media, embeddings, scripts and dot-folders,
// is unpacked like any other zip member. The names are not normalized, so a
// backslash name stays a plain member. The bytes of a match must also fit the
// name (see inert).
func ooxmlPart(name string) bool {
	lower := strings.ToLower(name)
	ext := path.Ext(lower)
	if lower == "[content_types].xml" || ext == ".rels" || path.Base(lower) == "vbaproject.bin" {
		return true
	}
	segs := strings.Split(lower, "/")
	if len(segs) < 2 || !slices.Contains([]string{"_rels", "docprops", "customxml", "word", "xl", "ppt"}, segs[0]) || ext != ".xml" {
		return false
	}
	return !slices.ContainsFunc(segs, func(seg string) bool { return strings.HasPrefix(seg, ".") })
}

// inert reports whether an OOXML part named by ooxmlPart holds what its name
// says: OLE for a VBA project, text for markup. Anything else, such as a zip or
// an executable renamed to styles.xml, must be unpacked. An encrypted part is
// left to the office analyzer as before, and one that cannot be read is not inert.
func (u *unpack) inert(zf *zip.File) bool {
	if zf.Flags&1 != 0 {
		return true
	}
	rc, err := zf.Open()
	if err != nil {
		return false
	}
	defer func() { _ = rc.Close() }() // in-memory reader
	head := make([]byte, partHeadLen)
	n, err := io.ReadFull(u.cap(rc), head)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return false
	}
	head = head[:n]
	kind := ident.Identify("", head)
	if path.Base(strings.ToLower(zf.Name)) == "vbaproject.bin" {
		return kind == ident.OLE
	}
	return !bytes.HasPrefix(head, []byte("PK")) && !bytes.HasPrefix(head, []byte("MZ")) &&
		bytes.IndexByte(head, 0) < 0 && (kind == ident.Text || kind == ident.Unknown)
}

// localNames returns the name in the local file header of every entry of zr, in
// directory order. It follows the offsets of the central directory records, the
// way the zip reader does, so a header that an attacker plants elsewhere cannot
// stand in for the real one. ok is false when the records do not match the
// reader's entries or point at no local header.
func localNames(data []byte, zr *zip.Reader) (names []string, ok bool) {
	pos, base, ok := directory(data)
	if !ok {
		return nil, false
	}
	size := int64(len(data))
	names = make([]string, 0, len(zr.File))
	for _, zf := range zr.File {
		if pos+dirHeadLen > size || !bytes.HasPrefix(data[pos:], dirSig) {
			return nil, false
		}
		rec := data[pos:]
		nameLen, extraLen, commentLen := int64(le.Uint16(rec[28:])), int64(le.Uint16(rec[30:])), int64(le.Uint16(rec[32:]))
		next := pos + dirHeadLen + nameLen + extraLen + commentLen
		if next > size || string(rec[dirHeadLen:dirHeadLen+nameLen]) != zf.Name {
			return nil, false
		}
		off := int64(le.Uint32(rec[42:]))
		if off == max32 {
			if off, ok = zip64Offset(rec[dirHeadLen+nameLen:dirHeadLen+nameLen+extraLen], le.Uint32(rec[24:]), le.Uint32(rec[20:])); !ok {
				return nil, false
			}
		}
		at := base + off
		if at < 0 || at+localHeadLen > size || !bytes.HasPrefix(data[at:], localSig) {
			return nil, false
		}
		end := at + localHeadLen + int64(le.Uint16(data[at+26:]))
		dataAt, err := zf.DataOffset()
		if end > size || err != nil || dataAt != end+int64(le.Uint16(data[at+28:])) {
			return nil, false
		}
		names = append(names, string(data[at+localHeadLen:end]))
		pos = next
	}
	return names, true
}

var le = binary.LittleEndian

// directory finds where the central directory records start and how far the
// offsets stored in them are shifted by data before the zip, as the zip reader
// does: from the end of central directory record and its zip64 form.
func directory(data []byte) (start, base int64, ok bool) {
	size := int64(len(data))
	lo := max(0, size-eocdWindow)
	last := size - eocdLen + int64(len(eocdSig))
	if last <= lo {
		return 0, 0, false
	}
	at := lo + int64(bytes.LastIndex(data[lo:last], eocdSig))
	if at < lo || at+eocdLen+int64(le.Uint16(data[at+20:])) > size {
		return 0, 0, false
	}
	dirSize, dirOff, end := int64(le.Uint32(data[at+12:])), int64(le.Uint32(data[at+16:])), at
	if le.Uint16(data[at+10:]) == 0xffff || dirSize == max32 || dirOff == max32 {
		// A zip64 locator sits right before the record, and the zip64 record holds the real values.
		if loc := at - 20; loc >= 0 && bytes.HasPrefix(data[loc:], []byte("PK\x06\x07")) && le.Uint32(data[loc+4:]) == 0 && le.Uint32(data[loc+16:]) == 1 {
			p := le.Uint64(data[loc+8:])
			if p > uint64(size) || int64(p)+56 > size || !bytes.HasPrefix(data[p:], []byte("PK\x06\x06")) {
				return 0, 0, false
			}
			sz, off := le.Uint64(data[p+40:]), le.Uint64(data[p+48:])
			if sz > 1<<62 || off > 1<<62 {
				return 0, 0, false
			}
			dirSize, dirOff, end = int64(sz), int64(off), int64(p)
		}
	}
	base = end - dirSize - dirOff
	if dirOff+base < 0 || dirOff+base >= size {
		return 0, 0, false
	}
	if base > 0 && validRecord(data[dirOff:]) {
		base = 0 // the records are valid without the shift, which the reader prefers
	}
	return dirOff + base, base, true
}

// validRecord reports whether rec starts with a central directory record that the
// zip reader accepts: the name, extra field and comment lie within rec, and every
// zip64 extra field is long enough for the values whose 32-bit fields are full.
// Like the reader, it does not ask for a zip64 field to be there.
func validRecord(rec []byte) bool {
	if len(rec) < dirHeadLen || !bytes.HasPrefix(rec, dirSig) {
		return false
	}
	nameLen, extraLen, commentLen := int(le.Uint16(rec[28:])), int(le.Uint16(rec[30:])), int(le.Uint16(rec[32:]))
	if dirHeadLen+nameLen+extraLen+commentLen > len(rec) {
		return false
	}
	full := 8 * (b2i(le.Uint32(rec[24:]) == max32) + b2i(le.Uint32(rec[20:]) == max32) + b2i(le.Uint32(rec[42:]) == max32))
	extra := rec[dirHeadLen+nameLen : dirHeadLen+nameLen+extraLen]
	for len(extra) >= 4 {
		id, n := le.Uint16(extra), int(le.Uint16(extra[2:]))
		if extra = extra[4:]; n > len(extra) {
			break
		}
		if id == 1 && n < full {
			return false
		}
		extra = extra[n:]
	}
	return true
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// zip64Offset reads the offset of a local header from the zip64 extra field of a
// central directory record, which holds only the values whose 32-bit fields are full.
func zip64Offset(extra []byte, usize, csize uint32) (int64, bool) {
	for len(extra) >= 4 {
		id, n := le.Uint16(extra), int(le.Uint16(extra[2:]))
		if extra = extra[4:]; n > len(extra) {
			return 0, false
		}
		if id == 1 {
			b := extra[:n]
			for _, full := range []bool{usize == max32, csize == max32} {
				if full {
					b = b[min(8, len(b)):]
				}
			}
			if len(b) < 8 || le.Uint64(b) > 1<<62 {
				return 0, false
			}
			return int64(le.Uint64(b)), true
		}
		extra = extra[n:]
	}
	return 0, false
}

func (u *unpack) reader() (*zip.Reader, error) {
	zr, err := zip.NewReader(bytes.NewReader(u.f.Data), int64(len(u.f.Data)))
	if err != nil && !errors.Is(err, zip.ErrInsecurePath) {
		return nil, err
	}
	return zr, nil
}

func (u *unpack) zip() error {
	zr, err := u.reader()
	if err != nil {
		return err
	}
	return u.members(zr)
}

// appended expands the zip of a self-extracting archive: an executable with the
// archive after its code. An executable without a readable zip is not an error.
func (u *unpack) appended() error {
	if !bytes.Contains(u.f.Data[max(0, len(u.f.Data)-eocdWindow):], eocdSig) {
		return nil
	}
	zr, err := u.reader()
	if err != nil {
		return nil
	}
	if u.f.Depth >= analyze.MaxNesting {
		u.skip(u.f.Path, protocol.SkipDepth)
		return nil
	}
	u.out.Findings = append(u.out.Findings, ruleAppended.Finding(protocol.Evidence{
		Path: u.f.Path, Snippet: protocol.Snippet(fmt.Sprintf("%d zip entries after the executable", len(zr.File))),
	}))
	return u.members(zr)
}

func (u *unpack) members(zr *zip.Reader) error {
	locals, matched := localNames(u.f.Data, zr)
	if !matched {
		u.names.add(u.f.Path, "the local headers do not match the central directory")
	}
	for i, zf := range zr.File {
		if err := u.ctx.Err(); err != nil {
			return err
		}
		ok, stop := u.admit(zf.Name)
		if stop {
			break
		}
		mode := zf.Mode()
		alt := ""
		if ok && matched && !mode.IsDir() {
			alt = u.mismatch(zf, locals[i])
		}
		switch {
		case !ok, mode.IsDir():
			continue
		case mode&fs.ModeSymlink != 0:
			u.link(zf.Name, "")
			continue
		case u.f.Kind == ident.OOXML && alt == "" && ooxmlPart(zf.Name) && u.inert(zf):
			continue // the office analyzer reads it or it is inert markup
		case zf.Flags&1 != 0:
			u.out.Findings = append(u.out.Findings, ruleEncrypted.Finding(protocol.Evidence{
				Path: u.member(zf.Name), Snippet: "encrypted entry",
			}))
			u.skip(u.member(zf.Name), protocol.SkipEncrypted)
			continue
		}
		rc, err := zf.Open()
		if err != nil {
			u.skip(u.member(zf.Name), protocol.SkipParseError)
			continue
		}
		before := len(u.out.Children)
		err = u.read(u.cap(rc), zf.Name)
		_ = rc.Close() // in-memory reader
		if alt != "" && len(u.out.Children) > before {
			// A streaming extractor writes the local name, so the bytes are analyzed under it too.
			u.out.Children = append(u.out.Children, analyze.File{Name: alt, Data: u.out.Children[before].Data})
		}
		if errors.Is(err, errBomb) {
			break
		}
	}
	return nil
}

// mismatch reports an entry whose local header name differs from its central
// directory name and returns the local name, or "" when there is nothing more to
// analyze: the names agree, or the local name escapes or reads the same.
func (u *unpack) mismatch(zf *zip.File, local string) string {
	if local == zf.Name {
		return ""
	}
	u.names.add(u.member(zf.Name), "central: "+zf.Name+", local: "+local)
	if escapes(local) {
		u.out.Findings = append(u.out.Findings, ruleSlip.Finding(protocol.Evidence{
			Path: u.member(local), Snippet: protocol.Snippet(local),
		}))
		return ""
	}
	if fsName(local) == fsName(zf.Name) {
		return ""
	}
	return local
}

func (u *unpack) tar(r io.Reader) error {
	tr := tar.NewReader(r)
	for {
		if err := u.ctx.Err(); err != nil {
			return err
		}
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if errors.Is(err, errBomb) {
			u.bomb(u.f.Name)
			return nil
		}
		if err != nil {
			u.skip(u.f.Path, protocol.SkipParseError)
			return nil
		}
		ok, stop := u.admit(hdr.Name)
		if stop {
			return nil
		}
		// Extractors write every other type, such as contiguous ('7') and sparse
		// ('S') files, as regular files, so they are read too.
		switch hdr.Typeflag {
		case tar.TypeDir, tar.TypeFifo, tar.TypeChar, tar.TypeBlock, tar.TypeXGlobalHeader:
		case tar.TypeSymlink, tar.TypeLink:
			if ok {
				u.link(hdr.Name, hdr.Linkname)
			}
		default:
			if ok && u.read(tr, hdr.Name) != nil {
				return nil
			}
		}
	}
}

// compressed expands a gzip or bzip2 stream. A tar inside is expanded into its
// members, anything else becomes one child named like the file without its suffix.
func (u *unpack) compressed(suffix, tarSuffix string, open func(io.Reader) (io.Reader, error)) error {
	dec, err := open(bytes.NewReader(u.f.Data))
	if err != nil {
		return err
	}
	br := bufio.NewReaderSize(u.cap(dec), tarHeadLen)
	lower := strings.ToLower(u.f.Name)
	inner := u.f.Name
	switch {
	case strings.HasSuffix(lower, tarSuffix):
		inner = inner[:len(inner)-len(tarSuffix)] + ".tar"
	case strings.HasSuffix(lower, suffix):
		inner = inner[:len(inner)-len(suffix)]
	default:
		inner += ".out"
	}
	head, err := br.Peek(tarHeadLen)
	if err != nil && !errors.Is(err, io.EOF) {
		if errors.Is(err, errBomb) {
			u.bomb(inner)
			return nil
		}
		return err
	}
	if ident.Identify(inner, head) == ident.Tar {
		return u.tar(br)
	}
	_ = u.read(br, inner) // a failed read is already recorded as a skip
	return nil
}
