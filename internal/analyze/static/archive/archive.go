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
	"errors"
	"io"
	"io/fs"
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
)

var (
	ruleSlip      = protocol.Rule{ID: "GAL-ARCHIVE-001", Severity: protocol.SeverityHigh, Title: "Archive entry path escapes the archive"}
	ruleLink      = protocol.Rule{ID: "GAL-ARCHIVE-002", Severity: protocol.SeverityMedium, Title: "Link entry in archive"}
	ruleBomb      = protocol.Rule{ID: "GAL-ARCHIVE-003", Severity: protocol.SeverityHigh, Title: "Decompression bomb"}
	ruleEncrypted = protocol.Rule{ID: "GAL-ARCHIVE-004", Severity: protocol.SeverityMedium, Title: "Encrypted archive entries could not be inspected", Attack: "T1027.013"}
)

var errBomb = errors.New("archive expands beyond its limits")

type analyzer struct{}

// New returns the archive analyzer.
func New() analyze.Analyzer { return analyzer{} }

func (analyzer) Name() string { return "archive" }

func (analyzer) Analyze(ctx context.Context, f analyze.File) (analyze.Output, error) {
	u := &unpack{ctx: ctx, f: f, left: allowance(len(f.Data))}
	var err error
	switch f.Kind {
	case ident.Zip:
		err = u.zip()
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
	return u.out, err
}

// allowance is how many bytes an archive of n compressed bytes may expand to.
func allowance(n int) int64 {
	return min(MaxArchiveBytes, max(minRatioBytes, int64(n)*MaxRatio))
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
	entries int
	bombed  bool
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
	return true, false
}

// escapes reports names that would leave the extraction directory: parent
// segments, absolute paths, drive letters and UNC paths, with either separator.
func escapes(name string) bool {
	n := strings.ReplaceAll(name, `\`, "/")
	if strings.HasPrefix(n, "/") {
		return true
	}
	if len(n) >= 2 && n[1] == ':' && n[0]|0x20 >= 'a' && n[0]|0x20 <= 'z' {
		return true
	}
	return slices.Contains(strings.Split(n, "/"), "..")
}

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
	u.out.Findings = append(u.out.Findings, ruleBomb.Finding(protocol.Evidence{
		Path: u.f.Path, Snippet: "expands beyond 100:1 or 256 MiB at " + protocol.Snippet(name),
	}))
	u.skip(u.member(name), protocol.SkipBudget)
}

func (u *unpack) zip() error {
	zr, err := zip.NewReader(bytes.NewReader(u.f.Data), int64(len(u.f.Data)))
	if err != nil && !errors.Is(err, zip.ErrInsecurePath) {
		return err
	}
	for _, zf := range zr.File {
		if err := u.ctx.Err(); err != nil {
			return err
		}
		ok, stop := u.admit(zf.Name)
		if stop {
			break
		}
		mode := zf.Mode()
		switch {
		case !ok, mode.IsDir():
			continue
		case mode&fs.ModeSymlink != 0:
			u.link(zf.Name, "")
			continue
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
		err = u.read(u.cap(rc), zf.Name)
		_ = rc.Close() // in-memory reader
		if errors.Is(err, errBomb) {
			break
		}
	}
	return nil
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
