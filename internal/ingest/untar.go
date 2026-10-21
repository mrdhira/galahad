// Package ingest turns input that reaches the guest into files for the analyzers. It
// parses untrusted bytes, so it runs in the guest only and the host never imports it.
package ingest

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/mrdhira/galahad/internal/protocol"
)

// Limits on one entry name.
const (
	maxName  = 4096 // bytes
	maxDepth = 64   // path elements, the same as the analyzers walk
)

// errTooDeep marks an entry name with more than maxDepth elements. Extract skips such an
// entry instead of failing, as the analyzers do for a directory that is too deep.
var errTooDeep = errors.New("path too deep")

// Errors Extract and Verify return, wrapped with detail. Test for them with errors.Is.
var (
	// ErrTooLarge means the input has more entries or bytes than the caps allow.
	ErrTooLarge = errors.New("input too large")
	// ErrUnsafePath means an entry name is absolute, has "..", or is otherwise not a plain relative path.
	ErrUnsafePath = errors.New("unsafe path in input")
	// ErrMismatch means the stream is not the one the End frame describes.
	ErrMismatch = errors.New("input does not match its end frame")
)

// Stream describes the raw tar stream Extract read.
type Stream struct {
	Bytes  int64
	SHA256 string
	// TooDeep counts the entries skipped for having more than 64 path elements, and
	// Shallowest is the clean path of the one with the fewest elements, the first of them
	// on a tie. Shallowest is empty when TooDeep is 0.
	TooDeep    int
	Shallowest string
}

// Verify checks the stream against the End frame the host sent.
func (s Stream) Verify(end protocol.End) error {
	if s.Bytes != end.Bytes {
		return fmt.Errorf("%w: read %d bytes, the host sent %d", ErrMismatch, s.Bytes, end.Bytes)
	}
	if s.SHA256 != end.SHA256 {
		return fmt.Errorf("%w: sha256 is %s, the host sent %s", ErrMismatch, s.SHA256, end.SHA256)
	}
	return nil
}

// Extract reads a tar stream from r and writes it into the directory dir, which must exist.
// It stops with the error of ctx, checked once per entry, when ctx is done; reads of r are
// bounded by the caller.
// All writes go through an os.Root, so no path can leave dir, and a symlink that was
// extracted earlier is never followed out of it. Entries are regular files,
// directories and symlinks; a symlink is created as a link and never followed. Other
// types (hard links, devices, FIFOs) are skipped, and so is an entry with more than 64
// path elements, which Stream reports. Absolute names and ".." are refused.
// At most protocol.MaxInputEntries entries and protocol.MaxInputBytes bytes of stream,
// and of file content, are accepted. Extract reads r to its end, so that the returned
// Stream covers every byte.
func Extract(ctx context.Context, r io.Reader, dir string) (Stream, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return Stream{}, err
	}
	defer func() { _ = root.Close() }() // the files are closed and checked as they are written

	sr := &streamReader{r: r, h: sha256.New()}
	tr := tar.NewReader(sr)
	entries := 0
	var content int64
	var res Stream // the skip counts; Bytes and SHA256 are set at the end
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return Stream{}, fmt.Errorf("read tar: %w", err)
		}
		if err := ctx.Err(); err != nil {
			return Stream{}, fmt.Errorf("extract: %w", err)
		}
		if entries++; entries > protocol.MaxInputEntries {
			return Stream{}, fmt.Errorf("%w: more than %d entries", ErrTooLarge, protocol.MaxInputEntries)
		}
		var werr error
		switch hdr.Typeflag {
		case tar.TypeDir:
			werr = mkdir(root, hdr)
		case tar.TypeReg:
			if content += hdr.Size; content > protocol.MaxInputBytes {
				return Stream{}, fmt.Errorf("%w: more than %d bytes of files", ErrTooLarge, int64(protocol.MaxInputBytes))
			}
			werr = writeFile(root, hdr, tr)
		case tar.TypeSymlink:
			werr = symlink(root, hdr)
		}
		if errors.Is(werr, errTooDeep) {
			res.skip(path.Clean(hdr.Name))
			werr = nil
		}
		if werr != nil {
			return Stream{}, werr
		}
	}
	if _, err := io.Copy(io.Discard, sr); err != nil {
		return Stream{}, fmt.Errorf("read tar: %w", err)
	}
	res.Bytes, res.SHA256 = sr.n, hex.EncodeToString(sr.h.Sum(nil))
	return res, nil
}

// skip records an entry that is too deep.
func (s *Stream) skip(name string) {
	if s.TooDeep++; s.Shallowest == "" || strings.Count(name, "/") < strings.Count(s.Shallowest, "/") {
		s.Shallowest = name
	}
}

// streamReader hashes and counts the bytes it passes on, and stops at the byte cap.
type streamReader struct {
	r io.Reader
	h hash.Hash
	n int64
}

func (s *streamReader) Read(p []byte) (int, error) {
	n, err := s.r.Read(p)
	s.h.Write(p[:n]) // a hash.Hash never returns an error
	if s.n += int64(n); s.n > protocol.MaxInputBytes {
		return n, fmt.Errorf("%w: more than %d bytes of stream", ErrTooLarge, int64(protocol.MaxInputBytes))
	}
	return n, err
}

// relName checks an entry name and returns it as a clean slash path below the root.
// The root itself is ".".
func relName(name string) (string, error) {
	switch {
	case name == "" || len(name) > maxName:
		return "", fmt.Errorf("%w: name is %d bytes", ErrUnsafePath, len(name))
	case strings.HasPrefix(name, "/") || strings.ContainsRune(name, 0):
		return "", fmt.Errorf("%w: %q", ErrUnsafePath, name)
	}
	for elem := range strings.SplitSeq(name, "/") {
		if elem == ".." {
			return "", fmt.Errorf("%w: %q", ErrUnsafePath, name)
		}
	}
	rel := path.Clean(name)
	if !filepath.IsLocal(filepath.FromSlash(rel)) {
		return "", fmt.Errorf("%w: %q", ErrUnsafePath, name)
	}
	if n := strings.Count(rel, "/") + 1; n > maxDepth {
		return "", fmt.Errorf("%w: %d elements deep, max %d", errTooDeep, n, maxDepth)
	}
	return rel, nil
}

func mkdir(root *os.Root, hdr *tar.Header) error {
	rel, err := relName(hdr.Name)
	if err != nil {
		return err
	}
	if rel == "." {
		return nil
	}
	if err := root.MkdirAll(rel, 0o750); err != nil {
		return fmt.Errorf("extract %q: %w", hdr.Name, err)
	}
	return nil
}

func writeFile(root *os.Root, hdr *tar.Header, r io.Reader) (err error) {
	rel, err := relName(hdr.Name)
	if err != nil {
		return err
	}
	if rel == "." {
		return fmt.Errorf("%w: file named %q", ErrUnsafePath, hdr.Name)
	}
	if err := mkParent(root, rel); err != nil {
		return fmt.Errorf("extract %q: %w", hdr.Name, err)
	}
	// Only the owner's bits survive: the agent is the only user, and it needs to read the file.
	mode := fs.FileMode(hdr.Mode).Perm()&0o700 | 0o600
	// O_EXCL also refuses a final component that is a symlink, instead of writing through it.
	f, err := root.OpenFile(rel, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return fmt.Errorf("extract %q: %w", hdr.Name, err)
	}
	defer func() {
		if cerr := f.Close(); err == nil && cerr != nil {
			err = fmt.Errorf("extract %q: %w", hdr.Name, cerr)
		}
	}()
	if _, err := io.Copy(f, r); err != nil {
		return fmt.Errorf("extract %q: %w", hdr.Name, err)
	}
	return nil
}

func symlink(root *os.Root, hdr *tar.Header) error {
	rel, err := relName(hdr.Name)
	if err != nil {
		return err
	}
	if rel == "." {
		return fmt.Errorf("%w: link named %q", ErrUnsafePath, hdr.Name)
	}
	if err := mkParent(root, rel); err != nil {
		return fmt.Errorf("extract %q: %w", hdr.Name, err)
	}
	if err := root.Symlink(hdr.Linkname, rel); err != nil {
		return fmt.Errorf("extract %q: %w", hdr.Name, err)
	}
	return nil
}

// mkParent creates the directories above rel.
func mkParent(root *os.Root, rel string) error {
	if dir := path.Dir(rel); dir != "." {
		return root.MkdirAll(dir, 0o750)
	}
	return nil
}
