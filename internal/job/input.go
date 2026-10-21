package job

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/mrdhira/galahad/internal/protocol"
	"github.com/mrdhira/galahad/internal/proxy"
)

const (
	chunkSize = 1 << 20 // the largest Data frame
	tarBlock  = 512
	// writeIdle is how long the host waits for the guest to take one frame.
	writeIdle = 60 * time.Second
)

// entry is one thing to send: the target, or something below it.
type entry struct {
	name string      // the name in the tar stream: the target name, then slash separated
	path string      // the place on disk
	info fs.FileInfo // from Lstat, so a symlink is a symlink
	link string      // the target of a symlink
}

// plan is what the host sends for one target. The host walks the tree but never reads
// what is in the files, except to copy it. A link has no entries: the guest downloads it.
type plan struct {
	source  string // protocol.SourceLocal, SourceURL, SourceDrive or SourceGit; empty for an update
	update  bool   // the update job: no target and no input, and the update policy
	url     string // the link of a url, drive or git target
	probe   string // the address of a net-probe job, which galahadtest builds can ask for; empty otherwise
	name    string // base name of the target, the single top-level element of the tar stream
	isDir   bool
	entries []entry
	size    int64 // the size of the tar stream, as far as it is known before it is written
}

// remote reports whether the guest downloads the target.
func (p *plan) remote() bool {
	return p.source == protocol.SourceURL || p.source == protocol.SourceDrive || p.source == protocol.SourceGit
}

// newPlan plans the target of a job. For a link, which only the guest ever fetches, it checks the
// length and nothing else.
func newPlan(source, target string) (*plan, error) {
	switch source {
	case "", protocol.SourceLocal:
		p, err := newLocalPlan(target)
		if p != nil {
			p.probe = netProbeURL()
		}
		return p, err
	case protocol.SourceURL, protocol.SourceDrive, protocol.SourceGit:
		if len(target) > protocol.MaxURL {
			return nil, fmt.Errorf("the link is %d bytes, the most is %d", len(target), protocol.MaxURL)
		}
		return &plan{source: source, url: target, isDir: source == protocol.SourceGit}, nil
	}
	return nil, fmt.Errorf("the source %q is not supported", source)
}

// policy builds the proxy policy of the job.
func (p *plan) policy(allowHosts []string) (proxy.Policy, error) {
	in := proxy.Input{Kind: protocol.KindScan, Source: p.source, AllowHosts: allowHosts}
	switch {
	case p.update: // only the ClamAV mirror and the YARA-Forge release host
		in = proxy.Input{Kind: protocol.KindUpdate}
	case p.remote():
		in.Target = p.url
	case p.probe != "":
		in.Source, in.Target = protocol.SourceURL, p.probe
	}
	return proxy.NewPolicy(in)
}

// jobTarget is the target of job.json. The kind of a link is its source.
func (p *plan) jobTarget(target string) Target {
	if p.remote() {
		return Target{Input: protocol.CleanPath(target), Kind: p.source}
	}
	return Target{Input: protocol.CleanPath(filepath.Clean(target)), Kind: "path"}
}

// newLocalPlan walks target without following any symlink, and checks the caps of the
// guest's extractor, so an input that is too large fails before the machine boots. Devices,
// FIFOs and sockets are left out.
func newLocalPlan(target string) (*plan, error) {
	abs, err := filepath.Abs(target)
	if err != nil {
		return nil, err
	}
	if filepath.Dir(abs) == abs {
		return nil, errors.New("cannot scan a filesystem root; pass a folder or a file")
	}
	p := &plan{source: protocol.SourceLocal, name: filepath.Base(abs), size: 2 * tarBlock} // the end of the archive
	if len(p.name) > protocol.MaxPath || !utf8.ValidString(p.name) {
		return nil, fmt.Errorf("the name %q is too long or is not valid UTF-8", protocol.CleanPath(p.name))
	}
	info, err := os.Lstat(abs)
	if err != nil {
		return nil, err
	}
	switch {
	case info.Mode()&fs.ModeSymlink != 0:
		return nil, errors.New("the target is a symlink; pass the path it points to")
	case info.Mode().IsRegular():
		err = p.add(entry{name: p.name, path: abs, info: info})
	case info.IsDir():
		p.isDir = true
		err = p.walk(abs)
	default:
		return nil, errors.New("the target is not a regular file or a folder")
	}
	if err != nil {
		return nil, err
	}
	return p, nil
}

func (p *plan) walk(root string) error {
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		e := entry{path: path, name: p.name}
		if path != root {
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			e.name = p.name + "/" + filepath.ToSlash(rel)
		}
		if e.info, err = d.Info(); err != nil {
			return err
		}
		switch t := e.info.Mode().Type(); {
		case t.IsDir():
		case t.IsRegular():
		case t == fs.ModeSymlink:
			if e.link, err = os.Readlink(path); err != nil {
				return err
			}
		default:
			return nil // device, FIFO, socket
		}
		return p.add(e)
	})
}

// add puts e in the plan unless that goes over the caps of the guest's extractor. The size
// counts a header block and the padded content of each entry.
func (p *plan) add(e entry) error {
	if p.entries = append(p.entries, e); len(p.entries) > protocol.MaxInputEntries {
		return fmt.Errorf("the input is too large: more than %d entries", protocol.MaxInputEntries)
	}
	p.size += tarBlock
	if e.info.Mode().IsRegular() {
		p.size += (e.info.Size() + tarBlock - 1) / tarBlock * tarBlock
	}
	if p.size > protocol.MaxInputBytes {
		return fmt.Errorf("the input is too large: more than %d bytes", int64(protocol.MaxInputBytes))
	}
	return nil
}

// sent is what the host learns while it sends the input.
type sent struct {
	fileSHA string // sha256 of the target, for a file target
	err     error
}

// send writes the Job frame, the tar stream as Data frames and the End frame. endSent is set
// before the End frame is written, so a Result that comes earlier is known to be out of order.
func (p *plan) send(conn net.Conn, job protocol.Job, endSent *atomic.Bool) sent {
	if err := writeJSON(conn, protocol.FrameJob, job); err != nil {
		return sent{err: fmt.Errorf("send job: %w", err)}
	}
	cw := &chunkWriter{conn: conn, h: sha256.New()}
	var fileSHA string
	if !p.remote() && !p.update { // a link and an update have no stream, and the End frame says so
		var err error
		if fileSHA, err = p.writeTar(cw); err != nil {
			return sent{err: err}
		}
		if err := cw.flush(); err != nil {
			return sent{err: fmt.Errorf("send input: %w", err)}
		}
	}
	endSent.Store(true)
	end := protocol.End{Bytes: cw.n, SHA256: hex.EncodeToString(cw.h.Sum(nil))}
	if err := writeJSON(conn, protocol.FrameEnd, end); err != nil {
		return sent{err: fmt.Errorf("send end: %w", err)}
	}
	return sent{fileSHA: fileSHA}
}

// writeTar writes the tar stream and returns the sha256 of the target if it is a file.
func (p *plan) writeTar(w io.Writer) (string, error) {
	tw := tar.NewWriter(w)
	var fileSHA string
	for _, e := range p.entries {
		hdr := &tar.Header{Name: e.name, Mode: int64(e.info.Mode().Perm())}
		switch t := e.info.Mode().Type(); {
		case t.IsDir():
			hdr.Typeflag, hdr.Name = tar.TypeDir, e.name+"/"
		case t == fs.ModeSymlink:
			hdr.Typeflag, hdr.Linkname = tar.TypeSymlink, e.link
		default:
			hdr.Typeflag, hdr.Size = tar.TypeReg, e.info.Size()
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return "", fmt.Errorf("send input: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		h := sha256.New()
		if err := copyFile(tw, h, e); err != nil {
			return "", err
		}
		if !p.isDir {
			fileSHA = hex.EncodeToString(h.Sum(nil))
		}
	}
	if err := tw.Close(); err != nil {
		return "", fmt.Errorf("send input: %w", err)
	}
	return fileSHA, nil
}

// copyFile copies the content of a regular file to w and h. The file must still be the one the walk saw.
func copyFile(w io.Writer, h hash.Hash, e entry) error {
	f, err := openInput(e.path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }() // read-only file
	if info, err := f.Stat(); err != nil || !info.Mode().IsRegular() || !os.SameFile(info, e.info) {
		return fmt.Errorf("%q changed while it was read", protocol.CleanPath(e.path))
	}
	n, err := io.Copy(io.MultiWriter(w, h), io.LimitReader(f, e.info.Size()))
	switch {
	case err != nil:
		return fmt.Errorf("send input: %w", err)
	case n != e.info.Size():
		return fmt.Errorf("%q changed while it was read", protocol.CleanPath(e.path))
	}
	return nil
}

// chunkWriter writes what it gets as Data frames of at most chunkSize bytes, and hashes and
// counts the stream. It stops at the byte cap of the guest.
type chunkWriter struct {
	conn net.Conn
	h    hash.Hash
	buf  []byte
	n    int64
}

func (c *chunkWriter) Write(p []byte) (int, error) {
	if c.n += int64(len(p)); c.n > protocol.MaxInputBytes {
		return 0, fmt.Errorf("the input is too large: more than %d bytes", int64(protocol.MaxInputBytes))
	}
	c.h.Write(p) // a hash.Hash never returns an error
	for rest := p; len(rest) > 0; {
		k := min(len(rest), chunkSize-len(c.buf))
		c.buf = append(c.buf, rest[:k]...)
		rest = rest[k:]
		if len(c.buf) == chunkSize {
			if err := c.flush(); err != nil {
				return 0, err
			}
		}
	}
	return len(p), nil
}

func (c *chunkWriter) flush() error {
	if len(c.buf) == 0 {
		return nil
	}
	if err := c.conn.SetWriteDeadline(time.Now().Add(writeIdle)); err != nil {
		return err
	}
	err := protocol.WriteFrame(c.conn, protocol.FrameData, c.buf)
	c.buf = c.buf[:0]
	return err
}
