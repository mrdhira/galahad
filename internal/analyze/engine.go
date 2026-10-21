// Package analyze is the analysis engine. It walks a target once within the
// global limits, identifies, hashes and measures every file, hands each file to
// the registered analyzers and collects their output into a protocol.Result.
//
// It parses untrusted bytes, so it belongs to the guest agent and must never be
// imported by the host.
package analyze

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/mrdhira/galahad/internal/analyze/ident"
	"github.com/mrdhira/galahad/internal/protocol"
)

// File is one file handed to analyzers.
type File struct {
	Path  string // cleaned, for evidence; container members use "!/"
	Name  string // raw base name
	Kind  ident.Kind
	Data  []byte
	Depth int // container depth, 0 for files on disk
}

// Output is what an analyzer found in one file. For Children, only Name (the
// member path inside the container) and Data are read; the engine sets the rest.
type Output struct {
	Findings []protocol.Finding
	IOCs     []protocol.IOC
	Children []File
	Skips    []protocol.Skip
}

// Analyzer inspects one file. It returns an empty Output quickly for files it
// does not handle and stops when ctx is done.
type Analyzer interface {
	Name() string
	Analyze(ctx context.Context, f File) (Output, error)
}

// Run analyzes the file or directory at path. Symlinks are never followed and
// FIFOs, devices and sockets are never opened. A cancelled ctx ends the walk
// early and marks the coverage truncated. The caller sets Result.Tool.
func Run(ctx context.Context, path string, analyzers []Analyzer) (protocol.Result, error) {
	info, err := os.Stat(path)
	if err != nil {
		return protocol.Result{}, err
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return protocol.Result{}, err
	}
	j := newJob(analyzers)
	j.res.StartedAt = time.Now().UTC()
	j.res.Target.Name = protocol.CleanPath(filepath.Base(abs))

	switch {
	case info.IsDir():
		j.res.Target.Kind = protocol.TargetDir
		err = j.walkDir(ctx, path)
	case info.Mode().IsRegular():
		j.res.Target.Kind = protocol.TargetFile
		j.res.Target.Size = info.Size()
		err = j.walkFile(ctx, path)
	default:
		err = fmt.Errorf("%s is not a regular file or directory", path)
	}
	if err != nil {
		return protocol.Result{}, err
	}
	return j.finish(), nil
}

type job struct {
	analyzers []Analyzer
	res       protocol.Result
	topFiles  int
	bytes     int64
	queue     []File
	perRule   map[string]int
	iocs      map[string]bool
}

func newJob(analyzers []Analyzer) *job {
	as := append([]Analyzer(nil), analyzers...)
	sort.SliceStable(as, func(a, b int) bool { return as[a].Name() < as[b].Name() })
	names := make([]string, len(as))
	for i, a := range as {
		names[i] = a.Name()
	}
	return &job{
		analyzers: as,
		perRule:   map[string]int{},
		iocs:      map[string]bool{},
		res: protocol.Result{
			SchemaVersion: protocol.SchemaVersion,
			Files:         []protocol.FileInfo{},
			Findings:      []protocol.Finding{},
			IOCs:          []protocol.IOC{},
			Reasons:       []string{},
			Coverage:      protocol.Coverage{Skipped: []protocol.Skip{}, Analyzers: names},
		},
	}
}

func (j *job) walkDir(ctx context.Context, path string) error {
	root, err := os.OpenRoot(path)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }() // read-only handle

	return fs.WalkDir(root.FS(), ".", func(p string, d fs.DirEntry, err error) error {
		if p == "." {
			return err
		}
		cp := protocol.CleanPath(p)
		switch {
		case err != nil:
			j.skip(cp, protocol.SkipParseError)
			return nil
		case d.IsDir():
			if strings.Count(p, "/")+1 > MaxDirDepth {
				j.skip(cp, protocol.SkipDepth)
				return fs.SkipDir
			}
			return nil
		}
		if ctx.Err() != nil {
			j.res.Coverage.Truncated = true
			return fs.SkipAll
		}
		ok, more := j.admit()
		switch {
		case !more:
			return fs.SkipAll
		case !ok:
			return nil
		case !d.Type().IsRegular():
			j.skip(cp, protocol.SkipUnsupported)
			return nil
		}
		f, err := root.Open(p)
		if err != nil {
			j.skip(cp, protocol.SkipParseError)
			return nil
		}
		defer func() { _ = f.Close() }() // read-only handle
		j.top(ctx, f, d.Name(), cp)
		return nil
	})
}

func (j *job) walkFile(ctx context.Context, path string) error {
	f, err := os.Open(path) // #nosec G304 -- the target is the explicit argument of the user
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }() // read-only handle
	j.admit()
	name := filepath.Base(path)
	j.top(ctx, f, name, protocol.CleanPath(name))
	if len(j.res.Files) == 1 {
		j.res.Target.SHA256 = j.res.Files[0].SHA256
	}
	return nil
}

// top reads one file from disk, dispatches it and then its members.
func (j *job) top(ctx context.Context, r io.Reader, name, cp string) {
	j.topFiles++
	if j.bytes >= MaxTotalBytes {
		j.res.Coverage.Truncated = true
		j.skip(cp, protocol.SkipBudget)
		return
	}
	limit := MaxTotalBytes - j.bytes
	h := sha256.New()
	data, err := io.ReadAll(io.LimitReader(r, MaxFileSize+1))
	if err != nil {
		j.skip(cp, protocol.SkipParseError)
		return
	}
	size := int64(len(data))
	_, _ = h.Write(data) // hash.Hash never fails
	if size > MaxFileSize {
		n, err := io.Copy(h, io.LimitReader(r, limit-size+1))
		size += n
		if err != nil {
			j.skip(cp, protocol.SkipParseError)
			return
		}
	}
	if size > limit {
		j.res.Coverage.Truncated = true
		j.skip(cp, protocol.SkipBudget)
		return
	}
	j.bytes += size
	if f, ok := j.accept(cp, name, 0, data, size, h.Sum(nil)); ok {
		j.dispatch(ctx, f)
	}
	j.drain(ctx)
}

// admit counts one more file seen. ok says the file may be analyzed; more says
// the walk should continue.
func (j *job) admit() (ok, more bool) {
	c := &j.res.Coverage
	if c.FilesSeen >= maxFilesSeen {
		c.Truncated = true
		return false, false
	}
	c.FilesSeen++
	if c.FilesSeen > MaxFiles {
		c.Truncated = true
		return false, true
	}
	return true, true
}

// accept records a file's info and returns it for analysis, unless it is too
// large to hand to analyzers.
func (j *job) accept(cp, name string, depth int, data []byte, size int64, sum []byte) (File, bool) {
	large := size > MaxFileSize
	head := data[:min(len(data), identifyWindow)]
	if !large {
		head = data
	}
	kind := ident.Identify(name, head)
	info := protocol.FileInfo{Path: cp, Size: size, Kind: string(kind), SHA256: hex.EncodeToString(sum)}
	if large {
		j.res.Files = append(j.res.Files, info)
		j.skip(cp, protocol.SkipTooLarge)
		return File{}, false
	}
	info.Entropy = ident.Entropy(data)
	j.res.Files = append(j.res.Files, info)
	return File{Path: cp, Name: name, Kind: kind, Data: data, Depth: depth}, true
}

// dispatch runs every analyzer on f and merges what they return. The file
// counts as analyzed only if no analyzer failed.
func (j *job) dispatch(ctx context.Context, f File) {
	failed := false
	for _, a := range j.analyzers {
		out, reason := call(ctx, a, f)
		if reason != "" {
			if !failed {
				j.skip(f.Path, reason)
			}
			failed = true
			continue
		}
		j.merge(a.Name(), f, out)
	}
	if !failed {
		j.res.Coverage.FilesAnalyzed++
	}
}

// call runs one analyzer with the per-file timeout. A panic, an error or a
// timeout yields a skip reason.
func call(ctx context.Context, a Analyzer, f File) (out Output, reason string) {
	ctx, cancel := context.WithTimeout(ctx, PerFileTimeout)
	defer cancel()
	defer func() {
		if recover() != nil {
			out, reason = Output{}, protocol.SkipPanic
		}
	}()
	out, err := a.Analyze(ctx, f)
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return Output{}, protocol.SkipTimeout
	case err != nil:
		return Output{}, protocol.SkipParseError
	}
	return out, ""
}

func (j *job) merge(analyzer string, parent File, out Output) {
	for _, fd := range out.Findings {
		if len(fd.Evidence) == 0 {
			continue
		}
		key := fd.RuleID + "\x00" + fd.Evidence[0].Path
		switch {
		case j.perRule[key] >= protocol.MaxFindingsPerRulePerFile:
			continue
		case len(j.res.Findings) >= protocol.MaxFindings:
			j.res.Coverage.Truncated = true
			continue
		}
		j.perRule[key]++
		fd.Analyzer = analyzer
		j.res.Findings = append(j.res.Findings, fd)
	}
	for _, ioc := range out.IOCs {
		key := ioc.Type + "\x00" + ioc.Value
		if j.iocs[key] || len(j.res.IOCs) >= protocol.MaxIOCs {
			continue
		}
		j.iocs[key] = true
		j.res.IOCs = append(j.res.IOCs, ioc)
	}
	for _, s := range out.Skips {
		if s.HidesContent() {
			// The skipped member was seen but never analyzed.
			j.admit()
		}
	}
	j.res.Coverage.Skipped = append(j.res.Coverage.Skipped, out.Skips...)
	for _, c := range out.Children {
		// Extractors on Windows split member names at a backslash, so path rules must too.
		c.Name = strings.ReplaceAll(c.Name, `\`, "/")
		c.Path = protocol.CleanPath(parent.Path + "!/" + c.Name)
		c.Name = c.Name[strings.LastIndexByte(c.Name, '/')+1:]
		c.Depth = parent.Depth + 1
		if j.bytes+int64(len(c.Data)) > MaxTotalBytes {
			// Queued members hold their bytes in memory, so they are charged here.
			j.admit()
			j.res.Coverage.Truncated = true
			j.skip(c.Path, protocol.SkipBudget)
			continue
		}
		j.bytes += int64(len(c.Data))
		j.queue = append(j.queue, c)
	}
}

// drain dispatches queued members in FIFO order; their own members join the queue.
func (j *job) drain(ctx context.Context) {
	for len(j.queue) > 0 {
		c := j.queue[0]
		j.queue[0] = File{} // let the member's bytes go once it is analyzed
		j.queue = j.queue[1:]
		if ctx.Err() != nil {
			j.res.Coverage.Truncated = true
			j.queue = nil
			return
		}
		ok, more := j.admit()
		switch {
		case !more:
			j.queue = nil
		case !ok:
		case c.Depth > MaxNesting:
			j.skip(c.Path, protocol.SkipDepth)
		default:
			sum := sha256.Sum256(c.Data)
			if f, ok := j.accept(c.Path, c.Name, c.Depth, c.Data, int64(len(c.Data)), sum[:]); ok {
				j.dispatch(ctx, f)
			}
		}
	}
}

func (j *job) skip(path, reason string) {
	j.res.Coverage.Skipped = append(j.res.Coverage.Skipped, protocol.Skip{Path: path, Reason: reason})
}

func (j *job) finish() protocol.Result {
	res := j.res
	res.Target.FileCount = j.topFiles
	res.FinishedAt = time.Now().UTC()
	sort.SliceStable(res.Findings, func(a, b int) bool {
		x, y := res.Findings[a], res.Findings[b]
		if rx, ry := severityRank[x.Severity], severityRank[y.Severity]; rx != ry {
			return rx > ry
		}
		if x.Evidence[0].Path != y.Evidence[0].Path {
			return x.Evidence[0].Path < y.Evidence[0].Path
		}
		if x.Evidence[0].Line != y.Evidence[0].Line {
			return x.Evidence[0].Line < y.Evidence[0].Line
		}
		return x.RuleID < y.RuleID
	})
	return res
}

var severityRank = map[protocol.Severity]int{
	protocol.SeverityInfo: 1, protocol.SeverityLow: 2, protocol.SeverityMedium: 3,
	protocol.SeverityHigh: 4, protocol.SeverityCritical: 5,
}
