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
	"path"
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

	// Member is the cleaned path of a container member inside its own container,
	// for example "repo/.vscode/tasks.json". It is empty for files on disk. The
	// engine sets it.
	Member string
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
	topBytes  int64
	bytes     int64
	queue     []File
	perRule   map[string]int
	iocs      map[string]bool
	unread    map[string]bool // paths of skipped members already counted as seen

	extraFiles int   // files read past the file cap or byte budget
	extraBytes int64 // their size
	extraFull  bool  // an extra file was refused for want of allowance
	memberCut  bool  // a member past the file cap was dropped, and a skip says so
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
		unread:    map[string]bool{},
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
			// The files after this one were never read.
			j.res.Coverage.Truncated = true
			j.skip(cp, protocol.SkipTimeout)
			return fs.SkipAll
		}
		ok, more := j.admit()
		switch {
		case !more:
			// Everything after this point is unread, and a payload could be in it.
			j.skip(cp, protocol.SkipBudget)
			return fs.SkipAll
		case !ok && !j.priority(cp):
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
		j.top(ctx, f, d.Name(), cp, !ok)
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
	j.top(ctx, f, name, protocol.CleanPath(name), false)
	// The top-level file is the first one accepted, whatever its members add after it.
	if len(j.res.Files) > 0 {
		j.res.Target.SHA256 = j.res.Files[0].SHA256
	}
	return nil
}

// top reads one file from disk, dispatches it and then its members. A late file
// is past the file cap: it has no share of the job budget and is analyzed only as
// an extra file.
func (j *job) top(ctx context.Context, r io.Reader, name, cp string, late bool) {
	j.topFiles++
	// Past the file cap, or with the job byte budget spent, only an auto-run file is
	// read, from the extra allowance and not the job budget.
	extraOnly := late || j.bytes >= MaxTotalBytes
	if extraOnly && !late && !j.priority(cp) {
		j.res.Coverage.Truncated = true
		j.skip(cp, protocol.SkipTooLarge)
		return
	}
	limit := MaxTotalBytes - j.bytes
	readMax := int64(MaxFileSize)
	if extraOnly {
		if j.extraFiles >= MaxExtraFiles || j.extraBytes >= MaxExtraBytes {
			j.res.Coverage.Truncated = true
			j.refuse(cp)
			return
		}
		readMax = min(readMax, MaxExtraBytes-j.extraBytes)
	}
	h := sha256.New()
	data, err := io.ReadAll(io.LimitReader(r, readMax+1))
	if err != nil {
		j.skip(cp, protocol.SkipParseError)
		return
	}
	size := int64(len(data))
	_, _ = h.Write(data) // hash.Hash never fails
	if size > MaxFileSize && !extraOnly {
		n, err := io.Copy(h, io.LimitReader(r, limit-size+1))
		size += n
		if err != nil {
			j.skip(cp, protocol.SkipParseError)
			return
		}
	}
	if extraOnly && size > readMax {
		// Over MaxFileSize or over what is left of the extra allowance. The bytes
		// read count against the allowance, so reading them stays bounded.
		j.res.Coverage.Truncated = true
		j.extraFiles++
		j.extraBytes += size
		j.skip(cp, j.unreadReason(cp))
		return
	}
	if extraOnly || size > limit {
		j.res.Coverage.Truncated = true
		if size > MaxFileSize || !j.priority(cp) {
			j.skip(cp, j.unreadReason(cp))
			return
		}
		j.extra(ctx, File{Path: cp, Name: name, Data: data}, h.Sum(nil))
		return
	}
	j.bytes += size
	j.topBytes += size
	if f, ok := j.accept(File{Path: cp, Name: name, Data: data}, size, h.Sum(nil)); ok {
		j.dispatch(ctx, f)
	}
	j.drain(ctx)
}

// unreadReason is the skip for a file over a size limit that no analyzer reads.
// An auto-run file that stays unread hides content, whatever its first bytes say.
func (j *job) unreadReason(path string) string {
	if j.priority(path) {
		return protocol.SkipBudget
	}
	return protocol.SkipTooLarge
}

// priority reports whether an analyzer must see the file at cp, a path on disk or
// a path inside a container.
func (j *job) priority(cp string) bool {
	for _, a := range j.analyzers {
		if p, ok := a.(Priority); ok && p.Priority(cp) {
			return true
		}
	}
	return false
}

// extra analyzes a small file that an analyzer must see although the file cap or
// the byte budget is spent. It draws on its own allowance and does not charge the
// job budget.
func (j *job) extra(ctx context.Context, c File, sum []byte) {
	if j.extraFiles >= MaxExtraFiles || j.extraBytes+int64(len(c.Data)) > MaxExtraBytes {
		j.refuse(c.Path)
		return
	}
	j.extraFiles++
	j.extraBytes += int64(len(c.Data))
	if f, ok := j.accept(c, int64(len(c.Data)), sum); ok {
		j.dispatch(ctx, f)
	}
	j.drain(ctx)
}

// refuse records that the extra allowance is gone. Further files are unread,
// which hides content, so one budget skip says so.
func (j *job) refuse(cp string) {
	if !j.extraFull {
		j.extraFull = true
		j.skip(cp, protocol.SkipBudget)
	}
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
func (j *job) accept(c File, size int64, sum []byte) (File, bool) {
	large := size > MaxFileSize
	head := c.Data[:min(len(c.Data), identifyWindow)]
	if !large {
		head = c.Data
	}
	kind := ident.Identify(c.Name, head)
	info := protocol.FileInfo{Path: c.Path, Size: size, Kind: string(kind), SHA256: hex.EncodeToString(sum)}
	if large {
		j.res.Files = append(j.res.Files, info)
		p := c.Path
		if c.Member != "" {
			p = c.Member
		}
		j.skip(c.Path, j.unreadReason(p))
		return File{}, false
	}
	info.Entropy = ident.Entropy(c.Data)
	j.res.Files = append(j.res.Files, info)
	c.Kind = kind
	return c, true
}

// dispatch runs every analyzer on f and merges what they return. The file
// counts as analyzed only if no analyzer failed.
func (j *job) dispatch(ctx context.Context, f File) {
	failed := false
	for _, a := range j.analyzers {
		out, reason := call(WithBudget(ctx, MaxTotalBytes-j.bytes), a, f)
		if reason != "" {
			if !failed {
				j.skip(f.Path, reason)
			}
			failed = true
			if reason != protocol.SkipTimeout {
				continue
			}
			// What the analyzer found before the time ran out still counts.
		}
		j.merge(a.Name(), f, out)
	}
	if !failed {
		j.res.Coverage.FilesAnalyzed++
	}
}

// call runs one analyzer with the per-file timeout. A panic, an error or a
// timeout yields a skip reason. ctx carries the job budget left.
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
		return out, protocol.SkipTimeout
	case err != nil:
		return Output{}, protocol.SkipParseError
	}
	return out, ""
}

// evictFor makes room for fd in a full findings list by replacing the newest
// finding of the lowest severity, if fd is more severe than it. Low findings can
// then never push out a critical one. Only a finding whose rule occurs more than
// once can be replaced, so the only finding of a rule always stays. It reports
// whether fd was added.
func (j *job) evictFor(fd protocol.Finding) bool {
	fs := j.res.Findings
	rules := map[string]int{}
	for _, f := range fs {
		rules[f.RuleID]++
	}
	victim := -1
	for i := len(fs) - 1; i >= 0; i-- {
		if rules[fs[i].RuleID] > 1 && (victim < 0 || severityRank[fs[i].Severity] < severityRank[fs[victim].Severity]) {
			victim = i
		}
	}
	if victim < 0 || severityRank[fd.Severity] <= severityRank[fs[victim].Severity] {
		return false
	}
	fs[victim] = fd
	return true
}

func (j *job) merge(analyzer string, parent File, out Output) {
	for _, fd := range out.Findings {
		if len(fd.Evidence) == 0 {
			continue
		}
		key := fd.RuleID + "\x00" + fd.Evidence[0].Path
		if j.perRule[key] >= protocol.MaxFindingsPerRulePerFile {
			continue
		}
		fd.Analyzer = analyzer
		if len(j.res.Findings) >= protocol.MaxFindings {
			j.res.Coverage.Truncated = true
			if !j.evictFor(fd) {
				continue
			}
		} else {
			j.res.Findings = append(j.res.Findings, fd)
		}
		j.perRule[key]++
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
		if s.Unread() && s.Path != parent.Path && !j.unread[s.Path] {
			// The skipped member was seen but never analyzed. A skip of the file the
			// analyzer was given, or one already counted, is not another file.
			j.unread[s.Path] = true
			j.admit()
		}
	}
	j.res.Coverage.Skipped = append(j.res.Coverage.Skipped, out.Skips...)
	for _, c := range out.Children {
		// Extractors on Windows split member names at a backslash, and any extractor
		// ignores empty and "." segments, so path rules must see the same path.
		c.Name = path.Clean(strings.ReplaceAll(c.Name, `\`, "/"))
		c.Path = protocol.CleanPath(parent.Path + "!/" + c.Name)
		c.Member = c.Name
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
			// This member and the ones queued after it were never analyzed.
			j.res.Coverage.Truncated = true
			j.skip(c.Path, protocol.SkipTimeout)
			j.queue = nil
			return
		}
		ok, more := j.admit()
		switch {
		case !more:
			j.dropMember(c.Path)
			j.queue = nil
		case !ok:
			// Past the file cap. A member an analyzer asks for is still analyzed from
			// the extra allowance, and any other is only counted.
			j.extraMember(ctx, c)
		case c.Depth > MaxNesting:
			j.skip(c.Path, protocol.SkipDepth)
		default:
			sum := sha256.Sum256(c.Data)
			if f, ok := j.accept(c, int64(len(c.Data)), sum[:]); ok {
				j.dispatch(ctx, f)
			}
		}
	}
}

// extraMember analyzes a member past the file cap if an analyzer asks for it.
func (j *job) extraMember(ctx context.Context, c File) {
	switch {
	case !j.priority(c.Member):
	case c.Depth > MaxNesting:
		j.skip(c.Path, protocol.SkipDepth)
	case int64(len(c.Data)) > MaxFileSize:
		j.skip(c.Path, j.unreadReason(c.Member))
	default:
		sum := sha256.Sum256(c.Data)
		j.extra(ctx, c, sum[:])
	}
}

// dropMember records that members past the counting limit were not analyzed.
// They could hold a payload, so one budget skip, at the first of them, says so.
func (j *job) dropMember(path string) {
	if !j.memberCut {
		j.memberCut = true
		j.skip(path, protocol.SkipBudget)
	}
}

func (j *job) skip(path, reason string) {
	j.res.Coverage.Skipped = append(j.res.Coverage.Skipped, protocol.Skip{Path: path, Reason: reason})
}

func (j *job) finish() protocol.Result {
	res := j.res
	res.Target.FileCount = j.topFiles
	if res.Target.Kind == protocol.TargetDir {
		res.Target.Size = j.topBytes
	}
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
