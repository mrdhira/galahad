// Package script looks for hidden, decoded-and-executed and secret-stealing
// code in JavaScript, TypeScript and Python files. The checks are lexical and
// line based, with no parsing of the language.
//
// Every check is linear in the size of the file. Whole-file passes use
// patterns that start with a literal word, which Go's regexp finds quickly. The
// slower signals patterns run only on windows around rare words such as curl,
// .ssh or process.env.API_TOKEN. The context is checked between windows of at
// most chunkSize bytes, so a file with one giant line costs the same as a
// normal one. Work is budgeted per file (signalBudget, argBudget, maxHits); a
// file that runs out gets a budget skip. Encoded blobs are decoded once (at
// most maxBlobs blobs and maxDecodedTotal bytes per file) and the decoded text
// gets one more pass of all checks. It is never decoded again.
package script

import (
	"bytes"
	"context"
	"path"
	"strings"

	"github.com/mrdhira/galahad/internal/analyze"
	"github.com/mrdhira/galahad/internal/protocol"
)

var (
	ruleHidden   = protocol.Rule{ID: "GAL-OBF-001", Severity: protocol.SeverityHigh, Title: "Code hidden after whitespace padding", Attack: "T1027"}
	ruleDecoded  = protocol.Rule{ID: "GAL-OBF-002", Severity: protocol.SeverityHigh, Title: "Dynamic execution of decoded data", Attack: "T1027"}
	ruleBlob     = protocol.Rule{ID: "GAL-OBF-003", Severity: protocol.SeverityLow, Title: "Long encoded blob", Attack: "T1027"}
	ruleExfil    = protocol.Rule{ID: "GAL-EXFIL-001", Severity: protocol.SeverityCritical, Title: "Reads secret material and sends data to the network", Attack: "T1041"}
	ruleEnvNet   = protocol.Rule{ID: "GAL-EXFIL-002", Severity: protocol.SeverityLow, Title: "Secret-named environment variable and network use in the same file", Attack: "T1552.001"}
	ruleDownload = protocol.Rule{ID: "GAL-EXEC-001", Severity: protocol.SeverityHigh, Title: "Downloads code and executes it", Attack: "T1105"}
	ruleSpawn    = protocol.Rule{ID: "GAL-EXEC-002", Severity: protocol.SeverityLow, Title: "Spawns shell commands", Attack: "T1059"}
)

// Limits. The input size limit is analyze.MaxFileSize.
const (
	padMin          = 200       // whitespace run that hides code
	blobMin         = 256       // characters of an encoded blob
	blobDiversity   = 10        // distinct characters a blob needs
	maxBlobChars    = 512 << 10 // characters of one blob that are decoded
	maxBlobs        = 16        // blobs decoded per file
	maxDecodedTotal = 1 << 20   // decoded bytes per file
	chunkSize       = 256 << 10 // bytes per regular expression window
	chunkOverlap    = 2 << 10   // overlap of windows cut inside a line
	maxArg          = 512       // bytes of a call argument that are read
	lookback        = 64 << 10  // bytes searched for the assignment of a variable
	lookbackBudget  = 4 << 20   // lookback bytes per file
	maxRHS          = 400       // bytes of an assignment that are read
	signalBudget    = 6 << 20   // bytes given to the slow signals patterns per file
	argBudget       = 32 << 20  // bytes of call arguments read per file
	maxFar          = 32 << 10  // bytes between secret material and the network use
	maxHits         = 1 << 20   // hits kept per kind and file
	maxShellMatch   = 512       // longest shell command match that counts
	commentBack     = 4 << 10   // bytes searched for the start of a line when keying a line
	snippetBack     = 120       // snippets start at the line start if it is this close
	snippetLead     = 60        // else this many bytes before the match
	snippetBytes    = 800       // bytes read for a snippet
	maxPairLines    = 100       // lines between secret material and the network use
)

type lang uint8

const (
	langJS lang = 1 << iota
	langPy
)

var extLang = map[string]lang{
	".js": langJS, ".mjs": langJS, ".cjs": langJS, ".jsx": langJS, ".ts": langJS, ".tsx": langJS,
	".py": langPy,
}

type analyzer struct{}

// New returns the JS/TS and Python script analyzer.
func New() analyze.Analyzer { return analyzer{} }

func (analyzer) Name() string { return "script" }

func (analyzer) Analyze(ctx context.Context, f analyze.File) (analyze.Output, error) {
	var out analyze.Output
	l, ok := extLang[strings.ToLower(path.Ext(f.Name))]
	if !ok || len(f.Data) == 0 {
		return out, nil
	}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	s := &scan{ctx: ctx, f: f, out: &out, counts: map[string]int{}}
	s.run(&doc{data: f.Data, lang: l})
	if s.limited && !s.timedOut {
		out.Skips = append(out.Skips, protocol.Skip{Path: f.Path, Reason: protocol.SkipBudget})
	}
	return out, nil
}

// doc is a text to check: the file, or a blob decoded from it.
type doc struct {
	data  []byte
	lang  lang
	depth int
	line  int // line of the literal a decoded text came from
	memo  lineMemo
	al    *aliasSet // found by aliasesOf

	childProc bool // the text mentions child_process
}

// lineMemo is the answer of commentLine for the line [lo, hi): the offsets
// before to are comment.
type lineMemo struct{ lo, hi, to int }

// scan collects the findings of one file.
type scan struct {
	ctx      context.Context
	f        analyze.File
	out      *analyze.Output
	counts   map[string]int // findings built per rule ID
	timedOut bool
	blobs    int // blobs decoded
	decoded  int // bytes decoded
	looked   int // lookback bytes used

	signalBytes int  // bytes given to the signals patterns
	argBytes    int  // bytes of call arguments read
	limited     bool // a budget ended the analysis early
}

// done reports whether the context has ended. The first time, it records a
// timeout skip; the findings so far are kept.
func (s *scan) done() bool {
	if s.ctx.Err() == nil {
		return false
	}
	if !s.timedOut {
		s.timedOut = true
		s.out.Skips = append(s.out.Skips, protocol.Skip{Path: s.f.Path, Reason: protocol.SkipTimeout})
	}
	return true
}

func (s *scan) full(r protocol.Rule) bool {
	return s.counts[r.ID] >= protocol.MaxFindingsPerRulePerFile
}

// emit records a finding of rule r with the evidence ev returns. The engine
// keeps only protocol.MaxFindingsPerRulePerFile findings per rule and file, so
// the rest are not built.
func (s *scan) emit(r protocol.Rule, ev func() []protocol.Evidence) {
	if s.full(r) {
		return
	}
	s.counts[r.ID]++
	s.out.Findings = append(s.out.Findings, r.Finding(ev()...))
}

// add records a finding of rule r at the byte offset off of d.
func (s *scan) add(d *doc, r protocol.Rule, off int) {
	s.emit(r, func() []protocol.Evidence { return []protocol.Evidence{s.ev(d, off, -1)} })
}

// ev returns evidence for the offset off of d. The snippet starts at from, or
// at the start of the line when that is close, or just before off.
// Decoded text points at the line of its literal and starts with "decoded: ".
func (s *scan) ev(d *doc, off, from int) protocol.Evidence {
	off = max(0, min(off, len(d.data)))
	if from < 0 {
		from = 0
		lo := max(0, off-snippetBack)
		if i := bytes.LastIndexByte(d.data[lo:off], '\n'); i >= 0 {
			from = lo + i + 1
		} else if lo > 0 {
			from = off - snippetLead
		}
	}
	for from < off && (d.data[from] == ' ' || d.data[from] == '\t') {
		from++
	}
	end := min(len(d.data), from+snippetBytes)
	text := d.data[from:end]
	if i := bytes.IndexAny(text, "\r\n"); i >= 0 {
		text = text[:i]
	}
	if d.depth == 0 {
		e := analyze.EvidenceAt(s.f, off)
		e.Snippet = protocol.Snippet(string(text))
		return e
	}
	return protocol.Evidence{Path: s.f.Path, Line: d.line, Snippet: protocol.Snippet("decoded: " + string(text))}
}

// run applies all checks to d.
func (s *scan) run(d *doc) {
	if s.padding(d); s.timedOut {
		return
	}
	if s.blobsIn(d); s.timedOut {
		return
	}
	f := s.collect(d)
	s.sinks(d, f)
	s.shell(d, f)
	s.exfil(d, f)
}

// commentLine reports whether off is in a whole-line comment: a line that
// starts with // (or # in Python), or the part of a line that starts with /* or *
// up to the first */. Code after the */ is code. It remembers the last line it
// saw, so the many matches on one long line cost one scan.
func (d *doc) commentLine(off int) bool {
	if off >= d.memo.lo && off < d.memo.hi {
		return off < d.memo.to
	}
	lo := bytes.LastIndexByte(d.data[:off], '\n') + 1
	hi := len(d.data)
	if i := bytes.IndexByte(d.data[off:], '\n'); i >= 0 {
		hi = off + i + 1
	}
	line := d.data[lo:hi]
	to := lo // the comment ends here
	text := bytes.TrimLeft(line, " \t")
	switch {
	case d.lang&langJS != 0 && bytes.HasPrefix(text, []byte("//")):
		to = hi
	case d.lang&langJS != 0 && (bytes.HasPrefix(text, []byte("/*")) || bytes.HasPrefix(text, []byte("*"))):
		to = hi
		if i := bytes.Index(line, []byte("*/")); i >= 0 {
			to = lo + i + 2
		}
	case d.lang&langPy != 0 && bytes.HasPrefix(text, []byte("#")) && !bytes.HasPrefix(text, []byte("#!")):
		to = hi
	}
	d.memo = lineMemo{lo, hi, to}
	return off < to
}
