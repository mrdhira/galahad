// Package inject reports text that tries to make an AI reviewer call the input
// safe. A finding needs two parts close together: text that addresses an AI or
// overrides its instructions, and text that steers the verdict.
//
// The text is copied once with zero-width characters dropped, ASCII letters
// lowercased and every line cut at analyze.MaxLineScan bytes. The phrases are
// RE2 patterns that start with a literal word, so Go's regexp finds them in
// linear time. Lists of phrases such as "safe/benign/clean" do not match: a
// phrase must end at a space or a punctuation mark other than a slash.
package inject

import (
	"bytes"
	"context"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/mrdhira/galahad/internal/analyze"
	"github.com/mrdhira/galahad/internal/analyze/ident"
	"github.com/mrdhira/galahad/internal/protocol"
)

var (
	ruleInject = protocol.Rule{ID: "GAL-INJECT-001", Severity: protocol.SeverityMedium, Title: "Text tries to make an AI reviewer call the input safe"}
	// ruleInjectTest has the ID of ruleInject with a lower severity, for files under test, fixture and
	// example folders. The scorer counts an ID once, at its highest severity.
	ruleInjectTest = protocol.Rule{ID: "GAL-INJECT-001", Severity: protocol.SeverityLow, Title: "Text tries to make an AI reviewer call the input safe"}
)

// Limits. The input size and line limits are analyze.MaxFileSize and analyze.MaxLineScan.
const (
	textWindow = 8192 // leading bytes checked for NUL, like the file identification
	maxGap     = 300  // bytes between the two parts when they are not on one line
	checkEvery = 256  // matches between checks of the context
)

var testDirs = map[string]bool{"test": true, "tests": true, "testdata": true, "__tests__": true, "fixtures": true, "examples": true}

// Pieces of the patterns, which run on lowercase text.
const (
	// end closes a phrase. It is not a slash, so "safe/benign/clean" in a list of words is not one.
	end = `(?:[^a-z0-9/]|$)`
	// verdict is a word that calls the input safe, with marks of emphasis or quotation around it.
	verdict = "(?:[*_`\"'“‘]+)?(?:safe|benign|clean|harmless|not\\s+malicious)" + end
	subject = `(?:it|them|(?:this|that|the)(?:\s+(?:repository|repo|code|codebase|file|project|package|library|input))?)`
	prior   = `(?:(?:all|any|every)\s+)?(?:(?:of\s+)?(?:the|your|my)\s+)?(?:previous|prior|above|earlier)\s+(?:instructions?|guidance|directions|prompts?)\b`
)

// overrides match text that addresses an AI or overrides its instructions, and steers
// match text that steers the verdict.
var (
	overrides = compile(
		`ignore\s+`+prior,
		`disregard\s+`+prior,
		`note\s+to\s+(?:the\s+|any\s+|all\s+)?(?:ai|assistant|reviewer|scanner|llm|model)s?`+end,
		`you\s+are\s+now\s+(?:an?|the|in|my|free|no\s+longer|acting|playing|operating|going)\b`,
		`system\s+prompts?\b`,
	)
	steers = compile(
		`this\s+(?:repository|repo|code|codebase|file|project|package|library|software|input|document|content)\s+(?:is|are|was)\s+(?:(?:completely|totally|entirely|perfectly|absolutely|100%)\s+)?`+verdict,
		`report\s+(?:`+subject+`\s+)?as\s+`+verdict,
		`classify\s+(?:`+subject+`\s+)?as\s+`+verdict,
		`mark\s+(?:`+subject+`\s+)?as\s+`+verdict,
		`treat\s+(?:`+subject+`\s+)?as\s+`+verdict,
		`do\s+not\s+(?:flag|report|warn)`+end,
		`don['’]t\s+(?:flag|report|warn)`+end,
	)
)

func compile(patterns ...string) []*regexp.Regexp {
	res := make([]*regexp.Regexp, len(patterns))
	for i, p := range patterns {
		res[i] = regexp.MustCompile(p)
	}
	return res
}

type analyzer struct{}

// New returns the prompt-injection analyzer.
func New() analyze.Analyzer { return analyzer{} }

func (analyzer) Name() string { return "inject" }

// hit is a match in the normalized text.
type hit struct {
	start, end int
	line       int  // 1-based
	steer      bool // the match steers the verdict
}

// found is a pair of close hits, placed at the earlier one.
type found struct{ start, line int }

func (analyzer) Analyze(ctx context.Context, f analyze.File) (analyze.Output, error) {
	var out analyze.Output
	if !readable(f) {
		return out, nil
	}
	flat, _ := normalize(f.Data, nil)
	pairs, err := findPairs(ctx, flat)
	if err != nil {
		return out, err
	}
	if len(pairs) == 0 {
		return out, nil
	}
	starts := make([]int, len(pairs))
	for i, p := range pairs {
		starts[i] = p.start
	}
	_, at := normalize(f.Data, starts)
	rule := ruleInject
	if inTestDir(f.Path) {
		rule = ruleInjectTest
	}
	for i, p := range pairs {
		out.Findings = append(out.Findings, rule.Finding(protocol.Evidence{Path: f.Path, Line: p.line, Snippet: snippet(f.Data, at[i])}))
	}
	return out, nil
}

// readable reports a text file: one the identification calls text, or leaves
// unknown without a NUL in its first window. Text in a legacy encoding is
// unknown to it, and must not hide a phrase.
func readable(f analyze.File) bool {
	if f.Kind != ident.Text && f.Kind != ident.Unknown {
		return false
	}
	return bytes.IndexByte(f.Data[:min(len(f.Data), textWindow)], 0) < 0
}

// iterator walks the matches of one pattern in order of position.
type iterator struct {
	re         *regexp.Regexp
	steer      bool
	pos        int // where the next search starts
	start, end int // the next match
	ok         bool
}

// advance finds the next match. Every pattern starts with a literal word, so
// searching from the end of the last match gives the same matches as a search of
// the whole text.
func (it *iterator) advance(flat []byte) {
	m := it.re.FindIndex(flat[it.pos:])
	it.ok = m != nil
	if it.ok {
		it.start, it.end = it.pos+m[0], it.pos+m[1]
		it.pos = it.end
	}
}

// findPairs returns the places where a hit that addresses an AI meets a hit that
// steers the verdict on the same line or within maxGap bytes, at most one per
// line and protocol.MaxFindingsPerRulePerFile in all, in order of position. It
// merges the matches of all patterns in order of position and keeps only the
// latest hit of each kind that is not in a pair yet, so any number of earlier
// matches cannot push out a later pair.
func findPairs(ctx context.Context, flat []byte) ([]found, error) {
	var its []*iterator
	for _, re := range overrides {
		its = append(its, &iterator{re: re})
	}
	for _, re := range steers {
		its = append(its, &iterator{re: re, steer: true})
	}
	for _, it := range its {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		it.advance(flat)
	}
	var pairs []found
	lines := map[int]bool{}
	var last [2]hit // the latest hit that addresses an AI, and the latest that steers
	var have [2]bool
	pos, line := 0, 1
	for n := 0; len(pairs) < protocol.MaxFindingsPerRulePerFile; n++ {
		if n%checkEvery == 0 {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}
		var next *iterator
		for _, it := range its {
			if it.ok && (next == nil || it.start < next.start) {
				next = it
			}
		}
		if next == nil {
			break
		}
		h := hit{start: next.start, end: next.end, steer: next.steer}
		next.advance(flat)
		line += bytes.Count(flat[pos:h.start], []byte{'\n'})
		pos = h.start
		h.line = line
		kind, otherKind := 0, 1
		if h.steer {
			kind, otherKind = 1, 0
		}
		other := last[otherKind]
		if !have[otherKind] || (other.line != h.line && h.start-other.end > maxGap) {
			last[kind], have[kind] = h, true
			continue
		}
		have = [2]bool{}
		if !lines[other.line] {
			lines[other.line] = true
			pairs = append(pairs, found{start: other.start, line: other.line})
		}
	}
	slices.SortFunc(pairs, func(a, b found) int { return a.start - b.start })
	return pairs, nil
}

// inTestDir reports a file below a test, fixture or example folder.
func inTestDir(p string) bool {
	dirs := strings.Split(strings.ToLower(p), "/")
	return slices.ContainsFunc(dirs[:len(dirs)-1], func(d string) bool { return testDirs[d] })
}

// normalize copies data with zero-width characters dropped, ASCII letters
// lowercased and each line cut at analyze.MaxLineScan bytes. Newlines stay, so a
// line of the copy is the line of data. With stops (ascending offsets in the
// copy) it makes no copy and returns instead the offset in data of each stop.
func normalize(data []byte, stops []int) (flat []byte, orig []int) {
	copying := len(stops) == 0
	if copying {
		flat = make([]byte, 0, len(data))
	}
	n, col := 0, 0 // bytes in the copy, and in its current line
	// put adds data[from:to] to the copy, or finds the stops in it.
	put := func(from, to int) {
		if copying {
			flat = append(flat, data[from:to]...)
		}
		for len(orig) < len(stops) && stops[len(orig)] < n+to-from {
			orig = append(orig, from+stops[len(orig)]-n)
		}
		n += to - from
		col += to - from
	}
	for i := 0; i < len(data) && (copying || len(orig) < len(stops)); {
		b := data[i]
		if col >= analyze.MaxLineScan && b != '\n' {
			// Skip the rest of the line.
			if j := bytes.IndexByte(data[i:], '\n'); j >= 0 {
				i += j
			} else {
				i = len(data)
			}
			continue
		}
		// A run of bytes that need no change.
		j, limit := i, min(len(data), i+analyze.MaxLineScan-col)
		for j < limit && data[j] != '\n' && data[j] < 0x80 && (data[j] < 'A' || data[j] > 'Z') {
			j++
		}
		if j > i {
			put(i, j)
			i = j
			continue
		}
		switch {
		case b == '\n':
			put(i, i+1)
			col = 0
		case b >= 0x80:
			w := zeroWidth(data[i:])
			if w == 0 {
				put(i, i+1)
				w = 1
			}
			i += w
			continue
		default:
			put(i, i+1)
			if copying {
				flat[len(flat)-1] += 'a' - 'A'
			}
		}
		i++
	}
	return flat, orig
}

// zeroWidth returns the length of the zero-width character at the start of b
// (U+200B to U+200D, U+2060 or U+FEFF), or 0.
func zeroWidth(b []byte) int {
	if len(b) < 3 {
		return 0
	}
	switch {
	case b[0] == 0xE2 && b[1] == 0x80 && b[2] >= 0x8B && b[2] <= 0x8D,
		b[0] == 0xE2 && b[1] == 0x81 && b[2] == 0xA0,
		b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF:
		return 3
	}
	return 0
}

const (
	snippetBack  = 120 // snippets start at the line start if it is this close
	snippetLead  = 60  // else this many bytes before the match
	snippetBytes = 800 // bytes read for a snippet
)

// snippet returns the text of the line of data at off, from the start of the
// line or just before off.
func snippet(data []byte, off int) string {
	start := bytes.LastIndexByte(data[:off], '\n') + 1
	if off-start > snippetBack {
		start = off - snippetLead
		for start < off && !utf8.RuneStart(data[start]) {
			start++
		}
	}
	text := data[start:min(len(data), start+snippetBytes)]
	if i := bytes.IndexAny(text, "\r\n"); i >= 0 {
		text = text[:i]
	}
	return protocol.Snippet(strings.TrimLeft(string(text), " \t"))
}
