// Package pdf is a lexical PDF scanner. It finds JavaScript, Launch actions,
// actions that run when the document opens, embedded files and URIs without
// building a document model.
//
// Streams that use only FlateDecode are decoded and scanned too, and so are
// object streams. A stream that needs any other decoder (LZW, ASCII85, ...) or
// that is encrypted or corrupt is reported as GAL-PDF-007 (low) instead of a
// coverage Skip: such PDFs are common and the file was still read in full, so
// coverage should not be penalised. Only a file over the object limit becomes a
// Skip.
package pdf

import (
	"bytes"
	"compress/zlib"
	"context"
	"io"
	"strconv"
	"strings"

	"github.com/mrdhira/galahad/internal/analyze"
	"github.com/mrdhira/galahad/internal/analyze/ident"
	"github.com/mrdhira/galahad/internal/protocol"
)

// Format limits.
const (
	MaxObjects     = 100000
	MaxStreamBytes = 16 << 20 // decoded bytes per stream
	MaxFileBytes   = 64 << 20 // decoded bytes per file
	MaxURILen      = 2048
)

const (
	maxEvidence   = 3
	maxRefDepth   = 4
	maxSnippetRaw = 400
)

var (
	ruleJS       = protocol.Rule{ID: "GAL-PDF-001", Severity: protocol.SeverityHigh, Title: "PDF contains JavaScript", Attack: "T1059.007"}
	ruleAuto     = protocol.Rule{ID: "GAL-PDF-002", Severity: protocol.SeverityMedium, Title: "PDF action runs automatically on open", Attack: "T1204.002"}
	ruleLaunch   = protocol.Rule{ID: "GAL-PDF-003", Severity: protocol.SeverityHigh, Title: "PDF Launch action", Attack: "T1204.002"}
	ruleEmbedded = protocol.Rule{ID: "GAL-PDF-004", Severity: protocol.SeverityMedium, Title: "PDF embeds a file", Attack: "T1027.006"}
	ruleLinks    = protocol.Rule{ID: "GAL-PDF-005", Severity: protocol.SeverityInfo, Title: "PDF contains external links", Attack: "T1566.002"}
	ruleObf      = protocol.Rule{ID: "GAL-PDF-006", Severity: protocol.SeverityMedium, Title: "PDF obfuscates names with hex escapes", Attack: "T1027"}
	ruleOpaque   = protocol.Rule{ID: "GAL-PDF-007", Severity: protocol.SeverityLow, Title: "PDF has encrypted or undecodable content"}
	ruleOrder    = []protocol.Rule{ruleJS, ruleAuto, ruleLaunch, ruleEmbedded, ruleLinks, ruleObf, ruleOpaque}
)

// actionTypes are the /S values that make an /OpenAction or /AA count.
var actionTypes = map[string]bool{"JavaScript": true, "Launch": true, "URI": true, "SubmitForm": true, "GoToR": true, "ImportData": true}

// skipRefKeys are keys whose references point at the page tree or destinations, not at actions.
var skipRefKeys = map[string]bool{"Parent": true, "P": true, "Dest": true, "D": true, "Pg": true, "Prev": true, "Kids": true}

// imageFilters decode picture data; they are normal and never reported.
var imageFilters = map[string]bool{"DCTDecode": true, "DCT": true, "JPXDecode": true, "JBIG2Decode": true, "CCITTFaxDecode": true, "CCF": true}

type analyzer struct{}

// New returns the PDF analyzer.
func New() analyze.Analyzer { return analyzer{} }

func (analyzer) Name() string { return "pdf" }

func (analyzer) Analyze(ctx context.Context, f analyze.File) (analyze.Output, error) {
	if f.Kind != ident.PDF {
		return analyze.Output{}, nil
	}
	s := &scanner{f: f, byNum: map[int]*object{}, hits: map[string]*hit{}, seenURI: map[string]bool{}}
	return s.run(ctx)
}

// object is one indirect object: where its dictionary is and what its stream holds.
type object struct {
	num      int
	hdr      int    // offset of "N G obj" in the file; evidence line
	buf      []byte // buffer holding the dictionary
	ds, de   int    // dictionary region in buf
	content  []byte // raw or decoded stream; nil without a stream
	objStm   bool
	n, first int  // /N and /First of an object stream
	skipScan bool // image or font data
}

type evidence struct {
	off  int
	snip string
}

type hit struct{ evs []evidence }

type scanner struct {
	f         analyze.File
	objs      []*object
	byNum     map[int]*object
	hits      map[string]*hit
	seenURI   map[string]bool
	iocs      []protocol.IOC
	decoded   int
	encrypted bool
	tooMany   bool
}

func (s *scanner) run(ctx context.Context) (analyze.Output, error) {
	var out analyze.Output
	s.encrypted = bytes.Contains(s.f.Data, []byte("/Encrypt"))
	if err := s.locate(ctx); err != nil {
		return out, err
	}
	if s.tooMany {
		out.Skips = append(out.Skips, protocol.Skip{Path: s.f.Path, Reason: protocol.SkipBudget})
		return out, nil
	}
	for _, o := range s.objs {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		s.scanRegion(tokenize(o.buf[o.ds:o.de]), o.hdr)
		if o.content != nil && !o.skipScan && (o.objStm || looksText(o.content)) {
			s.scanRegion(tokenize(o.content), o.hdr)
		}
	}
	s.scanTrailers()
	for _, r := range ruleOrder {
		h := s.hits[r.ID]
		if h == nil {
			continue
		}
		evs := make([]protocol.Evidence, 0, len(h.evs))
		for _, e := range h.evs {
			ev := analyze.EvidenceAt(s.f, e.off)
			if e.snip != "" {
				ev.Snippet = e.snip
			}
			evs = append(evs, ev)
		}
		out.Findings = append(out.Findings, r.Finding(evs...))
	}
	out.IOCs = s.iocs
	return out, nil
}

// add records a hit for the rule at the object header offset. A later snippet
// replaces an empty one for the same offset.
func (s *scanner) add(r protocol.Rule, off int, snip string) {
	h := s.hits[r.ID]
	if h == nil {
		h = &hit{}
		s.hits[r.ID] = h
	}
	for i := range h.evs {
		if h.evs[i].off == off {
			if h.evs[i].snip == "" {
				h.evs[i].snip = snip
			}
			return
		}
	}
	if len(h.evs) < maxEvidence {
		h.evs = append(h.evs, evidence{off: off, snip: snip})
	}
}

// locate finds every "N G obj" and decodes its stream.
func (s *scanner) locate(ctx context.Context) error {
	data := s.f.Data
	pos := 0
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		i := bytes.Index(data[pos:], []byte("obj"))
		if i < 0 {
			return nil
		}
		i += pos
		num, hdr, ok := headerBefore(data, i)
		if !ok || i+3 < len(data) && isRegular(data[i+3]) {
			pos = i + 3
			continue
		}
		bodyStart := i + 3
		end := bytes.Index(data[bodyStart:], []byte("endobj"))
		if end < 0 {
			end = len(data) - bodyStart
		}
		end += bodyStart
		o := &object{num: num, hdr: hdr, buf: data, ds: bodyStart, de: end}
		next := end
		if kw := streamKeyword(data[bodyStart:end]); kw >= 0 {
			kw += bodyStart
			ss := kw + len("stream")
			if ss < len(data) && data[ss] == '\r' {
				ss++
			}
			if ss < len(data) && data[ss] == '\n' {
				ss++
			}
			se := bytes.Index(data[ss:], []byte("endstream"))
			if se < 0 {
				se = len(data) - ss
			}
			se += ss
			o.de = kw
			if e := bytes.Index(data[se:], []byte("endobj")); e >= 0 {
				next = se + e
			} else {
				next = len(data)
			}
			s.prepareStream(o, data[ss:se])
		}
		if !s.register(o) {
			return nil
		}
		if o.objStm {
			s.registerMembers(o)
		}
		pos = next
		if pos <= i {
			pos = i + 3
		}
	}
}

func (s *scanner) register(o *object) bool {
	if len(s.objs) >= MaxObjects {
		s.tooMany = true
		return false
	}
	s.objs = append(s.objs, o)
	s.byNum[o.num] = o
	return true
}

// headerBefore parses "N G " before the obj keyword at i and returns N and the offset of N.
func headerBefore(data []byte, i int) (num, hdr int, ok bool) {
	j := i
	skipSpace := func() int {
		n := 0
		for j > 0 && isSpace(data[j-1]) {
			j--
			n++
		}
		return n
	}
	skipDigits := func() (int, int) {
		end := j
		for j > 0 && data[j-1] >= '0' && data[j-1] <= '9' {
			j--
		}
		return j, end
	}
	if skipSpace() == 0 {
		return 0, 0, false
	}
	if a, b := skipDigits(); a == b {
		return 0, 0, false
	}
	if skipSpace() == 0 {
		return 0, 0, false
	}
	a, b := skipDigits()
	if a == b || b-a > 9 || a > 0 && isRegular(data[a-1]) {
		return 0, 0, false
	}
	n, _ := strconv.Atoi(string(data[a:b]))
	return n, a, true
}

// streamKeyword returns the offset of a "stream" keyword (not "endstream") followed by a line end.
func streamKeyword(b []byte) int {
	off := 0
	for {
		i := bytes.Index(b[off:], []byte("stream"))
		if i < 0 {
			return -1
		}
		i += off
		after := i + len("stream")
		if (i == 0 || b[i-1] != 'd') && after < len(b) && (b[after] == '\r' || b[after] == '\n') {
			return i
		}
		off = after
	}
}

// prepareStream reads the stream metadata from the dictionary and sets o.content.
func (s *scanner) prepareStream(o *object, raw []byte) {
	var filters []string
	var n, first int
	toks := tokenize(o.buf[o.ds:o.de])
	for i, t := range toks {
		if t.kind != tName || i+1 >= len(toks) {
			continue
		}
		nx := toks[i+1]
		switch t.val {
		case "Filter":
			if nx.kind == tName {
				filters = append(filters, nx.val)
			}
			for j := i + 2; nx.kind == tPunct && nx.val == "[" && j < len(toks) && toks[j].kind == tName; j++ {
				filters = append(filters, toks[j].val)
			}
		case "Type":
			o.objStm = o.objStm || nx.val == "ObjStm"
		case "Subtype":
			o.skipScan = o.skipScan || nx.val == "Image"
		case "Length1", "Length2", "Length3":
			o.skipScan = true
		case "N":
			n, _ = strconv.Atoi(nx.val)
		case "First":
			first, _ = strconv.Atoi(nx.val)
		}
	}
	switch {
	case len(filters) == 0:
		o.content = raw
	case s.encrypted:
		s.add(ruleOpaque, o.hdr, "")
	case len(filters) == 1 && (filters[0] == "FlateDecode" || filters[0] == "Fl"):
		o.content = s.inflate(o, raw)
	default:
		if !o.skipScan && !slicesAny(filters, imageFilters) {
			s.add(ruleOpaque, o.hdr, "unsupported stream filter "+strings.Join(filters, " "))
		}
	}
	o.n, o.first = n, first
}

func slicesAny(filters []string, set map[string]bool) bool {
	for _, f := range filters {
		if set[f] {
			return true
		}
	}
	return false
}

// inflate decodes a Flate stream within the per-stream and per-file limits.
func (s *scanner) inflate(o *object, raw []byte) []byte {
	r, err := zlib.NewReader(bytes.NewReader(raw))
	if err != nil {
		s.add(ruleOpaque, o.hdr, "undecodable Flate stream")
		return nil
	}
	defer func() { _ = r.Close() }()
	limit := min(MaxStreamBytes, MaxFileBytes-s.decoded)
	out, err := io.ReadAll(io.LimitReader(r, int64(limit)+1))
	if len(out) > limit {
		out = out[:limit]
		err = io.ErrShortBuffer
	}
	s.decoded += len(out)
	if err != nil {
		s.add(ruleOpaque, o.hdr, "undecodable Flate stream")
	}
	return out
}
