// Package pdf is a lexical PDF scanner. It finds JavaScript, Launch actions,
// actions that run when the document opens, embedded files and URIs without
// building a document model.
//
// Streams that use FlateDecode, ASCIIHexDecode and ASCII85Decode, alone or
// chained, are decoded and scanned too, and so are object streams. Content that
// cannot be read is reported twice: as GAL-PDF-007 (low) with the object line,
// and as one coverage Skip per file, so the verdict cannot claim a full
// analysis. The Skip reason is "encrypted" for a document with an /Encrypt
// entry; "budget" when a limit left part of the file's syntax unread (more
// objects than MaxObjects, a dictionary, trailer or object stream cut by the
// token limit, an inline action dictionary longer than the examined tokens, an
// object stream that was cut by a size limit or could not be decoded), because
// a payload could sit in the part that was not read; "too_large" when only plain
// page content was cut by the token limit, which never holds actions; and
// "unsupported" when another non-image stream could not be decoded. A whole file
// over the size limit is skipped by the engine as "too_large" before this
// analyzer runs.
// Image streams are never decoded and never reported.
package pdf

import (
	"bytes"
	"compress/zlib"
	"context"
	"encoding/ascii85"
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
	maxInlineToks = 4096 // tokens examined for one inline action dictionary
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
	s := &scanner{ctx: ctx, f: f, byNum: map[int]*object{}, hits: map[string]*hit{}, seenURI: map[string]bool{}, memo: map[int]uint8{}, strs: map[int]stringVal{}, lineNo: 1}
	return s.run()
}

// object is one indirect object: where its dictionary is and what its stream holds.
type object struct {
	num      int
	hdr      int    // offset of "N G obj" in the file; evidence line of its decoded content
	buf      []byte // buffer holding the dictionary
	ds, de   int    // dictionary region in buf
	content  []byte // raw or decoded stream; nil without a stream
	rawAt    int    // file offset of content when it is the unfiltered stream; 0 otherwise
	objStm   bool
	n, first int      // /N and /First of an object stream
	members  [][2]int // member regions of an object stream inside content
	skipScan bool     // image or font data
}

// evidence is one place a rule fired: the file offset, the span of its line,
// the snippet to show instead of the line (decoded content, script text) and
// the key of the region or script object it came from.
type evidence struct {
	off        int
	start, end int
	snip       string
	key        int
}

// Evidence keys keep one hit per region (or per script object) of a rule, so a
// multi-line action does not use up the evidence slots.
const (
	keyFile   = iota // region in the file, by offset
	keyStream        // decoded content, by stream header offset
	keyObject        // script held by an object, by header offset
	keyToken         // script in an inline hex string, by offset
)

func evidenceKey(kind, off int) int { return off*4 + kind }

// region is a piece of PDF syntax to scan. at is the file offset of buf, or -1
// when buf is decoded data that is not in the file; hdr is then the offset of
// the stream object that holds it.
type region struct {
	buf     []byte
	at      int
	hdr     int
	content bool // page content or other plain stream data, not a dictionary or object stream
}

// key returns the evidence key of the region.
func (r region) key() int {
	if r.at >= 0 {
		return evidenceKey(keyFile, r.at)
	}
	return evidenceKey(keyStream, r.hdr)
}

// where returns the file offset and the snippet override for the token at
// buf[off]. Tokens in the file point at their own line. Decoded tokens point
// at the stream header and show the decoded text that follows the token.
func (r region) where(off int) (int, string) {
	if r.at >= 0 {
		return r.at + off, ""
	}
	text := string(r.buf[off:min(len(r.buf), off+maxSnippetRaw)])
	return r.hdr, protocol.Snippet("decoded: " + strings.Join(strings.Fields(text), " "))
}

type hit struct{ evs []evidence }

// stringVal is the cached result of stringAt for one object.
type stringVal struct {
	val string
	ok  bool
}

type scanner struct {
	ctx       context.Context
	f         analyze.File
	objs      []*object
	byNum     map[int]*object
	hits      map[string]*hit
	seenURI   map[string]bool
	memo      map[int]uint8 // objectIsAction results: 1 running, 2 no, 3 yes
	strs      map[int]stringVal
	iocs      []protocol.IOC
	decoded   int
	lineOff   int // lineAt cursor: offset in the file and its line number
	lineNo    int
	encrypted bool
	undecoded bool
	truncated bool // the token limit cut a dictionary, trailer or object stream: budget
	cutPlain  bool // the token limit cut plain stream content: too_large
	tooMany   bool
}

// tok tokenizes b and remembers that the token limit was hit.
func (s *scanner) tok(b []byte) []token {
	toks, cut := tokenize(b, maxTokens)
	s.truncated = s.truncated || cut
	return toks
}

func (s *scanner) run() (analyze.Output, error) {
	var out analyze.Output
	if err := s.locate(); err != nil {
		return out, err
	}
	for _, o := range s.objs {
		if err := s.scanObject(o); err != nil {
			return out, err
		}
	}
	if err := s.scanTrailers(); err != nil {
		return out, err
	}
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
	if s.tooMany || s.truncated {
		out.Skips = append(out.Skips, protocol.Skip{Path: s.f.Path, Reason: protocol.SkipBudget})
	} else if s.cutPlain {
		out.Skips = append(out.Skips, protocol.Skip{Path: s.f.Path, Reason: protocol.SkipTooLarge})
	}
	if s.encrypted {
		out.Skips = append(out.Skips, protocol.Skip{Path: s.f.Path, Reason: protocol.SkipEncrypted})
	} else if s.undecoded {
		out.Skips = append(out.Skips, protocol.Skip{Path: s.f.Path, Reason: protocol.SkipUnsupported})
	}
	return out, nil
}

// scanObject scans the dictionary and the stream content of one object.
func (s *scanner) scanObject(o *object) error {
	if err := s.scanRegion(region{buf: o.buf[o.ds:o.de], at: o.ds, hdr: o.hdr}); err != nil {
		return err
	}
	if o.content == nil || o.skipScan {
		return nil
	}
	at := -1
	if o.rawAt > 0 {
		at = o.rawAt
	}
	if len(o.members) > 0 {
		for _, m := range o.members {
			r := region{buf: o.content[m[0]:m[1]], at: at, hdr: o.hdr}
			if at >= 0 {
				r.at += m[0]
			}
			if err := s.scanRegion(r); err != nil {
				return err
			}
		}
		return nil
	}
	if o.objStm || looksText(o.content) {
		return s.scanRegion(region{buf: o.content, at: at, hdr: o.hdr, content: !o.objStm})
	}
	return nil
}

// full reports whether the rule already has all the evidence it keeps.
func (s *scanner) full(r protocol.Rule) bool {
	h := s.hits[r.ID]
	return h != nil && len(h.evs) >= maxEvidence
}

// hasKey reports whether the rule already has a hit with the evidence key.
func (s *scanner) hasKey(r protocol.Rule, key int) bool {
	h := s.hits[r.ID]
	if h == nil {
		return false
	}
	for _, e := range h.evs {
		if e.key == key {
			return true
		}
	}
	return false
}

// add records a hit for the rule at the token buf[off] of the region.
func (s *scanner) add(r protocol.Rule, reg region, off int) {
	if s.full(r) {
		return
	}
	at, snip := reg.where(off)
	s.addAt(r, at, snip, reg.key())
}

// addAt records a hit for the rule at a file offset. A hit is not repeated when
// the rule already has one with the same key, or when both show the same line.
func (s *scanner) addAt(r protocol.Rule, off int, snip string, key int) {
	if s.full(r) {
		return
	}
	h := s.hits[r.ID]
	if h == nil {
		h = &hit{}
		s.hits[r.ID] = h
	}
	for _, e := range h.evs {
		if key == e.key || snip == "" && e.snip == "" && off >= e.start && off < e.end {
			return
		}
	}
	data := s.f.Data
	off = min(off, len(data))
	start := bytes.LastIndexByte(data[:off], '\n') + 1
	end := len(data)
	if i := bytes.IndexByte(data[off:], '\n'); i >= 0 {
		end = off + i
	}
	h.evs = append(h.evs, evidence{off: off, start: start, end: end + 1, snip: snip, key: key})
}

// locate finds every "N G obj" and decodes its stream.
func (s *scanner) locate() error {
	data := s.f.Data
	pos := 0
	for {
		if err := s.ctx.Err(); err != nil {
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
		o := &object{num: num, hdr: hdr, buf: data, ds: bodyStart}
		kw, at := nextKeyword(data, bodyStart)
		next := at
		switch kw {
		case "endobj":
			o.de = at
			next = at + len("endobj")
		case "stream":
			o.de = at
			ss := at + len("stream")
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
			s.prepareStream(o, data[ss:se], ss)
			kw2, at2 := nextKeyword(data, min(len(data), se+len("endstream")))
			next = at2
			if kw2 == "endobj" {
				next = at2 + len("endobj")
			}
		default:
			o.de = at
		}
		if len(s.objs) >= MaxObjects {
			s.tooMany = true
			return nil
		}
		s.objs = append(s.objs, o)
		s.byNum[o.num] = o
		if o.objStm {
			if err := s.registerMembers(o); err != nil {
				return err
			}
		}
		pos = max(next, i+3)
	}
}

// nextKeyword walks data from pos like the tokenizer, skipping strings,
// comments and hex strings, and returns the next "endobj" or "stream" keyword
// (a stream keyword must end its line) or the header of the next object, with
// its offset. At the end of the data it returns "" and len(data).
func nextKeyword(data []byte, pos int) (string, int) {
	i := pos
	for i < len(data) {
		c := data[i]
		switch {
		case c == '(':
			i = skipString(data, i)
		case c == '%':
			for i < len(data) && data[i] != '\n' && data[i] != '\r' {
				i++
			}
		case c == '<' && i+1 < len(data) && data[i+1] != '<':
			e := bytes.IndexByte(data[i:], '>')
			if e < 0 {
				return "", len(data)
			}
			i += e + 1
		case isRegular(c):
			j := i
			for j < len(data) && isRegular(data[j]) {
				j++
			}
			switch string(data[i:j]) {
			case "endobj":
				return "endobj", i
			case "stream":
				if j < len(data) && (data[j] == '\r' || data[j] == '\n') {
					return "stream", i
				}
			case "obj":
				if _, hdr, ok := headerBefore(data, j-len("obj")); ok && hdr >= pos {
					return "obj", hdr
				}
			}
			i = j
		default:
			i++
		}
	}
	return "", len(data)
}

// skipString returns the offset after the literal string that starts at data[i].
func skipString(data []byte, i int) int {
	depth := 0
	for i < len(data) {
		switch data[i] {
		case '\\':
			i++
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i + 1
			}
		}
		i++
	}
	return len(data)
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

// prepareStream reads the stream metadata from the dictionary and sets o.content.
func (s *scanner) prepareStream(o *object, raw []byte, rawAt int) {
	var filters []string
	toks := s.tok(o.buf[o.ds:o.de])
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
			o.n, _ = strconv.Atoi(nx.val)
		case "First":
			o.first, _ = strconv.Atoi(nx.val)
		}
	}
	if o.objStm {
		o.skipScan = false
	}
	if len(filters) == 0 {
		o.content = raw
		o.rawAt = rawAt
		return
	}
	if o.skipScan || slicesAny(filters, imageFilters) {
		o.skipScan = true
		return
	}
	data := raw
	for _, f := range filters {
		out, err := s.decode(f, data)
		data = out
		if err != "" {
			s.addAt(ruleOpaque, o.hdr, err, evidenceKey(keyStream, o.hdr))
			s.undecoded = true
			s.truncated = s.truncated || o.objStm // its members stay unread
			break
		}
	}
	o.content = data
}

func slicesAny(filters []string, set map[string]bool) bool {
	for _, f := range filters {
		if set[f] {
			return true
		}
	}
	return false
}

// decode applies one filter within the per-stream and per-file limits. It returns
// the bytes it got and, when it could not decode everything, a reason.
func (s *scanner) decode(filter string, in []byte) ([]byte, string) {
	limit := min(MaxStreamBytes, MaxFileBytes-s.decoded)
	var r io.Reader
	switch filter {
	case "FlateDecode", "Fl":
		zr, err := zlib.NewReader(bytes.NewReader(in))
		if err != nil {
			return nil, "undecodable Flate stream"
		}
		defer func() { _ = zr.Close() }()
		r = zr
	case "ASCIIHexDecode", "AHx":
		out, over := decodeHexFilter(in, limit)
		s.decoded += len(out)
		if over {
			return out, "ASCIIHexDecode stream over the size limit"
		}
		return out, ""
	case "ASCII85Decode", "A85":
		in = bytes.TrimSpace(in)
		in = bytes.TrimPrefix(in, []byte("<~"))
		if e := bytes.Index(in, []byte("~>")); e >= 0 {
			in = in[:e]
		}
		r = ascii85.NewDecoder(bytes.NewReader(in))
	default:
		return nil, "unsupported stream filter " + filter
	}
	out, err := io.ReadAll(io.LimitReader(r, int64(limit)+1))
	if len(out) > limit {
		out = out[:limit]
		err = io.ErrShortBuffer
	}
	s.decoded += len(out)
	if err != nil {
		return out, "undecodable " + filter + " stream"
	}
	return out, ""
}

// decodeHexFilter decodes ASCIIHexDecode data up to limit bytes.
func decodeHexFilter(in []byte, limit int) ([]byte, bool) {
	if e := bytes.IndexByte(in, '>'); e >= 0 {
		in = in[:e]
	}
	out := decodeHex(in, limit+1)
	if len(out) > limit {
		return out[:limit], true
	}
	return out, false
}

// registerMembers makes the objects inside a decoded object stream resolvable
// and records their regions, which are scanned one by one.
func (s *scanner) registerMembers(o *object) error {
	if o.content == nil || o.first <= 0 || o.first > len(o.content) {
		return nil
	}
	head := s.tok(o.content[:o.first])
	type member struct{ num, off int }
	var ms []member
	for i := 0; i+1 < len(head) && len(ms) < o.n; i += 2 {
		if len(s.byNum)+len(ms) >= 2*MaxObjects {
			s.tooMany = true
			break
		}
		num, err1 := strconv.Atoi(head[i].val)
		off, err2 := strconv.Atoi(head[i+1].val)
		if err1 != nil || err2 != nil || off < 0 {
			break
		}
		ms = append(ms, member{num, off})
	}
	for i, m := range ms {
		if i&1023 == 0 {
			if err := s.ctx.Err(); err != nil {
				return err
			}
		}
		ds := o.first + m.off
		de := len(o.content)
		if i+1 < len(ms) {
			de = min(de, o.first+ms[i+1].off)
		}
		if ds > de {
			continue
		}
		o.members = append(o.members, [2]int{ds, de})
		s.byNum[m.num] = &object{num: m.num, hdr: o.hdr, buf: o.content, ds: ds, de: de}
	}
	return nil
}

// lineAt returns the line of a file offset. It counts from the line of the
// previous call, so scanning in file order costs one pass over the file.
func (s *scanner) lineAt(off int) int {
	data := s.f.Data
	off = max(0, min(off, len(data)))
	if off >= s.lineOff {
		s.lineNo += bytes.Count(data[s.lineOff:off], []byte{'\n'})
	} else {
		s.lineNo -= bytes.Count(data[off:s.lineOff], []byte{'\n'})
	}
	s.lineOff = off
	return s.lineNo
}
