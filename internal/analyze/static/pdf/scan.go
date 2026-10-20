package pdf

import (
	"bytes"
	"strings"
	"unicode/utf8"

	"github.com/mrdhira/galahad/internal/protocol"
)

// scanTrailers reads the trailer dictionaries, which sit outside any object.
func (s *scanner) scanTrailers() error {
	data := s.f.Data
	pos := 0
	for n := 0; n < 1000; n++ {
		i := bytes.Index(data[pos:], []byte("trailer"))
		if i < 0 {
			return nil
		}
		i += pos
		end := min(len(data), i+4096)
		if e := bytes.Index(data[i:end], []byte("startxref")); e >= 0 {
			end = i + e
		}
		if err := s.scanRegion(s.tok(data[i+len("trailer"):end]), i); err != nil {
			return err
		}
		pos = i + len("trailer")
	}
	return nil
}

// scanRegion looks at the names and strings of one dictionary or decoded stream.
// off is the offset of the containing object header in the file.
func (s *scanner) scanRegion(toks []token, off int) error {
	for i, t := range toks {
		if i&1023 == 0 {
			if err := s.ctx.Err(); err != nil {
				return err
			}
		}
		if t.kind != tName {
			continue
		}
		if t.obf {
			s.add(ruleObf, off, "")
		}
		next := token{}
		if i+1 < len(toks) {
			next = toks[i+1]
		}
		switch t.val {
		case "JS":
			s.add(ruleJS, off, s.jsSnippet(toks, i+1))
		case "S":
			switch {
			case next.kind == tName && next.val == "JavaScript":
				s.add(ruleJS, off, "")
			case next.kind == tName && next.val == "Launch":
				s.add(ruleLaunch, off, "")
			}
		case "URI":
			if uri, ok := s.stringAt(toks, i+1); ok {
				s.addURI(uri, off)
			}
		case "OpenAction", "AA":
			if s.targetsAction(toks, i+1) {
				s.add(ruleAuto, off, "")
			}
		case "EmbeddedFile", "EmbeddedFiles":
			s.add(ruleEmbedded, off, "")
		case "Encrypt":
			s.encrypted = true
			s.add(ruleOpaque, off, "encrypted document")
		}
	}
	return nil
}

// stringAt returns the string value at toks[i]: a literal or hex string, or a
// reference to an object that holds one.
func (s *scanner) stringAt(toks []token, i int) (string, bool) {
	if i >= len(toks) {
		return "", false
	}
	if toks[i].kind == tStr || toks[i].kind == tHex {
		return toks[i].val, true
	}
	n, ok := refAt(toks, i)
	if !ok {
		return "", false
	}
	o := s.byNum[n]
	if o == nil {
		return "", false
	}
	first, _ := tokenize(o.buf[o.ds:o.de], 1)
	if len(first) == 1 && (first[0].kind == tStr || first[0].kind == tHex) {
		return first[0].val, true
	}
	return "", false
}

// jsSnippet returns the start of the JavaScript that /JS at toks[i-1] points to, cleaned to one line.
func (s *scanner) jsSnippet(toks []token, i int) string {
	text, ok := s.stringAt(toks, i)
	if !ok {
		if n, isRef := refAt(toks, i); isRef {
			if o := s.byNum[n]; o != nil && o.content != nil {
				text = string(o.content[:min(len(o.content), maxSnippetRaw)])
			}
		}
	}
	if len(text) > maxSnippetRaw {
		text = text[:maxSnippetRaw]
	}
	return protocol.Snippet(strings.Join(strings.Fields(text), " "))
}

func (s *scanner) addURI(uri string, off int) {
	uri = strings.TrimSpace(uri)
	if len(uri) == 0 || len(uri) > MaxURILen || s.seenURI[uri] {
		return
	}
	for i := 0; i < len(uri); i++ {
		if uri[i] <= 0x20 || uri[i] >= 0x7f {
			return
		}
	}
	colon := strings.IndexByte(uri, ':')
	if colon < 1 || !isScheme(uri[:colon]) {
		return
	}
	s.seenURI[uri] = true
	typ, val := "url", uri
	if strings.EqualFold(uri[:colon], "mailto") {
		typ, val = "email", uri[colon+1:]
		if q := strings.IndexByte(val, '?'); q >= 0 {
			val = val[:q]
		}
		if val == "" {
			return
		}
	}
	s.add(ruleLinks, off, "")
	s.iocs = append(s.iocs, protocol.IOC{Type: typ, Value: val, Path: s.f.Path, Line: s.evidenceLine(off)})
}

func isScheme(x string) bool {
	for i := 0; i < len(x); i++ {
		c := x[i]
		alpha := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
		other := c >= '0' && c <= '9' || c == '+' || c == '-' || c == '.'
		if !alpha && (i == 0 || !other) {
			return false
		}
	}
	return true
}

// targetsAction reports whether the value that starts at toks[j] is an action.
// A destination array is not.
func (s *scanner) targetsAction(toks []token, j int) bool {
	if j >= len(toks) {
		return false
	}
	if toks[j].kind == tPunct && toks[j].val == "<<" {
		level := 0
		end := min(len(toks), j+maxInlineToks)
		for k := j; k < end; k++ {
			if toks[k].kind != tPunct {
				continue
			}
			switch toks[k].val {
			case "<<":
				level++
			case ">>":
				level--
			}
			if level == 0 {
				end = k + 1
				break
			}
		}
		return s.holdsAction(toks[j:end])
	}
	if n, ok := refAt(toks, j); ok {
		return s.objectIsAction(n)
	}
	return false
}

// holdsAction reports whether the tokens hold "/S /<action>" or a reference to an action.
func (s *scanner) holdsAction(toks []token) bool {
	for i, t := range toks {
		if t.kind == tName && t.val == "S" && i+1 < len(toks) && toks[i+1].kind == tName && actionTypes[toks[i+1].val] {
			return true
		}
		if n, ok := refAt(toks, i); ok {
			if i > 0 && toks[i-1].kind == tName && skipRefKeys[toks[i-1].val] {
				continue
			}
			if s.objectIsAction(n) {
				return true
			}
		}
	}
	return false
}

// objectIsAction reports whether object num is an action or refers to one. Each
// object is examined once per file, so the work is bounded by the object count
// and the recursion depth by MaxObjects. A depth limit is deliberately absent:
// it would make a memoized "no" depend on the path that reached the object.
func (s *scanner) objectIsAction(num int) bool {
	switch s.memo[num] {
	case 1, 2:
		return false
	case 3:
		return true
	}
	o := s.byNum[num]
	if o == nil || s.ctx.Err() != nil {
		return false
	}
	s.memo[num] = 1
	toks := s.tok(o.buf[o.ds:o.de])
	isArray := len(toks) > 0 && toks[0].kind == tPunct && toks[0].val == "["
	res := !isArray && s.holdsAction(toks)
	s.memo[num] = 2
	if res {
		s.memo[num] = 3
	}
	return res
}

// looksText reports whether the start of b is mostly printable ASCII or UTF-8 text.
func looksText(b []byte) bool {
	b = b[:min(len(b), 4096)]
	if len(b) == 0 {
		return false
	}
	ok := 0
	for _, c := range b {
		if c == '\t' || c == '\n' || c == '\r' || c >= 0x20 && c < 0x7f {
			ok++
		}
	}
	return ok*10 >= len(b)*9 || utf8.Valid(b) && ok*2 >= len(b)
}
