package pdf

import (
	"bytes"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/mrdhira/galahad/internal/protocol"
)

// registerMembers makes the objects inside a decoded object stream resolvable.
func (s *scanner) registerMembers(o *object) {
	if o.content == nil || o.first <= 0 || o.first > len(o.content) {
		return
	}
	head := tokenize(o.content[:o.first])
	type member struct{ num, off int }
	var ms []member
	for i := 0; i+1 < len(head) && len(ms) < o.n && len(s.objs)+len(ms) < MaxObjects; i += 2 {
		num, err1 := strconv.Atoi(head[i].val)
		off, err2 := strconv.Atoi(head[i+1].val)
		if err1 != nil || err2 != nil || off < 0 {
			break
		}
		ms = append(ms, member{num, off})
	}
	for i, m := range ms {
		ds := o.first + m.off
		de := len(o.content)
		if i+1 < len(ms) {
			de = min(de, o.first+ms[i+1].off)
		}
		if ds > de {
			continue
		}
		// Members are only looked up; scanning the whole decoded stream covers them.
		s.byNum[m.num] = &object{num: m.num, hdr: o.hdr, buf: o.content, ds: ds, de: de}
	}
}

// scanTrailers reads the trailer dictionaries, which sit outside any object.
func (s *scanner) scanTrailers() {
	data := s.f.Data
	pos := 0
	for n := 0; n < 1000; n++ {
		i := bytes.Index(data[pos:], []byte("trailer"))
		if i < 0 {
			return
		}
		i += pos
		end := min(len(data), i+4096)
		if e := bytes.Index(data[i:end], []byte("startxref")); e >= 0 {
			end = i + e
		}
		s.scanRegion(tokenize(data[i+len("trailer"):end]), i)
		pos = i + len("trailer")
	}
}

// scanRegion looks at the names and strings of one dictionary or decoded stream.
// off is the offset of the containing object header in the file.
func (s *scanner) scanRegion(toks []token, off int) {
	for i, t := range toks {
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
			if next.kind == tStr {
				s.addURI(next.val, off)
			}
		case "OpenAction", "AA":
			if s.targetsAction(toks, i+1, map[int]bool{}, 0) {
				s.add(ruleAuto, off, "")
			}
		case "EmbeddedFile", "EmbeddedFiles":
			s.add(ruleEmbedded, off, "")
		case "Encrypt":
			s.add(ruleOpaque, off, "encrypted document")
		}
	}
}

// jsSnippet returns the start of the JavaScript that /JS at toks[i-1] points to, cleaned to one line.
func (s *scanner) jsSnippet(toks []token, i int) string {
	var text string
	switch {
	case i >= len(toks):
	case toks[i].kind == tStr:
		text = toks[i].val
	default:
		if n, ok := refAt(toks, i); ok {
			if o := s.byNum[n]; o != nil {
				if o.content != nil {
					text = string(o.content[:min(len(o.content), maxSnippetRaw)])
				} else if rt := tokenize(o.buf[o.ds:o.de]); len(rt) > 0 && rt[0].kind == tStr {
					text = rt[0].val
				}
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
	ev := s.evidenceLine(off)
	s.iocs = append(s.iocs, protocol.IOC{Type: typ, Value: val, Path: s.f.Path, Line: ev})
}

func (s *scanner) evidenceLine(off int) int {
	return 1 + bytes.Count(s.f.Data[:min(off, len(s.f.Data))], []byte{'\n'})
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
func (s *scanner) targetsAction(toks []token, j int, seen map[int]bool, depth int) bool {
	if j >= len(toks) {
		return false
	}
	t := toks[j]
	switch {
	case t.kind == tPunct && t.val == "<<":
		level := 0
		for k := j; k < len(toks); k++ {
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
				return s.holdsAction(toks[j:k+1], seen, depth)
			}
		}
		return s.holdsAction(toks[j:], seen, depth)
	default:
		if n, ok := refAt(toks, j); ok {
			return s.objectIsAction(n, seen, depth)
		}
	}
	return false
}

// holdsAction reports whether the tokens hold "/S /<action>" or a reference to an action.
func (s *scanner) holdsAction(toks []token, seen map[int]bool, depth int) bool {
	for i, t := range toks {
		if t.kind == tName && t.val == "S" && i+1 < len(toks) && toks[i+1].kind == tName && actionTypes[toks[i+1].val] {
			return true
		}
		if n, ok := refAt(toks, i); ok && depth < maxRefDepth {
			if i > 0 && toks[i-1].kind == tName && skipRefKeys[toks[i-1].val] {
				continue
			}
			if s.objectIsAction(n, seen, depth+1) {
				return true
			}
		}
	}
	return false
}

func (s *scanner) objectIsAction(num int, seen map[int]bool, depth int) bool {
	o := s.byNum[num]
	if o == nil || seen[num] || depth > maxRefDepth {
		return false
	}
	seen[num] = true
	toks := tokenize(o.buf[o.ds:o.de])
	if len(toks) > 0 && toks[0].kind == tPunct && toks[0].val == "[" {
		return false
	}
	return s.holdsAction(toks, seen, depth)
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
