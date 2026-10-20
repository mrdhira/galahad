package script

import (
	"bytes"
	"slices"
	"sort"
	"strings"

	"github.com/mrdhira/galahad/internal/protocol"
)

// sinks checks the calls that run a string as code: eval, Function, a string
// timer, Python exec. The string must come from a decoder (GAL-OBF-002) or
// from the network (GAL-EXEC-001), either in the argument or in the variable
// the argument starts with.
func (s *scan) sinks(d *doc, f *found) {
	for i, m := range f.sinks {
		if i&255 == 255 && s.done() || s.full(ruleDecoded) && s.full(ruleDownload) {
			return
		}
		open := m[1] - 1
		timer := bytes.HasPrefix(d.data[m[0]:], []byte("set"))
		raw, read := argAt(d.data, open, timer)
		if s.argBytes += read + 1; s.argBytes > argBudget {
			s.limited = true
			return
		}
		arg := bytes.TrimSpace(raw)
		if len(arg) == 0 || isLiteral(arg) {
			continue
		}
		if timer && (bytes.HasPrefix(arg, []byte("function")) || bytes.HasPrefix(arg, []byte("async")) || bytes.Contains(arg, []byte("=>"))) {
			continue
		}
		decoded, download := s.decodes(d, arg), s.network(d, arg)
		via := -1
		if id := identRE.Find(arg); id != nil && !decoded && !download && (len(arg) == len(id) || arg[len(id)] != '(') {
			decoded, download, via = s.assigned(d, m[0], string(id))
		}
		if decoded {
			s.emit(ruleDecoded, s.sinkEvidence(d, m[0], via))
		}
		if download {
			s.emit(ruleDownload, s.sinkEvidence(d, m[0], via))
		}
	}
}

func (s *scan) sinkEvidence(d *doc, off, via int) func() []protocol.Evidence {
	return func() []protocol.Evidence {
		evs := []protocol.Evidence{s.ev(d, off, -1)}
		if via >= 0 {
			if e := s.ev(d, via, -1); e.Line != evs[0].Line {
				evs = append(evs, e)
			}
		}
		return evs
	}
}

// assigned looks back from the call at off for the last assignment "id = ..."
// and reports whether its right side decodes or downloads. It returns the
// offset of the assignment. The search reads at most lookback bytes per call
// and lookbackBudget per file.
func (s *scan) assigned(d *doc, off int, id string) (decoded, download bool, via int) {
	lo := max(0, off-lookback)
	if s.looked+off-lo > lookbackBudget {
		return false, false, -1
	}
	s.looked += off - lo
	win := d.data[lo:off]
	name := []byte(id)
	for end := len(win); end > 0; {
		i := bytes.LastIndex(win[:end], name)
		if i < 0 {
			break
		}
		end = i
		after := i + len(name)
		if i > 0 && isWord(win[i-1]) || after < len(win) && isWord(win[after]) {
			continue
		}
		for after < len(win) && (win[after] == ' ' || win[after] == '\t') {
			after++
		}
		if after+1 >= len(win) || win[after] != '=' || win[after+1] == '=' || win[after+1] == '>' {
			continue
		}
		rhs := win[after+1 : min(len(win), after+1+maxRHS)]
		if k := bytes.IndexAny(rhs, ";\n"); k >= 0 {
			rhs = rhs[:k]
		}
		return s.decodes(d, rhs), s.network(d, rhs), lo + i
	}
	return false, false, -1
}

// maxString is the longest string literal that argAt skips over.
const maxString = 8 << 20

// argAt returns the text of the call whose "(" is at data[open]: up to the
// matching ")" or, with first set, to the first top-level comma. The content
// of long string literals is left out (” stands for it), so that a decoder
// after a big blob is still seen. At most maxArg bytes of code are kept. It
// also returns the number of bytes read.
func argAt(data []byte, open int, first bool) (arg []byte, read int) {
	depth := 0
	i := open + 1
	for i < len(data) && len(arg) < maxArg {
		c := data[i]
		switch c {
		case '"', '\'', '`':
			end := stringEnd(data, i)
			if end < 0 {
				return append(arg, data[i:min(len(data), i+maxArg)]...), min(len(data), i+maxString) - open
			}
			body := data[i+1 : end]
			if len(body) > 64 && (c != '`' || !bytes.Contains(body, []byte("${"))) {
				arg = append(arg, c, c)
			} else {
				arg = append(arg, data[i:end+1]...)
			}
			i = end + 1
			continue
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth == 0 {
				return arg, i - open
			}
			depth--
		case ',':
			if first && depth == 0 {
				return arg, i - open
			}
		}
		arg = append(arg, c)
		i++
	}
	return arg, i - open
}

// stringEnd returns the offset of the quote that closes the string literal
// opened at data[open], or -1 if there is none within maxString bytes.
func stringEnd(data []byte, open int) int {
	set := string([]byte{data[open], '\\'})
	limit := min(len(data), open+maxString)
	for j := open + 1; j < limit; {
		k := bytes.IndexAny(data[j:limit], set)
		if k < 0 {
			return -1
		}
		j += k
		if data[j] != '\\' {
			return j
		}
		j += 2
	}
	return -1
}

// isLiteral reports whether arg is one plain string literal, which is code
// written out and not data decoded at run time.
func isLiteral(arg []byte) bool {
	i := 0
	for i < len(arg) && i < 2 && strings.IndexByte("bBrRuUfF", arg[i]) >= 0 {
		i++
	}
	if i >= len(arg) || strings.IndexByte("\"'`", arg[i]) < 0 {
		return false
	}
	quote := arg[i]
	for j := i + 1; j < len(arg); j++ {
		switch {
		case arg[j] == '\\':
			j++
		case quote == '`' && arg[j] == '$' && j+1 < len(arg) && arg[j+1] == '{':
			return false
		case arg[j] == quote:
			return j == len(arg)-1
		}
	}
	return false
}

// shell reports shell commands inside the code: download and run (GAL-EXEC-001),
// decode and run (GAL-OBF-002) and process starts (GAL-EXEC-002).
func (s *scan) shell(d *doc, f *found) {
	for _, off := range f.dl {
		s.add(d, ruleDownload, off)
	}
	for _, off := range f.dec {
		s.add(d, ruleDecoded, off)
	}
	for _, off := range f.spawns {
		s.add(d, ruleSpawn, off)
	}
}

// exfil pairs secret material with network use. The evidence is the secret line
// and the nearest network line. A secret-named variable (GAL-EXFIL-002) is a
// weak signal on its own, because calling an API with a key is normal, so it
// pairs with network use anywhere in the file. A .env read, a credential path
// or an environment dump (GAL-EXFIL-001) is critical, so it pairs only with
// network use within maxPairLines lines and maxFar bytes. Help texts and
// bundled libraries mention credential paths and call the network far apart.
func (s *scan) exfil(d *doc, f *found) {
	if len(f.nets) == 0 {
		return
	}
	slices.Sort(f.nets)
	slices.SortFunc(f.secrets, func(a, b secretHit) int { return a.off - b.off })
	type key struct {
		rule string
		line int
	}
	seen := map[key]bool{}
	for i, sec := range f.secrets {
		if i&255 == 255 && s.done() || s.full(ruleExfil) && s.full(ruleEnvNet) {
			return
		}
		r := ruleExfil
		if sec.kind == secretNamed {
			r = ruleEnvNet
		}
		if s.full(r) {
			continue
		}
		line := lineKey(d.data, sec.off)
		net, ok := pairNet(d.data, f.nets, sec)
		if seen[key{r.ID, line}] || !ok {
			continue
		}
		seen[key{r.ID, line}] = true
		s.emit(r, func() []protocol.Evidence {
			evs := []protocol.Evidence{s.ev(d, sec.off, -1)}
			if lineKey(d.data, net) != line {
				evs = append(evs, s.ev(d, net, -1))
			}
			return evs
		})
	}
}

// lineKey identifies the line that holds off: the offset of its start, or for
// a line longer than commentBack the start of the 4 KiB block that holds off.
func lineKey(data []byte, off int) int {
	lo := max(0, off-commentBack)
	if i := bytes.LastIndexByte(data[lo:off], '\n'); i >= 0 {
		return lo + i + 1
	}
	if lo == 0 {
		return 0
	}
	return off - off%commentBack
}

// near reports whether two offsets are at most maxPairLines lines and maxFar bytes apart.
func near(data []byte, a, b int) bool {
	a, b = min(a, b), max(a, b)
	return b-a <= maxFar && bytes.Count(data[a:b], []byte{'\n'}) <= maxPairLines
}

// pairNet picks the network use for a secret. Named variables pair with the
// nearest one. Other secrets pair with the nearest one that is near enough
// and, for a copy of the environment in a variable, that uses the variable.
func pairNet(data []byte, nets []int, sec secretHit) (int, bool) {
	if sec.kind == secretNamed {
		return nearest(nets, sec.off), true
	}
	i := sort.SearchInts(nets, sec.off)
	for lo, hi := i-1, i; (lo >= 0 || hi < len(nets)) && i-lo < 16 && hi-i < 16; {
		var net int
		if hi >= len(nets) || lo >= 0 && sec.off-nets[lo] <= nets[hi]-sec.off {
			net = nets[lo]
			lo--
		} else {
			net = nets[hi]
			hi++
		}
		if !near(data, sec.off, net) {
			return 0, false
		}
		if sec.name == "" || usesName(data[net:min(len(data), net+400)], sec.name) {
			return net, true
		}
	}
	return 0, false
}

// usesName reports whether text has name as a whole word.
func usesName(text []byte, name string) bool {
	for from := 0; ; {
		i := bytes.Index(text[from:], []byte(name))
		if i < 0 {
			return false
		}
		i += from
		end := i + len(name)
		if (i == 0 || !isWord(text[i-1])) && (end == len(text) || !isWord(text[end])) {
			return true
		}
		from = i + 1
	}
}

// nearest returns the element of the sorted, non-empty list closest to off.
func nearest(sorted []int, off int) int {
	i := sort.SearchInts(sorted, off)
	if i == len(sorted) || i > 0 && off-sorted[i-1] < sorted[i]-off {
		i--
	}
	return sorted[i]
}
