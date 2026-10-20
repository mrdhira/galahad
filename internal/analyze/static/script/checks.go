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
		raw := argAt(d.data, open, timer)
		if s.argBytes += len(raw) + 1; s.argBytes > argBudget {
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
		decoded, download := hasDecoder(arg), hasNetwork(arg)
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
		return hasDecoder(rhs), hasNetwork(rhs), lo + i
	}
	return false, false, -1
}

// argAt returns the text of the call whose "(" is at data[open]: up to the
// matching ")" or, with first set, to the first top-level comma. It reads at
// most maxArg bytes and skips over string literals.
func argAt(data []byte, open int, first bool) []byte {
	end := min(len(data), open+1+maxArg)
	depth := 0
	var quote byte
	for i := open + 1; i < end; i++ {
		c := data[i]
		if quote != 0 {
			switch c {
			case '\\':
				i++
			case quote:
				quote = 0
			}
			continue
		}
		switch c {
		case '"', '\'', '`':
			quote = c
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth == 0 {
				return data[open+1 : i]
			}
			depth--
		case ',':
			if first && depth == 0 {
				return data[open+1 : i]
			}
		}
	}
	return data[open+1 : end]
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
		net := nearest(f.nets, sec.off)
		if seen[key{r.ID, line}] || sec.kind != secretNamed && !near(d.data, sec.off, net) {
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

// nearest returns the element of the sorted, non-empty list closest to off.
func nearest(sorted []int, off int) int {
	i := sort.SearchInts(sorted, off)
	if i == len(sorted) || i > 0 && off-sorted[i-1] < sorted[i]-off {
		i--
	}
	return sorted[i]
}
