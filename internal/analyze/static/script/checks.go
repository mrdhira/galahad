package script

import (
	"bytes"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/mrdhira/galahad/internal/protocol"
)

// sinks checks the calls that run a string as code: eval, Function, a string
// timer, Python exec. The string must come from a decoder (GAL-OBF-002) or
// from the network (GAL-EXEC-001), either in the argument or in the variable
// the argument starts with. A plain variable or a response read
// (eval(body), Function(await r.text())) also counts as downloaded when a
// network call and a callback or await come shortly before it, and so does
// .then(eval).
func (s *scan) sinks(d *doc, f *found) {
	for _, off := range f.thenEval {
		if net := s.fetchedBefore(d, off, ""); net >= 0 {
			s.emit(ruleDownload, s.sinkEvidence(d, off, net))
		}
	}
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
		if !decoded && !download && !timer && dataArgRE.Match(arg) {
			if via = s.fetchedBefore(d, m[0], rootName(arg)); via >= 0 {
				download = true
			}
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
// and lookbackBudget per file, and the bytes it searched are what it is charged.
func (s *scan) assigned(d *doc, off int, id string) (decoded, download bool, via int) {
	if s.looked >= lookbackBudget {
		s.limited = true
		return false, false, -1
	}
	lo := max(0, off-lookback)
	win := d.data[lo:off]
	name := []byte(id)
	end := len(win)
	defer func() { s.looked += len(win) - end }()
	for end > 0 {
		i := bytes.LastIndex(win[:end], name)
		if i < 0 {
			end = 0
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

// dataArgRE matches an argument that is only data: a name, a member chain, a
// call with a short argument list, with an optional await.
var dataArgRE = regexp.MustCompile(`^(?:await\s+)?\(?[A-Za-z_$][\w$]*(?:\s*\.\s*[\w$]+|\s*\([^()]{0,40}\))*\)?$`)

// callbackWords show that code runs when a network call has finished.
var callbackWords = words(".then", ".on(", "await ")

// rootName returns the name that a data argument starts with: r for
// "await r.text()", body for "body".
func rootName(arg []byte) string {
	if rest, ok := bytes.CutPrefix(arg, []byte("await")); ok && len(rest) > 0 && (rest[0] == ' ' || rest[0] == '\t' || rest[0] == '\n') {
		arg = rest
	}
	return string(identRE.Find(bytes.TrimLeft(arg, "( \t\r\n")))
}

// fetchedBefore looks at the windowLines lines (at most windowBytes) before
// off for a network call and returns the offset of the last one, or -1. With a
// root name, the data must flow from the call to off: from the line of the
// network call on, the name must get its value from the response (see bound).
// Without a name (.then(eval)) the call alone counts. A name also asks for a
// callback or an await in the window, which carry the response to off.
func (s *scan) fetchedBefore(d *doc, off int, root string) int {
	n := min(off, windowBytes)
	if s.argBytes += n; s.argBytes > argBudget {
		s.limited = true
		return -1
	}
	lo, lines := off-n, 0
	for i := off; i > off-n; i-- {
		if d.data[i-1] == '\n' {
			if lines++; lines > windowLines {
				lo = i
				break
			}
		}
	}
	win := d.data[lo:off]
	if root != "" && !anyIn(win, callbackWords) {
		return -1
	}
	at := s.networkAt(d, win)
	if at < 0 || root != "" && !s.bound(d, win[bytes.LastIndexByte(win[:at], '\n')+1:], root, maxBindHops) {
		return -1
	}
	return lo + at
}

// responseReads show that a statement reads a response.
var responseReads = words("await", ".text(", ".json(", ".blob(", ".buffer(", ".arrayBuffer(", ".read(", ".data", ".body", "responseText")

// loopVarRE ends the text before a name that a for loop declares.
var loopVarRE = regexp.MustCompile(`\bfor\s*(?:await\s*)?\(\s*(?:const|let|var)\s+$`)

const (
	maxBindHops = 2   // plain assignments followed from a name to the one that gets the response
	maxBindUses = 64  // places where a name is looked at in one window
	maxBindSpan = 100 // bytes searched around a name for its parameter list or braces
	maxStmt     = 400 // bytes of a statement that are read
)

// bound reports whether the name root gets a value from the response of the
// network call that text starts at the line of. Its uses are looked at from the
// last one back. It is a parameter of a callback ("(t) =>", "t =>", "function
// (t)"), it is appended to ("body +=", "parts.push(await ...)"), it is
// assigned from an await or a response read ("const r = await ...", "d =
// res.data"), it is destructured from an await ("const { data } = await ..."),
// it is assigned from a name that is bound, up to hops assignments away, or it
// is the variable of a for loop over a network call. A name that is assigned
// from something else, such as process.argv, is not bound. The bytes searched
// are charged to the call argument budget.
func (s *scan) bound(d *doc, text []byte, root string, hops int) bool {
	if s.argBytes += len(text); s.argBytes > argBudget {
		s.limited = true
		return false
	}
	name := []byte(root)
	uses := 0
	for end := len(text); end > 0 && uses < maxBindUses; {
		i := bytes.LastIndex(text[:end], name)
		if i < 0 {
			break
		}
		end = i
		after := i + len(name)
		if i > 0 && (isWord(text[i-1]) || text[i-1] == '.') || after < len(text) && isWord(text[after]) {
			continue
		}
		uses++
		if s.binds(d, text, i, after, hops) {
			return true
		}
	}
	return false
}

// binds reports whether the use of a name at text[i:after] gives it a value
// from a response: see bound.
func (s *scan) binds(d *doc, text []byte, i, after, hops int) bool {
	rest := bytes.TrimLeft(text[after:], " \t")
	switch {
	case bytes.HasPrefix(rest, []byte("+=")), bytes.HasPrefix(rest, []byte("=>")):
		return true
	case bytes.HasPrefix(rest, []byte("=")) && !bytes.HasPrefix(rest, []byte("==")):
		stmt := statement(rest[1:])
		if anyIn(stmt, responseReads) {
			return true
		}
		other := bytes.TrimSpace(stmt)
		return hops > 0 && len(other) > 0 && len(identRE.Find(other)) == len(other) && s.bound(d, text[:i], string(other), hops-1)
	case bytes.HasPrefix(rest, []byte(".push(")), bytes.HasPrefix(rest, []byte(".concat(")):
		return anyIn(statement(rest), responseReads)
	case loopVarRE.Match(text[max(0, i-40):i]) && bytes.HasPrefix(rest, []byte("of ")):
		return s.networkAt(d, firstLine(rest)) >= 0
	}
	return inParams(text, i, after) || destructured(text, i, after)
}

// statement returns the text up to the end of the statement: a semicolon or a
// line break, at most maxStmt bytes.
func statement(b []byte) []byte {
	b = b[:min(len(b), maxStmt)]
	if k := bytes.IndexAny(b, ";\n"); k >= 0 {
		b = b[:k]
	}
	return b
}

func firstLine(b []byte) []byte {
	b = b[:min(len(b), maxStmt)]
	if k := bytes.IndexByte(b, '\n'); k >= 0 {
		b = b[:k]
	}
	return b
}

// around finds the bracket open that comes before text[i] and the bracket close that
// comes after text[after], with no other bracket of those two kinds between.
func around(text []byte, i, after int, open, closing byte) (lo, hi int, ok bool) {
	lo = -1
	for j := i - 1; j >= 0 && i-j <= maxBindSpan; j-- {
		if text[j] == closing {
			return 0, 0, false
		}
		if text[j] == open {
			lo = j
			break
		}
	}
	if lo < 0 {
		return 0, 0, false
	}
	for k := after; k < len(text) && k-after <= maxBindSpan; k++ {
		if text[k] == open {
			return 0, 0, false
		}
		if text[k] == closing {
			return lo, k, true
		}
	}
	return 0, 0, false
}

// inParams reports whether the name is in a parameter list: "(a, t) =>" or
// "function name(t)".
func inParams(text []byte, i, after int) bool {
	lo, hi, ok := around(text, i, after, '(', ')')
	if !ok {
		return false
	}
	if bytes.HasPrefix(bytes.TrimLeft(text[hi+1:], " \t"), []byte("=>")) {
		return true
	}
	head := bytes.TrimRight(text[:lo], " \t")
	if bytes.HasSuffix(head, []byte("function")) {
		return true
	}
	for len(head) > 0 && isWord(head[len(head)-1]) {
		head = head[:len(head)-1]
	}
	return bytes.HasSuffix(bytes.TrimRight(head, " \t"), []byte("function"))
}

// destructured reports whether the name is in "{ a, t } = await".
func destructured(text []byte, i, after int) bool {
	_, hi, ok := around(text, i, after, '{', '}')
	if !ok {
		return false
	}
	tail := bytes.TrimLeft(text[hi+1:], " \t")
	if !bytes.HasPrefix(tail, []byte("=")) || bytes.HasPrefix(tail, []byte("==")) {
		return false
	}
	return bytes.HasPrefix(bytes.TrimLeft(tail[1:], " \t"), []byte("await"))
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
// bundled libraries mention credential paths and call the network far apart,
// so a pair farther apart is reported at high severity.
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
	report := func(r protocol.Rule, sec secretHit, net int) {
		line := lineKey(d.data, sec.off)
		seen[key{r.ID, line}] = true
		s.emit(r, func() []protocol.Evidence {
			evs := []protocol.Evidence{s.ev(d, sec.off, -1)}
			if lineKey(d.data, net) != line {
				evs = append(evs, s.ev(d, net, -1))
			}
			return evs
		})
	}
	var apart []secretHit // not near any network use
	for i, sec := range f.secrets {
		if i&255 == 255 && s.done() || s.full(ruleExfil) && s.full(ruleEnvNet) {
			return
		}
		r := ruleExfil
		if sec.kind == secretNamed {
			r = ruleEnvNet
		}
		if s.full(r) || seen[key{r.ID, lineKey(d.data, sec.off)}] {
			continue
		}
		if sec.name != "" && s.done() {
			return
		}
		if net, ok := pairNet(d.data, f.nets, sec, s.carriers(d, sec), false); ok {
			report(r, sec, net)
		} else if sec.kind != secretNamed {
			apart = append(apart, sec)
		}
	}
	// Pairs far apart come after all near pairs, so that they cannot use up
	// the findings of the rule before a critical pair is reported.
	for _, sec := range apart {
		if s.done() || s.full(ruleExfilFar) {
			return
		}
		if seen[key{ruleExfilFar.ID, lineKey(d.data, sec.off)}] {
			continue
		}
		if net, ok := s.farNet(d, f.nets, sec); ok {
			report(ruleExfilFar, sec, net)
		}
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

// farNet pairs a credential path with network use at any distance in the file.
// Far apart, a mention of a path is not enough: the path must be assigned to a
// variable, and the network call must use that variable or one derived from
// it. Names of fewer than minFarName characters do not count, because they
// collide with the minified names of bundled libraries.
func (s *scan) farNet(d *doc, nets []int, sec secretHit) (int, bool) {
	if sec.kind != secretFile {
		return 0, false
	}
	before := d.data[max(0, sec.off-160):sec.off]
	if bytes.IndexByte(before, '=') < 0 {
		return 0, false
	}
	if s.farTries++; s.farTries > maxFarTries {
		s.limited = true
		return 0, false
	}
	g := assignRE.FindSubmatch(before)
	if g == nil || bytes.IndexByte(g[0], '\n') >= 0 {
		return 0, false
	}
	if sec.name = string(g[1]); len(sec.name) < minFarName {
		return 0, false
	}
	names := slices.DeleteFunc(s.carriers(d, sec), func(n string) bool { return len(n) < minFarName })
	return pairNet(d.data, nets, sec, names, true)
}

// carriers returns the variables that hold a copy of the environment: the one
// it is assigned to and the ones assigned from that, in the next maxFar bytes.
// A variable counts when the right side uses it as a whole, not one property
// and not as a function that is called.
// A hit that is not a copy has none. The search is bounded: a window is charged
// to the budget, a name is looked at in at most maxCarrierUses places, and
// the regular expression runs at most maxCarrierRuns times per file. When one
// of them runs out the result says so with s.limited.
func (s *scan) carriers(d *doc, sec secretHit) []string {
	if sec.name == "" {
		return nil
	}
	names := []string{sec.name}
	win := d.data[sec.off:min(len(d.data), sec.off+maxFar)]
	if s.argBytes += len(win); s.argBytes > argBudget {
		s.limited = true
		return names
	}
	for i := 0; i < len(names) && len(names) < maxCarriers; i++ {
		uses := 0
		for from := 0; ; {
			k := bytes.Index(win[from:], []byte(names[i]))
			if k < 0 {
				break
			}
			at := from + k
			from = at + 1
			end := at + len(names[i])
			if at > 0 && (isWord(win[at-1]) || win[at-1] == '.') || end < len(win) && (isWord(win[end]) || win[end] == '.' || win[end] == '[' || win[end] == '(') {
				continue
			}
			if uses++; uses > maxCarrierUses || s.carrierRuns >= maxCarrierRuns {
				s.limited = true
				break
			}
			lo := max(0, at-160)
			if !assignsBefore(win[lo:at]) {
				continue
			}
			s.carrierRuns++
			s.argBytes += at - lo
			g := assignRE.FindSubmatch(win[lo:at])
			if g == nil || bytes.IndexByte(g[0], '\n') >= 0 || slices.Contains(names, string(g[1])) {
				continue
			}
			if names = append(names, string(g[1])); len(names) == maxCarriers {
				break
			}
		}
	}
	return names
}

// assignsBefore reports whether an equals sign comes between the start of the
// statement (a semicolon or a line break) and the end of text.
func assignsBefore(text []byte) bool {
	for i := len(text) - 1; i >= 0; i-- {
		switch text[i] {
		case '=':
			return true
		case ';', '\n':
			return false
		}
	}
	return false
}

// pairNet picks the network use for a secret. Named variables pair with the
// nearest one. Other secrets pair with the nearest one that is near enough,
// or with any when far is set, and, for a copy of the environment in
// variables, that sends one of them (see sends).
func pairNet(data []byte, nets []int, sec secretHit, names []string, far bool) (int, bool) {
	if sec.kind == secretNamed {
		return nearest(nets, sec.off), true
	}
	uses := usesAny
	if sec.kind == secretDump {
		uses = sendsAny
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
		if !far && !near(data, sec.off, net) {
			return 0, false
		}
		if names == nil || uses(data[net:min(len(data), net+400)], names) {
			return net, true
		}
	}
	return 0, false
}

func usesAny(text []byte, names []string) bool {
	for _, n := range names {
		if usesName(text, n) {
			return true
		}
	}
	return false
}

// sendsAny reports whether text sends one of the copies of the environment.
func sendsAny(text []byte, names []string) bool {
	for _, n := range names {
		if sends(text, n) {
			return true
		}
	}
	return false
}

// notSentRE ends the text before a copy of the environment that is not sent:
// the env or proxies option of a call, and the restore of the environment.
var notSentRE = regexp.MustCompile(`(?:\b(?:env|proxies|proxy)\s*[:=]\s*(?:\{\s*\*\*\s*)?|\benviron\s*\.\s*update\(\s*|\bprocess\.env\s*,\s*)$`)

// sends reports whether text has the copy of the environment name as a whole
// word, and uses it as a whole: not as the target of an assignment or a keyword
// ("old_env = ...", "data=..."), not to read one value (see readsOne),
// not as the environment of a child process or the proxies of a request, and
// not to restore the environment.
func sends(text []byte, name string) bool {
	for from := 0; ; {
		i := bytes.Index(text[from:], []byte(name))
		if i < 0 {
			return false
		}
		i += from
		from = i + 1
		end := i + len(name)
		if i > 0 && isWord(text[i-1]) || end < len(text) && isWord(text[end]) {
			continue
		}
		after := bytes.TrimLeft(text[end:min(len(text), end+32)], " \t")
		if len(after) > 0 && after[0] == '=' && !bytes.HasPrefix(after, []byte("==")) || readsOne(after) || notSentRE.Match(text[max(0, i-40):i]) {
			continue
		}
		return true
	}
}

// readsOne reports whether the text after a copy of the environment reads one
// value from it: an index, .get( .pop( .setdefault(, or a property. Any other
// method call, such as .encode() or .toString(), uses the copy as a whole.
func readsOne(after []byte) bool {
	if len(after) == 0 {
		return false
	}
	if after[0] == '[' {
		return true
	}
	if after[0] != '.' {
		return false
	}
	member := bytes.TrimLeft(after[1:], " \t")
	n := 0
	for n < len(member) && isWord(member[n]) {
		n++
	}
	switch string(member[:n]) {
	case "get", "pop", "setdefault":
		return true
	}
	return !bytes.HasPrefix(bytes.TrimLeft(member[n:], " \t"), []byte("("))
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
