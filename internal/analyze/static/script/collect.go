package script

import (
	"bytes"
	"regexp"
	"slices"
	"strings"

	"github.com/mrdhira/galahad/internal/analyze/static/signals"
)

type secretKind uint8

const (
	secretNamed secretKind = iota // a secret-named variable: GAL-EXFIL-002
	secretDump                    // the whole environment: GAL-EXFIL-001 when the network use is near
	secretFile                    // a .env read or a credential path: GAL-EXFIL-001
)

type secretHit struct {
	off  int
	kind secretKind
	name string // for a copy of the environment: the variable it is assigned to
}

// found holds the byte offsets that the patterns matched in a doc.
type found struct {
	sinks    [][2]int // calls that run a string as code: [start, end) with the "(" last
	dl       []int    // shell download-and-run commands
	dec      []int    // shell decode-and-run commands
	spawns   []int    // process starts
	thenEval []int    // .then(eval) callbacks
	secrets  []secretHit
	nets     []int // network use
}

// anchor is a literal (lowercase) that every match of some pattern contains.
// ok, when set, looks at the original text around an occurrence and rejects
// the ones that cannot start a match.
type anchor struct {
	lit string
	ok  func(data []byte, i int) bool
}

var shellAnchors = []anchor{
	{"curl", nil}, {"wget", nil}, {"iwr", wordStart}, {"irm", wordStart}, {"invoke-", nil},
	{"downloadstring", nil}, {"downloadfile", nil}, {"base64 -", nil}, {"xxd", wordStart},
	{"powershell", nil}, {"pwsh", nil}, {"frombase64string", nil}, {"bitsadmin", nil},
	{"start-bitstransfer", nil}, {"netcat", nil}, {"ncat", wordStart}, {"socat", nil},
	{"telnet", nil}, {"sftp", wordStart}, {"/dev/tcp/", nil}, {"webclient", nil},
	{"nc ", wordStart}, {"scp ", wordStart}, {"ftp ", wordStart},
}

var secretAnchors = []anchor{
	{"process.env", sensitiveEnv}, {"os.environ", nil}, {"os.getenv", nil}, {"getenv(", nil},
	{"env[", func(data []byte, i int) bool { return bytes.HasPrefix(data[i:], []byte("ENV[")) }},
	{"$", dollarName}, {"$env:", nil}, {".env", dotEnvFile},
	{"printenv", wordStart}, {"env |", wordStart}, {"env|", wordStart},
	{"/proc/self/environ", nil}, {".ssh", nil}, {"id_rsa", nil}, {"id_dsa", nil}, {"id_ecdsa", nil},
	{"id_ed25519", nil}, {".aws", nil}, {".gnupg", nil}, {".kube", nil}, {".docker", nil},
	{".config", nil}, {"user data", nil}, {"mozilla", nil}, {"wallet.dat", nil}, {".electrum", nil},
	{"nkbihfbeogaeaoehlefnkodbefgpgknn", nil}, {"exodus", nil},
}

func isWord(c byte) bool {
	return c == '_' || c == '$' || '0' <= c && c <= '9' || 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z'
}

func wordStart(data []byte, i int) bool { return i == 0 || !isWord(data[i-1]) }

// dotEnvFile accepts ".env" that is not the end of a name such as process.env.
func dotEnvFile(data []byte, i int) bool {
	return i == 0 || !isWord(data[i-1]) && data[i-1] != '.'
}

// dollarName accepts "$NAME" and "${NAME" in upper case, the shell form of a variable.
func dollarName(data []byte, i int) bool {
	i++
	if i < len(data) && data[i] == '{' {
		i++
	}
	return i < len(data) && 'A' <= data[i] && data[i] <= 'Z'
}

// sensitiveEnv accepts process.env[...] and process.env.NAME where NAME holds
// KEY, SECRET, TOKEN, PASSWORD or PASSWD, or starts with AWS_.
func sensitiveEnv(data []byte, i int) bool {
	i += len("process.env")
	if i >= len(data) {
		return false
	}
	if data[i] == '[' {
		return true
	}
	if data[i] != '.' {
		return false
	}
	j := i + 1
	for j < len(data) && j-i < 64 && isWord(data[j]) {
		j++
	}
	name := string(data[i+1 : j])
	return strings.HasPrefix(name, "AWS_") || strings.Contains(name, "KEY") || strings.Contains(name, "SECRET") ||
		strings.Contains(name, "TOKEN") || strings.Contains(name, "PASSWORD") || strings.Contains(name, "PASSWD")
}

// maxAnchors is how many anchor hits are kept. Past it the whole file is scanned.
const maxAnchors = 1 << 20

// windows returns the merged byte ranges around the anchors in d: before bytes
// ahead of an anchor and after bytes behind it.
func (s *scan) windows(d *doc, low []byte, as []anchor, before, after int) [][2]int {
	var pos []int
	for i, a := range as {
		if i&7 == 7 && s.done() {
			return nil
		}
		lit := []byte(a.lit)
		for from := 0; from < len(low); {
			k := bytes.Index(low[from:], lit)
			if k < 0 {
				break
			}
			from += k + 1
			if a.ok == nil || a.ok(d.data, from-1) {
				pos = append(pos, from-1)
			}
			if len(pos) > maxAnchors {
				return [][2]int{{0, len(d.data)}}
			}
		}
	}
	slices.Sort(pos)
	var out [][2]int
	for _, p := range pos {
		lo, hi := max(0, p-before), min(len(d.data), p+after)
		if n := len(out); n > 0 && lo <= out[n-1][1] {
			out[n-1][1] = max(out[n-1][1], hi)
		} else {
			out = append(out, [2]int{lo, hi})
		}
	}
	return out
}

// asciiLower lowercases ASCII letters and keeps every offset.
func asciiLower(b []byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		out[i] = c
	}
	return out
}

// pieces calls fn for the text of data[lo:hi] in pieces of at most chunkSize
// bytes and checks the context between pieces. A piece ends at a line break.
// A line longer than a piece is cut, and the next piece starts chunkOverlap
// bytes earlier so that a match across the cut is still found. fn gets the
// offset of the piece and minEnd, the offset up to which matches were seen in
// the previous piece. It returns false if the context ended.
func (s *scan) pieces(d *doc, lo, hi int, fn func(base, minEnd int, text string)) bool {
	minEnd := 0
	for pos := lo; pos < hi; {
		if s.done() {
			return false
		}
		end := min(hi, pos+chunkSize)
		next, nextMin := end, 0
		if end < hi {
			if i := bytes.LastIndexByte(d.data[pos:end], '\n'); i >= 0 {
				end = pos + i + 1
				next = end
			} else {
				next, nextMin = end-chunkOverlap, end
			}
		}
		fn(pos, minEnd, string(d.data[pos:end]))
		pos, minEnd = next, nextMin
	}
	return true
}

// collect finds the matches of all checks in d. Whole-file passes use only
// patterns that start with a literal. Everything else runs on windows around
// rare words, so the time stays linear and small on ordinary code. The network
// calls matter only next to a secret, so they are searched only when there is one.
func (s *scan) collect(d *doc) *found {
	f := &found{}
	d.childProc = bytes.Contains(d.data, []byte("child_process"))
	if !s.pieces(d, 0, len(d.data), func(base, minEnd int, text string) { s.scanCode(d, f, base, minEnd, text) }) {
		return f
	}
	low := asciiLower(d.data)
	for _, w := range s.windows(d, low, shellAnchors, 512, 640) {
		s.pieces(d, w[0], w[1], func(base, minEnd int, text string) { s.scanShell(d, f, base, minEnd, text) })
	}
	for _, w := range s.windows(d, low, secretAnchors, 256, 512) {
		s.pieces(d, w[0], w[1], func(base, minEnd int, text string) { s.scanSecrets(d, f, base, minEnd, text) })
	}
	if len(f.secrets) > 0 {
		s.aliasesOf(d)
		s.pieces(d, 0, len(d.data), func(base, minEnd int, text string) { s.scanNet(d, f, base, minEnd, text) })
	}
	return f
}

// match returns the absolute offset of the match [start, end) of text, which
// starts at base, if it counts: it ends after minEnd and is not on a comment
// line. Leading white space is skipped so that the offset is on the match line.
func match(d *doc, base, minEnd int, text string, start, end int) (int, bool) {
	for start < end && strings.IndexByte(" \t\r\n", text[start]) >= 0 {
		start++
	}
	off := base + start
	return off, base+end > minEnd && !d.commentLine(off)
}

// keep appends v to list unless the list is full. A full list means the
// file is too dense with matches to check all of them, which the result reports.
func keep[T any](s *scan, list *[]T, v T) {
	if len(*list) >= maxHits {
		s.limited = true
		return
	}
	*list = append(*list, v)
}

// eachMatch calls fn with the absolute offset and end of each match of res in text.
func eachMatch(d *doc, res []*regexp.Regexp, base, minEnd int, text string, fn func(off, end int)) {
	for _, re := range res {
		for _, m := range re.FindAllStringIndex(text, maxHits+1) {
			if off, ok := match(d, base, minEnd, text, m[0], m[1]); ok && (off == 0 || !isWord(d.data[off-1])) {
				fn(off, base+m[1])
			}
		}
	}
}

// scanCode finds the calls that run a string as code, process starts and
// environment dumps.
func (s *scan) scanCode(d *doc, f *found, base, minEnd int, text string) {
	sinks := sinksBoth
	switch d.lang {
	case langJS:
		sinks = sinksJS
	case langPy:
		sinks = sinksPy
	}
	eachMatch(d, sinks, base, minEnd, text, func(off, end int) { keep(s, &f.sinks, [2]int{off, end}) })
	if d.lang&langJS != 0 {
		eachMatch(d, thenEval, base, minEnd, text, func(off, _ int) { keep(s, &f.thenEval, off) })
	}
	spawn := func(off, _ int) { keep(s, &f.spawns, off) }
	if d.lang&langJS != 0 && d.childProc {
		eachMatch(d, spawnsJS, base, minEnd, text, func(off, end int) {
			if (off == 0 || d.data[off-1] != '.' || receiver(d.data, off-1)) && !definition(d.data, off) {
				spawn(off, end)
			}
		})
	}
	if d.lang&langPy != 0 {
		eachMatch(d, spawnsPy, base, minEnd, text, spawn)
	}
	eachMatch(d, bulkEnv, base, minEnd, text, func(off, _ int) {
		if name, ok := copyName(d.data, off); ok {
			keep(s, &f.secrets, secretHit{off: off, kind: secretDump, name: name})
		}
	})
	eachMatch(d, bulkEnvVar, base, minEnd, text, func(off, _ int) {
		if g := assignRE.FindSubmatch(d.data[max(0, off-160):off]); g != nil && !bytes.ContainsRune(g[0], '\n') {
			keep(s, &f.secrets, secretHit{off: off, kind: secretDump, name: string(g[1])})
		}
	})
}

// copyName returns the name that the copy of the environment at off is given
// by an assignment ("old = dict(os.environ)"). It is "" for a copy that is not
// assigned, or that is an argument of a network call. ok is false for a copy
// that is an argument of a call that starts a process: the environment of a child.
func copyName(data []byte, off int) (name string, ok bool) {
	before := data[max(0, off-160):off]
	if g := copyRE.FindSubmatchIndex(before); g != nil && !unclosed(before[:g[2]]) {
		if hasNetwork(before[g[0]:]) {
			return "", true
		}
		return string(before[g[2]:g[3]]), true
	}
	return "", !inProcessCall(before)
}

// unclosed reports whether text ends inside a bracket that it opens.
func unclosed(text []byte) bool {
	depth := 0
	for _, c := range text {
		switch c {
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			depth--
		}
	}
	return depth > 0
}

// inProcessCall reports whether text ends inside the arguments of a call that
// starts a process.
func inProcessCall(text []byte) bool {
	depth := 0
	for i := len(text) - 1; i >= 0; i-- {
		switch text[i] {
		case ')':
			depth++
		case '(':
			if depth > 0 {
				depth--
				continue
			}
			start := i
			for start > 0 && (isWord(text[start-1]) || text[start-1] == '.') {
				start--
			}
			call := string(text[start : i+1])
			for _, re := range slices.Concat(spawnsJS, spawnsPy) {
				if re.MatchString(call) {
					return true
				}
			}
		}
	}
	return false
}

// definition reports whether the call-like text at off defines a function or
// a method: "function f(a) {", "async f(a) {", "f(a) {" at the start of a line.
func definition(data []byte, off int) bool {
	line := bytes.TrimSpace(lineAround(data, off))
	if !bytes.HasSuffix(line, []byte(") {")) && !bytes.HasSuffix(line, []byte("){")) {
		return false
	}
	lo := max(0, off-256)
	prefix := strings.Fields(string(data[lo+bytes.LastIndexByte(data[lo:off], '\n')+1 : off]))
	if len(prefix) == 0 {
		return true
	}
	switch prefix[len(prefix)-1] {
	case "function", "function*", "async", "static", "get", "set":
		return true
	}
	return false
}

// globalObject reports whether the name before the dot at data[dot] is a global object.
func globalObject(data []byte, dot int) bool {
	i := dot
	for i > 0 && isWord(data[i-1]) {
		i--
	}
	switch string(data[i:dot]) {
	case "window", "self", "globalThis", "global":
		return true
	}
	return false
}

// receiver reports whether the name before the dot at data[dot] is a
// child_process module name.
func receiver(data []byte, dot int) bool {
	i := dot
	for i > 0 && isWord(data[i-1]) {
		i--
	}
	switch string(data[i:dot]) {
	case "child_process", "childProcess", "cp":
		return true
	}
	return false
}

// scanNet finds network calls, including calls through an alias.
func (s *scan) scanNet(d *doc, f *found, base, minEnd int, text string) {
	calls := networkCalls
	if anyIn(d.data[base:base+len(text)], pyNetWords) {
		calls = allNetworkCalls
	}
	eachMatch(d, calls, base, minEnd, text, func(off, _ int) {
		if !definition(d.data, off) && (!bytes.HasPrefix(d.data[off:], []byte("fetch")) || off == 0 || d.data[off-1] != '.' || globalObject(d.data, off-1)) {
			keep(s, &f.nets, off)
		}
	})
	call := func(off, _ int) {
		if (off == 0 || d.data[off-1] != '.') && !definition(d.data, off) {
			keep(s, &f.nets, off)
		}
	}
	eachMatch(d, d.al.nsCalls, base, minEnd, text, call)
	eachMatch(d, d.al.fnCalls, base, minEnd, text, call)
}

// scanShell finds shell commands that download, decode or send data, in a
// window around a word such as curl.
func (s *scan) scanShell(d *doc, f *found, base, minEnd int, text string) {
	if !s.spend(len(text)) {
		return
	}
	dl := signals.DownloadExec(text)
	dec := signals.DecodeExec(text)
	tools := signals.NetworkTools(text)
	s.limited = s.limited || cut(dl) || cut(dec) || cut(tools)
	for _, m := range dl {
		off, ok := match(d, base, minEnd, text, m.Start, m.End)
		// A command has an operator or a URL. A list of PowerShell aliases has neither.
		if t := text[m.Start:m.End]; ok && len(t) <= maxShellMatch && strings.ContainsAny(t, "|&;($") && !inManifest(d, off) {
			keep(s, &f.dl, off)
		}
	}
	for _, m := range dec {
		if off, ok := match(d, base, minEnd, text, m.Start, m.End); ok && shellDecode(text[m.Start:m.End]) && !inManifest(d, off) {
			keep(s, &f.dec, off)
		}
	}
	for _, m := range tools {
		if off, ok := match(d, base, minEnd, text, m.Start, m.End); ok && !weakWord(text, m.Start, m.End) {
			keep(s, &f.nets, off)
		}
	}
}

// cut reports whether a signals call hit its limit of matches, which drops the
// matches that come last in the text.
func cut(ms []signals.Match) bool { return len(ms) == signals.MaxMatches }

// inManifest reports whether off sits in the "scripts" of a package manifest
// that was embedded as text. Those commands are data, not code that runs.
func inManifest(d *doc, off int) bool {
	return bytes.Contains(d.data[max(0, off-300):off], []byte(`"scripts"`))
}

// weakWord reports whether text[start:end] is a short tool name (nc, scp, ftp)
// that is used in prose and not as a command. A command follows a quote or an
// operator and has an argument after it.
func weakWord(text string, start, end int) bool {
	switch strings.ToLower(text[start:end]) {
	case "nc", "ncat", "netcat", "socat", "scp", "sftp", "ftp", "telnet":
	default:
		return false
	}
	prev := byte('\n')
	if start > 0 {
		prev = text[start-1]
	}
	arg := end+1 < len(text) && text[end] == ' ' && text[end+1] != ' ' && text[end+1] != '\n'
	return strings.IndexByte("'\"`;|&(", prev) < 0 || !arg
}

// scanSecrets finds secret references in a window around a word such as .ssh.
func (s *scan) scanSecrets(d *doc, f *found, base, minEnd int, text string) {
	if !s.spend(len(text)) {
		return
	}
	refs := signals.SecretRefs(text)
	s.limited = s.limited || cut(refs)
	for _, m := range refs {
		off, ok := match(d, base, minEnd, text, m.Start, m.End)
		if !ok {
			continue
		}
		if kind, ok := classify(d, off, text[m.Start:m.End]); ok {
			keep(s, &f.secrets, secretHit{off: off, kind: kind})
		}
	}
	segments := segmentRE.FindAllStringSubmatchIndex(text, signals.MaxMatches)
	s.limited = s.limited || len(segments) == signals.MaxMatches
	for _, m := range segments {
		if off, ok := match(d, base, minEnd, text, m[0], m[1]); ok && s.builtPath(d.data, off, text[m[2]:m[3]]) {
			keep(s, &f.secrets, secretHit{off: off, kind: secretFile})
		}
	}
}

// builtPath reports whether the quoted directory name at off is a segment of a
// path that the code builds, and the path is one that signals.SecretRefs
// counts: .ssh alone or followed by a private key, .gnupg, .aws followed by
// credentials, .kube by config, .docker by config.json, and .env on a line
// that reads, and not for dotenv.
// A path that is the return value of an arrow function or a function ("() =>
// process.env.X || join(", "return path.join(") only defines where a file
// lives and is not a read.
func (s *scan) builtPath(data []byte, off int, name string) bool {
	if !s.spend(pathLook) {
		return false
	}
	if counts, ok := segmentNext[name]; ok {
		if seg, ok := nextSegment(data, off+len(name)+2); !counts(seg, ok) {
			return false
		}
	}
	if !pathlibOperand(data, off) {
		call := enclosingPathCall(data, off)
		if call < 0 || returned(data, call) {
			return false
		}
	}
	if name != ".env" {
		return true
	}
	line := lineAround(data, off)
	return envReadRE.Match(line) && !dotenvRE.Match(line)
}

// pathLook is how far back builtPath looks for the start of a path call.
const pathLook = 256

// pathlibOperand reports whether the / operator of pathlib ends the text
// before off, on the same line or on a line before it.
func pathlibOperand(data []byte, off int) bool {
	return bytes.HasSuffix(bytes.TrimRight(data[max(0, off-pathLook):off], " \t\r\n"), []byte("/"))
}

// enclosingPathCall returns the offset where the callee of a join, joinpath or
// resolve call that is still open at off starts (path.join starts at path),
// looking back across lines, or -1. It counts parentheses and stops at a
// semicolon.
func enclosingPathCall(data []byte, off int) int {
	depth := 0
	for i := off - 1; i >= max(0, off-pathLook); i-- {
		switch data[i] {
		case ')':
			depth++
		case '(':
			if depth > 0 {
				depth--
				continue
			}
			end := i
			for end > 0 && (data[end-1] == ' ' || data[end-1] == '\t') {
				end--
			}
			start := end
			for start > 0 && isWord(data[start-1]) {
				start--
			}
			switch string(data[start:end]) {
			case "join", "joinpath", "resolve":
				for start > 0 && (isWord(data[start-1]) || data[start-1] == '.') {
					start--
				}
				return start
			}
		case ';':
			if depth == 0 {
				return -1
			}
		}
	}
	return -1
}

// returnedRE matches the text between "=>" or "return" and a callee when the
// callee is the value that the function returns: nothing, or a chain of names
// joined by || or ??.
var returnedRE = regexp.MustCompile(`^\s*\(?\s*(?:[\w$.]+\s*(?:\|\||\?\?)\s*)*[\w$.]*$`)

// returned reports whether the callee that starts at callee is the return
// value of an arrow function or a function.
func returned(data []byte, callee int) bool {
	lo := max(0, callee-pathLook)
	before := data[lo:callee]
	end := -1
	if i := bytes.LastIndex(before, []byte("=>")); i >= 0 {
		end = i + 2
	}
	for from := len(before); ; {
		i := bytes.LastIndex(before[:from], []byte("return"))
		if i < 0 {
			break
		}
		if wordStart(before, i) && (i+6 == len(before) || !isWord(before[i+6])) {
			end = max(end, i+6)
			break
		}
		from = i
	}
	return end >= 0 && returnedRE.Match(before[end:])
}

// maxSegment is the longest path segment that nextSegment reads.
const maxSegment = 64

// nextSegment returns the quoted segment that follows after a comma or a /
// operator at data[i:], across lines, or false if there is none.
func nextSegment(data []byte, i int) (string, bool) {
	skip := func(i int) int {
		for n := 0; n < pathLook && i < len(data) && strings.IndexByte(" \t\r\n", data[i]) >= 0; n++ {
			i++
		}
		return i
	}
	i = skip(i)
	if i >= len(data) || data[i] != ',' && data[i] != '/' {
		return "", false
	}
	i = skip(i + 1)
	if i >= len(data) || strings.IndexByte("'\"`", data[i]) < 0 {
		return "", false
	}
	end := bytes.IndexByte(data[i+1:min(len(data), i+1+maxSegment)], data[i])
	if end < 0 {
		return "", false
	}
	return string(data[i+1 : i+1+end]), true
}

// spend charges n bytes of text given to the signals patterns, which are slow
// on dense text, and reports whether the file is still within its budget.
func (s *scan) spend(n int) bool {
	s.signalBytes += n
	if s.signalBytes > signalBudget {
		s.limited = true
		return false
	}
	return true
}

// shellDecode keeps the signals.DecodeExec matches that are shell commands.
// The pattern for exec and eval near a decoder in one line is left to the
// call-argument check, because on a minified line it matches unrelated code.
func shellDecode(m string) bool {
	m = strings.ToLower(m)
	for _, p := range []string{"exec", "eval", "atob", "b64decode", "unhexlify", "fromhex"} {
		if strings.HasPrefix(m, p) {
			return p == "eval" && strings.Contains(m, "$(")
		}
	}
	return true
}

// classify sorts a signals.SecretRefs match. It drops the matches that are
// ordinary code: a bare "env" word, and a .env mention that is not a read
// (dotenv.config, .env.example).
func classify(d *doc, off int, m string) (secretKind, bool) {
	word := strings.TrimLeft(m, " \t\r\n;&|(\"'")
	switch {
	case namedEnvRE.MatchString(m):
		return secretNamed, true
	case strings.HasPrefix(word, "env"), strings.HasPrefix(word, "printenv"):
		return secretDump, strings.HasSuffix(strings.TrimSpace(m), "|")
	case strings.Contains(m, ".env"):
		line := lineAround(d.data, off)
		return secretFile, envReadRE.Match(line) && !dotenvRE.Match(line)
	}
	return secretFile, true
}

// lineAround returns the line that holds off, at most 512 bytes of it.
func lineAround(data []byte, off int) []byte {
	lo, hi := max(0, off-256), min(len(data), off+256)
	seg := data[lo:hi]
	rel := off - lo
	start := bytes.LastIndexByte(seg[:rel], '\n') + 1
	end := len(seg)
	if i := bytes.IndexByte(seg[rel:], '\n'); i >= 0 {
		end = rel + i
	}
	return seg[start:end]
}
