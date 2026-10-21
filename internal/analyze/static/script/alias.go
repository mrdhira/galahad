package script

import (
	"regexp"
	"slices"
	"strings"
)

// Aliases let the network and decoder checks follow a name that was imported
// or assigned under another name: const client = require('https'),
// import { request } from 'node:https', import requests as r,
// from base64 import b64decode as d, const d = atob.

// netMethods are the calls on a network module that send or connect.
const netMethods = `request|get|post|put|patch|delete|head|connect|createConnection|send|urlopen|urlretrieve|Request|Session|Client|AsyncClient|ClientSession|socket|create_connection|HTTPConnection|HTTPSConnection|SMTP|SMTP_SSL`

// jsNetModules are the Node modules whose calls reach the network. The second
// map holds the modules that are themselves a function.
var (
	jsNetModules  = map[string]bool{"http": true, "https": true, "http2": true, "net": true, "tls": true, "dgram": true, "dns": true}
	jsCallModules = map[string]bool{"axios": true, "got": true, "node-fetch": true, "needle": true, "undici": true, "superagent": true, "request": true}
)

// pyNetNames are the names of each Python network module that make a request.
var pyNetNames = map[string]string{
	"requests":       "get post put patch delete head request Session",
	"urllib.request": "urlopen Request urlretrieve",
	"urllib":         "urlopen urlretrieve",
	"urllib2":        "urlopen Request",
	"socket":         "socket create_connection",
	"http.client":    "HTTPConnection HTTPSConnection",
	"httpx":          "get post put patch delete request Client AsyncClient",
	"aiohttp":        "ClientSession",
	"smtplib":        "SMTP SMTP_SSL",
}

// pyDecoderNames are the decoders of each Python module.
var pyDecoderNames = map[string]string{
	"base64":   "b64decode b32decode b16decode a85decode b85decode urlsafe_b64decode",
	"binascii": "unhexlify a2b_base64 a2b_hex",
	"zlib":     "decompress",
	"marshal":  "loads",
	"codecs":   "decode",
}

var (
	jsRequireRE  = regexp.MustCompile(`require\s*\(\s*['"](?:node:)?([\w@/.-]+)['"]\s*\)`)
	jsImportRE   = regexp.MustCompile(`import\s+([^;'"]*?)\s*from\s*['"](?:node:)?([\w@/.-]+)['"]`)
	jsAtobRE     = regexp.MustCompile(`atob[ \t\r]*(?:[;,\n]|$)`)
	pyImportAsRE = regexp.MustCompile(`import\s+([\w.]+)\s+as\s+(\w+)`)
	pyFromRE     = regexp.MustCompile(`from\s+([\w.]+)\s+import\s+\(?([^\n#;)]*)`)

	// pyDynREs start with a literal word each, so that the search stays fast.
	pyDynREs = []*regexp.Regexp{
		regexp.MustCompile(`__import__\s*\(\s*['"]([\w.]+)['"]`),
		regexp.MustCompile(`importlib\s*\.\s*import_module\s*\(\s*['"]([\w.]+)['"]`),
	}

	// tailAssignRE and tailDestructRE end at the end of the text before a
	// require call: "name =" and "{ a, b } =".
	tailAssignRE   = regexp.MustCompile(`([A-Za-z_$][\w$]*)\s*=\s*(?:await\s+)?(?:(?:window|self|globalThis|global)\s*\.\s*)?$`)
	tailDestructRE = regexp.MustCompile(`\{([^{}]*)\}\s*=\s*(?:await\s+)?$`)
)

const (
	maxAliases    = 32
	maxWindowHits = 64   // network calls listed in a window
	maxCopies     = 1024 // copies of a known name followed per round and window
)

// nsCall follows the name of a network module: .request(, .default.request(
// of a module imported as a namespace, urllib.request.urlopen(.
const nsCall = `\s*\.\s*(?:(?:default|request)\s*\.\s*)?(?:` + netMethods + `)\s*\(`

func quoteNames(names []string) string {
	q := make([]string, len(names))
	for i, n := range names {
		q[i] = regexp.QuoteMeta(n)
	}
	return strings.Join(q, "|")
}

// aliasSet holds the names found in a doc and the patterns built from them.
type aliasSet struct {
	ns, fn, dec []string // module names (name.request()), function names (name()), decoder names

	nsCalls, fnCalls []*regexp.Regexp // whole-file patterns, each starts with a name
	argNet, argDec   *regexp.Regexp   // patterns for a short text; nil if there is no name
}

// aliasesOf finds the aliases of d once.
func (s *scan) aliasesOf(d *doc) *aliasSet {
	if d.al != nil {
		return d.al
	}
	a := &aliasSet{}
	d.al = a
	s.pieces(d, 0, len(d.data), func(base, minEnd int, text string) {
		if d.lang&langJS != 0 {
			a.scanJS(d, base, minEnd, text)
		}
		if d.lang&langPy != 0 {
			a.scanPy(text)
		}
	})
	a.copies(s, d)
	a.build()
	return a
}

// copies follows "b = a" for each known name a, so that b becomes a name too.
// It takes at most three rounds.
func (a *aliasSet) copies(s *scan, d *doc) {
	for range 3 {
		names := slices.Concat(a.ns, a.fn, a.dec)
		if len(names) == 0 {
			return
		}
		re := regexp.MustCompile(`=\s*(` + quoteNames(names) + `)[ \t]*(?:[;,)\n]|$)`)
		before := len(names)
		s.pieces(d, 0, len(d.data), func(base, _ int, text string) {
			for _, m := range re.FindAllStringSubmatchIndex(text, maxCopies) {
				lhs, ok := assignedName(text, m[0])
				if !ok {
					continue
				}
				from := text[m[2]:m[3]]
				for _, l := range []*[]string{&a.ns, &a.fn, &a.dec} {
					if slices.Contains(*l, from) {
						a.add(l, lhs)
					}
				}
			}
		})
		if len(a.ns)+len(a.fn)+len(a.dec) == before {
			return
		}
	}
}

// assignedName returns the variable that the "=" at text[eq] assigns to. It
// rejects comparisons, compound assignments, properties and destructuring.
func assignedName(text string, eq int) (string, bool) {
	if eq > 0 && strings.IndexByte("=!<>+-*/%&|^", text[eq-1]) >= 0 {
		return "", false
	}
	if eq+1 < len(text) && (text[eq+1] == '=' || text[eq+1] == '>') {
		return "", false
	}
	end := eq
	for end > 0 && (text[end-1] == ' ' || text[end-1] == '\t') {
		end--
	}
	start := end
	for start > 0 && isWord(text[start-1]) {
		start--
	}
	if start == end || start > 0 && text[start-1] == '.' || '0' <= text[start] && text[start] <= '9' {
		return "", false
	}
	return text[start:end], true
}

func (a *aliasSet) add(list *[]string, name string) {
	if name == "" || len(a.ns)+len(a.fn)+len(a.dec) >= maxAliases {
		return
	}
	for _, n := range *list {
		if n == name {
			return
		}
	}
	*list = append(*list, name)
}

func (a *aliasSet) scanJS(d *doc, base, minEnd int, text string) {
	for _, m := range jsRequireRE.FindAllStringSubmatchIndex(text, -1) {
		if base+m[1] <= minEnd {
			continue
		}
		mod := text[m[2]:m[3]]
		if !jsNetModules[mod] && !jsCallModules[mod] {
			continue
		}
		before := tailBefore(text, m[0])
		if g := tailAssignRE.FindStringSubmatch(before); g != nil {
			a.add(&a.ns, g[1])
			if jsCallModules[mod] {
				a.add(&a.fn, g[1])
			}
		} else if g := tailDestructRE.FindStringSubmatch(before); g != nil {
			for _, n := range importNames(g[1], ":") {
				a.add(&a.fn, n)
			}
		}
	}
	for _, m := range jsImportRE.FindAllStringSubmatchIndex(text, -1) {
		if base+m[1] <= minEnd {
			continue
		}
		mod := text[m[4]:m[5]]
		if !jsNetModules[mod] && !jsCallModules[mod] {
			continue
		}
		clause := text[m[2]:m[3]]
		if i := strings.IndexByte(clause, '{'); i >= 0 {
			j := strings.IndexByte(clause[i:], '}')
			if j < 0 {
				j = len(clause) - i
			}
			for _, n := range importNames(clause[i+1:i+j], " as ") {
				a.add(&a.fn, n)
			}
			clause = clause[:i]
		}
		clause = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(clause), ","))
		clause = strings.TrimSpace(strings.TrimPrefix(clause, "*"))
		clause = strings.TrimSpace(strings.TrimPrefix(clause, "as "))
		if id := identRE.FindString(clause); id != "" {
			a.add(&a.ns, id)
			if jsCallModules[mod] {
				a.add(&a.fn, id)
			}
		}
	}
	for _, m := range jsAtobRE.FindAllStringIndex(text, -1) {
		if base+m[1] <= minEnd {
			continue
		}
		if g := tailAssignRE.FindStringSubmatch(tailBefore(text, m[0])); g != nil {
			a.add(&a.dec, g[1])
		}
	}
}

func (a *aliasSet) scanPy(text string) {
	for _, re := range pyDynREs {
		for _, m := range re.FindAllStringSubmatchIndex(text, -1) {
			if _, ok := pyNetNames[text[m[2]:m[3]]]; !ok {
				continue
			}
			if g := tailAssignRE.FindStringSubmatch(tailBefore(text, m[0])); g != nil {
				a.add(&a.ns, g[1])
			}
		}
	}
	for _, m := range pyImportAsRE.FindAllStringSubmatch(text, -1) {
		if _, ok := pyNetNames[m[1]]; ok {
			a.add(&a.ns, m[2])
		}
	}
	for _, m := range pyFromRE.FindAllStringSubmatch(text, -1) {
		mod, names := m[1], importNames(m[2], " as ")
		if (mod == "urllib" || mod == "http") && len(names) > 0 {
			for _, n := range names {
				a.add(&a.ns, n) // from urllib import request
			}
		}
		for _, item := range strings.Split(m[2], ",") {
			orig, local := splitAs(item, " as ")
			if strings.Contains(" "+pyNetNames[mod]+" ", " "+orig+" ") {
				a.add(&a.fn, local)
			}
			if strings.Contains(" "+pyDecoderNames[mod]+" ", " "+orig+" ") {
				a.add(&a.dec, local)
			}
		}
	}
}

// importNames returns the local names of an import list "a, b as c" (sep " as ")
// or a destructuring list "a, b: c" (sep ":").
func importNames(list, sep string) []string {
	var out []string
	for _, item := range strings.Split(list, ",") {
		_, local := splitAs(item, sep)
		if id := identRE.FindString(local); id != "" {
			out = append(out, id)
		}
	}
	return out
}

// splitAs splits "orig as local" at sep. Without sep both are the item.
func splitAs(item, sep string) (orig, local string) {
	item = strings.TrimSpace(item)
	if i := strings.Index(item, sep); i >= 0 {
		return strings.TrimSpace(item[:i]), strings.TrimSpace(item[i+len(sep):])
	}
	return item, item
}

// tailBefore returns the text before off, at most 160 bytes. The name that a
// call is assigned to may be on the line before it.
func tailBefore(text string, off int) string { return text[max(0, off-160):off] }

func (a *aliasSet) build() {
	quote := quoteNames
	for _, n := range a.ns {
		a.nsCalls = append(a.nsCalls, regexp.MustCompile(regexp.QuoteMeta(n)+nsCall))
	}
	for _, n := range a.fn {
		a.fnCalls = append(a.fnCalls, regexp.MustCompile(regexp.QuoteMeta(n)+`\s*\(`))
	}
	var parts []string
	if len(a.ns) > 0 {
		parts = append(parts, `(?:`+quote(a.ns)+`)`+nsCall)
	}
	if len(a.fn) > 0 {
		parts = append(parts, `(?:`+quote(a.fn)+`)\s*\(`)
	}
	if len(parts) > 0 {
		a.argNet = regexp.MustCompile(`(?:^|[^\w$.])(?:` + strings.Join(parts, "|") + `)`)
	}
	if len(a.dec) > 0 {
		a.argDec = regexp.MustCompile(`(?:^|[^\w$.])(?:` + quote(a.dec) + `)\s*\(`)
	}
}

// network reports whether b, a short text, makes a network call, directly or
// through an alias.
func (s *scan) network(d *doc, b []byte) bool {
	if hasNetwork(b) {
		return true
	}
	a := s.aliasesOf(d)
	return a.argNet != nil && a.argNet.Match(b)
}

// decodes reports whether b, a short text, calls a decoder, directly or
// through an alias.
func (s *scan) decodes(d *doc, b []byte) bool {
	if hasDecoder(b) {
		return true
	}
	a := s.aliasesOf(d)
	return a.argDec != nil && a.argDec.Match(b)
}

// networkAt returns the offset of the last network call in b, a short text,
// direct or through an alias, or -1.
func (s *scan) networkAt(d *doc, b []byte) int {
	at := -1
	if anyIn(b, networkWords) {
		for _, m := range networkRE.FindAllIndex(b, maxWindowHits) {
			at = m[0]
		}
	}
	if a := s.aliasesOf(d); a.argNet != nil {
		for _, m := range a.argNet.FindAllIndex(b, maxWindowHits) {
			at = max(at, m[0])
		}
	}
	return at
}
