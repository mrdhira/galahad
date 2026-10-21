package script

import (
	"bytes"
	"regexp"
	"slices"
	"strings"
)

// All patterns are RE2, so matching time is linear in the length of the text.
// Go's regexp skips ahead with a fast literal search only when a pattern
// starts with a literal, so the patterns that run over whole files each start
// with a literal word, and the callers check the word boundary before it.
// Patterns with gaps or alternations run only on short windows: one call
// argument, one bounded lookback, or the neighbourhood of an anchor.
const (
	decoderSrc = `\batob\s*\(` +
		"|Buffer\\s*\\.\\s*from\\s*\\([^\\n]{0,200}?['\"`](?:base64|base64url|hex)['\"`]" +
		`|\bfromCharCode\b` +
		`|\bzlib\s*\.\s*(?:inflate|gunzip|unzip|brotliDecompress)(?:Sync)?\s*\(` +
		`|\b(?:b64decode|b32decode|b16decode|a85decode|b85decode|unhexlify|fromhex)\s*\(` +
		`|\ba2b_(?:base64|hex)\s*\(` +
		`|\b(?:zlib|bz2|lzma|gzip)\.decompress\s*\(` +
		`|\bmarshal\.loads\s*\(` +
		`|\.decode\(\s*['"](?:base64|hex|rot_?13|zlib|bz2)` +
		`|\bcodecs\.decode\s*\([^\n]{0,300}?,\s*['"](?:base64|hex|rot_?13|zlib|bz2)`
)

// networkParts are the network calls, each starting with a literal word.
var networkParts = []string{
	`fetch\s*\(`,
	`https?\s*\.\s*(?:request|get)\s*\(`,
	`require\s*\(\s*['"](?:node:)?(?:https?|http2|net|tls)['"]\s*\)\s*\.\s*(?:request|get|connect|createConnection)\s*\(`,
	`axios\s*(?:\.\s*(?:get|post|put|patch|delete|head|request)\s*)?\(`,
	`new\s+(?:XMLHttpRequest\b|net\s*\.\s*Socket\b)`,
	`net\s*\.\s*(?:connect|createConnection)\s*\(`,
	`navigator\s*\.\s*sendBeacon\s*\(`,
	`tls\s*\.\s*connect\s*\(`,
	`requests\s*\.\s*(?:get|post|put|patch|delete|head|request|Session)\b`,
	`urllib2?\s*\.\s*(?:request\s*\.\s*)?(?:urlopen|Request|urlretrieve)\b`,
	`urlopen\s*\(`,
	`http\s*\.\s*client\s*\.\s*HTTPS?Connection\b`,
	`HTTPS?Connection\s*\(`,
	`socket\s*\.\s*(?:socket|create_connection)\s*\(`,
	`httpx\s*\.\s*(?:get|post|put|request|Client|AsyncClient)\b`,
	`aiohttp\s*\.\s*ClientSession\b`,
	`smtplib\s*\.\s*SMTP`,
}

// dynNetworkParts are the Python network calls on a module that is imported by
// name at run time. Every match contains the name of a network module, so they
// are searched only in text that has one.
var dynNetworkParts = []string{
	`__import__\s*\(\s*['"]` + pyNetModule + `['"]\s*\)` + nsCall,
	`importlib\s*\.\s*import_module\s*\(\s*['"]` + pyNetModule + `['"]\s*\)` + nsCall,
}

// pyNetModule names the Python modules that reach the network.
const pyNetModule = `(?:requests|urllib(?:\.request)?|urllib2|socket|http\.client|httpx|aiohttp|smtplib)`

var (
	decoderRE = regexp.MustCompile(decoderSrc)
	networkRE = regexp.MustCompile(`\b(?:` + strings.Join(slices.Concat(networkParts, dynNetworkParts), "|") + `)`)
	identRE   = regexp.MustCompile(`^[A-Za-z_$][A-Za-z0-9_$]*`)

	// networkCalls are searched in a whole file. allNetworkCalls add the calls
	// on a module imported by name, for text that has a network module name.
	networkCalls    = compile(networkParts...)
	allNetworkCalls = compile(slices.Concat(networkParts, dynNetworkParts)...)

	// Calls that run a string as code, by language.
	sinksJS   = compile(`eval\s*\(`, `Function\s*\(`, `setTimeout\s*\(`, `setInterval\s*\(`)
	sinksPy   = compile(`eval\s*\(`, `exec\s*\(`)
	sinksBoth = compile(`eval\s*\(`, `exec\s*\(`, `Function\s*\(`, `setTimeout\s*\(`, `setInterval\s*\(`)

	// Calls that start a process.
	spawnsJS = compile(`exec(?:File)?(?:Sync)?\s*\(`, `spawn(?:Sync)?\s*\(`, `fork\s*\(`)
	spawnsPy = compile(
		`os\s*\.\s*(?:system|popen)\s*\(`,
		`subprocess\s*\.\s*(?:run|call|Popen|check_call|check_output|getoutput|getstatusoutput)\s*\(`,
		`pty\s*\.\s*spawn\s*\(`,
		`commands\s*\.\s*getoutput\s*\(`,
	)

	// bulkEnv finds the whole environment turned into data.
	bulkEnv = compile(
		`JSON\s*\.\s*stringify\(\s*\{?\s*(?:\.\.\.\s*)?(?:Object\s*\.\s*(?:fromEntries|entries)\(\s*)?process\.env\b`,
		`querystring\s*\.\s*stringify\(\s*process\.env\b`,
		`qs\s*\.\s*stringify\(\s*process\.env\b`,
		`URLSearchParams\(\s*process\.env\b`,
		`dict\(\s*os\.environ\s*\)`,
		`str\(\s*os\.environ\s*\)`,
		`repr\(\s*os\.environ\s*\)`,
		`json\.dumps\(\s*(?:dict\(\s*)?os\.environ\b`,
		`\*\*\s*os\.environ\b`,
		`data\s*=\s*os\.environ[ \t]*(?:[,)\n]|$)`,
		`json\s*=\s*os\.environ[ \t]*(?:[,)\n]|$)`,
		`params\s*=\s*os\.environ[ \t]*(?:[,)\n]|$)`,
		`body\s*=\s*os\.environ[ \t]*(?:[,)\n]|$)`,
	)

	// bulkEnvVar finds ways to copy the environment that are common in
	// harmless code (a spread into a child's options, a copy for a child). They
	// count only when the copy is assigned to a variable that the network call
	// uses: const e = process.env; ... fetch(url, { body: JSON.stringify(e) }).
	bulkEnvVar = compile(
		`\.\.\.\s*process\.env\s*[,}]`,
		`Object\s*\.\s*(?:entries|values)\(\s*process\.env\s*\)`,
		`Object\s*\.\s*assign\(\s*\{\s*\}\s*,\s*process\.env\s*\)`,
		`os\.environ\.copy\(\)`,
		`process\.env[ \t]*(?:[;\n]|$)`,
	)

	// assignRE ends at the end of a line prefix and captures the name in
	// "name = ...".
	assignRE = regexp.MustCompile(`([A-Za-z_$][\w$]*)\s*=(?:[^=>;\n][^=;\n]*)?$`)

	// thenEval is .then(eval): the response text is handed to eval.
	thenEval = compile(`then\s*\??\.?\s*\(\s*(?:(?:window|self|globalThis|global)\s*\.\s*)?eval\s*(?:\)|\.\s*(?:bind|call)\b)`)

	// segmentRE is a quoted directory name that holds credentials, a segment of
	// a path built with join, joinpath, resolve or the / operator. These are
	// the paths that signals.SecretRefs counts when they are written in one
	// literal, so segmentNext says which quoted segment after the directory
	// makes it a credential file. ok is false when none follows.
	segmentRE   = regexp.MustCompile("['\"`](\\.ssh|\\.aws|\\.gnupg|\\.docker|\\.kube|\\.env)['\"`]")
	segmentNext = map[string]func(seg string, ok bool) bool{
		".aws":    file("credentials"),
		".kube":   file("config"),
		".docker": file("config.json"),
		// A private key, or the directory itself. Not config, known_hosts or a public key.
		".ssh": func(seg string, ok bool) bool {
			return !ok || strings.HasPrefix(seg, "id_") && !strings.HasSuffix(seg, ".pub")
		},
	}

	// Secret classification of a signals.SecretRefs match.
	namedEnvRE = regexp.MustCompile(`^(?:\$|%|process\.env|os\.environ|os\.getenv|getenv|ENV\[)`)
	envReadRE  = regexp.MustCompile(`(?i)read|open\s*\(|\bcat\s`)
	dotenvRE   = regexp.MustCompile(`(?i)dotenv|\.env\.(?:example|sample|template|dist)`)
)

// Words that every decoder and every network call contains. The patterns for
// them are slow on long text, so they run only on text that has a word.
var (
	decoderWords = words("atob", "Buffer", "fromCharCode", "zlib", "decode", "bz2", "lzma", "gzip", "unhexlify", "fromhex", "a2b_", "marshal", "codecs")
	networkWords = words("fetch", "http", "HTTP", "axios", "XMLHttp", "net", "navigator", "tls", "requests", "urllib", "urlopen", "socket", "smtplib")

	// pyNetWords are in the name of every module of pyNetNames.
	pyNetWords = words("requests", "urllib", "socket", "http.client", "httpx", "aiohttp", "smtplib")
)

// file accepts the segment name only.
func file(name string) func(string, bool) bool {
	return func(seg string, ok bool) bool { return ok && seg == name }
}

func words(w ...string) [][]byte {
	out := make([][]byte, len(w))
	for i, s := range w {
		out[i] = []byte(s)
	}
	return out
}

func anyIn(b []byte, words [][]byte) bool {
	for _, w := range words {
		if bytes.Contains(b, w) {
			return true
		}
	}
	return false
}

// hasDecoder reports whether b calls a decoder. hasNetwork reports whether b
// makes a network call.
func hasDecoder(b []byte) bool { return anyIn(b, decoderWords) && decoderRE.Match(b) }
func hasNetwork(b []byte) bool { return anyIn(b, networkWords) && networkRE.Match(b) }

func compile(patterns ...string) []*regexp.Regexp {
	out := make([]*regexp.Regexp, len(patterns))
	for i, p := range patterns {
		out[i] = regexp.MustCompile(p)
	}
	return out
}
