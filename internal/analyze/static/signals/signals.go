// Package signals holds the shared text patterns for secret references, shell
// network tools, download-and-execute chains and decode-and-execute chains.
// Analyzers use the matches to build their own findings: every function takes
// text and returns byte offsets into it, which analyze.EvidenceAt turns into
// path:line evidence. The patterns are RE2, so matching time is linear in the
// length of the text.
package signals

import (
	"regexp"
	"slices"
)

// MaxMatches bounds how many matches one call returns.
const MaxMatches = 1000

// Match is a half-open byte range [Start, End) of the text that was scanned.
type Match struct{ Start, End int }

const (
	sensitiveVar = `[A-Za-z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD|PASSWD)[A-Za-z0-9_]*|AWS_[A-Za-z0-9_]+`
	envPrefix    = `\$\{?|\$env:|%|process\.env\.|process\.env\[\s*['"]|os\.environ(?:\.get)?[\[(]\s*['"]|os\.getenv\(\s*['"]|getenv\(\s*['"]|ENV\[\s*['"]`
	sh           = `(?:[bzdk]?a?sh|python[0-9.]*|perl|ruby|node|php)`
	fetcher      = `(?:curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod)`
)

var (
	secretPatterns = compile(
		`(?:`+envPrefix+`)(?:`+sensitiveVar+`)`,
		// a .env file, but not process.env or .envrc
		`(?:^|[^A-Za-z0-9_.])\.env(?:\.[A-Za-z]+)?(?:$|[^A-Za-z0-9_])`,
		// a bulk dump of the environment
		`(?:^|[\s;&|("'])(?:printenv|env)(?:\s+-0)?\s*(?:\||\n|;|\)|$)`,
		`/proc/self/environ`,
		`\.ssh[/\\]`,
		`\bid_(?:rsa|dsa|ecdsa|ed25519)\b`,
		`\.aws[/\\]credentials`,
		`\.gnupg\b`,
		`\.kube[/\\]config`,
		`\.docker[/\\]config\.json`,
		// browser profiles and crypto wallets
		`\.config[/\\](?:google-chrome|chromium|BraveSoftware)`,
		`User Data[/\\]Default`,
		`Mozilla[/\\]Firefox[/\\]Profiles|\.mozilla[/\\]firefox`,
		`wallet\.dat|\.electrum\b|nkbihfbeogaeaoehlefnkodbefgpgknn|Exodus[/\\]exodus\.wallet`,
	)
	networkPatterns = compile(
		`\b(?:curl|wget|nc|ncat|netcat|socat|scp|sftp|ftp|telnet)\b`,
		`(?i)\b(?:invoke-webrequest|invoke-restmethod|iwr|irm|start-bitstransfer|bitsadmin)\b`,
		`(?i)Net\.WebClient|\.download(?:string|file)\b`,
		`/dev/tcp/`,
	)
	downloadExecPatterns = compile(
		`(?i)\b`+fetcher+`\b[^\n|]*\|\s*(?:sudo\s+)?(?:`+sh+`|iex|invoke-expression|powershell|pwsh)\b`,
		`(?i)\b[bzdk]?a?sh\s+(?:-c\s+["']?\$\(|<\()\s*`+fetcher+`\b`,
		`(?i)\b(?:source|\.)\s+<\(\s*`+fetcher+`\b`,
		`(?i)\b(?:iex|invoke-expression)\b[^\n]*(?:\.downloadstring|\.downloadfile|\b(?:irm|iwr|invoke-webrequest|invoke-restmethod)\b)`,
		`(?i)\.downloadstring\([^\n]*\|\s*(?:iex|invoke-expression)\b`,
		`(?i)\b(?:curl|wget)\b[^\n]*(?:&&|;)\s*(?:chmod\s+\+x\b|(?:ba)?sh\s|\./\S)`,
	)
	decodeExecPatterns = compile(
		`(?i)\bbase64\s+(?:-d|--decode)\b[^\n|]*\|\s*(?:sudo\s+)?(?:`+sh+`|eval|iex)\b`,
		`(?i)\bxxd\s+-r\b[^\n|]*\|\s*(?:sudo\s+)?`+sh+`\b`,
		`(?i)\b(?:eval|[bzdk]?a?sh\s+-c)\s+["']?\$\([^\n]*\bbase64\s+(?:-d|--decode)\b`,
		`(?i)\b(?:powershell|pwsh)(?:\.exe)?\b[^\n]*\s-e(?:nc(?:odedcommand)?)?\s+[A-Za-z0-9+/=]{16,}`,
		`(?i)\b(?:iex|invoke-expression)\b[^\n]*FromBase64String|FromBase64String\([^\n]*\|\s*(?:iex|invoke-expression)\b`,
		`(?i)\b(?:exec|eval)\b[^\n]*\b(?:b64decode|atob|unhexlify|fromhex)\b|\b(?:b64decode|atob|unhexlify|fromhex)\b[^\n]*\b(?:exec|eval)\b`,
	)
)

func compile(patterns ...string) []*regexp.Regexp {
	out := make([]*regexp.Regexp, len(patterns))
	for i, p := range patterns {
		out[i] = regexp.MustCompile(p)
	}
	return out
}

// SecretRefs finds references to secret material: secret-named environment
// variables (*KEY*, *SECRET*, *TOKEN*, *PASSWORD*, AWS_*), .env files, SSH and
// cloud credential files, and browser and wallet directories.
func SecretRefs(text string) []Match { return find(secretPatterns, text) }

// NetworkTools finds shell network tools: curl, wget, nc, scp, PowerShell web
// cmdlets, .NET web clients and /dev/tcp.
func NetworkTools(text string) []Match { return find(networkPatterns, text) }

// DownloadExec finds a download piped into an interpreter, or downloaded and
// then run (curl ... | sh, iex (iwr ...), curl -o x && sh x).
func DownloadExec(text string) []Match { return find(downloadExecPatterns, text) }

// DecodeExec finds encoded data decoded into an interpreter (base64 -d | sh,
// xxd -r | sh, powershell -enc, exec of b64decode).
func DecodeExec(text string) []Match { return find(decodeExecPatterns, text) }

// find returns the matches of all patterns sorted by start, at most MaxMatches.
func find(res []*regexp.Regexp, text string) []Match {
	var out []Match
	for _, re := range res {
		for _, m := range re.FindAllStringIndex(text, MaxMatches) {
			out = append(out, Match{Start: m[0], End: m[1]})
		}
	}
	slices.SortFunc(out, func(a, b Match) int { return a.Start - b.Start })
	return out[:min(len(out), MaxMatches)]
}
