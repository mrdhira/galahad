package decision

import (
	"math"
	"regexp"
	"strings"

	"github.com/mrdhira/galahad/internal/protocol"
)

// minEntropy is the Shannon entropy, in bits per character, that a long base64 run must exceed to be
// taken for a secret. A hex hash has at most 4 bits, so it stays.
const minEntropy = 4.2

// redactRule replaces what re matches with a marker for kind. If re has a group, only the text of
// the first group is replaced, so a name in front of a value stays. keep, if set, says that a
// matched text is left alone.
type redactRule struct {
	kind string
	re   *regexp.Regexp
	keep func(matched string) bool
}

// valueRe is one character of an assignment value: not a quote, a space or a character that ends an
// argument.
const valueRe = `[^\s"',;&|)]`

// The order matters. A rule that matches more of the text comes first, so that its secret is counted
// once and under its own kind, and the rules after it see only the marker, which none of them match.
var redactRules = []redactRule{
	{kind: protocol.RedactPrivateKey, re: regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*`)},
	{kind: protocol.RedactURLCredentials, re: regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.-]*://([^\s/@:]+:[^\s/@]+@)`)},
	{kind: protocol.RedactAWSSecret, re: regexp.MustCompile(`(?i)aws_secret_access_key["']?[ \t]*[=:][ \t]*["']?(` + valueRe + `+)`), keep: isReference},
	{kind: protocol.RedactGitHubToken, re: regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}`)},
	{kind: protocol.RedactSlackToken, re: regexp.MustCompile(`xox[abpors]-[A-Za-z0-9-]{10,}`)},
	{kind: protocol.RedactStripeKey, re: regexp.MustCompile(`[sr]k_(?:live|test)_[A-Za-z0-9]{16,}`)},
	{kind: protocol.RedactAPIKey, re: regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{20,}|AIza[A-Za-z0-9_-]{35}`)},
	{kind: protocol.RedactJWT, re: regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*`)},
	{kind: protocol.RedactAWSAccessKey, re: regexp.MustCompile(`(?:AKIA|ASIA|ABIA|ACCA|AGPA|AIDA|AIPA|ANPA|ANVA|AROA|ASCA)[A-Z0-9]{16}`)},

	// A string that the cut ended inside a token: a known prefix and four or more token characters at its end.
	{kind: protocol.RedactAWSAccessKey, re: regexp.MustCompile(`(?:AKIA|ASIA)[A-Z0-9]{4,}$`)},
	{kind: protocol.RedactGitHubToken, re: regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{4,}$|github_pat_[A-Za-z0-9_]{4,}$`)},
	{kind: protocol.RedactSlackToken, re: regexp.MustCompile(`xox[A-Za-z0-9-]{4,}$`)},
	{kind: protocol.RedactAPIKey, re: regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{4,}$|AIza[A-Za-z0-9_-]{4,}$`)},
	{kind: protocol.RedactJWT, re: regexp.MustCompile(`eyJ[A-Za-z0-9_.-]{4,}$`)},

	{kind: protocol.RedactAssignment, re: regexp.MustCompile(`(?i)(?:password|passwd|secret|token|api_key|apikey|access_key|auth)[A-Za-z0-9_.-]*["']?[ \t]*[=:][ \t]*["']?((?:(?:bearer|basic|token)[ \t]+)?` + valueRe + `{6,})`), keep: isReference},
	{kind: protocol.RedactHighEntropy, re: regexp.MustCompile(`[A-Za-z0-9+/_=-]{32,}`), keep: func(s string) bool { return entropy(s) <= minEntropy }},
}

// Redact replaces the secrets in the paths, titles and snippets of req with [REDACTED:<kind>] and
// returns how many it replaced of each kind, for Decision.Redactions. The other fields of the request
// are fixed values or identifiers that Validate has checked. The patterns are fixed RE2 expressions
// and nothing is decoded, so the time is linear in the length of the text. It changes req in place.
func Redact(req *protocol.DecisionRequest) map[string]int {
	counts := make(map[string]int)
	for i := range req.Input.Findings {
		f := &req.Input.Findings[i]
		f.Path = redactString(f.Path, counts)
		f.Title = redactString(f.Title, counts)
		f.Snippet = redactString(f.Snippet, counts)
	}
	return counts
}

func redactString(s string, counts map[string]int) string {
	for _, r := range redactRules {
		s = r.apply(s, counts)
	}
	return s
}

func (r redactRule) apply(s string, counts map[string]int) string {
	var b strings.Builder
	last := 0
	for _, m := range r.re.FindAllStringSubmatchIndex(s, -1) {
		from, to := m[0], m[1]
		if len(m) > 2 {
			from, to = m[2], m[3]
		}
		if r.keep != nil && r.keep(s[from:to]) {
			continue
		}
		b.WriteString(s[last:from])
		b.WriteString("[REDACTED:" + r.kind + "]")
		last = to
		counts[r.kind]++
	}
	if last == 0 {
		return s
	}
	b.WriteString(s[last:])
	return b.String()
}

// isReference reports whether a value names a variable and so holds no secret: $X, ${X}, %X%,
// process.env.X, os.environ[...], or text that is already redacted. An optional word before the
// value (Bearer, Basic, Token) is ignored.
func isReference(v string) bool {
	v = v[strings.LastIndexAny(v, " \t")+1:] // an assignment may start with Bearer, Basic or Token
	lower := strings.ToLower(v)
	return strings.HasPrefix(v, "$") || len(v) > 1 && strings.HasPrefix(v, "%") && strings.HasSuffix(v, "%") ||
		strings.HasPrefix(lower, "process.env.") || strings.HasPrefix(lower, "os.environ") || strings.HasPrefix(v, "[REDACTED:")
}

// entropy returns the Shannon entropy of s in bits per byte.
func entropy(s string) float64 {
	var freq [256]int
	for i := 0; i < len(s); i++ {
		freq[s[i]]++
	}
	h := 0.0
	for _, n := range freq {
		if n > 0 {
			p := float64(n) / float64(len(s))
			h -= p * math.Log2(p)
		}
	}
	return h
}
