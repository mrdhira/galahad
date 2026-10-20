// Package defang makes URLs, hosts and email addresses harmless to click or
// copy, so renderers can show untrusted indicators. It is pure and host-safe.
package defang

import (
	"regexp"
	"strings"
)

// Defang defangs one URL, host, IP address or email address: a leading http
// becomes hxxp (only before ://), every dot becomes [.] and every at sign becomes [@]. Parts
// that are already defanged stay as they are.
func Defang(s string) string {
	var b strings.Builder
	rest := s
	if len(rest) >= 4 && strings.EqualFold(rest[:4], "http") {
		n := 4
		if len(rest) > n && (rest[n] == 's' || rest[n] == 'S') {
			n++
		}
		if strings.HasPrefix(rest[n:], "://") {
			b.WriteString("hxxp" + strings.ToLower(rest[4:n]))
			rest = rest[n:]
		}
	}
	for rest != "" {
		switch {
		case strings.HasPrefix(rest, "[.]"), strings.HasPrefix(rest, "[@]"):
			b.WriteString(rest[:3])
			rest = rest[3:]
		case rest[0] == '.':
			b.WriteString("[.]")
			rest = rest[1:]
		case rest[0] == '@':
			b.WriteString("[@]")
			rest = rest[1:]
		default:
			b.WriteByte(rest[0])
			rest = rest[1:]
		}
	}
	return b.String()
}

// urlOrEmail finds URLs first (also when glued to a preceding character), so an at sign inside a URL belongs to the URL.
var urlOrEmail = regexp.MustCompile(`(?i)(?:https?|ftp)://[^\s<>"'` + "`" + `\\^{}|]+|[a-z0-9._%+-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,}`)

// DefangText defangs every URL and email address in free text and leaves the
// rest unchanged. Punctuation that ends a sentence is not part of a URL.
func DefangText(s string) string {
	var b strings.Builder
	last := 0
	for _, m := range urlOrEmail.FindAllStringIndex(s, -1) {
		end := m[0] + len(strings.TrimRight(s[m[0]:m[1]], ".,;:!?)]"))
		b.WriteString(s[last:m[0]])
		b.WriteString(Defang(s[m[0]:end]))
		last = end
	}
	b.WriteString(s[last:])
	return b.String()
}
