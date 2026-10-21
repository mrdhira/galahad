// Package defang makes URLs, hosts and email addresses harmless to click or
// copy, so renderers can show untrusted indicators. It is pure and host-safe.
package defang

import (
	"regexp"
	"strings"
)

// schemes maps a URL scheme to its defanged form. https and ftps come before http and ftp.
var schemes = []struct{ from, to string }{
	{"https", "hxxps"}, {"http", "hxxp"}, {"ftps", "fxps"}, {"ftp", "fxp"}, {"file", "fxle"},
}

// Defang defangs one URL, host, IP address or email address: a leading http, ftp or file scheme
// becomes hxxp, fxp or fxle (only before ://), every dot becomes [.] and every at sign becomes
// [@]. Parts that are already defanged stay as they are.
func Defang(s string) string {
	var b strings.Builder
	rest := s
	for _, sc := range schemes {
		n := len(sc.from)
		if len(rest) >= n+3 && strings.EqualFold(rest[:n], sc.from) && rest[n:n+3] == "://" {
			b.WriteString(sc.to)
			rest = rest[n:]
			break
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
var urlOrEmail = regexp.MustCompile(`(?i)(?:https?|ftps?|file)://[^\s<>"'` + "`" + `\\^{}|]+|[a-z0-9._%+-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,}`)

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

// DefangHosts defangs every occurrence of the given hosts (domains or IP addresses) in free text.
// A host matches exactly, ignoring case, and only as a whole name: a letter, digit, hyphen or
// underscore next to it, or a dot followed by a name character, means it is part of something
// else. File names such as setup.js are never touched unless they are one of the hosts.
func DefangHosts(s string, hosts []string) string {
	for _, h := range hosts {
		if h == "" {
			continue
		}
		s = defangHost(s, h)
	}
	return s
}

func defangHost(s, host string) string {
	lower := asciiLower(s)
	h := asciiLower(host)
	var b strings.Builder
	last := 0
	for from := 0; ; {
		i := strings.Index(lower[from:], h)
		if i < 0 {
			break
		}
		start := from + i
		end := start + len(h)
		from = end
		if !wholeName(s, start, end) {
			continue
		}
		b.WriteString(s[last:start])
		b.WriteString(Defang(s[start:end]))
		last = end
	}
	if last == 0 {
		return s
	}
	b.WriteString(s[last:])
	return b.String()
}

// wholeName reports whether s[start:end] is not glued to more name characters.
func wholeName(s string, start, end int) bool {
	if start > 0 && (nameChar(s[start-1]) || s[start-1] == '.' && start > 1 && nameChar(s[start-2])) {
		return false
	}
	if end < len(s) && (nameChar(s[end]) || s[end] == '.' && end+1 < len(s) && nameChar(s[end+1])) {
		return false
	}
	return true
}

func nameChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c >= 0x80
}

// asciiLower lowercases ASCII letters only, so byte offsets stay the same as in s.
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}
