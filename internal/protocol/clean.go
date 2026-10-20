package protocol

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// unsafeRune reports control characters and bidirectional formatting characters.
func unsafeRune(r rune) bool {
	if unicode.IsControl(r) {
		return true
	}
	switch {
	case r == 0x061C, r == 0x200E, r == 0x200F,
		r >= 0x202A && r <= 0x202E,
		r >= 0x2066 && r <= 0x2069:
		return true
	}
	return false
}

// clean renders unsafe runes as literal \uXXXX text and invalid UTF-8 bytes as
// literal \xNN text (lowercase hex) and stops
// before the output would exceed limit, measured by size.
func clean(raw string, limit int, size func(string) int) string {
	var b strings.Builder
	used := 0
	for i := 0; i < len(raw); {
		r, w := utf8.DecodeRuneInString(raw[i:])
		var piece string
		switch {
		case r == utf8.RuneError && w == 1:
			piece = fmt.Sprintf(`\x%02x`, raw[i])
		case unsafeRune(r):
			piece = fmt.Sprintf(`\u%04x`, r)
		default:
			piece = raw[i : i+w]
		}
		i += w
		n := size(piece)
		if used+n > limit {
			break
		}
		used += n
		b.WriteString(piece)
	}
	return b.String()
}

// CleanPath makes an untrusted path safe to print: invalid UTF-8 bytes become
// literal \xNN text, control and bidi characters become literal \uXXXX text,
// and the result is cut at MaxPath bytes.
func CleanPath(raw string) string {
	return clean(raw, MaxPath, func(s string) int { return len(s) })
}

// Snippet makes untrusted text safe to print like CleanPath and cuts it at MaxSnippet runes.
func Snippet(raw string) string {
	return clean(raw, MaxSnippet, utf8.RuneCountInString)
}
