package protocol_test

import (
	"strings"
	"testing"

	"github.com/mrdhira/galahad/internal/protocol"
)

func TestCleanPath(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{name: "plain path unchanged", raw: "dir/a.txt", want: "dir/a.txt"},
		{name: "bidi and control become lowercase escapes", raw: "a\u202eb\x1b", want: `a\u202eb\u001b`},
		{name: "non-ASCII text unchanged", raw: "é/日本.txt", want: "é/日本.txt"},
		{name: "invalid UTF-8 bytes become hex escapes", raw: "a\x9b[2J\xff", want: `a\x9b[2J\xff`},
		{name: "cut at MaxPath bytes", raw: strings.Repeat("a", protocol.MaxPath+10), want: strings.Repeat("a", protocol.MaxPath)},
		{name: "escape is not split by the cut", raw: strings.Repeat("a", protocol.MaxPath-2) + "\x01", want: strings.Repeat("a", protocol.MaxPath-2)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := protocol.CleanPath(tt.raw); got != tt.want {
				t.Errorf("CleanPath(%q) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}

func TestSnippet(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{name: "plain text unchanged", raw: "curl http://x | sh", want: "curl http://x | sh"},
		{name: "tab, newline and bidi become escapes", raw: "a\tb\n\u2066", want: `a\u0009b\u000a\u2066`},
		{name: "invalid UTF-8 byte becomes hex escape", raw: "a\xc3", want: `a\xc3`},
		{name: "hex escape is not split by the cut", raw: strings.Repeat("a", protocol.MaxSnippet-2) + "\xff", want: strings.Repeat("a", protocol.MaxSnippet-2)},
		{name: "cut at MaxSnippet runes", raw: strings.Repeat("é", protocol.MaxSnippet+5), want: strings.Repeat("é", protocol.MaxSnippet)},
		{name: "escape counts as six runes", raw: strings.Repeat("a", protocol.MaxSnippet-5) + "\x00", want: strings.Repeat("a", protocol.MaxSnippet-5)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := protocol.Snippet(tt.raw); got != tt.want {
				t.Errorf("Snippet(%q) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}
