package analyze_test

import (
	"strings"
	"testing"

	"github.com/mrdhira/galahad/internal/analyze"
	"github.com/mrdhira/galahad/internal/protocol"
)

func TestEvidenceAt(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		data   string
		offset int
		// expectations
		wantLine    int
		wantSnippet string
	}{
		{name: "second line", data: "one\ntwo\nthree\n", offset: 5, wantLine: 2, wantSnippet: "two"},
		{name: "first line", data: "one\ntwo\n", offset: 1, wantLine: 1, wantSnippet: "one"},
		{name: "last line without newline", data: "one\ntwo", offset: 6, wantLine: 2, wantSnippet: "two"},
		{name: "carriage return is trimmed", data: "one\r\ntwo\r\n", offset: 1, wantLine: 1, wantSnippet: "one"},
		{name: "control characters are cleaned", data: "a\x1b[31mb", offset: 0, wantLine: 1, wantSnippet: `a\u001b[31mb`},
		{name: "offset past the end is clamped", data: "one\ntwo", offset: 99, wantLine: 2, wantSnippet: "two"},
		{name: "negative offset is clamped", data: "one\ntwo", offset: -4, wantLine: 1, wantSnippet: "one"},
		{name: "long line is cut", data: strings.Repeat("a", protocol.MaxSnippet+50), offset: 0, wantLine: 1, wantSnippet: strings.Repeat("a", protocol.MaxSnippet)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := analyze.File{Path: "dir/f.txt", Data: []byte(tt.data)}
			got := analyze.EvidenceAt(f, tt.offset)
			if got.Path != "dir/f.txt" || got.Line != tt.wantLine || got.Snippet != tt.wantSnippet {
				t.Errorf("EvidenceAt = %+v, want path dir/f.txt line %d snippet %q", got, tt.wantLine, tt.wantSnippet)
			}
		})
	}
}
