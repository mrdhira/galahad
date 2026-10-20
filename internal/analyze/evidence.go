package analyze

import (
	"bytes"

	"github.com/mrdhira/galahad/internal/protocol"
)

// EvidenceAt returns evidence for the byte offset in f.Data: the file path, the
// 1-based line number and the cleaned text of that line. The offset is clamped
// to the data.
func EvidenceAt(f File, byteOffset int) protocol.Evidence {
	off := max(0, min(byteOffset, len(f.Data)))
	line := 1 + bytes.Count(f.Data[:off], []byte{'\n'})
	start := bytes.LastIndexByte(f.Data[:off], '\n') + 1
	end := len(f.Data)
	if i := bytes.IndexByte(f.Data[off:], '\n'); i >= 0 {
		end = off + i
	}
	text := bytes.TrimSuffix(f.Data[start:end], []byte{'\r'})
	text = text[:min(len(text), MaxLineScan)]
	return protocol.Evidence{Path: f.Path, Line: line, Snippet: protocol.Snippet(string(text))}
}
