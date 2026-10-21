package script

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"slices"
	"unicode/utf8"

	"github.com/mrdhira/galahad/internal/analyze"
	"github.com/mrdhira/galahad/internal/analyze/static/ioc"
	"github.com/mrdhira/galahad/internal/protocol"
)

// base64Char marks the characters of base64, standard and URL-safe.
var base64Char = func() (t [256]bool) {
	for _, c := range []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/-_") {
		t[c] = true
	}
	return t
}()

// padding finds code that follows a run of at least padMin spaces or tabs on
// the same line (GAL-OBF-001). The snippet starts at the hidden code.
func (s *scan) padding(d *doc) {
	data := d.data
	run := 0
	for i := 0; i < len(data); i++ {
		if i&(1<<20-1) == 0 && s.done() {
			return
		}
		c := data[i]
		if c == ' ' || c == '\t' {
			run++
			continue
		}
		if run >= padMin && c > ' ' && c != 0x7f && !d.commentLine(i) {
			if s.full(ruleHidden) {
				return
			}
			s.emit(ruleHidden, func() []protocol.Evidence { return []protocol.Evidence{s.ev(d, i, i)} })
		}
		run = 0
	}
}

// blobsIn finds encoded blobs (GAL-OBF-003). A blob of a file that decodes to
// text is checked again as a document of its own.
func (s *scan) blobsIn(d *doc) {
	data := d.data
	checked := 0
	for i := 0; i < len(data); {
		if i-checked >= 1<<20 {
			checked = i
			if s.done() {
				return
			}
		}
		if !base64Char[data[i]] {
			i++
			continue
		}
		j := i
		for j < len(data) && base64Char[data[j]] {
			j++
		}
		if j-i >= blobMin {
			s.blob(d, i, j)
		}
		i = j
	}
}

func (s *scan) blob(d *doc, start, end int) {
	run := d.data[start:end]
	if dataURI(d.data, start) || !encodedLike(run) {
		return
	}
	s.add(d, ruleBlob, start)
	if d.depth > 0 || s.blobs >= maxBlobs {
		return
	}
	text := decodeText(run[:min(len(run), maxBlobChars)])
	if text == nil || s.decoded+len(text) > maxDecodedTotal {
		return
	}
	s.blobs++
	s.decoded += len(text)
	line := analyze.EvidenceAt(s.f, start).Line
	s.indicators(text, line)
	s.run(&doc{data: text, lang: langJS | langPy, depth: 1, line: line})
}

// indicators lists the URLs, domains, addresses and emails of a decoded text.
// They point at the line of the literal. The engine drops the ones that the
// file lists in the clear.
func (s *scan) indicators(text []byte, line int) {
	for _, m := range ioc.Extract(text) {
		if len(s.out.IOCs) >= maxBlobIOCs {
			return
		}
		i := protocol.IOC{Type: m.Type, Value: m.Value, Path: s.f.Path, Line: line}
		if !slices.Contains(s.out.IOCs, i) {
			s.out.IOCs = append(s.out.IOCs, i)
		}
	}
}

// dataURI reports whether the blob at start is the payload of a data URI that
// does not carry text or script (an image, font or wasm module).
func dataURI(data []byte, start int) bool {
	const marker = "base64,"
	if start < len(marker) || string(data[start-len(marker):start]) != marker {
		return false
	}
	head := data[max(0, start-80):start]
	i := bytes.LastIndex(head, []byte("data:"))
	if i < 0 {
		return false
	}
	for _, kind := range []string{"text/", "script", "html"} {
		if bytes.Contains(head[i:], []byte(kind)) {
			return false
		}
	}
	return true
}

// encodedLike tells encoded data from a long name or a row of dashes: encoded
// data has many different characters and, at 64 characters per digit set, at
// least one digit in twenty.
func encodedLike(b []byte) bool {
	var seen [256]bool
	kinds, digits := 0, 0
	for _, c := range b {
		if !seen[c] {
			seen[c] = true
			kinds++
		}
		if '0' <= c && c <= '9' {
			digits++
		}
	}
	return kinds >= blobDiversity && digits*20 >= len(b)
}

// decodeText decodes a blob and returns the result if it is printable text,
// else nil. A short prefix is decoded first so that binary data is rejected
// cheaply.
func decodeText(run []byte) []byte {
	const probe = 4096
	if len(run) > probe {
		if p := decode(run[:probe]); len(p) < 4 || !printable(p[:len(p)-3]) {
			return nil
		}
	}
	text := decode(run)
	if !printable(text) {
		return nil
	}
	return text
}

// decode decodes hex, or base64 in the standard or URL-safe alphabet without
// padding. A trailing partial group is dropped.
func decode(run []byte) []byte {
	if len(run)%2 == 0 && isHex(run) {
		if b, err := hex.DecodeString(string(run)); err == nil {
			return b
		}
	}
	enc := base64.RawStdEncoding
	std, url := bytes.ContainsAny(run, "+/"), bytes.ContainsAny(run, "-_")
	if std && url {
		return nil
	}
	if url {
		enc = base64.RawURLEncoding
	}
	b, err := enc.DecodeString(string(run[:len(run)-len(run)%4]))
	if err != nil {
		return nil
	}
	return b
}

func isHex(b []byte) bool {
	for _, c := range b {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

// printable reports whether b is valid UTF-8 with at most 1% control characters
// other than tab, CR and LF.
func printable(b []byte) bool {
	if len(b) == 0 || !utf8.Valid(b) {
		return false
	}
	ctl := 0
	for _, c := range b {
		if c < 0x20 && c != '\n' && c != '\r' && c != '\t' || c == 0x7f {
			ctl++
		}
	}
	return ctl*100 <= len(b)
}
