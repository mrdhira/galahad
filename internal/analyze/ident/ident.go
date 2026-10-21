// Package ident identifies file kinds from their bytes and measures entropy.
// Both functions are pure.
package ident

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"errors"
	"math"
	"strings"
	"unicode/utf8"
)

// Kind is the detected type of a file.
type Kind string

// Kinds.
const (
	Text    Kind = "text"
	PDF     Kind = "pdf"
	Zip     Kind = "zip"
	OOXML   Kind = "ooxml" // zip with [Content_Types].xml at its root
	Gzip    Kind = "gzip"
	Bzip2   Kind = "bzip2"
	Tar     Kind = "tar"
	OLE     Kind = "ole"
	PE      Kind = "pe"
	ELF     Kind = "elf"
	MachO   Kind = "macho"
	LNK     Kind = "lnk"
	Unknown Kind = "unknown"
)

const textWindow = 8192

// Identify returns the kind of a file from its magic bytes. The name is used
// only for tar, whose oldest format has no magic.
func Identify(name string, data []byte) Kind {
	switch {
	case bytes.HasPrefix(data, []byte("%PDF-")):
		return PDF
	case bytes.HasPrefix(data, []byte("PK\x03\x04")), bytes.HasPrefix(data, []byte("PK\x05\x06")):
		if isOOXML(data) {
			return OOXML
		}
		return Zip
	case bytes.HasPrefix(data, []byte{0x1f, 0x8b}):
		return Gzip
	case bytes.HasPrefix(data, []byte("BZh")):
		return Bzip2
	case bytes.HasPrefix(data, []byte{0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1}):
		return OLE
	case bytes.HasPrefix(data, []byte("\x7fELF")):
		return ELF
	case bytes.HasPrefix(data, []byte{0x4c, 0, 0, 0, 0x01, 0x14, 0x02, 0}):
		return LNK
	case isPE(data):
		return PE
	case isMachO(data):
		return MachO
	case isTar(name, data):
		return Tar
	case isText(data):
		return Text
	}
	return Unknown
}

// isOOXML reports a zip whose central directory lists [Content_Types].xml at the
// archive root. Part names are case-insensitive in OPC, so the case is ignored.
// A zip that cannot be read is not OOXML.
func isOOXML(data []byte) bool {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil && !errors.Is(err, zip.ErrInsecurePath) {
		return false
	}
	for _, zf := range zr.File {
		if strings.EqualFold(zf.Name, "[Content_Types].xml") {
			return true
		}
	}
	return false
}

func isPE(data []byte) bool {
	if len(data) < 0x40 || data[0] != 'M' || data[1] != 'Z' {
		return false
	}
	off := int64(binary.LittleEndian.Uint32(data[0x3c:]))
	return off+4 <= int64(len(data)) && bytes.Equal(data[off:off+4], []byte("PE\x00\x00"))
}

func isMachO(data []byte) bool {
	if len(data) < 8 {
		return false
	}
	switch binary.BigEndian.Uint32(data) {
	case 0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe:
		return true
	case 0xcafebabe:
		// A universal binary lists a few architectures; a Java class has a version here.
		return binary.BigEndian.Uint32(data[4:]) < 20
	}
	return false
}

func isTar(name string, data []byte) bool {
	if len(data) >= 262 && bytes.Equal(data[257:262], []byte("ustar")) {
		return true
	}
	return len(data) >= 512 && strings.HasSuffix(strings.ToLower(name), ".tar")
}

// isText reports data whose first window has no NUL byte and is valid UTF-8.
func isText(data []byte) bool {
	head := data[:min(len(data), textWindow)]
	if bytes.IndexByte(head, 0) >= 0 {
		return false
	}
	if len(head) == len(data) {
		return utf8.Valid(head)
	}
	// The window may cut a multi-byte character; allow up to 3 trailing bytes to be dropped.
	for cut := 0; cut < utf8.UTFMax; cut++ {
		if utf8.Valid(head[:len(head)-cut]) {
			return true
		}
	}
	return false
}

// Entropy returns the Shannon entropy of data in bits per byte, from 0 (empty
// or constant data) to 8 (uniformly random data).
func Entropy(data []byte) float64 {
	if len(data) == 0 {
		return 0
	}
	var counts [256]int
	for _, b := range data {
		counts[b]++
	}
	n := float64(len(data))
	h := 0.0
	for _, c := range counts {
		if c > 0 {
			p := float64(c) / n
			h -= p * math.Log2(p)
		}
	}
	return h
}
