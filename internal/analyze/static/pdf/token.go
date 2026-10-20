package pdf

import (
	"bytes"
	"strconv"
	"unicode/utf16"
)

type tokKind uint8

const (
	tName  tokKind = iota // /Name, val is the decoded name
	tStr                  // (literal string), val is the decoded text
	tHex                  // <hex string>, value ignored
	tWord                 // number, keyword or reference part
	tPunct                // [ ] << >>
)

type token struct {
	kind tokKind
	val  string
	off  int  // offset in the scanned buffer
	obf  bool // name hides a plain character behind a #xx escape
}

const (
	maxTokens     = 1 << 20   // tokens kept per region
	maxStringKeep = 256 << 10 // bytes of one string kept
)

func isSpace(c byte) bool {
	return c == 0 || c == '\t' || c == '\n' || c == '\f' || c == '\r' || c == ' '
}

func isDelim(c byte) bool {
	switch c {
	case '(', ')', '<', '>', '[', ']', '{', '}', '/', '%':
		return true
	}
	return false
}

func isRegular(c byte) bool { return !isSpace(c) && !isDelim(c) }

func hexVal(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}

// tokenize splits PDF syntax into at most max tokens. It never fails: unbalanced
// input just ends early. The second result is true when tokens were left over.
func tokenize(b []byte, max int) ([]token, bool) {
	var toks []token
	i := 0
	for i < len(b) {
		if len(toks) >= max {
			return toks, true
		}
		c := b[i]
		switch {
		case isSpace(c):
			i++
		case c == '%':
			for i < len(b) && b[i] != '\n' && b[i] != '\r' {
				i++
			}
		case c == '/':
			name, obf, n := readName(b[i+1:])
			toks = append(toks, token{kind: tName, val: name, off: i, obf: obf})
			i += 1 + n
		case c == '(':
			s, n := readString(b[i:])
			toks = append(toks, token{kind: tStr, val: s, off: i})
			i += n
		case c == '<' && i+1 < len(b) && b[i+1] == '<':
			toks = append(toks, token{kind: tPunct, val: "<<", off: i})
			i += 2
		case c == '<':
			end := bytes.IndexByte(b[i:], '>')
			if end < 0 {
				end = len(b) - i
			}
			toks = append(toks, token{kind: tHex, val: decodeText(decodeHex(b[i+1:i+end], maxStringKeep)), off: i})
			i += end + 1
		case c == '>' && i+1 < len(b) && b[i+1] == '>':
			toks = append(toks, token{kind: tPunct, val: ">>", off: i})
			i += 2
		case c == '[' || c == ']':
			toks = append(toks, token{kind: tPunct, val: string(c), off: i})
			i++
		case isDelim(c):
			i++
		default:
			j := i
			for j < len(b) && isRegular(b[j]) {
				j++
			}
			toks = append(toks, token{kind: tWord, val: string(b[i:j]), off: i})
			i = j
		}
	}
	return toks, false
}

// decodeHex decodes the digits of a hex string, ignoring anything that is not a
// digit. It stops after max bytes.
func decodeHex(b []byte, max int) []byte {
	var out []byte
	hi := -1
	for _, c := range b {
		v := hexVal(c)
		if v < 0 {
			continue
		}
		if hi < 0 {
			hi = v
			continue
		}
		if len(out) >= max {
			return out
		}
		out = append(out, byte(hi<<4|v))
		hi = -1
	}
	if hi >= 0 && len(out) < max {
		out = append(out, byte(hi<<4))
	}
	return out
}

// readName reads a name after its slash and decodes #xx escapes. obf is true when an
// escape stands for a character that needs no escape. It returns the bytes consumed.
func readName(b []byte) (name string, obf bool, n int) {
	var out []byte
	for n < len(b) && isRegular(b[n]) {
		if b[n] == '#' && n+2 < len(b) && hexVal(b[n+1]) >= 0 && hexVal(b[n+2]) >= 0 {
			v := byte(hexVal(b[n+1])<<4 | hexVal(b[n+2]))
			if v > 0x20 && v < 0x7f && isRegular(v) && v != '#' {
				obf = true
			}
			out = append(out, v)
			n += 3
			continue
		}
		out = append(out, b[n])
		n++
	}
	return string(out), obf, n
}

// readString decodes a literal string starting at b[0] == '(' and returns the bytes consumed.
func readString(b []byte) (string, int) {
	var out []byte
	depth := 0
	i := 0
	keep := func(c byte) {
		if len(out) < maxStringKeep {
			out = append(out, c)
		}
	}
	for i < len(b) {
		c := b[i]
		i++
		switch c {
		case '(':
			depth++
			if depth > 1 {
				keep(c)
			}
		case ')':
			depth--
			if depth == 0 {
				return decodeText(out), i
			}
			keep(c)
		case '\\':
			if i >= len(b) {
				return decodeText(out), i
			}
			e := b[i]
			i++
			switch e {
			case 'n':
				keep('\n')
			case 'r':
				keep('\r')
			case 't':
				keep('\t')
			case 'b':
				keep('\b')
			case 'f':
				keep('\f')
			case '\r':
				if i < len(b) && b[i] == '\n' {
					i++
				}
			case '\n':
			case '0', '1', '2', '3', '4', '5', '6', '7':
				v := int(e - '0')
				for k := 0; k < 2 && i < len(b) && b[i] >= '0' && b[i] <= '7'; k++ {
					v = v*8 + int(b[i]-'0')
					i++
				}
				keep(byte(v))
			default:
				keep(e)
			}
		default:
			keep(c)
		}
	}
	return decodeText(out), i
}

// decodeText turns UTF-16BE strings (byte order mark FE FF) into UTF-8.
func decodeText(b []byte) string {
	if len(b) >= 2 && b[0] == 0xfe && b[1] == 0xff {
		u := make([]uint16, 0, len(b)/2)
		for i := 2; i+1 < len(b); i += 2 {
			u = append(u, uint16(b[i])<<8|uint16(b[i+1]))
		}
		return string(utf16.Decode(u))
	}
	return string(b)
}

// isInt reports whether t is a word made only of digits.
func isInt(t token) bool {
	if t.kind != tWord {
		return false
	}
	_, err := strconv.ParseUint(t.val, 10, 31)
	return err == nil
}

// refAt returns the object number when toks[i:] is "N G R".
func refAt(toks []token, i int) (int, bool) {
	if i+2 >= len(toks) || !isInt(toks[i]) || !isInt(toks[i+1]) || toks[i+2].kind != tWord || toks[i+2].val != "R" {
		return 0, false
	}
	n, _ := strconv.Atoi(toks[i].val)
	return n, true
}
