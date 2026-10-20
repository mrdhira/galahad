package autoexec

import (
	"encoding/json"
	"errors"
)

// Limits of the JSON reader. The size limit is analyze.MaxConfigSize.
const (
	maxJSONDepth = 64
	maxJSONNodes = 100000
)

// StripJSONC returns data with // and /* */ comments and trailing commas
// replaced by spaces. Newlines are kept and every other byte stays at its
// offset, so offsets and line numbers in the result match the input.
func StripJSONC(data []byte) []byte {
	out := make([]byte, len(data))
	copy(out, data)
	blank := func(from, to int) {
		for i := from; i < to; i++ {
			if out[i] != '\n' {
				out[i] = ' '
			}
		}
	}
	lastComma := -1 // offset of a comma not yet followed by a value
	for i := 0; i < len(data); {
		c := data[i]
		switch {
		case c == '"':
			lastComma = -1
			i++
			for i < len(data) && data[i] != '"' && data[i] != '\n' {
				if data[i] == '\\' {
					i++
				}
				i++
			}
			i++
		case c == '/' && i+1 < len(data) && data[i+1] == '/':
			j := i
			for j < len(data) && data[j] != '\n' {
				j++
			}
			blank(i, j)
			i = j
		case c == '/' && i+1 < len(data) && data[i+1] == '*':
			j := i + 2
			for j+1 < len(data) && (data[j] != '*' || data[j+1] != '/') {
				j++
			}
			j = min(j+2, len(data))
			blank(i, j)
			i = j
		case c == ',':
			lastComma = i
			i++
		case c == '}' || c == ']':
			if lastComma >= 0 {
				out[lastComma] = ' '
			}
			lastComma = -1
			i++
		case c == ' ' || c == '\t' || c == '\r' || c == '\n':
			i++
		default:
			lastComma = -1
			i++
		}
	}
	return out
}

// node is a parsed JSON value with the byte offset where it starts.
type node struct {
	kind  byte // 'o' object, 'a' array, 's' string, 'x' number, bool or null
	start int
	str   string   // 's'
	keys  []string // 'o'
	vals  []*node  // 'o' values parallel to keys; 'a' elements
}

// get returns the value of key in an object, or nil.
func (n *node) get(key string) *node {
	if n == nil || n.kind != 'o' {
		return nil
	}
	for i, k := range n.keys {
		if k == key {
			return n.vals[i]
		}
	}
	return nil
}

var errJSON = errors.New("invalid json")

// parseJSON parses comment-free JSON (see StripJSONC) within depth and node limits.
func parseJSON(b []byte) (*node, error) {
	p := &parser{b: b}
	n, err := p.value(0)
	if err != nil {
		return nil, err
	}
	p.space()
	if p.i != len(b) {
		return nil, errJSON
	}
	return n, nil
}

type parser struct {
	b     []byte
	i     int
	nodes int
}

func (p *parser) space() {
	for p.i < len(p.b) && (p.b[p.i] == ' ' || p.b[p.i] == '\t' || p.b[p.i] == '\r' || p.b[p.i] == '\n') {
		p.i++
	}
}

func (p *parser) value(depth int) (*node, error) {
	p.space()
	p.nodes++
	if depth > maxJSONDepth || p.nodes > maxJSONNodes || p.i >= len(p.b) {
		return nil, errJSON
	}
	n := &node{start: p.i}
	switch p.b[p.i] {
	case '{':
		n.kind = 'o'
		p.i++
		return n, p.members(n, '}', depth, true)
	case '[':
		n.kind = 'a'
		p.i++
		return n, p.members(n, ']', depth, false)
	case '"':
		s, err := p.str()
		n.kind, n.str = 's', s
		return n, err
	default:
		n.kind = 'x'
		for p.i < len(p.b) && p.b[p.i] != ',' && p.b[p.i] != '}' && p.b[p.i] != ']' && p.b[p.i] > ' ' {
			p.i++
		}
		if p.i == n.start {
			return nil, errJSON
		}
		return n, nil
	}
}

// members reads the entries of an object or array up to the closing byte.
func (p *parser) members(n *node, closer byte, depth int, object bool) error {
	p.space()
	if p.i < len(p.b) && p.b[p.i] == closer {
		p.i++
		return nil
	}
	for {
		p.space()
		if object {
			if p.i >= len(p.b) || p.b[p.i] != '"' {
				return errJSON
			}
			k, err := p.str()
			if err != nil {
				return err
			}
			p.space()
			if p.i >= len(p.b) || p.b[p.i] != ':' {
				return errJSON
			}
			p.i++
			n.keys = append(n.keys, k)
		}
		v, err := p.value(depth + 1)
		if err != nil {
			return err
		}
		n.vals = append(n.vals, v)
		p.space()
		if p.i >= len(p.b) {
			return errJSON
		}
		c := p.b[p.i]
		p.i++
		if c == closer {
			return nil
		}
		if c != ',' {
			return errJSON
		}
	}
}

// str reads a string literal starting at the opening quote.
func (p *parser) str() (string, error) {
	start := p.i
	p.i++
	for p.i < len(p.b) && p.b[p.i] != '"' {
		if p.b[p.i] == '\\' {
			p.i++
		}
		p.i++
	}
	if p.i >= len(p.b) {
		return "", errJSON
	}
	p.i++
	var s string
	if err := json.Unmarshal(p.b[start:p.i], &s); err != nil {
		return "", errJSON
	}
	return s, nil
}
