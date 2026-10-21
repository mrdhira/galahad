package deps

import (
	"context"
	"strings"

	"github.com/mrdhira/galahad/internal/analyze"
	"github.com/mrdhira/galahad/internal/protocol"
)

// How the strings of a TOML value are read.
const (
	valueNone         = iota
	valueRequirement  // PEP 508 requirement strings
	valueIndex        // index URLs: a custom host or a path is a custom index
	valueFindLinks    // find-links: only a URL on another host is custom
	valueIndexTable   // inline tables with a "url" index
	valueSources      // inline tables with a "git" or "url" source
	valueSourceString // a git or url key of a source table
)

// pyproject reads the dependency and index settings of a pyproject.toml:
// [project], [build-system], [dependency-groups], [tool.uv] and [tool.poetry].
func pyproject(ctx context.Context, f analyze.File) ([]protocol.Finding, error) {
	return readTOML(ctx, f, "")
}

// uvToml reads uv.toml, which holds the [tool.uv] table of pyproject.toml at its top level.
func uvToml(ctx context.Context, f analyze.File) ([]protocol.Finding, error) {
	return readTOML(ctx, f, "tool.uv")
}

// toml is a line reader for the parts of TOML that name dependencies. A value
// may continue over lines while its brackets are open.
type toml struct {
	f       analyze.File
	prefix  string
	section string
	kind    int // how the strings of the value being read are used
	open    int // brackets and braces of that value still open
	braces  int
	multi   byte   // quote of the multi-line string that is open at the end of the line
	key     string // inline table key before the next string
	word    string // last bare word, the key if "=" follows
	found   []protocol.Finding
}

// lit is a string of a value and, in an inline table, the key it belongs to.
type lit struct {
	val, key string
	inTable  bool
}

func readTOML(ctx context.Context, f analyze.File, prefix string) ([]protocol.Finding, error) {
	t := &toml{f: f, prefix: prefix, section: prefix}
	err := eachLine(ctx, f, t.line)
	return t.found, err
}

func (t *toml) line(line string, off int) {
	if t.multi != 0 {
		// inside a multi-line string: brackets and tables there are text
		end := strings.Index(line, strings.Repeat(string(t.multi), 3))
		if end < 0 {
			return
		}
		t.multi = 0
		t.value(line[end+3:], off)
		return
	}
	if t.open > 0 {
		t.value(line, off)
		return
	}
	s := strings.TrimSpace(line)
	switch {
	case s == "" || s[0] == '#':
	case s[0] == '[':
		name, _, _ := strings.Cut(strings.TrimLeft(s, "[ "), "]")
		name = strings.ToLower(strings.NewReplacer(`"`, "", "'", "", " ", "", "\t", "").Replace(name))
		t.section = strings.TrimPrefix(t.prefix+"."+name, ".")
	default:
		key, rest, ok := cutKey(s)
		if !ok {
			return
		}
		t.kind = valueKindOf(strings.TrimPrefix(t.section+"."+key, "."))
		t.open, t.braces, t.key, t.word = 0, 0, "", ""
		t.value(rest, off)
	}
}

// cutKey splits "key = value". Quotes around the key are dropped.
func cutKey(s string) (key, value string, ok bool) {
	quote := byte(0)
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
		case c == '=':
			key = strings.ToLower(strings.NewReplacer(`"`, "", "'", "", " ", "", "\t", "").Replace(s[:i]))
			return key, s[i+1:], key != ""
		}
	}
	return "", "", false
}

// valueKindOf says how to read the value at a full path: the section and the
// dotted key together, so "[tool]" with "uv.sources.x = ..." and "[tool.uv.sources]"
// with "x = ..." are the same place.
func valueKindOf(p string) int {
	switch {
	case p == "project.dependencies", p == "build-system.requires", p == "project.optional-dependencies", p == "dependency-groups",
		strings.HasPrefix(p, "project.optional-dependencies."), strings.HasPrefix(p, "dependency-groups."):
		return valueRequirement
	case p == "tool.uv.index-url", p == "tool.uv.extra-index-url", p == "tool.uv.pip.index-url", p == "tool.uv.pip.extra-index-url",
		p == "tool.uv.index.url", p == "tool.poetry.source.url":
		return valueIndex
	case p == "tool.uv.find-links", p == "tool.uv.pip.find-links":
		return valueFindLinks
	case p == "tool.uv.index":
		return valueIndexTable
	}
	if rest, ok := sourcesRest(p); ok {
		if strings.HasSuffix(rest, ".git") || strings.HasSuffix(rest, ".url") {
			return valueSourceString
		}
		return valueSources
	}
	return valueNone
}

// sourcesRest reports whether p is in a table with one entry per dependency, the
// uv sources or a Poetry dependency table, and returns the path below it.
func sourcesRest(p string) (string, bool) {
	for _, table := range []string{"tool.uv.sources", "tool.poetry.dependencies", "tool.poetry.dev-dependencies"} {
		if p == table {
			return "", true
		}
		if rest, ok := strings.CutPrefix(p, table+"."); ok {
			return rest, true
		}
	}
	group, ok := strings.CutPrefix(p, "tool.poetry.group.")
	if !ok {
		return "", false
	}
	_, below, _ := strings.Cut(group, ".") // the group name
	if below == "dependencies" {
		return "", true
	}
	return strings.CutPrefix(below, "dependencies.")
}

// value reads the strings of text, which is the rest of a key line or a
// continuation line, and records a finding for each string the kind calls out.
func (t *toml) value(text string, off int) {
	if t.kind == valueNone {
		t.scan(text) // keep the brackets balanced
		return
	}
	ev := analyze.EvidenceAt(t.f, off)
	for _, l := range t.scan(text) {
		switch {
		case l.val == "":
		case t.kind == valueRequirement && l.key != "include-group":
			t.found = append(t.found, requirement(l.val, ev)...)
		case t.kind == valueIndex && !l.inTable, t.kind == valueIndexTable && l.inTable && l.key == "url":
			if foreignHost(l.val, pypiHosts) || !strings.Contains(l.val, "://") {
				t.found = append(t.found, ruleIndex.Finding(ev))
			}
		case t.kind == valueFindLinks && !l.inTable:
			if foreignHost(l.val, pypiHosts) {
				t.found = append(t.found, ruleIndex.Finding(ev))
			}
		case t.kind == valueSources && l.inTable && (l.key == "git" || l.key == "url"), t.kind == valueSourceString && !l.inTable:
			if !strings.HasPrefix(strings.ToLower(l.val), "file:") {
				t.found = append(t.found, ruleURL.Finding(ev))
			}
		}
	}
}

// scan returns the strings of text and keeps count of the open brackets and braces.
func (t *toml) scan(text string) []lit {
	var out []lit
	for i := 0; i < len(text); i++ {
		switch c := text[i]; c {
		case '#':
			return out
		case '"', '\'':
			if triple := strings.Repeat(string(c), 3); strings.HasPrefix(text[i:], triple) {
				end := strings.Index(text[i+3:], triple)
				if end < 0 {
					t.multi = c
					return out
				}
				out = append(out, lit{val: text[i+3 : i+3+end], key: t.key, inTable: t.braces > 0})
				t.key = ""
				i += 3 + end + 2
				continue
			}
			end := i + 1
			for end < len(text) && text[end] != c {
				if c == '"' && text[end] == '\\' {
					end++
				}
				end++
			}
			val := text[i+1 : min(end, len(text))]
			i = end
			if rest := strings.TrimLeft(text[min(i+1, len(text)):], " \t"); strings.HasPrefix(rest, "=") {
				t.word = strings.ToLower(val) // a quoted key
				continue
			}
			out = append(out, lit{val: val, key: t.key, inTable: t.braces > 0})
			t.key = ""
		case '[':
			t.open++
		case '{':
			t.open++
			t.braces++
		case ']', '}':
			t.open = max(0, t.open-1)
			if c == '}' {
				t.braces = max(0, t.braces-1)
			}
		case '=':
			t.key = t.word
		case ',', ' ', '\t':
		default:
			start := i
			for i+1 < len(text) && !strings.ContainsRune(" \t,=[]{}#\"'", rune(text[i+1])) {
				i++
			}
			t.word = strings.ToLower(text[start : i+1])
		}
	}
	return out
}
