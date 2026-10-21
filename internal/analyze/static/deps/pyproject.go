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
		t.kind = valueKindOf(t.section, key)
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

// valueKindOf says how to read the value of key in section.
func valueKindOf(section, key string) int {
	switch {
	case section == "project" && key == "dependencies", section == "project.optional-dependencies",
		section == "dependency-groups", section == "build-system" && key == "requires":
		return valueRequirement
	case (section == "tool.uv" || section == "tool.uv.pip") && (key == "index-url" || key == "extra-index-url"):
		return valueIndex
	case (section == "tool.uv" || section == "tool.uv.pip") && key == "find-links":
		return valueFindLinks
	case section == "tool.uv" && key == "index":
		return valueIndexTable
	case (section == "tool.uv.index" || section == "tool.poetry.source") && key == "url":
		return valueIndex
	case isSources(section):
		if strings.HasSuffix(key, ".git") || strings.HasSuffix(key, ".url") {
			return valueSourceString
		}
		return valueSources
	case isSources(section[:max(0, strings.LastIndex(section, "."))]) && (key == "git" || key == "url"):
		return valueSourceString
	}
	return valueNone
}

// isSources reports whether section holds one entry per dependency: the uv
// sources and the Poetry dependency tables.
func isSources(section string) bool {
	return section == "tool.uv.sources" || section == "tool.poetry.dependencies" || section == "tool.poetry.dev-dependencies" ||
		strings.HasPrefix(section, "tool.poetry.group.") && strings.HasSuffix(section, ".dependencies")
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
		case t.kind == valueRequirement && !l.inTable:
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
