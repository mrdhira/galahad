package deps

import (
	"context"
	"regexp"
	"strings"

	"github.com/mrdhira/galahad/internal/analyze"
	"github.com/mrdhira/galahad/internal/protocol"
)

// How a string at a TOML path is read.
const (
	valueNone         = iota
	valueRequirement  // PEP 508 requirement string
	valueIndex        // index URL: a custom host or a path is a custom index
	valueFindLinks    // find-links: only a URL on another host is custom
	valueSourceString // git or url of a dependency source
)

// Limits of the TOML reader. A value nested deeper than maxTOMLDepth, or an
// inline table key whose path grows past maxTOMLPath bytes, stops the read with
// errDepth, so the file is reported as a skip that may hide content.
const (
	maxTOMLDepth = 32
	maxTOMLPath  = 1024
)

// tomlContinuation is a TOML line continuation in a multi-line string: a
// backslash and the blanks and newlines after it.
var tomlContinuation = regexp.MustCompile(`\\[ \t\r\n]+`)

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
// may continue over lines while its brackets are open or a multi-line string
// is. Every string is classified by its full path: the section, the dotted key
// and the inline table keys above it.
type toml struct {
	f         analyze.File
	prefix    string
	section   string
	base      string          // path of the key being read
	frames    []frame         // open brackets and braces of that value
	word      string          // last bare word, the key if "=" follows
	off       int             // offset of the line being read
	multi     byte            // quote of the multi-line string that is open at the end of the line
	multiText strings.Builder // its text so far
	multiPath string          // its path
	multiOff  int             // where it opened
	found     []protocol.Finding
	err       error // errDepth once a limit is hit; the rest of the file is not read
}

// frame is an open bracket or brace. outer is the path of the value it opens,
// path the path of the strings in it: outer plus the latest key of a table.
type frame struct {
	table bool
	outer string
	path  string
}

// lit is a string of a value and its path.
type lit struct{ val, path string }

func readTOML(ctx context.Context, f analyze.File, prefix string) ([]protocol.Finding, error) {
	t := &toml{f: f, prefix: prefix, section: prefix}
	err := eachLine(ctx, f, t.line)
	if err == nil {
		err = t.err
	}
	return t.found, err
}

func (t *toml) line(line string, off int) {
	if t.err != nil {
		return
	}
	if t.multi != 0 {
		// inside a multi-line string: brackets and tables there are text
		end := strings.Index(line, strings.Repeat(string(t.multi), 3))
		if end < 0 {
			t.multiText.WriteString(line)
			t.multiText.WriteByte('\n')
			return
		}
		t.multiText.WriteString(line[:end])
		text := tomlContinuation.ReplaceAllString(t.multiText.String(), "")
		t.multi = 0
		t.multiText.Reset()
		t.apply(lit{val: strings.TrimSpace(text), path: t.multiPath}, analyze.EvidenceAt(t.f, t.multiOff))
		t.value(line[end+3:], off)
		return
	}
	if len(t.frames) > 0 {
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
		t.base = strings.TrimPrefix(t.section+"."+key, ".")
		t.frames, t.word = nil, ""
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

// valueKindOf says how to read a string at a full path, so "[tool]" with
// "uv.sources.x = ..." and "[tool.uv.sources]" with "x = ..." are the same place.
func valueKindOf(p string) int {
	switch {
	case strings.HasSuffix(p, ".include-group"):
		return valueNone
	case p == "project.dependencies", p == "build-system.requires", p == "project.optional-dependencies", p == "dependency-groups",
		p == "tool.uv.dev-dependencies", p == "tool.uv.override-dependencies", p == "tool.uv.constraint-dependencies",
		strings.HasPrefix(p, "project.optional-dependencies."), strings.HasPrefix(p, "dependency-groups."):
		return valueRequirement
	case p == "tool.uv.index-url", p == "tool.uv.extra-index-url", p == "tool.uv.pip.index-url", p == "tool.uv.pip.extra-index-url",
		p == "tool.uv.index.url", p == "tool.poetry.source.url":
		return valueIndex
	case p == "tool.uv.find-links", p == "tool.uv.pip.find-links":
		return valueFindLinks
	}
	if rest, ok := sourcesRest(p); ok && (strings.HasSuffix(rest, ".git") || strings.HasSuffix(rest, ".url")) {
		return valueSourceString
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
// continuation line, and records a finding for each string that calls for one.
func (t *toml) value(text string, off int) {
	t.off = off
	ev := analyze.EvidenceAt(t.f, off)
	for _, l := range t.scan(text) {
		t.apply(l, ev)
	}
}

// apply records the finding for a string at its path, if any.
func (t *toml) apply(l lit, ev protocol.Evidence) {
	if l.val == "" {
		return
	}
	switch valueKindOf(l.path) {
	case valueRequirement:
		t.found = append(t.found, requirement(l.val, ev)...)
	case valueIndex:
		if foreignHost(l.val, pypiHosts) || !strings.Contains(l.val, "://") {
			t.found = append(t.found, ruleIndex.Finding(ev))
		}
	case valueFindLinks:
		if foreignHost(l.val, pypiHosts) {
			t.found = append(t.found, ruleIndex.Finding(ev))
		}
	case valueSourceString:
		if !strings.HasPrefix(strings.ToLower(l.val), "file:") {
			t.found = append(t.found, ruleURL.Finding(ev))
		}
	}
}

// path is the path of the string being read: the key line and the key of every
// open inline table.
func (t *toml) path() string {
	if n := len(t.frames); n > 0 {
		return t.frames[n-1].path
	}
	return t.base
}

// scan returns the strings of text and keeps track of the open brackets, braces
// and inline table keys. At a limit it sets t.err and stops.
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
					t.multi, t.multiPath, t.multiOff = c, t.path(), t.off
					t.multiText.WriteString(text[i+3:])
					t.multiText.WriteByte('\n')
					return out
				}
				out = append(out, lit{val: text[i+3 : i+3+end], path: t.path()})
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
			out = append(out, lit{val: val, path: t.path()})
		case '[', '{':
			if len(t.frames) >= maxTOMLDepth {
				t.err = errDepth
				return out
			}
			p := t.path()
			t.frames = append(t.frames, frame{table: c == '{', outer: p, path: p})
		case ']', '}':
			if n := len(t.frames); n > 0 {
				t.frames = t.frames[:n-1]
			}
		case '=':
			if n := len(t.frames); n > 0 && t.frames[n-1].table {
				fr := &t.frames[n-1]
				fr.path = fr.outer
				if t.word != "" {
					if len(fr.outer)+1+len(t.word) > maxTOMLPath {
						t.err = errDepth
						return out
					}
					fr.path += "." + t.word
				}
			}
		case ',':
			if n := len(t.frames); n > 0 && t.frames[n-1].table {
				t.frames[n-1].path = t.frames[n-1].outer
			}
		case ' ', '\t':
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
