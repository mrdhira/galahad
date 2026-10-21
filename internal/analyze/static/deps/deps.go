// Package deps finds typosquatted dependency names and dependencies that come
// from outside the default package registries. It reads package.json,
// package-lock.json, yarn.lock, pyproject.toml, uv.toml and pip requirements
// files.
//
// A requirements file is any requirements*.txt, any .txt under a requirements
// directory, and any other .txt that looks like one (see looksLikeRequirements).
// That covers the files a requirements file pulls in with -r or -c, because an
// analyzer sees one file at a time.
package deps

import (
	"bytes"
	"context"
	_ "embed" // popular package snapshots
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"unicode"

	"github.com/mrdhira/galahad/internal/analyze"
	"github.com/mrdhira/galahad/internal/protocol"
)

var (
	ruleTypo  = protocol.Rule{ID: "GAL-DEPS-001", Severity: protocol.SeverityHigh, Title: "Likely typosquat of a popular package", Attack: "T1195.001"}
	ruleURL   = protocol.Rule{ID: "GAL-DEPS-002", Severity: protocol.SeverityMedium, Title: "Dependency from git or URL instead of the registry", Attack: "T1195.001"}
	ruleLock  = protocol.Rule{ID: "GAL-DEPS-003", Severity: protocol.SeverityMedium, Title: "Lockfile resolves from a non-default host", Attack: "T1195.001"}
	ruleIndex = protocol.Rule{ID: "GAL-DEPS-004", Severity: protocol.SeverityMedium, Title: "Custom Python package index", Attack: "T1195.001"}
)

// Snapshots of widely used packages; the source and date are in each file header.
var (
	//go:embed top-npm.txt
	npmSnapshot string
	//go:embed top-pypi.txt
	pypiSnapshot string

	topNpm  = load(npmSnapshot)
	topPypi = load(pypiSnapshot)
)

const (
	maxJSONDepth = 32
	minSquatLen  = 5 // shortest popular name a one-edit match is made against
)

var (
	npmHosts  = map[string]bool{"registry.npmjs.org": true}
	yarnHosts = map[string]bool{"registry.npmjs.org": true, "registry.yarnpkg.com": true}
	pypiHosts = map[string]bool{"pypi.org": true, "files.pythonhosted.org": true}

	depSections  = map[string]bool{"dependencies": true, "devdependencies": true, "optionaldependencies": true, "peerdependencies": true}
	npmShort     = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(#.*)?$`)
	pyName       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*`)
	pySeparators = regexp.MustCompile(`[-_.]+`)
	pyScheme     = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*://`)
	errDepth     = errors.New("nested too deeply")
)

type analyzer struct{}

// New returns the dependency analyzer.
func New() analyze.Analyzer { return analyzer{} }

func (analyzer) Name() string { return "deps" }

func (analyzer) Analyze(ctx context.Context, f analyze.File) (analyze.Output, error) {
	var scan func(context.Context, analyze.File) ([]protocol.Finding, error)
	name := strings.ToLower(f.Name)
	switch {
	case name == "package.json":
		scan = packageJSON
	case name == "package-lock.json":
		scan = packageLock
	case name == "yarn.lock":
		scan = yarnLock
	case name == "pyproject.toml":
		scan = pyproject
	case name == "uv.toml":
		scan = uvToml
	case strings.HasPrefix(name, "requirements") && strings.HasSuffix(name, ".txt"),
		strings.HasSuffix(name, ".txt") && (inRequirementsDir(f.Path) || looksLikeRequirements(f.Data)):
		scan = requirements
	default:
		return analyze.Output{}, nil
	}
	var out analyze.Output
	if len(f.Data) > analyze.MaxConfigSize && name != "package-lock.json" && name != "yarn.lock" {
		out.Skips = append(out.Skips, protocol.Skip{Path: f.Path, Reason: protocol.SkipTooLarge})
		return out, nil
	}
	findings, err := scan(ctx, f)
	out.Findings = findings
	switch {
	case ctx.Err() != nil:
		return out, ctx.Err()
	case errors.Is(err, errDepth):
		out.Skips = append(out.Skips, protocol.Skip{Path: f.Path, Reason: protocol.SkipDepth})
	case err != nil:
		out.Skips = append(out.Skips, protocol.Skip{Path: f.Path, Reason: protocol.SkipParseError})
	}
	return out, nil
}

func packageJSON(_ context.Context, f analyze.File) ([]protocol.Finding, error) {
	members, err := walkJSON(f.Data)
	var found []protocol.Finding
	for _, m := range members {
		if len(m.path) != 2 || !depSections[strings.ToLower(m.path[0])] {
			continue
		}
		name, spec := m.path[1], strings.TrimSpace(m.val)
		lower := strings.ToLower(spec)
		if strings.HasPrefix(lower, "file:") || strings.HasPrefix(lower, "workspace:") || strings.HasPrefix(lower, "link:") {
			continue
		}
		if isNpmRemote(lower, spec) && !full(found, ruleURL) {
			found = append(found, ruleURL.Finding(analyze.EvidenceAt(f, m.off)))
		}
		if alias, ok := strings.CutPrefix(lower, "npm:"); ok {
			name = aliasTarget(alias)
		}
		if npmSquat(name) && !full(found, ruleTypo) {
			found = append(found, ruleTypo.Finding(analyze.EvidenceAt(f, m.off)))
		}
	}
	return found, err
}

func packageLock(_ context.Context, f analyze.File) ([]protocol.Finding, error) {
	members, err := walkJSON(f.Data)
	var found []protocol.Finding
	for _, m := range members {
		if len(m.path) == 3 && m.path[0] == "packages" && m.path[2] == "resolved" && foreignHost(m.val, npmHosts) {
			if full(found, ruleLock) {
				break
			}
			found = append(found, ruleLock.Finding(analyze.EvidenceAt(f, m.off)))
		}
	}
	return found, err
}

// full reports whether found holds protocol.MaxFindingsPerRulePerFile findings of
// rule r. The engine keeps no more than that, and EvidenceAt counts lines from the
// start of the file, so building evidence for every finding of a large file is
// quadratic.
func full(found []protocol.Finding, r protocol.Rule) bool {
	n := 0
	for _, fd := range found {
		if fd.RuleID == r.ID {
			n++
		}
	}
	return n >= protocol.MaxFindingsPerRulePerFile
}

func yarnLock(ctx context.Context, f analyze.File) ([]protocol.Finding, error) {
	var found []protocol.Finding
	err := eachLine(ctx, f, func(line string, n int) {
		rest, ok := strings.CutPrefix(strings.TrimSpace(line), "resolved ")
		if !ok {
			return
		}
		val, _, _ := strings.Cut(strings.Trim(strings.TrimSpace(rest), `"`), "#")
		if foreignHost(val, yarnHosts) {
			if full(found, ruleLock) {
				return
			}
			found = append(found, ruleLock.Finding(where{f.Path, n, line}.evidence()))
		}
	})
	return found, err
}

func requirements(ctx context.Context, f analyze.File) ([]protocol.Finding, error) {
	var found []protocol.Finding
	err := eachLine(ctx, f, func(line string, n int) {
		s := strings.TrimSpace(line)
		if i := strings.Index(s, " #"); i >= 0 {
			s = strings.TrimSpace(s[:i])
		}
		if s == "" || s[0] == '#' {
			return
		}
		at := where{f.Path, n, line}
		if s[0] == '-' {
			opt, val := splitOption(s)
			switch opt {
			case "-i", "--index-url", "--extra-index-url":
				if foreignHost(val, pypiHosts) || !strings.Contains(val, "://") {
					found = append(found, ruleIndex.Finding(at.evidence()))
				}
				return
			case "-f", "--find-links":
				if foreignHost(val, pypiHosts) {
					found = append(found, ruleIndex.Finding(at.evidence()))
				}
				return
			case "-e", "--editable":
				s = val
			default:
				return
			}
		}
		found = append(found, requirement(s, at)...)
	})
	return found, err
}

// How much of an unnamed .txt file looksLikeRequirements reads.
const (
	sniffSize  = 64 << 10
	sniffLines = 50
	sniffWidth = 1000
)

var (
	pipOption    = regexp.MustCompile(`^--?[A-Za-z][A-Za-z-]*(?:[= \t]\S.*)?$`)
	pipStrongOpt = regexp.MustCompile(`^(?:-[rceif]\b|--(?:requirement|constraint|editable|index-url|extra-index-url|find-links|trusted-host)\b)`)
	reqVersioned = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*\s*(?:\[[A-Za-z0-9._, -]*\])?\s*((?:(?:===|==|~=|!=|<=|>=|<|>)\s*[A-Za-z0-9.*+!_-]+\s*,?\s*)*)(?:;.*)?$`)
	reqDirectURL = regexp.MustCompile(`^(?:[A-Za-z0-9][A-Za-z0-9._-]*\s*(?:\[[A-Za-z0-9._, -]*\])?\s*@\s*[A-Za-z][A-Za-z0-9+.-]*://\S+|git\+\S+)(?:\s+;.*)?$`)
	reqBareURL   = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*://\S+$`)
)

// inRequirementsDir reports whether p has a directory named requirements.
func inRequirementsDir(p string) bool {
	dirs := strings.Split(strings.ToLower(strings.ReplaceAll(p, "!/", "/")), "/")
	return slices.Contains(dirs[:len(dirs)-1], "requirements")
}

// looksLikeRequirements reports whether the start of a .txt file reads as a pip
// requirements file. Its first 50 non-comment lines must all be pip options or
// requirement specifiers, and at least one must be clearly pip: an option such
// as -r or --index-url, a version pin such as name==1.0, or name @ url. Bare
// package names, bare URLs and e-mail addresses on their own do not count, so
// README.txt, LICENSE.txt, notes and word or link lists are not requirements.
func looksLikeRequirements(data []byte) bool {
	data = data[:min(len(data), sniffSize)]
	seen, strong := 0, false
	for len(data) > 0 && seen < sniffLines {
		line, rest, _ := bytes.Cut(data, []byte{'\n'})
		data = rest
		s := strings.TrimSpace(string(line))
		if i := strings.Index(s, " #"); i >= 0 {
			s = strings.TrimSpace(s[:i])
		}
		s = strings.TrimSpace(strings.TrimSuffix(s, "\\"))
		if s == "" || s[0] == '#' {
			continue
		}
		seen++
		var ok, pinned bool
		switch m := reqVersioned.FindStringSubmatch(s); {
		case len(s) > sniffWidth:
		case s[0] == '-':
			ok, pinned = pipOption.MatchString(s), pipStrongOpt.MatchString(s)
		case reqDirectURL.MatchString(s):
			ok, pinned = true, true
		case m != nil:
			ok, pinned = true, strings.TrimSpace(m[1]) != ""
		default:
			ok = reqBareURL.MatchString(s)
		}
		if !ok {
			return false
		}
		strong = strong || pinned
	}
	return strong
}

// requirement checks one requirement specifier: a URL requirement and the name.
func requirement(s string, at where) []protocol.Finding {
	var found []protocol.Finding
	spec, name := strings.ToLower(s), ""
	if !pyScheme.MatchString(s) && !strings.HasPrefix(spec, "git+") {
		name = pyName.FindString(s)
		spec = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(s[len(name):]), "@")))
		for _, ext := range []string{".whl", ".gz", ".zip"} {
			if strings.HasSuffix(strings.ToLower(name), ext) {
				name = "" // an archive file name, not a project name
			}
		}
	}
	if (strings.Contains(spec, "://") || strings.HasPrefix(spec, "git+")) && !strings.HasPrefix(spec, "file:") {
		found = append(found, ruleURL.Finding(at.evidence()))
	}
	if name != "" && topPypi.squat(pypiName(name)) {
		found = append(found, ruleTypo.Finding(at.evidence()))
	}
	return found
}

// splitOption splits "--opt value", "--opt=value", "--opt<TAB>value", "-o value" and "-ovalue".
// Long options that pip accepts abbreviated are expanded to their full name.
func splitOption(s string) (opt, val string) {
	if !strings.HasPrefix(s, "--") {
		opt, val = s[:min(2, len(s))], s[min(2, len(s)):]
	} else {
		end := strings.IndexFunc(s, func(r rune) bool { return r == '=' || unicode.IsSpace(r) })
		if end < 0 {
			end = len(s)
		}
		opt, val = s[:end], s[end:]
		for _, long := range []string{"--index-url", "--extra-index-url", "--find-links", "--editable"} {
			if len(opt) >= 5 && strings.HasPrefix(long, opt) {
				opt = long
			}
		}
	}
	val = strings.TrimSpace(val)
	return opt, strings.TrimSpace(strings.TrimPrefix(val, "="))
}

// where is a line of a file: its path, 1-based number and text. Its evidence is
// built only for a finding, because counting lines from the start of the file
// for every line read is quadratic.
type where struct {
	path string
	n    int
	text string
}

func (w where) evidence() protocol.Evidence {
	return protocol.Evidence{Path: w.path, Line: w.n, Snippet: protocol.Snippet(strings.TrimSuffix(w.text, "\r"))}
}

// eachLine calls fn with every line, cut at MaxLineScan, and its 1-based number,
// and stops when ctx is done.
func eachLine(ctx context.Context, f analyze.File, fn func(line string, n int)) error {
	off := 0
	for n := 1; len(f.Data) > off; n++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		end := bytes.IndexByte(f.Data[off:], '\n')
		next := len(f.Data)
		if end >= 0 {
			next = off + end + 1
			end += off
		} else {
			end = len(f.Data)
		}
		line := f.Data[off:end]
		fn(string(line[:min(len(line), analyze.MaxLineScan)]), n)
		off = next
	}
	return nil
}

// isNpmRemote reports whether an npm version spec points at git or a URL.
func isNpmRemote(lower, spec string) bool {
	for _, p := range []string{"git+", "git://", "git@", "github:", "gitlab:", "bitbucket:", "gist:", "http://", "https://", "ssh://"} {
		if strings.HasPrefix(lower, p) {
			return true
		}
	}
	return npmShort.MatchString(spec) && !strings.HasPrefix(spec, "@")
}

// foreignHost reports whether raw is a URL whose host is not in allowed.
// Values that are not URLs (no scheme separator) are ignored.
func foreignHost(raw string, allowed map[string]bool) bool {
	if !strings.Contains(raw, "://") {
		return false
	}
	u, err := url.Parse(raw)
	return err != nil || !allowed[strings.ToLower(u.Hostname())]
}

// npmScopes are well-known scopes. Every package in one of them is treated as
// legitimate, and a scope one edit away from one is a typosquat of it.
var npmScopes = []string{
	"@angular", "@apollo", "@aws-cdk", "@aws-sdk", "@azure", "@babel", "@emotion", "@eslint",
	"@eslint-community", "@fortawesome", "@google-cloud", "@humanwhocodes", "@jest", "@jridgewell",
	"@mui", "@nestjs", "@npmcli", "@octokit", "@opentelemetry", "@playwright", "@reduxjs", "@rollup",
	"@sentry", "@sigstore", "@smithy", "@storybook", "@swc", "@tanstack", "@testing-library",
	"@tsconfig", "@types", "@typescript-eslint", "@vitejs", "@vue",
}

// npmSquat reports whether an npm package name looks like a popular package.
// A scoped name is compared by its scope: the bare name of a scoped package
// belongs to its owner, so it says nothing about the popular unscoped packages.
func npmSquat(name string) bool {
	name = strings.ToLower(name)
	scope, _, scoped := strings.Cut(name, "/")
	if !scoped || !strings.HasPrefix(name, "@") {
		return topNpm.squat(name)
	}
	if slices.Contains(npmScopes, scope) {
		return false
	}
	return slices.ContainsFunc(npmScopes, func(s string) bool { return len(s) > minSquatLen && oneEdit(scope, s) })
}

// pypiName applies the PEP 503 normalization.
func pypiName(name string) string {
	return pySeparators.ReplaceAllString(strings.ToLower(name), "-")
}

// popular is a snapshot of well-known package names.
type popular struct {
	names    map[string]bool
	stripped map[string]bool  // names without - _ .
	long     map[int][]string // names of at least minSquatLen characters, by length
}

func load(snapshot string) popular {
	p := popular{names: map[string]bool{}, stripped: map[string]bool{}, long: map[int][]string{}}
	for line := range strings.SplitSeq(snapshot, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' {
			continue
		}
		p.names[line] = true
		p.stripped[strip(line)] = true
		if len(line) >= minSquatLen {
			p.long[len(line)] = append(p.long[len(line)], line)
		}
	}
	return p
}

// squat reports whether name is not popular itself but looks like a popular
// name: one edit away from a name of minSquatLen or more characters, or the same
// once separators are dropped. A name shorter than minSquatLen+1 is only compared
// for separators, because short real names collide by chance (socks and sockjs).
func (p popular) squat(name string) bool {
	if p.names[name] {
		return false
	}
	if p.stripped[strip(name)] {
		return true
	}
	if len(name) <= minSquatLen {
		return false
	}
	// one edit changes the length by at most one
	for l := len(name) - 1; l <= len(name)+1; l++ {
		for _, n := range p.long[l] {
			if oneEdit(name, n) {
				return true
			}
		}
	}
	return false
}

// separators are dropped by strip. The replacer is built once: building it per
// name is most of the cost of a long requirements file.
var separators = strings.NewReplacer("-", "", "_", "", ".", "")

func strip(s string) string {
	return separators.Replace(s)
}

// oneEdit reports whether a and b are at Damerau-Levenshtein distance exactly 1:
// one insertion, deletion, substitution or swap of adjacent characters.
func oneEdit(a, b string) bool {
	if len(a) > len(b) {
		a, b = b, a
	}
	if len(b)-len(a) > 1 {
		return false
	}
	i := 0
	for i < len(a) && a[i] == b[i] {
		i++
	}
	switch {
	case i == len(a):
		return len(b) == len(a)+1
	case len(b) > len(a):
		return a[i:] == b[i+1:]
	}
	return a[i+1:] == b[i+1:] || (i+2 <= len(a) && a[i] == b[i+1] && a[i+1] == b[i] && a[i+2:] == b[i+2:])
}

// member is a string value in a JSON object: the keys leading to it and the
// offset just after the last key.
type member struct {
	path []string
	val  string
	off  int
}

// walkJSON lists every string member of every object in data, in file order,
// to a nesting depth of maxJSONDepth. On an error it returns what it read so far.
func walkJSON(data []byte) ([]member, error) {
	type frame struct{ obj, wantKey bool }
	dec := json.NewDecoder(bytes.NewReader(data))
	var (
		out    []member
		stack  []frame
		path   []string
		keyOff []int
	)
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			if len(stack) > 0 {
				err = io.ErrUnexpectedEOF
			} else {
				return out, nil
			}
		}
		if err != nil {
			return out, err
		}
		inObj := len(stack) > 0 && stack[len(stack)-1].obj
		switch v := tok.(type) {
		case json.Delim:
			if v == '{' || v == '[' {
				if len(stack) >= maxJSONDepth {
					return out, errDepth
				}
				stack = append(stack, frame{obj: v == '{', wantKey: v == '{'})
				continue
			}
			stack = stack[:len(stack)-1]
			if len(stack) > 0 && stack[len(stack)-1].obj {
				path, keyOff = path[:len(path)-1], keyOff[:len(keyOff)-1]
				stack[len(stack)-1].wantKey = true
			}
		default:
			switch {
			case inObj && stack[len(stack)-1].wantKey:
				key, _ := tok.(string)
				path, keyOff = append(path, key), append(keyOff, int(dec.InputOffset()))
				stack[len(stack)-1].wantKey = false
			case inObj:
				if s, ok := tok.(string); ok {
					out = append(out, member{path: append([]string(nil), path...), val: s, off: keyOff[len(keyOff)-1]})
				}
				path, keyOff = path[:len(path)-1], keyOff[:len(keyOff)-1]
				stack[len(stack)-1].wantKey = true
			}
		}
	}
}

// aliasTarget returns the package name in "name@range" (the part after "npm:").
func aliasTarget(s string) string {
	if i := strings.LastIndex(s, "@"); i > 0 {
		return s[:i]
	}
	return s
}
