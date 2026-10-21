package autoexec

import (
	"bytes"
	"encoding/json"
	"net/url"
	"path"
	"regexp"
	"strings"

	"github.com/mrdhira/galahad/internal/analyze/static/signals"
)

const maxBlock = 4096 // bytes read for one Prisma generator block or one gyp expansion

var (
	scopedRegistryRE = regexp.MustCompile(`^@[^:\s]+:registry$`)
	yamlKeyRE        = regexp.MustCompile(`^(\s*)(?:-\s+)?["']?([A-Za-z_][A-Za-z0-9_-]*)["']?\s*:(?:\s+(.*))?$`)
	yamlKeysRE       = regexp.MustCompile(`(?:^|[\s{,\[])["']?(?:yarnPath|npmRegistryServer|plugins)["']?\s*:`)
	yamlItemRE       = regexp.MustCompile(`^\s*-\s+(\S.*)$`)
	yarnReleaseRE    = regexp.MustCompile(`^\.yarn/releases/yarn-[A-Za-z0-9._-]+\.c?js$`)
	yarnPluginRE     = regexp.MustCompile(`^\.yarn/plugins/@yarnpkg/plugin-[A-Za-z0-9._-]+\.c?js$`)
	generatorRE      = regexp.MustCompile(`\bgenerator\s+[A-Za-z_][A-Za-z0-9_]*\s*\{`)
	providerRE       = regexp.MustCompile(`\bprovider\s*=\s*`)
	npmNameRE        = regexp.MustCompile(`^(?:@[a-z0-9][a-z0-9_.~-]*/)?[a-z0-9][a-z0-9_.~-]*$`)
	nodeModuleRE     = regexp.MustCompile(`^node node_modules/(?:@[a-z0-9][a-z0-9_.~-]*/)?[a-z0-9][a-z0-9_.~-]*/?$`)
	gypExpandRE      = regexp.MustCompile(`[<>^]!@?(?:pymod_do_main)?\(`)
	gypActionsRE     = regexp.MustCompile(`["']actions["']\s*:`)

	// gypKnownRE matches the expansions that the common addons use to find the
	// include directories of node-addon-api and nan, and to ask pkg-config.
	gypKnownRE  = regexp.MustCompile(`^(?:node -[pe] "require\('node-addon-api'\)\.(?:include|include_dir|gyp|targets)"|node -e "require\('nan'\)"|pkg-config(?: --?[a-z][a-z-]*| [A-Za-z0-9_.+-]+)+(?: \| sed s/-I//g)?)$`)
	gypUnescape = strings.NewReplacer(`\"`, `"`, `\'`, `'`)

	// defaultRegistries are the hosts npm and Yarn use when nothing is configured.
	defaultRegistries = map[string]bool{"registry.npmjs.org": true, "registry.yarnpkg.com": true}
)

// defaultRegistry reports whether v is empty or a URL on a default registry host.
func defaultRegistry(v string) bool {
	if v == "" {
		return true
	}
	u, err := url.Parse(v)
	return err == nil && defaultRegistries[strings.ToLower(u.Hostname())]
}

// inRepo reports whether a path setting is relative, so it points into the repository.
func inRepo(v string) bool {
	if v == "" || strings.ContainsRune(`/\~$%`, rune(v[0])) {
		return false
	}
	return len(v) < 2 || v[1] != ':'
}

// unquote trims blanks and one pair of quotes.
func unquote(v string) string {
	v = strings.TrimSpace(v)
	if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
		return v[1 : len(v)-1]
	}
	return v
}

// iniValue reads a key or value the way the ini package of npm does. A value in
// double quotes is decoded as JSON and one in single quotes is taken as is.
// Otherwise it ends at the first ; or # that is not escaped with a backslash.
func iniValue(v string) string {
	v = strings.TrimSpace(v)
	if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
		if v[0] == '\'' {
			v = v[1 : len(v)-1]
		}
		var decoded string
		if json.Unmarshal([]byte(v), &decoded) == nil {
			return decoded
		}
		return v
	}
	var b strings.Builder
	for i := 0; i < len(v); i++ {
		switch c := v[i]; c {
		case ';', '#':
			return strings.TrimSpace(b.String())
		case '\\':
			if i+1 < len(v) && (v[i+1] == '\\' || v[i+1] == ';' || v[i+1] == '#') {
				i++
				b.WriteByte(v[i])
				continue
			}
			b.WriteByte(c)
		default:
			b.WriteByte(c)
		}
	}
	return strings.TrimSpace(b.String())
}

// npmrc reads the keys of an .npmrc that move where npm fetches from or what it runs.
func (s *scan) npmrc() {
	for _, l := range splitLines(s.f.Data) {
		if s.done() {
			return
		}
		text := strings.TrimSpace(l.text)
		if text == "" || text[0] == '#' || text[0] == ';' || (text[0] == '[' && text[len(text)-1] == ']') {
			continue
		}
		key, value, _ := strings.Cut(text, "=")
		key, value = strings.ToLower(iniValue(key)), iniValue(value)
		switch {
		case key == "registry", scopedRegistryRE.MatchString(key):
			if !defaultRegistry(value) {
				s.add(ruleConfig, l.off)
			}
		case key == "node-options", key == "script-shell", key == "git", key == "node-gyp":
			if value != "" {
				s.add(ruleConfig, l.off)
				s.riskAt(value, l.off)
			}
		case key == "userconfig", key == "globalconfig", key == "pnpmfile", key == "global-pnpmfile":
			if value != "" {
				s.add(ruleConfig, l.off)
			}
		case key == "prefix", key == "cache":
			if inRepo(value) {
				s.add(ruleConfig, l.off)
			}
		}
	}
}

// yarnrcPair splits a Yarn 1 .yarnrc line into key and value. The key may be
// quoted, and the separator is a blank, = or :.
func yarnrcPair(text string) (key, value string) {
	if q := text[0]; q == '"' || q == '\'' {
		if j := strings.IndexByte(text[1:], q); j >= 0 {
			return text[1 : j+1], unquote(strings.TrimLeft(text[j+2:], " \t=:"))
		}
	}
	i := strings.IndexAny(text, " \t=:")
	if i < 0 {
		return text, ""
	}
	return text[:i], unquote(strings.TrimLeft(text[i:], " \t=:"))
}

// yarnrc reads a Yarn 1 .yarnrc: "key value" lines.
func (s *scan) yarnrc() {
	for _, l := range splitLines(s.f.Data) {
		if s.done() {
			return
		}
		text := strings.TrimSpace(l.text)
		if text == "" || text[0] == '#' {
			continue
		}
		key, value := yarnrcPair(text)
		switch {
		case key == "yarn-path":
			s.committed(value, yarnReleaseRE, l.off)
		case key == "registry", scopedRegistryRE.MatchString(key):
			if !defaultRegistry(value) {
				s.add(ruleConfig, l.off)
			}
		}
	}
}

// committed reports a tool file that Yarn loads from the repo. A file where
// Yarn Berry puts its own releases and plugins is standard practice and only
// listed; any other path is a change to what install runs.
func (s *scan) committed(value string, standard *regexp.Regexp, off int) {
	if value == "" {
		return
	}
	if standard.MatchString(path.Clean(strings.ReplaceAll(value, "\\", "/"))) {
		s.add(ruleVendored, off)
		return
	}
	s.add(ruleConfig, off)
}

// yarnrcYML reads a Yarn Berry .yarnrc.yml with a line reader: the top-level
// yarnPath and plugins, and npmRegistryServer at any level (npmScopes entries).
// A scalar may sit on the next, more indented line. It fails closed: a key the
// reader does not consume (in a flow mapping, nested, or in a shape it does not
// read) is reported.
func (s *scan) yarnrcYML() {
	lines := splitLines(s.f.Data)
	inPlugins := false
	for i, l := range lines {
		if s.done() {
			return
		}
		text := l.text
		if j := strings.Index(text, " #"); j >= 0 {
			text = text[:j]
		}
		trimmed := strings.TrimSpace(text)
		if trimmed == "" || trimmed[0] == '#' {
			continue
		}
		if text[0] != ' ' && text[0] != '\t' && text[0] != '-' {
			inPlugins = false
		}
		consumed := false
		if m := yamlKeyRE.FindStringSubmatch(text); m != nil {
			key, value := m[2], unquote(m[3])
			scalar := func() string {
				if value != "" && !blockScalar[value] {
					return value
				}
				return nextScalar(lines[i:])
			}
			switch {
			case key == "yarnPath" && m[1] == "":
				consumed = true
				s.committed(scalar(), yarnReleaseRE, l.off)
			case key == "npmRegistryServer":
				consumed = true
				if !defaultRegistry(scalar()) {
					s.add(ruleConfig, l.off)
				}
			case key == "plugins" && m[1] == "":
				consumed, inPlugins = true, true
				if (strings.HasPrefix(value, "[") && value != "[]") || (strings.HasPrefix(value, "{") && value != "{}") {
					s.add(ruleConfig, l.off) // a flow collection is not read
				}
			case key == "path" && inPlugins:
				consumed = true
				s.committed(scalar(), yarnPluginRE, l.off)
			}
		} else if item := yamlItemRE.FindStringSubmatch(text); inPlugins && item != nil {
			consumed = true
			s.committed(unquote(item[1]), yarnPluginRE, l.off)
		}
		if !consumed && yamlKeysRE.MatchString(text) {
			s.add(ruleConfig, l.off)
		}
	}
}

// nextScalar returns the plain scalar on the line after lines[0] when that line
// is more indented than lines[0], or "".
func nextScalar(lines []line) string {
	base := len(lines[0].text) - len(strings.TrimLeft(lines[0].text, " \t"))
	for _, next := range lines[1:] {
		text := next.text
		if j := strings.Index(text, " #"); j >= 0 {
			text = text[:j]
		}
		trimmed := strings.TrimSpace(text)
		if trimmed == "" || trimmed[0] == '#' {
			continue
		}
		if len(text)-len(strings.TrimLeft(text, " \t")) > base && trimmed[0] != '-' && !yamlKeyRE.MatchString(text) {
			return unquote(trimmed)
		}
		return ""
	}
	return ""
}

// blankComments returns data as text with the comments that start with marker
// blanked, keeping every byte at its offset. Quoted text is kept; a quote ends at
// the end of its line. For the # marker (Python syntax) a triple-quoted string
// runs over lines and is kept whole.
func blankComments(data []byte, marker string) string {
	b := bytes.Clone(data)
	var quote, triple byte
	for i := 0; i < len(b); i++ {
		c := b[i]
		switch {
		case triple != 0:
			switch {
			case c == '\\':
				i++
			case c == triple && i+2 < len(b) && b[i+1] == c && b[i+2] == c:
				i += 2
				triple = 0
			}
		case quote != 0:
			switch c {
			case '\\':
				i++
			case quote, '\n':
				quote = 0
			}
		case c == '"' || c == '\'':
			if marker == "#" && i+2 < len(b) && b[i+1] == c && b[i+2] == c {
				triple = c
				i += 2
			} else {
				quote = c
			}
		case bytes.HasPrefix(b[i:], []byte(marker)):
			for ; i < len(b) && b[i] != '\n'; i++ {
				b[i] = ' '
			}
		}
	}
	return string(b)
}

// prisma reads the generator blocks of a Prisma schema. Prisma starts a provider
// that is not a plain package name as a command.
func (s *scan) prisma() {
	text := blankComments(s.f.Data, "//")
	for _, g := range generatorRE.FindAllStringIndex(text, signals.MaxMatches) {
		if s.done() {
			return
		}
		body := text[g[1]:min(len(text), g[1]+maxBlock)]
		body = body[:blockEnd(body)]
		loc := providerRE.FindStringIndex(body)
		if loc == nil {
			continue
		}
		value, plain := providerValue(body[loc[1]:])
		if !plain {
			s.add(rulePrisma, g[1]+loc[0])
			s.riskAt(value, g[1]+loc[0])
		}
	}
}

// blockEnd returns the offset of the first closing brace outside a string.
func blockEnd(body string) int {
	inString := false
	for i := 0; i < len(body); i++ {
		switch body[i] {
		case '\\':
			i++
		case '"':
			inString = !inString
		case '\n':
			inString = false
		case '}':
			if !inString {
				return i
			}
		}
	}
	return len(body)
}

// providerValue returns the value that follows "provider =" and whether it is a
// quoted npm package name, or "node" and the path of an installed package.
func providerValue(rest string) (value string, plain bool) {
	if !strings.HasPrefix(rest, `"`) {
		line, _, _ := strings.Cut(rest, "\n")
		return strings.TrimSpace(line), false
	}
	for i := 1; i < len(rest) && rest[i] != '\n'; i++ {
		switch rest[i] {
		case '\\':
			i++
		case '"':
			value = rest[1:i]
			lower := strings.ToLower(value)
			return value, npmNameRE.MatchString(lower) || nodeModuleRE.MatchString(lower)
		}
	}
	return rest[1:], false
}

// gyp reads a node-gyp file: <!( and <!@( run a command while gyp reads the
// file, which npm install does for any package with a binding.gyp. >!( and ^!(
// run it in the later phases. The expansions that find node-addon-api, nan and
// pkg-config are the common benign use and are not reported, but are graded.
func (s *scan) gyp() {
	text := blankComments(s.f.Data, "#")
	for _, loc := range gypExpandRE.FindAllStringIndex(text, signals.MaxMatches) {
		if s.done() {
			return
		}
		cmd := expansion(text[loc[1]:min(len(text), loc[1]+maxBlock)])
		if text[loc[0]] != '<' || strings.Contains(text[loc[0]:loc[1]], "pymod") || !gypKnownRE.MatchString(cmd) {
			s.add(ruleGypExpand, loc[0])
		}
		s.riskAt(cmd, loc[0])
	}
	for _, loc := range gypActionsRE.FindAllStringIndex(text, signals.MaxMatches) {
		s.add(ruleGypAction, loc[0])
	}
}

// expansion returns the text up to the parenthesis that closes the expansion,
// with escaped quotes unescaped and blanks trimmed.
func expansion(rest string) string {
	depth := 1
	for i := 0; i < len(rest); i++ {
		switch rest[i] {
		case '(':
			depth++
		case ')':
			if depth--; depth == 0 {
				return strings.TrimSpace(gypUnescape.Replace(rest[:i]))
			}
		}
	}
	return strings.TrimSpace(gypUnescape.Replace(rest))
}
