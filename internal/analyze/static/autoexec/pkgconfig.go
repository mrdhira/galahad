package autoexec

import (
	"bytes"
	"net/url"
	"path"
	"regexp"
	"strings"

	"github.com/mrdhira/galahad/internal/analyze/static/signals"
)

const (
	maxBlock   = 4096 // bytes read for one Prisma generator block or one gyp expansion
	maxPlugins = 100  // plugin entries read from one .yarnrc.yml
)

var (
	scopedRegistryRE = regexp.MustCompile(`^@[^:\s]+:registry$`)
	yamlKeyRE        = regexp.MustCompile(`^(\s*)(?:-\s+)?([A-Za-z_][A-Za-z0-9_-]*)\s*:(?:\s+(.*))?$`)
	yamlItemRE       = regexp.MustCompile(`^\s*-\s+(\S.*)$`)
	yarnReleaseRE    = regexp.MustCompile(`^\.yarn/releases/yarn-[A-Za-z0-9._-]+\.c?js$`)
	yarnPluginRE     = regexp.MustCompile(`^\.yarn/plugins/@yarnpkg/plugin-[A-Za-z0-9._-]+\.c?js$`)
	generatorRE      = regexp.MustCompile(`\bgenerator\s+[A-Za-z_][A-Za-z0-9_]*\s*\{`)
	providerRE       = regexp.MustCompile(`\bprovider\s*=\s*`)
	npmNameRE        = regexp.MustCompile(`^(?:@[a-z0-9][a-z0-9_.~-]*/)?[a-z0-9][a-z0-9_.~-]*$`)
	gypExpandRE      = regexp.MustCompile(`<!@?(?:pymod_do_main)?\(`)
	gypActionsRE     = regexp.MustCompile(`["']actions["']\s*:`)

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

// npmrc reads the keys of an .npmrc that move where npm fetches from or what it runs.
func (s *scan) npmrc() {
	for _, l := range splitLines(s.f.Data) {
		if s.done() {
			return
		}
		text := strings.TrimSpace(l.text)
		if text == "" || text[0] == '#' || text[0] == ';' {
			continue
		}
		key, value, _ := strings.Cut(text, "=")
		key = strings.ToLower(strings.TrimSpace(key))
		if i := strings.IndexAny(value, ";#"); i >= 0 && (i == 0 || value[i-1] == ' ' || value[i-1] == '\t') {
			value = value[:i]
		}
		value = unquote(value)
		switch {
		case key == "registry", scopedRegistryRE.MatchString(key):
			if !defaultRegistry(value) {
				s.add(ruleConfig, l.off)
			}
		case key == "node-options", key == "script-shell", key == "git":
			if value != "" {
				s.add(ruleConfig, l.off)
				s.riskAt(value, l.off)
			}
		case key == "userconfig", key == "globalconfig":
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
		i := strings.IndexAny(text, " \t=")
		if i < 0 {
			continue
		}
		key, value := unquote(text[:i]), unquote(strings.TrimLeft(text[i:], " \t="))
		switch key {
		case "yarn-path":
			s.committed(value, yarnReleaseRE, l.off)
		case "registry":
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
func (s *scan) yarnrcYML() {
	inPlugins, plugins := false, 0
	for _, l := range splitLines(s.f.Data) {
		if s.done() {
			return
		}
		text := l.text
		if i := strings.Index(text, " #"); i >= 0 {
			text = text[:i]
		}
		trimmed := strings.TrimSpace(text)
		if trimmed == "" || trimmed[0] == '#' {
			continue
		}
		if text[0] != ' ' && text[0] != '\t' && text[0] != '-' {
			inPlugins = false
		}
		m := yamlKeyRE.FindStringSubmatch(text)
		if m == nil {
			if item := yamlItemRE.FindStringSubmatch(text); inPlugins && item != nil && plugins < maxPlugins {
				plugins++
				s.committed(unquote(item[1]), yarnPluginRE, l.off)
			}
			continue
		}
		key, value := m[2], unquote(m[3])
		switch {
		case key == "yarnPath" && m[1] == "":
			s.committed(value, yarnReleaseRE, l.off)
		case key == "npmRegistryServer":
			if !defaultRegistry(value) {
				s.add(ruleConfig, l.off)
			}
		case key == "plugins" && m[1] == "":
			inPlugins = true
			if strings.HasPrefix(value, "[") && value != "[]" {
				s.add(ruleConfig, l.off) // a flow list is not read
			}
		case key == "path" && inPlugins && plugins < maxPlugins:
			plugins++
			s.committed(value, yarnPluginRE, l.off)
		}
	}
}

// blankComments returns data as text with the comments that start with marker
// blanked, keeping every byte at its offset. Quoted text is kept; a quote ends at
// the end of its line.
func blankComments(data []byte, marker string) string {
	b := bytes.Clone(data)
	var quote byte
	for i := 0; i < len(b); i++ {
		switch c := b[i]; {
		case quote != 0:
			switch c {
			case '\\':
				i++
			case quote, '\n':
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
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
// quoted plain npm package name.
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
			return value, npmNameRE.MatchString(strings.ToLower(value))
		}
	}
	return rest[1:], false
}

// gyp reads a node-gyp file: <!( and <!@( run a command while gyp reads the
// file, which npm install does for any package with a binding.gyp.
func (s *scan) gyp() {
	text := blankComments(s.f.Data, "#")
	for _, loc := range gypExpandRE.FindAllStringIndex(text, signals.MaxMatches) {
		if s.done() {
			return
		}
		s.add(ruleGypExpand, loc[0])
		s.riskAt(expansion(text[loc[1]:min(len(text), loc[1]+maxBlock)]), loc[0])
	}
	for _, loc := range gypActionsRE.FindAllStringIndex(text, signals.MaxMatches) {
		s.add(ruleGypAction, loc[0])
	}
}

// expansion returns the text up to the parenthesis that closes the expansion.
func expansion(rest string) string {
	depth := 1
	for i := 0; i < len(rest); i++ {
		switch rest[i] {
		case '(':
			depth++
		case ')':
			if depth--; depth == 0 {
				return rest[:i]
			}
		}
	}
	return rest
}
