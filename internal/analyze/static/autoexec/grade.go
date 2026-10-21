package autoexec

import (
	"errors"
	"io/fs"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/mrdhira/galahad/internal/analyze"
	"github.com/mrdhira/galahad/internal/protocol"
)

// This file decides when an install-time script (GAL-AUTOEXEC-005) or a
// devcontainer lifecycle command (GAL-AUTOEXEC-004) is only low severity. There
// are two narrow cases, and everything else stays medium.
//
// A. A plain install: npm, yarn, pnpm or bun with install, ci or i, a few flags
// that change nothing, and an optional "cd <dir> &&" in front. The package.json
// in <dir> must exist, declare none of the scripts an install runs (unless
// --ignore-scripts is given), nothing that redirects a dependency and no package
// manager other than a plain version, and <dir> has no binding.gyp. No package
// in <dir> or a parent declares workspaces, and no package manager config file
// sits there.
//
// B. Only for an npm script: exactly one known tool with no arguments. The tool
// must be declared as a dependency with a registry version, must not be
// committed under node_modules/.bin, and nothing may redirect it: every entry
// for it is a registry version, no workspaces in the package or a parent, no
// override, resolution or patch that names it, no package manager config file
// except a pnpm-workspace.yaml that sets none of that, and no package manager
// other than a plain version (pnpm 9 or later when pnpm-workspace.yaml lists
// packages, since older pnpm links a workspace package of the same name).
//
// The command is attacker-controlled text, so only a small alphabet is parsed.
// The neighbor files are read through File.Open; without it nothing is benign.

// Limits of the grader. The size limit of a file read is analyze.MaxConfigSize.
const (
	maxGradeReads = 128  // files read to grade the commands of one file
	maxCommandLen = 4096 // bytes of one command
)

var (
	// wordsRE is the alphabet of one part of a command: words, paths and flags.
	// Quotes, "$", backticks, redirections, parentheses, ";", "|", "#" and
	// newlines are missing on purpose.
	wordsRE = regexp.MustCompile(`^[A-Za-z0-9 \t_./=,-]+$`)
	// versionRE is a registry version range. A tag, a path, a URL and a prefix
	// such as file: or git+ are not one.
	versionRE = regexp.MustCompile(`^[\^~<>=v0-9xX*.|\- ]*[0-9xX*][\^~<>=v0-9xX*.|\- ]*$`)

	installPMs = setOf("npm", "yarn", "pnpm", "bun")
	// installFlags change nothing about where an install fetches from or what it runs.
	installFlags = setOf("--frozen-lockfile", "--immutable", "--prefer-offline", "--no-audit", "--no-fund",
		"--ignore-scripts", "--production", "--omit=dev")
	installSubs = setOf("install", "ci", "i")
	// installScripts are the scripts an install runs on its own.
	installScripts = []string{"preinstall", "install", "postinstall", "prepublish", "preprepare", "prepare", "postprepare", "dependencies", "pnpm:devPreinstall"}
	// installConfigs change what an install runs or fetches.
	installConfigs = []string{".npmrc", ".yarnrc", ".yarnrc.yml", ".pnpmfile.cjs", "pnpm-workspace.yaml", "bunfig.toml"}
	// redirects are the package.json members that can replace a dependency with
	// other code. The pnpm member holds overrides and patchedDependencies.
	redirects = []string{"overrides", "resolutions", "pnpm", "patchedDependencies"}
	// managerRE is a packageManager value that names a released version. A URL
	// makes corepack download and run that file.
	managerRE = regexp.MustCompile(`^(npm|yarn|pnpm|bun)@[0-9][0-9A-Za-z.+-]*$`)
	// pnpm9RE is a packageManager value that pins pnpm 9 or later.
	pnpm9RE = regexp.MustCompile(`^pnpm@([1-9][0-9]+|9)\.`)

	// tools maps a whole command to the package that provides it and its
	// name under node_modules/.bin.
	tools = map[string]struct{ pkg, bin string }{
		"husky":               {"husky", "husky"},
		"simple-git-hooks":    {"simple-git-hooks", "simple-git-hooks"},
		"patch-package":       {"patch-package", "patch-package"},
		"lefthook install":    {"lefthook", "lefthook"},
		"tsc":                 {"typescript", "tsc"},
		"prisma generate":     {"prisma", "prisma"},
		"npx only-allow npm":  {"only-allow", "only-allow"},
		"npx only-allow yarn": {"only-allow", "only-allow"},
		"npx only-allow pnpm": {"only-allow", "only-allow"},
		"npx only-allow bun":  {"only-allow", "only-allow"},
	}
	prismaConfigs = []string{"prisma.config.ts", "prisma.config.mts", "prisma.config.cts", "prisma.config.js", "prisma.config.mjs", "prisma.config.cjs"}
)

func setOf(items ...string) map[string]bool {
	m := make(map[string]bool, len(items))
	for _, s := range items {
		m[s] = true
	}
	return m
}

// grader grades the commands of one file.
type grader struct {
	s     *scan
	reads int
	dir   string // folder of the package.json being analyzed, when there is one
	own   *node  // its root
}

func newGrader(s *scan) *grader { return &grader{s: s} }

// read returns the file at rel, relative to the target.
func (g *grader) read(rel string) ([]byte, error) {
	if g.s.f.Open == nil || g.reads >= maxGradeReads || g.s.ctx.Err() != nil {
		return nil, errors.New("file not readable")
	}
	g.reads++
	return g.s.f.Open(rel)
}

// absent reports whether nothing exists at rel. A file that cannot be read
// exists as far as this is concerned.
func (g *grader) absent(rel string) bool {
	_, err := g.read(rel)
	return errors.Is(err, fs.ErrNotExist)
}

// absentUp reports whether none of the names exists in dir or a parent folder
// up to the root of the target.
func (g *grader) absentUp(dir string, names ...string) bool {
	for {
		for _, name := range names {
			if !g.absent(path.Join(dir, name)) {
				return false
			}
		}
		if dir == "" {
			return true
		}
		dir = parentDir(dir)
	}
}

// parentDir returns the folder that holds dir. The root is "".
func parentDir(dir string) string {
	if dir = path.Dir(dir); dir == "." {
		return ""
	}
	return dir
}

// inWorkspace reports whether the package.json in dir or a parent folder
// declares workspaces, so that the package manager may link a sibling package
// in place of a registry one. A package.json that cannot be read counts.
func (g *grader) inWorkspace(dir string) bool {
	for d := dir; ; d = parentDir(d) {
		p, _ := within(d, "package.json")
		if g.own != nil && d == g.dir || !g.absent(p) {
			if pkg := g.packageAt(d); pkg == nil || pkg.get("workspaces") != nil {
				return true
			}
		}
		if d == "" {
			return false
		}
	}
}

// alias reports whether a YAML line holds an alias (*name), which starts a
// value after a blank. A star inside a scalar such as workspace:* is not one.
func alias(line string) bool {
	return strings.Contains(line, " *") || strings.Contains(line, "\t*")
}

// mentions reports whether a key anywhere under n contains name.
func mentions(n *node, name string) bool {
	if n == nil || n.kind != 'o' {
		return false
	}
	for i, k := range n.keys {
		if strings.Contains(k, name) || mentions(n.vals[i], name) {
			return true
		}
	}
	return false
}

// pnpmClean reports whether no pnpm-workspace.yaml in dir or a parent folder
// sets a pnpmfile or linkWorkspacePackages, lists packages unless pnpm9 is set,
// or names the package name in its overrides or patchedDependencies. Only top-level block keys are read; anything that could
// hide a key (flow style, anchors, escapes) counts as naming it.
func (g *grader) pnpmClean(dir, name string, pnpm9 bool) bool {
	for d := dir; ; d = parentDir(d) {
		p, _ := within(d, "pnpm-workspace.yaml")
		data, err := g.read(p)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return false
		}
		block := ""
		for _, line := range strings.Split(strings.TrimPrefix(string(data), "\ufeff"), "\n") {
			if line != "" && !strings.ContainsAny(line[:1], " \t#-") {
				key, _, _ := strings.Cut(line, ":")
				block = strings.Trim(strings.TrimSpace(key), `"'`)
				if strings.ContainsAny(line[:1], "{[?&*!|>%@`\\") || strings.Contains(block, "\\") || strings.Contains(block, "npmfile") ||
					block == "linkWorkspacePackages" || block == "packages" && !pnpm9 {
					return false
				}
			}
			if (block == "overrides" || block == "patchedDependencies") && (strings.Contains(line, name) || strings.ContainsAny(line, "\\&<{[?") || alias(line)) {
				return false
			}
		}
		if d == "" {
			return true
		}
	}
}

// within joins name to the folder dir, both relative to the target, and says
// whether the result stays inside it. The root is "".
func within(dir, name string) (string, bool) {
	if name == "" || name[0] == '/' {
		return "", false
	}
	p := path.Join(dir, name)
	switch {
	case p == "..", strings.HasPrefix(p, "../"):
		return "", false
	case p == ".":
		return "", true
	}
	return p, true
}

// packageAt returns the root of the package.json in dir, or nil when it does
// not exist or cannot be read.
func (g *grader) packageAt(dir string) *node {
	if g.own != nil && dir == g.dir {
		return g.own
	}
	p, _ := within(dir, "package.json")
	data, err := g.read(p)
	if err != nil {
		return nil
	}
	root, err := parseJSON(StripJSONC(data))
	if err != nil || root.kind != 'o' {
		return nil
	}
	return root
}

// benign reports whether cmd, run in the folder dir, is benign. A tool is
// accepted only when script is set, for a script of the package.json in dir.
func (g *grader) benign(cmd, dir string, script bool) bool {
	if len(cmd) > maxCommandLen {
		return false
	}
	parts := strings.Split(cmd, "&&")
	if len(parts) > 2 || slices.ContainsFunc(parts, func(p string) bool { return !wordsRE.MatchString(p) }) {
		return false
	}
	words := strings.Fields(parts[len(parts)-1])
	if len(words) == 0 {
		return false
	}
	if len(parts) == 2 {
		cd := strings.Fields(parts[0])
		if len(cd) != 2 || cd[0] != "cd" {
			return false
		}
		next, ok := within(dir, cd[1])
		return ok && g.install(words, next)
	}
	return g.install(words, dir) || (script && g.tool(strings.Join(words, " "), dir))
}

// install grades a plain install in dir.
func (g *grader) install(words []string, dir string) bool {
	if len(words) < 2 || !installPMs[words[0]] || !installSubs[words[1]] {
		return false
	}
	ignoreScripts := false
	for _, w := range words[2:] {
		if !installFlags[w] {
			return false
		}
		ignoreScripts = ignoreScripts || w == "--ignore-scripts"
	}
	pkg := g.packageAt(dir)
	if pkg == nil || g.inWorkspace(dir) || slices.ContainsFunc(redirects, func(k string) bool { return pkg.get(k) != nil }) {
		return false
	}
	if !plainManager(pkg) {
		return false
	}
	if p, _ := within(dir, "binding.gyp"); !g.absent(p) {
		return false
	}
	if scripts := pkg.get("scripts"); !ignoreScripts && scripts != nil && scripts.kind == 'o' {
		if slices.ContainsFunc(installScripts, func(name string) bool { return scripts.get(name) != nil }) {
			return false
		}
	}
	return g.absentUp(dir, installConfigs...)
}

// tool grades a script that is one known tool without arguments, in the package
// in dir.
func (g *grader) tool(cmd, dir string) bool {
	t, ok := tools[cmd]
	pkg := g.packageAt(dir)
	if !ok || pkg == nil || !g.declared(pkg, t.pkg) || g.inWorkspace(dir) {
		return false
	}
	if !plainManager(pkg) || slices.ContainsFunc(redirects, func(k string) bool { return mentions(pkg.get(k), t.pkg) }) {
		return false
	}
	m := pkg.get("packageManager")
	if !g.pnpmClean(dir, t.pkg, m != nil && pnpm9RE.MatchString(m.str)) {
		return false
	}
	names := append([]string{path.Join("node_modules", ".bin", t.bin)}, slices.DeleteFunc(slices.Clone(installConfigs), func(n string) bool { return n == "pnpm-workspace.yaml" })...)
	if !g.absentUp(dir, names...) {
		return false
	}
	if t.pkg == "prisma" {
		return g.prismaClean(dir)
	}
	return true
}

// declared reports whether pkg lists name in dependencies or devDependencies,
// and every entry for name in any dependency section is a registry version
// range. The package manager installs one of them, so each must be safe.
func (g *grader) declared(pkg *node, name string) bool {
	found := false
	for _, section := range []string{"dependencies", "devDependencies", "optionalDependencies", "peerDependencies"} {
		v := pkg.get(section).get(name)
		if v == nil {
			continue
		}
		if v.kind != 's' || !versionRE.MatchString(v.str) {
			return false
		}
		found = found || section == "dependencies" || section == "devDependencies"
	}
	return found
}

// plainManager reports whether pkg names no package manager, or one by a
// released version. devEngines can also make corepack fetch one, so it must be
// absent.
func plainManager(pkg *node) bool {
	m := pkg.get("packageManager")
	return pkg.get("devEngines") == nil && (m == nil || m.kind == 's' && managerRE.MatchString(m.str))
}

// prismaClean reports whether the schema that prisma generate reads has no
// generator that runs a command, and no config file is there to run.
func (g *grader) prismaClean(dir string) bool {
	for _, name := range prismaConfigs {
		if p, _ := within(dir, name); !g.absent(p) {
			return false
		}
	}
	for _, name := range []string{"prisma/schema.prisma", "schema.prisma"} {
		p, _ := within(dir, name)
		data, err := g.read(p)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return false
		}
		out, err := analyzer{}.Analyze(g.s.ctx, analyze.File{Path: p, Name: path.Base(p), Data: data})
		return err == nil && len(out.Findings) == 0 && len(out.Skips) == 0
	}
	return false
}

// allBenign reports whether every command in a lifecycle command value, run in
// the folder dir, is benign.
func (g *grader) allBenign(n *node, dir string) bool {
	for _, cmd := range leafCommands(n, nil) {
		if !g.benign(cmd, dir, false) {
			return false
		}
	}
	return true
}

// leafCommands appends the command of each leaf of a lifecycle command value:
// the string, the array of strings joined by blanks, or each value of an object
// of parallel commands.
func leafCommands(n *node, dst []string) []string {
	if n.kind == 'o' {
		for _, v := range n.vals {
			dst = leafCommands(v, dst)
		}
		return dst
	}
	return append(dst, strings.Join(strs(n, nil), " "))
}

// workspaceDir is the folder a devcontainer runs its commands in: the one that
// holds the .devcontainer folder, or the file itself for .devcontainer.json.
func workspaceDir(rel string) string {
	segs := strings.Split(rel, "/")
	for i := len(segs) - 2; i >= 0; i-- {
		if strings.EqualFold(segs[i], ".devcontainer") {
			return strings.Join(segs[:i], "/")
		}
	}
	if dir := path.Dir(rel); dir != "." {
		return dir
	}
	return ""
}

// lowered returns the rule with its severity set to low.
func lowered(r protocol.Rule) protocol.Rule {
	r.Severity = protocol.SeverityLow
	return r
}
