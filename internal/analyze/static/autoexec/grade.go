package autoexec

import (
	"errors"
	"io/fs"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/mrdhira/galahad/internal/analyze"
	"github.com/mrdhira/galahad/internal/analyze/static/script"
	"github.com/mrdhira/galahad/internal/protocol"
)

// This file decides when an install-time script (GAL-AUTOEXEC-005) or a
// devcontainer lifecycle command (GAL-AUTOEXEC-004) is only low severity.
//
// A command is benign when the parser below understands every part of it and
// every part is on a short list of commands that run no code the repository
// controls beyond what the report already shows:
//   - npm, yarn, pnpm and bun calls that install, rebuild or run a script of the
//     same package.json, with flags from a fixed list and no package names;
//   - a few local development tools (husky, patch-package and so on);
//   - a script file of the repository that has no finding of medium severity or
//     higher: a JavaScript or Python file the script analyzer reads, or a shell
//     file whose every line is benign itself.
//
// The command is attacker-controlled text, so the parser accepts only a small
// alphabet (no quotes, expansions, redirections or newlines) and treats
// everything else as "not benign", which keeps the medium severity.
//
// Package manager calls also run what the repository configures: lifecycle
// scripts, .npmrc, .yarnrc.yml, .pnpmfile.cjs. Those are read through File.Open
// and must be clean too. Without File.Open (a container member, a single file)
// nothing that needs a neighbor file is benign.

// Limits of the grader. The size limit of a file read is analyze.MaxConfigSize.
const (
	maxGradeReads  = 64       // files read to grade the commands of one file
	maxGradeDepth  = 4        // nested scripts and package.json hops
	maxCommandLen  = 4096     // bytes of one command
	maxScriptLines = 200      // lines of a shell script
	maxScriptBytes = 64 << 10 // bytes of a shell script
)

var (
	// commandRE is the alphabet of a command that can be benign: words, paths,
	// flags and the chain operators. Quotes, "$", backticks, redirections,
	// parentheses, braces, globs, "#" and newlines are missing on purpose, so
	// none of them can hide a second command or an expansion.
	commandRE = regexp.MustCompile(`^[A-Za-z0-9 \t_./=,:&;|-]+$`)
	chainRE   = regexp.MustCompile(`&&|\|\||;`)
	shebangRE = regexp.MustCompile(`^#!\s*(?:/usr)?/bin/(?:env\s+)?(?:ba)?sh$`)
	setArgRE  = regexp.MustCompile(`^[-+][A-Za-z]+$`)
	builderRE = regexp.MustCompile(`"builder"\s*:\s*"[./]`)

	// pmFlags are the flags of a package manager call that change nothing
	// about where it fetches from or what it runs. Value flags such as --prefix,
	// --script-shell, --userconfig, --registry and --cache are not here.
	pmFlags = setOf("--ignore-scripts", "--frozen-lockfile", "--immutable", "--production", "--prod", "--omit=dev",
		"--no-audit", "--no-fund", "--legacy-peer-deps", "--silent", "--quiet", "--no-progress",
		"--prefer-offline", "--offline", "--if-present")
	installSubs = map[string]map[string]bool{
		"npm":  setOf("install", "i", "ci", "rebuild"),
		"yarn": setOf("", "install"),
		"pnpm": setOf("install", "i"),
		"bun":  setOf("install", "i"),
	}
	runSubs   = map[string]map[string]bool{"npm": setOf("run", "run-script"), "yarn": setOf("run"), "pnpm": setOf("run"), "bun": setOf("run")}
	pmConfigs = []string{".npmrc", ".yarnrc", ".yarnrc.yml", ".pnpmfile.cjs", ".pnpmfile.mjs"}
	// lifecycle are the scripts an install of the package runs on its own.
	lifecycle = []string{"preinstall", "install", "postinstall", "preprepare", "prepare", "postprepare"}

	// tools are local development tools that run nothing from the network. subs
	// lists the allowed first arguments, loose allows more arguments after it.
	tools = map[string]struct {
		subs  []string
		loose bool
	}{
		"husky":            {subs: []string{"", "install"}, loose: true},
		"simple-git-hooks": {subs: []string{""}},
		"patch-package":    {subs: []string{""}, loose: true},
		"lefthook":         {subs: []string{"install"}, loose: true},
		"node-gyp":         {subs: []string{"rebuild"}},
		"prisma":           {subs: []string{"generate"}, loose: true},
		"tsc":              {subs: []string{""}, loose: true},
		"ng":               {subs: []string{"build"}, loose: true},
	}
	// scriptExts are the extensions an interpreter may run.
	scriptExts = map[string]map[string]bool{
		"node": setOf(".js", ".mjs", ".cjs"),
		"py":   setOf(".py"),
		"sh":   setOf(".sh"),
	}
	prismaConfigs = []string{"prisma.config.ts", "prisma.config.mts", "prisma.config.cts", "prisma.config.js", "prisma.config.mjs", "prisma.config.cjs"}

	errNoRead = errors.New("file not readable")
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
	s       *scan
	reads   int
	active  map[string]bool              // scripts being graded, so a cycle ends
	scripts map[string]map[string]string // scripts of the package.json of a folder; a nil map: no such file
	config  map[string]bool              // package manager config files of a folder are clean
	cleaned map[string]bool              // files already checked by clean
}

func newGrader(s *scan) *grader {
	return &grader{s: s, active: map[string]bool{}, scripts: map[string]map[string]string{}, config: map[string]bool{}, cleaned: map[string]bool{}}
}

// preload records the scripts object of the package.json being analyzed, which
// sits in folder dir. The last of duplicate keys wins, as in npm.
func (g *grader) preload(dir string, scripts *node) {
	m := map[string]string{}
	if scripts != nil && scripts.kind == 'o' {
		for i, k := range scripts.keys {
			if v := scripts.vals[i]; v.kind == 's' {
				m[k] = v.str
			} else {
				delete(m, k)
			}
		}
	}
	g.scripts[dir] = m
}

// read returns the file at rel, relative to the target.
func (g *grader) read(rel string) ([]byte, error) {
	if g.s.f.Open == nil || g.reads >= maxGradeReads || g.s.ctx.Err() != nil {
		return nil, errNoRead
	}
	g.reads++
	return g.s.f.Open(rel)
}

// absent reports whether the file at rel does not exist.
func (g *grader) absent(rel string) bool {
	_, err := g.read(rel)
	return errors.Is(err, fs.ErrNotExist)
}

// clean reports whether this analyzer finds nothing in the file at rel. A
// missing file is clean when optional.
func (g *grader) clean(rel string, optional bool) bool {
	if ok, done := g.cleaned[rel]; done {
		return ok
	}
	ok := false
	data, err := g.read(rel)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		ok = optional
	case err == nil:
		out, err := analyzer{}.Analyze(g.s.ctx, analyze.File{Path: rel, Name: path.Base(rel), Data: data})
		ok = err == nil && len(out.Findings) == 0 && len(out.Skips) == 0
	}
	g.cleaned[rel] = ok
	return ok
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

// scriptsOf returns the scripts of the package.json in dir. A missing file has
// no scripts.
func (g *grader) scriptsOf(dir string) (map[string]string, error) {
	if m, ok := g.scripts[dir]; ok {
		return m, nil
	}
	p, _ := within(dir, "package.json")
	data, err := g.read(p)
	if errors.Is(err, fs.ErrNotExist) {
		g.scripts[dir] = nil
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	root, err := parseJSON(StripJSONC(data))
	if err != nil || root.kind != 'o' {
		return nil, errNoRead
	}
	g.preload(dir, root.get("scripts"))
	return g.scripts[dir], nil
}

// hook grades the script name of the package in dir, which must exist.
func (g *grader) hook(dir, name string, depth int) bool {
	scripts, err := g.scriptsOf(dir)
	body, ok := scripts[name]
	if err != nil || !ok {
		return false
	}
	key := "script\x00" + dir + "\x00" + name
	if g.active[key] {
		return true // its body is graded by the call that is running it
	}
	g.active[key] = true
	defer delete(g.active, key)
	return g.benign(body, dir, depth+1)
}

// benign reports whether cmd, run in the folder dir, is benign.
func (g *grader) benign(cmd, dir string, depth int) bool {
	cwd := dir
	return g.run(cmd, &cwd, depth)
}

// run grades the parts of a command chain in order. A cd changes cwd for the
// parts after it.
func (g *grader) run(cmd string, cwd *string, depth int) bool {
	if depth > maxGradeDepth || len(cmd) > maxCommandLen || !commandRE.MatchString(cmd) {
		return false
	}
	hasOr := strings.Contains(cmd, "||")
	for _, part := range chainRE.Split(cmd, -1) {
		words := strings.Fields(part)
		if len(words) == 0 || (hasOr && words[0] == "cd") {
			return false
		}
		for _, w := range words {
			if strings.ContainsAny(w, "&|") || strings.Contains(w, "//") || strings.Contains(w, ":/") {
				return false
			}
		}
		if !g.simple(words, cwd, depth) {
			return false
		}
	}
	return true
}

// simple grades one command.
func (g *grader) simple(words []string, cwd *string, depth int) bool {
	prog, args := words[0], words[1:]
	switch prog {
	case "cd":
		if len(args) != 1 || args[0][0] == '-' || args[0][0] == '~' {
			return false
		}
		next, ok := within(*cwd, args[0])
		*cwd = next
		return ok
	case "set":
		return !slices.ContainsFunc(args, func(a string) bool { return a != "pipefail" && !setArgRE.MatchString(a) })
	case "echo":
		return true
	case "npm", "yarn", "pnpm", "bun":
		return g.packageManager(prog, args, *cwd, depth)
	case "npx":
		// The one remote tool that is accepted, with a fixed argument.
		return len(args) == 2 && args[0] == "only-allow" && installSubs[args[1]] != nil
	case "node":
		return len(args) > 0 && g.local("node", args[0], *cwd, depth)
	case "python", "python3":
		return len(args) > 0 && g.local("py", args[0], *cwd, depth)
	case "bash", "sh":
		return len(args) > 0 && g.local("sh", args[0], *cwd, depth)
	}
	if strings.Contains(prog, "/") {
		// A name with a slash runs the file at that path.
		return g.local("sh", prog, *cwd, depth)
	}
	return g.tool(prog, args, *cwd)
}

// packageManager grades an npm, yarn, pnpm or bun call: an install without
// package names, or a run of a script of the package.json in dir.
func (g *grader) packageManager(prog string, args []string, dir string, depth int) bool {
	var words []string
	ignoreScripts := false
	for _, a := range args {
		if a[0] != '-' {
			words = append(words, a)
			continue
		}
		if !pmFlags[a] {
			return false
		}
		ignoreScripts = ignoreScripts || a == "--ignore-scripts"
	}
	if !g.packageConfigClean(prog, dir) {
		return false
	}
	sub := ""
	if len(words) > 0 {
		sub = words[0]
	}
	switch {
	case installSubs[prog][sub] && len(words) <= 1:
		return ignoreScripts || g.lifecycleClean(dir, depth)
	case runSubs[prog][sub] && len(words) == 2:
		return g.runScript(dir, words[1], depth)
	case (prog == "yarn" || prog == "pnpm") && (sub == "build" || sub == "prepare") && len(words) == 1:
		return g.runScript(dir, sub, depth)
	}
	return false
}

// packageConfigClean reports whether the files that change what the package
// manager runs or fetches are clean, in dir and at the root of the target.
func (g *grader) packageConfigClean(prog, dir string) bool {
	if prog == "bun" {
		// bunfig.toml can preload a script; it is not read, so it must not exist.
		if p, _ := within(dir, "bunfig.toml"); !g.absent(p) {
			return false
		}
	}
	if ok, done := g.config[dir]; done {
		return ok
	}
	ok := true
	for _, d := range slices.Compact([]string{dir, ""}) {
		for _, name := range pmConfigs {
			p, _ := within(d, name)
			ok = ok && g.clean(p, true)
		}
	}
	g.config[dir] = ok
	return ok
}

// lifecycleClean reports whether the scripts that an install of the package in
// dir runs on its own are benign.
func (g *grader) lifecycleClean(dir string, depth int) bool {
	scripts, err := g.scriptsOf(dir)
	if err != nil {
		return false
	}
	for _, name := range lifecycle {
		if _, ok := scripts[name]; ok && !g.hook(dir, name, depth) {
			return false
		}
	}
	return true
}

// runScript grades a run of the script name, with the pre and post scripts that
// npm runs around it.
func (g *grader) runScript(dir, name string, depth int) bool {
	scripts, err := g.scriptsOf(dir)
	if _, ok := scripts[name]; err != nil || !ok {
		return false
	}
	for _, n := range []string{"pre" + name, name, "post" + name} {
		if _, ok := scripts[n]; ok && !g.hook(dir, n, depth) {
			return false
		}
	}
	return true
}

// tool grades a local development tool.
func (g *grader) tool(prog string, args []string, cwd string) bool {
	t, ok := tools[prog]
	if !ok {
		return false
	}
	sub := ""
	if len(args) > 0 && args[0][0] != '-' {
		sub, args = args[0], args[1:]
	}
	if !slices.Contains(t.subs, sub) || (!t.loose && len(args) > 0) {
		return false
	}
	switch prog {
	case "node-gyp":
		// binding.gyp expansions and actions run commands.
		p, _ := within(cwd, "binding.gyp")
		return g.clean(p, false)
	case "prisma":
		return g.prismaClean(args, cwd)
	case "ng":
		// A builder given as a path runs repository code.
		p, _ := within(cwd, "angular.json")
		data, err := g.read(p)
		return err == nil && !builderRE.Match(data)
	}
	return true
}

// prismaClean reports whether the schema that prisma generate reads has no
// generator that runs a command, and no config file is there to run.
func (g *grader) prismaClean(args []string, cwd string) bool {
	schemas := []string{"prisma/schema.prisma", "schema.prisma"}
	for i, a := range args {
		if v, ok := strings.CutPrefix(a, "--schema="); ok {
			schemas = []string{v}
		} else if a == "--schema" && i+1 < len(args) {
			schemas = []string{args[i+1]}
		}
	}
	for _, name := range prismaConfigs {
		if p, _ := within(cwd, name); !g.absent(p) {
			return false
		}
	}
	for _, name := range schemas {
		p, ok := within(cwd, name)
		if !ok {
			return false
		}
		if g.absent(p) {
			continue
		}
		return g.clean(p, false)
	}
	return false
}

// local grades a run of a script file of the repository with an interpreter
// ("node", "py" or "sh"). A script of JavaScript or Python is graded by the
// script analyzer, and a shell script by its lines.
func (g *grader) local(interp, file, cwd string, depth int) bool {
	p, ok := within(cwd, file)
	if file[0] == '-' || !ok || !scriptExts[interp][strings.ToLower(path.Ext(file))] {
		return false
	}
	key := "file\x00" + p
	if g.active[key] {
		return true
	}
	g.active[key] = true
	defer delete(g.active, key)
	data, err := g.read(p)
	if err != nil {
		return false
	}
	if interp == "sh" {
		return g.shell(data, cwd, depth)
	}
	out, err := script.New().Analyze(g.s.ctx, analyze.File{Path: p, Name: path.Base(p), Data: data})
	if err != nil || len(out.Skips) > 0 {
		return false
	}
	for _, f := range out.Findings {
		if f.Severity != protocol.SeverityInfo && f.Severity != protocol.SeverityLow {
			return false
		}
	}
	return true
}

// shell grades a shell script line by line. Only lines that are benign
// commands count: there is no analysis of other shell code, so a script that
// uses anything else keeps the medium severity.
func (g *grader) shell(data []byte, cwd string, depth int) bool {
	lines := strings.Split(string(data), "\n")
	if len(data) > maxScriptBytes || len(lines) > maxScriptLines {
		return false
	}
	for i, line := range lines {
		line = strings.TrimSpace(line)
		switch {
		case line == "":
		case i == 0 && strings.HasPrefix(line, "#!"):
			if !shebangRE.MatchString(line) {
				return false
			}
		case line[0] == '#':
		case !g.run(line, &cwd, depth+1):
			return false
		}
	}
	return true
}

// allBenign reports whether every command in a lifecycle command value, run in
// the folder dir, is benign.
func (g *grader) allBenign(n *node, dir string) bool {
	for _, cmd := range leafCommands(n, nil) {
		if !g.benign(cmd, dir, 0) {
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
