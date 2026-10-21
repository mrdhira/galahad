// Package autoexec lists the places where a repository runs code on its own
// (folder open, install, commit, git operations, entering a directory) and
// grades the risk of the commands behind the truly automatic triggers.
//
// Command-risk checks (rules 010 to 012) run only for triggers that need no
// action from the user: VS Code tasks that run on folder open, devcontainer
// commands, npm lifecycle scripts, husky hooks, local pre-commit hooks, git
// config and .envrc. Makefile, build.rs and CI workflows are inventory only,
// so a tool installer such as "curl ... | sh" in a Makefile is not graded.
//
// Package manager and build configuration that changes what an ordinary install
// runs is reported as well (rules 013 to 018): .npmrc, .yarnrc, .yarnrc.yml,
// .pnpmfile.cjs, Prisma generator providers and node-gyp command expansions.
// Command values in them are graded with the same checks.
package autoexec

import (
	"bytes"
	"context"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"path"
	"regexp"
	"strings"

	"github.com/mrdhira/galahad/internal/analyze"
	"github.com/mrdhira/galahad/internal/analyze/static/signals"
	"github.com/mrdhira/galahad/internal/protocol"
)

var (
	ruleTask      = protocol.Rule{ID: "GAL-AUTOEXEC-001", Severity: protocol.SeverityHigh, Title: "VS Code task runs on folder open", Attack: "T1204.002"}
	ruleSetting   = protocol.Rule{ID: "GAL-AUTOEXEC-002", Severity: protocol.SeverityMedium, Title: "VS Code setting points a tool path into the repo", Attack: "T1574"}
	ruleDevInit   = protocol.Rule{ID: "GAL-AUTOEXEC-003", Severity: protocol.SeverityHigh, Title: "devcontainer initializeCommand runs on the host", Attack: "T1204.002"}
	ruleDevLife   = protocol.Rule{ID: "GAL-AUTOEXEC-004", Severity: protocol.SeverityMedium, Title: "devcontainer lifecycle command", Attack: "T1204.002"}
	ruleNpm       = protocol.Rule{ID: "GAL-AUTOEXEC-005", Severity: protocol.SeverityMedium, Title: "npm install-time script", Attack: "T1195.001"}
	ruleHook      = protocol.Rule{ID: "GAL-AUTOEXEC-006", Severity: protocol.SeverityLow, Title: "Commit hook or prepare script"}
	rulePython    = protocol.Rule{ID: "GAL-AUTOEXEC-007", Severity: protocol.SeverityLow, Title: "Python build runs repo code on install"}
	ruleOther     = protocol.Rule{ID: "GAL-AUTOEXEC-008", Severity: protocol.SeverityInfo, Title: "Other automation (Makefile, build.rs, .envrc, CI workflow)"}
	ruleGit       = protocol.Rule{ID: "GAL-AUTOEXEC-009", Severity: protocol.SeverityHigh, Title: "Git config executes commands", Attack: "T1059.004"}
	ruleExfil     = protocol.Rule{ID: "GAL-AUTOEXEC-010", Severity: protocol.SeverityCritical, Title: "Auto-run command sends secrets to the network", Attack: "T1041"}
	ruleDownload  = protocol.Rule{ID: "GAL-AUTOEXEC-011", Severity: protocol.SeverityCritical, Title: "Auto-run command downloads and executes code", Attack: "T1105"}
	ruleObfuscate = protocol.Rule{ID: "GAL-AUTOEXEC-012", Severity: protocol.SeverityHigh, Title: "Auto-run command is obfuscated", Attack: "T1027"}
	ruleConfig    = protocol.Rule{ID: "GAL-AUTOEXEC-013", Severity: protocol.SeverityMedium, Title: "Package manager config changes what install runs or fetches", Attack: "T1195.001"}
	ruleVendored  = protocol.Rule{ID: "GAL-AUTOEXEC-014", Severity: protocol.SeverityLow, Title: "Package manager runtime or plugin committed to the repo"}
	rulePnpm      = protocol.Rule{ID: "GAL-AUTOEXEC-015", Severity: protocol.SeverityMedium, Title: "pnpm runs .pnpmfile on install", Attack: "T1195.001"}
	rulePrisma    = protocol.Rule{ID: "GAL-AUTOEXEC-016", Severity: protocol.SeverityMedium, Title: "Prisma generator provider is a command, not a package", Attack: "T1059"}
	ruleGypExpand = protocol.Rule{ID: "GAL-AUTOEXEC-017", Severity: protocol.SeverityMedium, Title: "node-gyp command expansion runs at build", Attack: "T1059"}
	ruleGypAction = protocol.Rule{ID: "GAL-AUTOEXEC-018", Severity: protocol.SeverityLow, Title: "node-gyp build actions"}
)

var (
	shellArgsRE  = regexp.MustCompile(`(?i)(?:^|\s)(?:-c|-command|-encodedcommand|-enc|/c)(?:\s|$)`)
	repoRE       = regexp.MustCompile(`^\s*-\s*repo:\s*(\S+)`)
	entryRE      = regexp.MustCompile(`^(\s*)(?:-\s*)?entry:\s*(.*)$`)
	sectionRE    = regexp.MustCompile(`^\s*\[\s*([A-Za-z0-9._-]+)(?:\s+"([^"]*)")?\s*\]`)
	keyValueRE   = regexp.MustCompile(`^\s*([A-Za-z][A-Za-z0-9_-]*)\s*=\s*(.*?)\s*$`)
	setupCallRE  = regexp.MustCompile(`\bsetup\s*\(`)
	blockScalar  = map[string]bool{"|": true, ">": true, "|-": true, ">-": true, "|+": true, ">+": true}
	boolLike     = map[string]bool{"true": true, "false": true, "yes": true, "no": true, "on": true, "off": true, "1": true, "0": true, "": true}
	huskyPaths   = map[string]bool{".husky": true, ".husky/_": true}
	devLifecycle = []string{"onCreateCommand", "updateContentCommand", "postCreateCommand", "postStartCommand", "postAttachCommand"}
	npmInstall   = []string{"preinstall", "install", "postinstall"}
	npmPrepare   = []string{"preprepare", "prepare", "postprepare"}
	lfsFilterRE  = regexp.MustCompile(`^git[- ]lfs (?:smudge|clean|filter-process)(?: -- %f)?$`)
)

type analyzer struct{}

// New returns the auto-execution analyzer.
func New() analyze.Analyzer { return analyzer{} }

func (analyzer) Name() string { return "autoexec" }

// Priority reports whether the file at path, a path on disk, is one that runs
// code on its own. The engine reads such a file even when the job is past its
// file or byte limits, so padding a repository cannot hide it. Files that only
// list where automation exists (Makefile, build.rs, CI workflows) are left out:
// a large tree has thousands of them, and they cannot run anything by themselves.
func (analyzer) Priority(path string) bool {
	t := route(path)
	return t != none && t != inventoryFile
}

// trigger is a kind of file that Analyze handles.
type trigger int

const (
	none trigger = iota
	toolBinFile
	tasksFile
	workspaceFile
	settingsFile
	devcontainerFile
	packageFile
	huskyHook
	huskyGenerated
	preCommitFile
	gitConfigFile
	npmrcFile
	yarnrcFile
	yarnrcYMLFile
	pnpmfile
	prismaFile
	gypFile
	setupFile
	pyprojectFile
	envrcFile
	inventoryFile
)

// route says which kind of file the path names, matched case-insensitively. The
// path is relative to the target or, for a container member, to its container
// (analyze.File.Member), never cut at a "!/" that a directory name may hold.
func route(rel string) trigger {
	segs := strings.Split(strings.ToLower(rel), "/")
	base := segs[len(segs)-1]
	dirs := segs[:len(segs)-1]
	parent := ""
	if len(dirs) > 0 {
		parent = dirs[len(dirs)-1]
	}
	inToolBin := underDir(dirs, "node_modules", ".bin") || underDir(dirs, ".venv", "bin") || underDir(dirs, "venv", "bin") ||
		underDir(dirs, ".venv", "scripts") || underDir(dirs, "venv", "scripts")
	if slicesContains(dirs, "node_modules") && !inToolBin {
		return none
	}

	switch {
	case inToolBin:
		// Package manager output. repoPath exempts these paths from the settings check, so a script
		// committed here is graded instead. A real venv's bin/python is a symlink, which is never read.
		return toolBinFile
	case base == "tasks.json" && parent == ".vscode":
		return tasksFile
	case strings.HasSuffix(base, ".code-workspace"):
		return workspaceFile
	case base == "settings.json" && parent == ".vscode":
		return settingsFile
	case base == ".devcontainer.json", base == "devcontainer.json" && slicesContains(dirs, ".devcontainer"):
		return devcontainerFile
	case base == "package.json":
		return packageFile
	case parent == ".husky" && !strings.HasPrefix(base, ".") && base != "husky.sh":
		return huskyHook
	case parent == "_" && len(dirs) > 1 && dirs[len(dirs)-2] == ".husky" && !strings.HasPrefix(base, ".") && base != "husky.sh":
		// Files husky generates: core.hooksPath may point here, so grade them without an inventory finding.
		return huskyGenerated
	case base == ".pre-commit-config.yaml":
		return preCommitFile
	case base == "config" && parent == ".git":
		return gitConfigFile
	case base == ".npmrc":
		return npmrcFile
	case base == ".yarnrc":
		return yarnrcFile
	case base == ".yarnrc.yml":
		return yarnrcYMLFile
	case base == ".pnpmfile.cjs", base == ".pnpmfile.mjs":
		return pnpmfile
	case strings.HasSuffix(base, ".prisma"):
		return prismaFile
	case path.Ext(base) == ".gyp", path.Ext(base) == ".gypi":
		return gypFile
	case base == "setup.py":
		return setupFile
	case base == "pyproject.toml":
		return pyprojectFile
	case base == ".envrc":
		return envrcFile
	case base == "build.rs", base == "makefile", base == "gnumakefile", isWorkflow(dirs, base):
		return inventoryFile
	}
	return none
}

func (analyzer) Analyze(ctx context.Context, f analyze.File) (analyze.Output, error) {
	var out analyze.Output
	if err := ctx.Err(); err != nil {
		return out, err
	}
	s := &scan{ctx: ctx, f: f, out: &out, counts: map[string]int{}}

	var run func()
	rel := f.Path
	if f.Member != "" {
		rel = f.Member
	}
	trig := route(rel)
	switch trig {
	case toolBinFile, huskyGenerated:
		run = s.riskFile
	case tasksFile:
		run = func() { s.json(s.tasks, s.tasksLexical) }
	case workspaceFile:
		run = func() { s.json(func(root *node) { s.tasks(root.get("tasks")) }, s.tasksLexical) }
	case settingsFile:
		run = func() { s.json(s.settings, nil) }
	case devcontainerFile:
		run = func() { s.json(s.devcontainer, s.devcontainerLexical) }
	case packageFile:
		run = func() { s.json(s.packageJSON, nil) }
	case huskyHook:
		run = s.husky
	case preCommitFile:
		run = s.preCommit
	case gitConfigFile:
		run = s.gitConfig
	case npmrcFile:
		run = s.npmrc
	case yarnrcFile:
		run = s.yarnrc
	case yarnrcYMLFile:
		run = s.yarnrcYML
	case pnpmfile:
		// Reported before the size check, so a padded file is not a way past the rule.
		s.add(rulePnpm, 0)
		run = s.riskFile
	case prismaFile:
		run = s.prisma
	case gypFile:
		run = s.gyp
	case setupFile:
		run = s.setupPy
	case pyprojectFile:
		run = s.pyproject
	case envrcFile:
		run = s.envrc
	case inventoryFile:
		s.add(ruleOther, 0)
		return out, nil
	default:
		return out, nil
	}
	if len(f.Data) > analyze.MaxConfigSize {
		// Too big to read, and a file that runs code is where a payload hides behind
		// padding. A copied interpreter or native tool in a tool directory is not a
		// config file, but only if it really is an executable: a script can start with
		// the magic bytes of one, because a shell skips a first line it cannot run.
		reason := protocol.SkipBudget
		if trig == toolBinFile && isExecutable(f.Data) {
			reason = protocol.SkipTooLarge
		}
		out.Skips = append(out.Skips, protocol.Skip{Path: f.Path, Reason: reason})
		return out, nil
	}
	run()
	return out, nil
}

// isExecutable reports whether data parses as an ELF, PE or Mach-O file.
func isExecutable(data []byte) bool {
	r := bytes.NewReader(data)
	if f, err := elf.NewFile(r); err == nil {
		_ = f.Close()
		return true
	}
	if f, err := pe.NewFile(r); err == nil {
		_ = f.Close()
		return true
	}
	if f, err := macho.NewFile(r); err == nil {
		_ = f.Close()
		return true
	}
	if f, err := macho.NewFatFile(r); err == nil {
		_ = f.Close()
		return true
	}
	return false
}

func isWorkflow(dirs []string, base string) bool {
	n := len(dirs)
	return n >= 2 && dirs[n-2] == ".github" && dirs[n-1] == "workflows" && (path.Ext(base) == ".yml" || path.Ext(base) == ".yaml")
}

// underDir reports whether dirs holds parent directly followed by child.
func underDir(dirs []string, parent, child string) bool {
	for i := 0; i+1 < len(dirs); i++ {
		if dirs[i] == parent && dirs[i+1] == child {
			return true
		}
	}
	return false
}

func slicesContains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// scan collects the findings of one file.
type scan struct {
	ctx      context.Context
	f        analyze.File
	out      *analyze.Output
	counts   map[string]int // findings built per rule ID
	timedOut bool
}

// done reports whether the context has ended. The first time, it records a
// timeout skip; the findings so far are kept.
func (s *scan) done() bool {
	if s.ctx.Err() == nil {
		return false
	}
	if !s.timedOut {
		s.timedOut = true
		s.out.Skips = append(s.out.Skips, protocol.Skip{Path: s.f.Path, Reason: protocol.SkipTimeout})
	}
	return true
}

// emit records a finding of rule with the evidence ev returns. The engine keeps
// only protocol.MaxFindingsPerRulePerFile findings per rule and file, so the
// rest are not built: evidence costs a pass over the file each.
func (s *scan) emit(r protocol.Rule, ev func() []protocol.Evidence) {
	if s.counts[r.ID] >= protocol.MaxFindingsPerRulePerFile {
		return
	}
	s.counts[r.ID]++
	s.out.Findings = append(s.out.Findings, r.Finding(ev()...))
}

// add records a finding for rule at the byte offset.
func (s *scan) add(r protocol.Rule, off int) {
	s.emit(r, func() []protocol.Evidence { return []protocol.Evidence{analyze.EvidenceAt(s.f, off)} })
}

// risk grades a command that runs automatically. at maps an offset in text to
// the evidence to report, which lets the caller point at a file line or at the
// config value the text came from.
func (s *scan) risk(text string, at func(int) protocol.Evidence) {
	for _, m := range signals.DecodeExec(text) {
		s.emit(ruleObfuscate, func() []protocol.Evidence { return []protocol.Evidence{at(m.Start)} })
	}
	for _, m := range signals.DownloadExec(text) {
		s.emit(ruleDownload, func() []protocol.Evidence { return []protocol.Evidence{at(m.Start)} })
	}
	secrets, network := signals.SecretRefs(text), signals.NetworkTools(text)
	if len(secrets) == 0 || len(network) == 0 {
		return
	}
	s.emit(ruleExfil, func() []protocol.Evidence {
		ev := []protocol.Evidence{at(secrets[0].Start)}
		if n := at(network[0].Start); n.Line != ev[0].Line {
			ev = append(ev, n)
		}
		return ev
	})
}

// riskAt grades text that is not literally in the file (an unescaped JSON
// string, a YAML value) and reports the line at off.
func (s *scan) riskAt(text string, off int) {
	s.risk(text, func(int) protocol.Evidence { return analyze.EvidenceAt(s.f, off) })
}

// riskFile grades shell text that is the file itself, with comments blanked.
func (s *scan) riskFile() {
	s.risk(shellText(s.f.Data), func(off int) protocol.Evidence { return analyze.EvidenceAt(s.f, off) })
}

// shellText returns the file as text with comment lines blanked and line
// continuations joined, keeping every other byte at its offset.
func shellText(data []byte) string {
	b := make([]byte, len(data))
	copy(b, data)
	for i := 0; i < len(b); {
		j := i
		for j < len(b) && b[j] != '\n' {
			j++
		}
		k := i
		for k < j && (b[k] == ' ' || b[k] == '\t') {
			k++
		}
		if k < j && b[k] == '#' {
			for ; k < j; k++ {
				b[k] = ' '
			}
		}
		if j > i && b[j-1] == '\\' && j < len(b) {
			b[j-1], b[j] = ' ', ' '
		}
		i = j + 1
	}
	return string(b)
}

// json parses the file as JSONC and passes the root to fn. When the file does
// not parse, lexical (if not nil) still looks for the automatic triggers, so a
// syntax error that VS Code tolerates is not a way past the analyzer.
func (s *scan) json(fn func(root *node), lexical func()) {
	root, err := parseJSON(StripJSONC(s.f.Data))
	if err != nil || root.kind != 'o' {
		s.out.Skips = append(s.out.Skips, protocol.Skip{Path: s.f.Path, Reason: protocol.SkipParseError})
		if lexical != nil {
			lexical()
		}
		return
	}
	fn(root)
}

// strs appends the strings of a command value: a string, an array of strings
// or objects with a "value" (VS Code task arguments).
func strs(n *node, dst []string) []string {
	if n == nil {
		return dst
	}
	switch n.kind {
	case 's':
		dst = append(dst, n.str)
	case 'a':
		for _, v := range n.vals {
			dst = strs(v, dst)
		}
	case 'o':
		if v := n.get("value"); v != nil && v.kind == 's' {
			dst = append(dst, v.str)
		}
	}
	return dst
}

// tasks reads the "tasks" list of holder (tasks.json, or the "tasks" section of
// a .code-workspace file). VS Code lowercases runOn, so the comparison ignores case.
func (s *scan) tasks(holder *node) {
	list := holder.get("tasks")
	if list == nil || list.kind != 'a' {
		return
	}
	byLabel := map[string]*node{}
	for _, t := range list.vals {
		if l := t.get("label"); l != nil && l.kind == 's' {
			byLabel[l.str] = t
		}
	}
	seen := map[*node]bool{} // shared, so a task that many tasks depend on is graded once
	for _, t := range list.vals {
		if s.done() {
			return
		}
		if t.kind != 'o' {
			continue
		}
		if runOn := t.get("runOptions").get("runOn"); runOn == nil || runOn.kind != 's' || !strings.EqualFold(runOn.str, "folderOpen") {
			continue
		}
		s.add(ruleTask, commandOffset(t))
		s.gradeTask(t, byLabel, seen)
	}
}

// gradeTask grades every string of a task that runs automatically, and of the
// tasks it depends on.
func (s *scan) gradeTask(t *node, byLabel map[string]*node, seen map[*node]bool) {
	if seen[t] || s.done() {
		return
	}
	seen[t] = true
	s.riskAt(strings.Join(taskStrings(t, nil), " "), commandOffset(t))
	for _, label := range dependLabels(t.get("dependsOn"), nil) {
		if dep := byLabel[label]; dep != nil {
			s.gradeTask(dep, byLabel, seen)
		}
	}
}

// dependLabels appends the labels a dependsOn value names: a label, a task
// identifier ({"type": ..., "task": label}) or an array of either.
func dependLabels(n *node, dst []string) []string {
	if n == nil {
		return dst
	}
	switch n.kind {
	case 's':
		dst = append(dst, n.str)
	case 'a':
		for _, v := range n.vals {
			dst = dependLabels(v, dst)
		}
	case 'o':
		if v := n.get("task"); v != nil && v.kind == 's' {
			dst = append(dst, v.str)
		}
	}
	return dst
}

// commandOffset is where a task's command starts, or the task itself without one.
func commandOffset(t *node) int {
	for _, scope := range []*node{t, t.get("windows"), t.get("linux"), t.get("osx")} {
		if c := scope.get("command"); c != nil {
			return c.start
		}
	}
	return t.start
}

// taskStrings appends all strings of a task (command, args, options, per-OS
// scopes) except those of keys that never run anything.
func taskStrings(n *node, dst []string) []string {
	switch n.kind {
	case 's':
		dst = append(dst, n.str)
	case 'a':
		for _, v := range n.vals {
			dst = taskStrings(v, dst)
		}
	case 'o':
		for i, k := range n.keys {
			switch k {
			case "label", "group", "problemMatcher", "presentation", "detail", "dependsOn", "runOptions":
			default:
				dst = taskStrings(n.vals[i], dst)
			}
		}
	}
	return dst
}

var (
	folderOpenRE = regexp.MustCompile(`(?i)runOn"\s*:\s*"folderOpen"`)
	devInitRE    = regexp.MustCompile(`(?i)"initializeCommand"\s*:`)
	devLifeRE    = regexp.MustCompile(`(?i)"(?:onCreate|updateContent|postCreate|postStart|postAttach)Command"\s*:`)
)

// tasksLexical is the fallback for a tasks file that does not parse.
func (s *scan) tasksLexical() {
	s.lexical(lexRule{ruleTask, folderOpenRE})
}

// devcontainerLexical is the fallback for a devcontainer file that does not parse.
func (s *scan) devcontainerLexical() {
	s.lexical(lexRule{ruleDevInit, devInitRE}, lexRule{ruleDevLife, devLifeRE})
}

type lexRule struct {
	rule protocol.Rule
	re   *regexp.Regexp
}

// lexical reports each rule at every match of its pattern and grades the whole
// file. It reads the file the way a tolerant JSON reader would: comments are
// blank and string escapes are decoded, so neither hides a trigger.
func (s *scan) lexical(rules ...lexRule) {
	text, offs := lexView(s.f.Data)
	at := func(off int) int {
		if off < len(offs) {
			return offs[off]
		}
		return 0
	}
	for _, r := range rules {
		for _, loc := range r.re.FindAllStringIndex(text, signals.MaxMatches) {
			s.add(r.rule, at(loc[0]))
		}
	}
	s.risk(text, func(off int) protocol.Evidence { return analyze.EvidenceAt(s.f, at(off)) })
}

func (s *scan) settings(root *node) {
	var walk func(n *node, prefix string)
	walk = func(n *node, prefix string) {
		for i := range n.keys {
			v, key := n.vals[i], prefix+strings.ToLower(n.keys[i])
			if v.kind == 'o' {
				walk(v, key+".")
				continue
			}
			switch {
			case strings.HasSuffix(key, "path") && v.kind == 's' && repoPath(v.str):
				s.add(ruleSetting, v.start)
			case strings.HasPrefix(key, "terminal.integrated.") && strings.Contains(key, "args"):
				args := strings.Join(strs(v, nil), " ")
				if shellArgsRE.MatchString(args) || repoPath(args) || len(signals.NetworkTools(args))+len(signals.SecretRefs(args))+len(signals.DecodeExec(args)) > 0 {
					s.add(ruleSetting, v.start)
				}
			}
		}
	}
	walk(root, "")
}

// repoPath reports whether a setting value points into the repository: a
// workspace variable or a relative path. Virtualenv and node_modules paths are
// package manager output and not reported.
func repoPath(v string) bool {
	v = strings.TrimSpace(v)
	lower := strings.ToLower(strings.ReplaceAll(v, "\\", "/"))
	// Cleaned first, so ".venv/../tools/x" is not taken for a virtualenv path.
	for _, seg := range strings.Split(path.Clean(lower), "/") {
		if seg == ".venv" || seg == "venv" || seg == "node_modules" {
			return false
		}
	}
	if strings.HasPrefix(lower, "${workspacefolder}") || strings.HasPrefix(lower, "${workspaceroot}") || strings.HasPrefix(lower, "${filedirname}") {
		return true
	}
	switch {
	case lower == "", strings.HasPrefix(lower, "/"), strings.HasPrefix(lower, "~"), strings.HasPrefix(lower, "${"):
		return false
	case len(lower) > 1 && lower[1] == ':':
		return false
	}
	return strings.Contains(lower, "/")
}

func (s *scan) devcontainer(root *node) {
	var leaves func(n *node)
	leaves = func(n *node) {
		if n.kind == 'o' {
			for _, v := range n.vals {
				leaves(v)
			}
			return
		}
		s.riskAt(strings.Join(strs(n, nil), " "), n.start)
	}
	if v := root.get("initializeCommand"); v != nil {
		s.add(ruleDevInit, v.start)
		leaves(v)
	}
	// These change the environment or the folder every command runs in: a PATH
	// or NODE_OPTIONS from the file, or a workspace other than the one graded.
	changed := root.get("containerEnv") != nil || root.get("remoteEnv") != nil ||
		root.get("workspaceFolder") != nil || root.get("workspaceMount") != nil
	g := newGrader(s)
	dir := workspaceDir(s.rel())
	for _, key := range devLifecycle {
		if v := root.get(key); v != nil {
			s.addGraded(ruleDevLife, v.start, !changed && g.allBenign(v, dir))
			leaves(v)
		}
	}
}

func (s *scan) packageJSON(root *node) {
	scripts := root.get("scripts")
	dir := path.Dir(s.rel())
	if dir == "." {
		dir = ""
	}
	g := newGrader(s)
	g.preload(dir, scripts)
	for _, group := range []struct {
		rule  protocol.Rule
		names []string
		grade bool // low severity when the script is benign
	}{{ruleNpm, npmInstall, true}, {ruleHook, npmPrepare, false}} {
		for _, name := range group.names {
			if v := scripts.get(name); v != nil && v.kind == 's' {
				s.addGraded(group.rule, v.start, group.grade && g.hook(dir, name, 0))
				s.riskAt(v.str, v.start)
			}
		}
	}
	// husky 4 keeps its hooks in package.json
	if hooks := root.get("husky").get("hooks"); hooks != nil && hooks.kind == 'o' {
		for _, v := range hooks.vals {
			if v.kind == 's' {
				s.add(ruleHook, v.start)
				s.riskAt(v.str, v.start)
			}
		}
	}
}

// rel is the path of the file inside its container, or on disk.
func (s *scan) rel() string {
	if s.f.Member != "" {
		return s.f.Member
	}
	return s.f.Path
}

// addGraded records a finding for rule at the byte offset, at low severity when
// the command behind it is benign.
func (s *scan) addGraded(r protocol.Rule, off int, benign bool) {
	if benign {
		r = lowered(r)
	}
	s.add(r, off)
}

// line is one line of a text file and its byte offset.
type line struct {
	off  int
	text string
}

func splitLines(data []byte) []line {
	var out []line
	for off := 0; off < len(data); {
		end := off
		for end < len(data) && data[end] != '\n' {
			end++
		}
		out = append(out, line{off: off, text: strings.TrimSuffix(string(data[off:min(end, off+analyze.MaxLineScan)]), "\r")})
		off = end + 1
	}
	return out
}

func (s *scan) husky() {
	text := shellText(s.f.Data)
	first := 0
	for _, l := range splitLines([]byte(text)) {
		if t := strings.TrimSpace(l.text); t != "" && !strings.Contains(t, "husky.sh") {
			first = l.off
			break
		}
	}
	s.add(ruleHook, first)
	s.riskFile()
}

func (s *scan) envrc() {
	s.add(ruleOther, 0)
	s.riskFile()
}

func (s *scan) preCommit() {
	lines := splitLines(s.f.Data)
	local, entries, repoOff := false, 0, 0
	closeBlock := func() {
		if local && entries == 0 {
			s.add(ruleHook, repoOff)
		}
	}
	for i, l := range lines {
		if m := repoRE.FindStringSubmatch(l.text); m != nil {
			closeBlock()
			local, entries, repoOff = strings.Trim(m[1], `"'`) == "local", 0, l.off
			continue
		}
		m := entryRE.FindStringSubmatch(l.text)
		if !local || m == nil {
			continue
		}
		entries++
		value := strings.TrimSpace(m[2])
		if blockScalar[value] {
			var parts []string
			for _, next := range lines[i+1:] {
				if strings.TrimSpace(next.text) != "" && len(next.text)-len(strings.TrimLeft(next.text, " \t")) <= len(m[1]) {
					break
				}
				parts = append(parts, next.text)
			}
			value = strings.Join(parts, "\n")
		}
		s.add(ruleHook, l.off)
		s.riskAt(strings.Trim(value, `"'`), l.off)
	}
	closeBlock()
}

func (s *scan) gitConfig() {
	section := ""
	for _, l := range splitLines(s.f.Data) {
		text := l.text
		if m := sectionRE.FindStringSubmatch(text); m != nil {
			section = strings.ToLower(m[1])
			// git accepts "[core] fsmonitor = cmd" on the header line
			text = text[len(m[0]):]
		}
		m := keyValueRE.FindStringSubmatch(text)
		if m == nil {
			continue
		}
		key, value := strings.ToLower(m[1]), strings.Trim(m[2], `"`)
		lowValue := strings.ToLower(value)
		var runs bool
		switch {
		case section == "core" && key == "fsmonitor":
			runs = !boolLike[lowValue]
		case section == "core" && key == "hookspath":
			runs = value != "" && !huskyPaths[strings.TrimSuffix(value, "/")]
		case section == "core" && key == "sshcommand":
			runs = value != ""
		case section == "filter" && (key == "smudge" || key == "clean" || key == "process"):
			runs = value != "" && !lfsFilterRE.MatchString(lowValue)
		default:
			continue
		}
		if runs {
			s.add(ruleGit, l.off)
		}
		// the value is graded even when the setting itself is a known tool
		s.riskAt(value, l.off)
	}
}

func (s *scan) setupPy() {
	off := 0
	if loc := setupCallRE.FindIndex(s.f.Data); loc != nil {
		off = loc[0]
	}
	s.add(rulePython, off)
}

func (s *scan) pyproject() {
	inBuild := false
	for _, l := range splitLines(s.f.Data) {
		if m := sectionRE.FindStringSubmatch(l.text); m != nil {
			inBuild = strings.ToLower(m[1]) == "build-system"
			continue
		}
		if m := keyValueRE.FindStringSubmatch(l.text); inBuild && m != nil && m[1] == "backend-path" {
			s.add(rulePython, l.off)
		}
	}
}
