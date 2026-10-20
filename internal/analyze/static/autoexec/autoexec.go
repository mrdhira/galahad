// Package autoexec lists the places where a repository runs code on its own
// (folder open, install, commit, git operations, entering a directory) and
// grades the risk of the commands behind the truly automatic triggers.
//
// Command-risk checks (rules 010 to 012) run only for triggers that need no
// action from the user: VS Code tasks that run on folder open, devcontainer
// commands, npm lifecycle scripts, husky hooks, local pre-commit hooks, git
// config and .envrc. Makefile, build.rs and CI workflows are inventory only,
// so a tool installer such as "curl ... | sh" in a Makefile is not graded.
package autoexec

import (
	"context"
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
)

type analyzer struct{}

// New returns the auto-execution analyzer.
func New() analyze.Analyzer { return analyzer{} }

func (analyzer) Name() string { return "autoexec" }

func (analyzer) Analyze(ctx context.Context, f analyze.File) (analyze.Output, error) {
	var out analyze.Output
	if err := ctx.Err(); err != nil {
		return out, err
	}
	rel := f.Path
	if i := strings.LastIndex(rel, "!/"); i >= 0 {
		rel = rel[i+2:]
	}
	segs := strings.Split(strings.ToLower(rel), "/")
	base := segs[len(segs)-1]
	dirs := segs[:len(segs)-1]
	parent := ""
	if len(dirs) > 0 {
		parent = dirs[len(dirs)-1]
	}
	if slicesContains(dirs, "node_modules") {
		return out, nil
	}
	s := &scan{f: f, out: &out}

	var run func()
	switch {
	case base == "tasks.json" && parent == ".vscode":
		run = func() { s.json(s.tasks) }
	case base == "settings.json" && parent == ".vscode":
		run = func() { s.json(s.settings) }
	case base == ".devcontainer.json", base == "devcontainer.json" && slicesContains(dirs, ".devcontainer"):
		run = func() { s.json(s.devcontainer) }
	case base == "package.json":
		run = func() { s.json(s.packageJSON) }
	case parent == ".husky" && !strings.HasPrefix(base, ".") && base != "husky.sh":
		run = s.husky
	case base == ".pre-commit-config.yaml":
		run = s.preCommit
	case base == "config" && parent == ".git":
		run = s.gitConfig
	case base == "setup.py":
		run = s.setupPy
	case base == "pyproject.toml":
		run = s.pyproject
	case base == ".envrc":
		run = s.envrc
	case base == "build.rs", base == "makefile", base == "gnumakefile", isWorkflow(dirs, base):
		s.add(ruleOther, 0)
		return out, nil
	default:
		return out, nil
	}
	if len(f.Data) > analyze.MaxConfigSize {
		out.Skips = append(out.Skips, protocol.Skip{Path: f.Path, Reason: protocol.SkipTooLarge})
		return out, nil
	}
	run()
	return out, nil
}

func isWorkflow(dirs []string, base string) bool {
	n := len(dirs)
	return n >= 2 && dirs[n-2] == ".github" && dirs[n-1] == "workflows" && (path.Ext(base) == ".yml" || path.Ext(base) == ".yaml")
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
	f   analyze.File
	out *analyze.Output
}

// add records a finding for rule at the byte offset.
func (s *scan) add(r protocol.Rule, off int) {
	s.out.Findings = append(s.out.Findings, r.Finding(analyze.EvidenceAt(s.f, off)))
}

// risk grades a command that runs automatically. at maps an offset in text to
// the evidence to report, which lets the caller point at a file line or at the
// config value the text came from.
func (s *scan) risk(text string, at func(int) protocol.Evidence) {
	for _, m := range signals.DecodeExec(text) {
		s.out.Findings = append(s.out.Findings, ruleObfuscate.Finding(at(m.Start)))
	}
	for _, m := range signals.DownloadExec(text) {
		s.out.Findings = append(s.out.Findings, ruleDownload.Finding(at(m.Start)))
	}
	secrets, network := signals.SecretRefs(text), signals.NetworkTools(text)
	if len(secrets) == 0 || len(network) == 0 {
		return
	}
	ev := []protocol.Evidence{at(secrets[0].Start)}
	if n := at(network[0].Start); n.Line != ev[0].Line {
		ev = append(ev, n)
	}
	s.out.Findings = append(s.out.Findings, ruleExfil.Finding(ev...))
}

// riskAt grades text that is not literally in the file (an unescaped JSON
// string, a YAML value) and reports the line at off.
func (s *scan) riskAt(text string, off int) {
	ev := analyze.EvidenceAt(s.f, off)
	s.risk(text, func(int) protocol.Evidence { return ev })
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

// json parses the file as JSONC and passes the root to fn.
func (s *scan) json(fn func(root *node)) {
	root, err := parseJSON(StripJSONC(s.f.Data))
	if err != nil || root.kind != 'o' {
		s.out.Skips = append(s.out.Skips, protocol.Skip{Path: s.f.Path, Reason: protocol.SkipParseError})
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

func (s *scan) tasks(root *node) {
	list := root.get("tasks")
	if list == nil || list.kind != 'a' {
		return
	}
	for _, t := range list.vals {
		if t.kind != 'o' {
			continue
		}
		if runOn := t.get("runOptions").get("runOn"); runOn == nil || runOn.str != "folderOpen" {
			continue
		}
		off := t.start
		var parts []string
		for _, scope := range []*node{t, t.get("windows"), t.get("linux"), t.get("osx")} {
			if c := scope.get("command"); c != nil {
				if off == t.start {
					off = c.start
				}
				parts = strs(c, parts)
			}
			parts = strs(scope.get("args"), parts)
		}
		s.add(ruleTask, off)
		s.riskAt(strings.Join(parts, " "), off)
	}
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
	for _, seg := range strings.Split(lower, "/") {
		if seg == ".venv" || seg == "venv" || seg == "node_modules" {
			return false
		}
	}
	switch {
	case strings.HasPrefix(lower, "${workspacefolder}"), strings.HasPrefix(lower, "${workspaceroot}"), strings.HasPrefix(lower, "${filedirname}"):
		return true
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
	for _, key := range devLifecycle {
		if v := root.get(key); v != nil {
			s.add(ruleDevLife, v.start)
			leaves(v)
		}
	}
}

func (s *scan) packageJSON(root *node) {
	scripts := root.get("scripts")
	if scripts == nil || scripts.kind != 'o' {
		return
	}
	for _, name := range append(npmInstall, "prepare") {
		v := scripts.get(name)
		if v == nil || v.kind != 's' {
			continue
		}
		if name == "prepare" {
			s.add(ruleHook, v.start)
		} else {
			s.add(ruleNpm, v.start)
		}
		s.riskAt(v.str, v.start)
	}
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
		if m := sectionRE.FindStringSubmatch(l.text); m != nil {
			section = strings.ToLower(m[1])
			continue
		}
		m := keyValueRE.FindStringSubmatch(l.text)
		if m == nil {
			continue
		}
		key, value := strings.ToLower(m[1]), strings.Trim(m[2], `"`)
		lowValue := strings.ToLower(value)
		switch {
		case section == "core" && key == "fsmonitor" && !boolLike[lowValue],
			section == "core" && key == "hookspath" && value != "" && !huskyPaths[strings.TrimSuffix(value, "/")],
			section == "core" && key == "sshcommand" && value != "",
			section == "filter" && (key == "smudge" || key == "clean") && value != "" &&
				!strings.HasPrefix(lowValue, "git-lfs ") && !strings.HasPrefix(lowValue, "git lfs "):
			s.add(ruleGit, l.off)
			s.riskAt(value, l.off)
		}
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
