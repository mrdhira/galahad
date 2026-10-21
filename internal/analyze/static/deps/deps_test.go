package deps_test

import (
	"context"
	"fmt"
	"math"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mrdhira/galahad/internal/analyze"
	"github.com/mrdhira/galahad/internal/analyze/static/deps"
)

const (
	pyprojectRequirements = `[project]
name = "demo"
dependencies = [
  "requests>=2",
  "reqeusts==1",
  "pkg @ https://dl.sinkhole.test/pkg.zip",
  "other @ git+https://git.sinkhole.test/o.git",
]
[project.optional-dependencies]
dev = ["pytest", "localpkg @ file:///tmp/t"]
[build-system]
requires = ["setuptools>=61", "bad @ https://dl.sinkhole.test/b.zip"]
[dependency-groups]
test = ["pytest", {include-group = "lint"}]
`
	pyprojectUV = `[tool.uv]
index-url = "https://pypi.org/simple"
extra-index-url = ["https://pypi.sinkhole.test/simple",
  "https://pypi.org/simple"] # second is the default
find-links = ["./wheels", "https://wheels.sinkhole.test/"]
index = [{ url = "https://idx.sinkhole.test/simple", name = "x" }]
[tool.uv.pip]
extra-index-url = "local-index"
[[tool.uv.index]]
name = "internal"
url = "https://uv.sinkhole.test/simple"
[[tool.uv.index]]
url = "https://pypi.org/simple"
`
	pyprojectSources = `[tool.uv.sources]
a = { git = "https://git.sinkhole.test/a.git" }
b = { path = "../b" }
c = [
  { url = "https://dl.sinkhole.test/c.whl", marker = "sys_platform == 'win32'" },
]
d.git = "https://git.sinkhole.test/d.git"
e = { workspace = true }
"g" = { "git" = "https://git.sinkhole.test/g.git" }
h = { url = "file:///tmp/h.whl" }
[tool.uv.sources.f]
git = "https://git.sinkhole.test/f.git"
`
	pyprojectPoetry = `[[tool.poetry.source]]
name = "priv"
url = "https://poetry.sinkhole.test/simple"
[tool.poetry.dependencies]
python = "^3.9"
g = { git = "https://git.sinkhole.test/g.git", branch = "main" }
h = "^1.0"
[tool.poetry.group.dev.dependencies]
i = { url = "https://dl.sinkhole.test/i.whl" }
[tool.poetry.group.dev.dependencies.j]
git = "https://git.sinkhole.test/j.git"
[tool.other]
k = { git = "https://git.sinkhole.test/k.git" }
`
	pyprojectMultiline = `[project]
summary = '''one [ line'''
description = """
[tool.uv]
index-url = "https://pypi.sinkhole.test/simple"
dependencies = [ "
"""
dependencies = [
  "pkg @ https://dl.sinkhole.test/p.zip",
]
`
	pyprojectDotted = `[tool]
uv.sources.a = { git = "https://git.sinkhole.test/a.git" }
uv.index-url = "https://pypi.sinkhole.test/simple"
uv.sources.b.url = "https://dl.sinkhole.test/b.whl"
poetry.dependencies.c = { url = "https://dl.sinkhole.test/c.whl" }
[tool.uv]
sources = { d = { git = "https://git.sinkhole.test/d.git" }, e = { path = "../e" } }
index = [{ url = "https://idx.sinkhole.test/simple" }]
[project]
optional-dependencies = { dev = ["pkg @ https://dl.sinkhole.test/p.zip", "pytest"], docs = ["sphinx"] }
dependencies = []
[dependency-groups]
all = [{include-group = "dev"}]
`
	pyprojectMultilineValues = `[tool.uv]
index-url = """\
    https://pypi.sinkhole.test/simple"""
[tool.uv.sources]
helper = { git = """\
    https://git.sinkhole.test/h.git""" }
other = { git = "https://git.sinkhole.test/o.git" }
`
	pyprojectNestedTables = `[tool]
uv = { sources = { helper = { git = "https://git.sinkhole.test/h.git" } }, index-url = "https://pypi.sinkhole.test/simple" }
uv.pip = { extra-index-url = ["https://pypi.org/simple", "https://p2.sinkhole.test/simple"] }
`
	pyprojectBenign = `[build-system]
requires = ["setuptools>=61", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "tinylib"
dependencies = ["requests>=2.31", "numpy"]

[project.optional-dependencies]
dev = ["pytest"]

[tool.uv]
index-url = "https://pypi.org/simple"

[tool.uv.sources]
tinylib = { workspace = true }
local = { path = "../local" }

[tool.poetry.dependencies]
python = "^3.9"
flask = "^3.0"
`
	uvTomlSettings = `index-url = "https://pypi.org/simple"
extra-index-url = ["https://pypi.sinkhole.test/simple"]
[pip]
find-links = ["https://wheels.sinkhole.test/"]
[[index]]
url = "https://uv.sinkhole.test/simple"
[sources]
a = { git = "https://git.sinkhole.test/a.git" }
`
)

func TestAnalyze(t *testing.T) {
	filler := strings.Repeat("x", 3<<19) // 1.5 MiB, above MaxConfigSize
	deep := strings.Repeat(`{"a":`, 40) + "1" + strings.Repeat("}", 40)
	var manyGit, manyLock, manyYarn strings.Builder
	var wantManyGit, wantManyLock, wantManyYarn []string
	for i := range 25 {
		fmt.Fprintf(&manyGit, "\"g%d\": \"git+https://git.sinkhole.test/g%d.git\",\n", i, i)
		fmt.Fprintf(&manyLock, "\"node_modules/l%d\": {\"resolved\": \"https://npm.sinkhole.test/l%d.tgz\"},\n", i, i)
		fmt.Fprintf(&manyYarn, "a%d@^1:\n  resolved \"https://npm.sinkhole.test/a%d.tgz#x\"\n", i, i)
		if i < 20 {
			wantManyYarn = append(wantManyYarn, fmt.Sprintf("GAL-DEPS-003@%d", 2*i+2))
			wantManyGit = append(wantManyGit, fmt.Sprintf("GAL-DEPS-002@%d", i+3))
			wantManyLock = append(wantManyLock, fmt.Sprintf("GAL-DEPS-003@%d", i+3))
		}
	}
	slices.Sort(wantManyGit)
	slices.Sort(wantManyLock)
	slices.Sort(wantManyYarn)
	tomlAtLimit := "[project]\noptional-dependencies = " + strings.Repeat("{a=", 31) + `["pkg @ https://dl.sinkhole.test/p.zip"]` + strings.Repeat("}", 31) + "\n"
	tomlTooDeep := "[tool]\nx = " + strings.Repeat("{a=", 33) + `"v"` + strings.Repeat("}", 33) + "\n"
	tests := []struct {
		name string
		// inputs
		file string
		data string
		// expectations
		wantFindings []string // "RULE@line" sorted
		wantSkip     string
	}{
		{
			name:         "package.json with typosquats and a git dependency",
			file:         "package.json",
			data:         "{\n  \"name\": \"demo\",\n  \"version\": \"1.0.0\",\n  \"private\": true,\n  \"dependencies\": {\n    \"expresss\": \"^4.18.2\",\n    \"lodahs\": \"^4.17.21\",\n    \"my-utils\": \"github:someone/utils\"\n  }\n}\n",
			wantFindings: []string{"GAL-DEPS-001@6", "GAL-DEPS-001@7", "GAL-DEPS-002@8"},
		},
		{name: "unrelated file is ignored", file: "index.js", data: "const x = 'expresss'\n"},
		{name: "oversized config is skipped", file: "package.json", data: "{" + strings.Repeat(" ", analyze.MaxConfigSize) + "}", wantSkip: "too_large"},
		{
			name:         "all four dependency sections are checked",
			file:         "package.json",
			data:         "{\n\"dependencies\": {\"expresss\": \"1\"},\n\"devDependencies\": {\"lodahs\": \"1\"},\n\"optionalDependencies\": {\"reactt\": \"1\"},\n\"peerDependencies\": {\"axioss\": \"1\"},\n\"scripts\": {\"expresss\": \"x\"}\n}",
			wantFindings: []string{"GAL-DEPS-001@2", "GAL-DEPS-001@3", "GAL-DEPS-001@4", "GAL-DEPS-001@5"},
		},
		{
			name: "file workspace and link specs are ignored",
			file: "package.json",
			data: "{\n\"dependencies\": {\n\"expresss\": \"file:../x\",\n\"lodahs\": \"workspace:*\",\n\"reactt\": \"link:../r\"\n}\n}",
		},
		{
			name:         "git, github shorthand and tarball specs",
			file:         "package.json",
			data:         "{\n\"dependencies\": {\n\"a-one\": \"git+https://git.example.test/a.git\",\n\"b-two\": \"someone/utils#v1\",\n\"c-three\": \"https://dl.example.test/c.tgz\",\n\"d-four\": \"^1.2.3\",\n\"e-five\": \"npm:other@1.0.0\",\n\"@scope/f-six\": \"1.0.0\"\n}\n}",
			wantFindings: []string{"GAL-DEPS-002@3", "GAL-DEPS-002@4", "GAL-DEPS-002@5"},
		},
		{
			name:         "popular names are fine, a typo of a popular name is caught",
			file:         "package.json",
			data:         "{\n\"dependencies\": {\n\"express\": \"1\",\n\"@types/react\": \"1\",\n\"lodahs\": \"1\",\n\"Ex_Press\": \"1\"\n}\n}",
			wantFindings: []string{"GAL-DEPS-001@5", "GAL-DEPS-001@6"},
		},
		{
			name: "real packages one edit from a popular name are not typosquats",
			file: "package.json",
			data: "{\n\"devDependencies\": {\"socks\": \"1\", \"eclint\": \"1\", \"jsdoc\": \"1\", \"json-schema\": \"1\", \"npm-run-all2\": \"1\"}\n}",
		},
		{name: "a five-character name one edit from a popular name is not a typosquat", file: "package.json", data: "{\n\"dependencies\": {\"reacx\": \"1\"}\n}"},
		{
			name: "packages in a popular scope are never typosquats",
			file: "package.json",
			data: "{\n\"devDependencies\": {\"@typescript-eslint/parser\": \"1\", \"@types/estree\": \"1\", \"@babel/parser\": \"1\", \"@types/lodahs\": \"1\"}\n}",
		},
		{
			name:         "a scoped name is compared by its scope, not its bare name",
			file:         "package.json",
			data:         "{\n\"dependencies\": {\n\"@typscript-eslint/parser\": \"1\",\n\"@evil/lodahs\": \"1\",\n\"@jest/core\": \"1\",\n\"@babell/core\": \"1\"\n}\n}",
			wantFindings: []string{"GAL-DEPS-001@3", "GAL-DEPS-001@6"},
		},
		{
			name:         "package.json reports only the findings per rule the engine keeps",
			file:         "package.json",
			data:         "{\n\"dependencies\": {\n" + manyGit.String() + "\"x\": \"1\"\n}\n}\n",
			wantFindings: wantManyGit,
		},
		{name: "malformed json keeps what was read and skips the rest", file: "package.json", data: "{\n\"dependencies\": {\n\"expresss\": \"1\",\n", wantFindings: []string{"GAL-DEPS-001@3"}, wantSkip: "parse_error"},
		{name: "deeply nested json is skipped", file: "package.json", data: deep, wantSkip: "depth"},
		{
			name:         "lockfile resolving from another host",
			file:         "package-lock.json",
			data:         "{\n\"packages\": {\n\"\": {\"name\": \"x\"},\n\"node_modules/a\": {\n\"resolved\": \"https://registry.npmjs.org/a/-/a-1.tgz\"\n},\n\"node_modules/b\": {\n\"resolved\": \"https://npm.sinkhole.test/b/-/b-1.tgz\"\n},\n\"node_modules/c\": {\n\"resolved\": \"file:../c\"\n},\n\"node_modules/d\": {\n\"resolved\": \"git+ssh://git@git.example.test/d.git\"\n}\n}\n}",
			wantFindings: []string{"GAL-DEPS-003@14", "GAL-DEPS-003@8"},
		},
		{
			name:         "lockfile reports only the findings the engine keeps",
			file:         "package-lock.json",
			data:         "{\n\"packages\": {\n" + manyLock.String() + "\"x\": {}\n}\n}\n",
			wantFindings: wantManyLock,
		},
		{
			name:         "yarn lock resolved lines",
			file:         "yarn.lock",
			data:         "# yarn lockfile v1\n\na@^1:\n  version \"1.0.0\"\n  resolved \"https://registry.yarnpkg.com/a/-/a-1.0.0.tgz#abc\"\n\nb@^1:\n  version \"1.0.0\"\n  resolved \"https://npm.sinkhole.test/b/-/b-1.0.0.tgz#def\"\n",
			wantFindings: []string{"GAL-DEPS-003@9"},
		},
		{
			name:         "yarn lock reports only the findings the engine keeps",
			file:         "yarn.lock",
			data:         manyYarn.String(),
			wantFindings: wantManyYarn,
		},
		{
			name:         "pyproject project, build-system and dependency-group requirements",
			file:         "pyproject.toml",
			data:         pyprojectRequirements,
			wantFindings: []string{"GAL-DEPS-001@5", "GAL-DEPS-002@12", "GAL-DEPS-002@6", "GAL-DEPS-002@7"},
		},
		{
			name:         "pyproject uv index settings",
			file:         "pyproject.toml",
			data:         pyprojectUV,
			wantFindings: []string{"GAL-DEPS-004@11", "GAL-DEPS-004@3", "GAL-DEPS-004@5", "GAL-DEPS-004@6", "GAL-DEPS-004@8"},
		},
		{
			name:         "pyproject uv sources from git and URL",
			file:         "pyproject.toml",
			data:         pyprojectSources,
			wantFindings: []string{"GAL-DEPS-002@12", "GAL-DEPS-002@2", "GAL-DEPS-002@5", "GAL-DEPS-002@7", "GAL-DEPS-002@9"},
		},
		{
			name:         "pyproject poetry source and git or URL dependencies",
			file:         "pyproject.toml",
			data:         pyprojectPoetry,
			wantFindings: []string{"GAL-DEPS-002@11", "GAL-DEPS-002@6", "GAL-DEPS-002@9", "GAL-DEPS-004@3"},
		},
		{name: "pyproject with only PyPI dependencies", file: "pyproject.toml", data: pyprojectBenign},
		{
			name:         "pyproject multi-line strings hide no table or bracket",
			file:         "pyproject.toml",
			data:         pyprojectMultiline,
			wantFindings: []string{"GAL-DEPS-002@9"},
		},
		{
			name:         "pyproject multi-line string values are joined across line continuations",
			file:         "pyproject.toml",
			data:         pyprojectMultilineValues,
			wantFindings: []string{"GAL-DEPS-002@5", "GAL-DEPS-002@7", "GAL-DEPS-004@2"},
		},
		{
			name:         "pyproject nested inline tables are classified by the keys above them",
			file:         "pyproject.toml",
			data:         pyprojectNestedTables,
			wantFindings: []string{"GAL-DEPS-002@2", "GAL-DEPS-004@2", "GAL-DEPS-004@3"},
		},
		{
			name:         "pyproject dotted keys and inline tables are classified by their full path",
			file:         "pyproject.toml",
			data:         pyprojectDotted,
			wantFindings: []string{"GAL-DEPS-002@10", "GAL-DEPS-002@2", "GAL-DEPS-002@4", "GAL-DEPS-002@5", "GAL-DEPS-002@7", "GAL-DEPS-004@3", "GAL-DEPS-004@8"},
		},
		{
			name:         "uv.toml settings are read as tool.uv",
			file:         "uv.toml",
			data:         uvTomlSettings,
			wantFindings: []string{"GAL-DEPS-002@8", "GAL-DEPS-004@2", "GAL-DEPS-004@4", "GAL-DEPS-004@6"},
		},
		{
			name:         "pyproject uv dev, override and constraint dependencies are requirements",
			file:         "pyproject.toml",
			data:         "[tool.uv]\ndev-dependencies = [\"pkg @ git+https://git.sinkhole.test/p.git\"]\noverride-dependencies = [\"o @ https://dl.sinkhole.test/o.zip\"]\nconstraint-dependencies = [\"c @ git+https://git.sinkhole.test/c.git\", \"requests>=2\"]\n",
			wantFindings: []string{"GAL-DEPS-002@2", "GAL-DEPS-002@3", "GAL-DEPS-002@4"},
		},
		{name: "pyproject value nested to the depth limit is read", file: "pyproject.toml", data: tomlAtLimit, wantFindings: []string{"GAL-DEPS-002@2"}},
		{name: "pyproject value nested past the depth limit is skipped", file: "pyproject.toml", data: tomlTooDeep, wantSkip: "depth"},
		{name: "pyproject table name past the path limit is skipped", file: "pyproject.toml", data: "[" + strings.Repeat("t", 1100) + "]\nx = \"v\"\n", wantSkip: "depth"},
		{name: "pyproject inline table key path past the limit is skipped", file: "pyproject.toml", data: "[tool]\nx = { " + strings.Repeat("k", 1100) + " = \"v\" }\n", wantSkip: "depth"},
		{
			name:         "requirements index options",
			file:         "requirements-dev.txt",
			data:         "-i https://pypi.org/simple\n--index-url=https://files.pythonhosted.org/simple\n--extra-index-url https://pypi.sinkhole.test/simple\n-i https://other.sinkhole.test/simple\n--extra-index-url local-dir\n-r base.txt\n",
			wantFindings: []string{"GAL-DEPS-004@3", "GAL-DEPS-004@4", "GAL-DEPS-004@5"},
		},
		{
			name:         "requirements typosquats and URL requirements",
			file:         "requirements.txt",
			data:         "# comment\nrequests>=2\nreqeusts==1  # swapped\nnum_py\ngit+https://git.example.test/x.git#egg=x\n-e git+https://git.example.test/y.git#egg=y\npkg @ https://dl.example.test/pkg.zip\nfile:///tmp/z\n-e .\n./local\nfoo-1.0-py3-none-any.whl\nsome-lib[extra]>=1 ; python_version>'3'\n\n",
			wantFindings: []string{"GAL-DEPS-001@3", "GAL-DEPS-001@4", "GAL-DEPS-002@5", "GAL-DEPS-002@6", "GAL-DEPS-002@7"},
		},
		{
			name:         "requirements option spellings",
			file:         "requirements.txt",
			data:         "-ihttps://a.sinkhole.test/simple\n--index-url\thttps://b.sinkhole.test/simple\n--extra-index=https://c.sinkhole.test/simple\n--extra-index-url\thttps://pypi.org/simple\n-f https://d.sinkhole.test/wheels\n--find-links=https://pypi.org/x\n-f ./wheels\n--no-binary :all:\n",
			wantFindings: []string{"GAL-DEPS-004@1", "GAL-DEPS-004@2", "GAL-DEPS-004@3", "GAL-DEPS-004@5"},
		},
		{
			name:         "included file with another name that has a version pin",
			file:         "base.txt",
			data:         "# base\nrequests==2.31.0\n--extra-index-url https://pypi.sinkhole.test/simple\nreqeusts==1\n",
			wantFindings: []string{"GAL-DEPS-001@4", "GAL-DEPS-004@3"},
		},
		{
			name:         "included file recognized by its -r and -c options",
			file:         "deps.txt",
			data:         "-r base.txt\n--constraint=pins.txt\npkg @ https://dl.sinkhole.test/pkg.zip\n",
			wantFindings: []string{"GAL-DEPS-002@3"},
		},
		{
			name:         "included file with hash continuation lines",
			file:         "locked.txt",
			data:         "reqeusts==1.0 \\\n    --hash=sha256:abc\n",
			wantFindings: []string{"GAL-DEPS-001@1"},
		},
		{
			name:         "any txt under a requirements directory",
			file:         "pip/requirements/dev.txt",
			data:         "reqeusts\npkg @ https://dl.sinkhole.test/x.zip\n",
			wantFindings: []string{"GAL-DEPS-001@1", "GAL-DEPS-002@2"},
		},
		{
			name:         "only the first 50 lines decide whether a txt file is requirements",
			file:         "more.txt",
			data:         "requests==1\nrequests==1\nreqeusts==1\n" + strings.Repeat("requests==1\n", 47) + "some prose here\n",
			wantFindings: []string{"GAL-DEPS-001@3"},
		},
		{name: "README text is not requirements", file: "README.txt", data: "Project notes\nSee https://docs.sinkhole.test/guide for details.\nInstall with requests==2.0 first.\n"},
		{name: "license text is not requirements", file: "LICENSE.txt", data: "MIT License\n\nCopyright (c) 2024 Someone\n"},
		{name: "list of words is not requirements", file: "words.txt", data: "reqeusts\nbeta\ngamma\n"},
		{name: "list of links is not requirements", file: "links.txt", data: "https://a.sinkhole.test/x\nhttps://b.sinkhole.test/y\n"},
		{name: "list of e-mail addresses is not requirements", file: "contacts.txt", data: "dev@example.test\nops@example.test\n"},
		{name: "bullet list is not requirements", file: "todo.txt", data: "- item one\n- item two\n"},
		{name: "requirement lines followed by prose are not requirements", file: "notes.txt", data: "requests==2.0\nThis is not a requirements file.\n"},
		{name: "comments only is not requirements", file: "comments.txt", data: "# just a comment\n\n"},
		{name: "very long line is not requirements", file: "wide.txt", data: "requests==2.0\n" + strings.Repeat("a", 1001) + "\n"},
		{name: "large txt that is not requirements is not a coverage gap", file: "wordlist.txt", data: filler},
		{name: "large txt that is requirements is skipped", file: "huge.txt", data: strings.Repeat("requests==1\n", 100000), wantSkip: "too_large"},
		{
			name:         "lockfile above the config size limit is still checked",
			file:         "package-lock.json",
			data:         "{\n\"x\": \"" + filler + "\",\n\"packages\": {\n\"node_modules/b\": {\n\"resolved\": \"https://npm.sinkhole.test/b.tgz\"\n}\n}\n}",
			wantFindings: []string{"GAL-DEPS-003@5"},
		},
		{
			name:         "yarn lock above the config size limit is still checked",
			file:         "yarn.lock",
			data:         "# " + filler + "\nb@^1:\n  resolved \"https://npm.sinkhole.test/b.tgz#x\"\n",
			wantFindings: []string{"GAL-DEPS-003@3"},
		},
		{
			name:         "npm alias targets are checked",
			file:         "package.json",
			data:         "{\n\"dependencies\": {\n\"x\": \"npm:expresss@1.0.0\",\n\"y\": \"npm:express@1.0.0\",\n\"z\": \"npm:@babell/core\"\n}\n}",
			wantFindings: []string{"GAL-DEPS-001@3", "GAL-DEPS-001@5"},
		},
		{
			name: "popular packages missing from earlier snapshots are not typosquats",
			file: "package.json",
			data: "{\n\"dependencies\": {\"recharts\": \"1\", \"cookies\": \"1\", \"xtend\": \"1\", \"merge2\": \"1\", \"colord\": \"1\"}\n}",
		},
		{name: "popular python packages missing from earlier snapshots", file: "requirements.txt", data: "psycopg\ncattrs\npymssql\npyaml\ntyping__extensions\nTyping.Extensions\n"},
		{name: "benign requirements", file: "requirements.txt", data: "requests>=2.31\nnumpy>=1.26\nFlask_Cors==4\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := analyze.File{Path: "app/" + tt.file, Name: tt.file, Data: []byte(tt.data)}

			out, err := deps.New().Analyze(context.Background(), f)

			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, fd := range out.Findings {
				ev := fd.Evidence[0]
				if ev.Path != f.Path {
					t.Errorf("evidence path = %q, want %q", ev.Path, f.Path)
				}
				got = append(got, fmt.Sprintf("%s@%d", fd.RuleID, ev.Line))
			}
			slices.Sort(got)
			if !slices.Equal(got, tt.wantFindings) {
				t.Errorf("findings = %q, want %q", got, tt.wantFindings)
			}
			gotSkip := ""
			if len(out.Skips) > 0 {
				gotSkip = out.Skips[0].Reason
			}
			if gotSkip != tt.wantSkip {
				t.Errorf("skip = %q, want %q", gotSkip, tt.wantSkip)
			}
		})
	}
}

func TestAnalyzeMetadata(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		file string
		data string
		// expectations
		wantRule     string
		wantSeverity string
		wantAttack   string
		wantSnippet  string
	}{
		{name: "typosquat is high", file: "package.json", data: "{\"dependencies\": {\"expresss\": \"1\"}}", wantRule: "GAL-DEPS-001", wantSeverity: "high", wantAttack: "T1195.001", wantSnippet: `{"dependencies": {"expresss": "1"}}`},
		{name: "python index is medium", file: "requirements.txt", data: "--index-url https://x.sinkhole.test/\n", wantRule: "GAL-DEPS-004", wantSeverity: "medium", wantAttack: "T1195.001", wantSnippet: "--index-url https://x.sinkhole.test/"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := analyze.File{Path: tt.file, Name: tt.file, Data: []byte(tt.data)}

			out, err := deps.New().Analyze(context.Background(), f)

			if err != nil || len(out.Findings) != 1 {
				t.Fatalf("err = %v, findings = %+v, want 1 finding", err, out.Findings)
			}
			fd := out.Findings[0]
			if fd.RuleID != tt.wantRule || string(fd.Severity) != tt.wantSeverity || fd.Attack != tt.wantAttack || fd.Evidence[0].Snippet != tt.wantSnippet {
				t.Errorf("finding = %s %s %s %q, want %s %s %s %q", fd.RuleID, fd.Severity, fd.Attack, fd.Evidence[0].Snippet, tt.wantRule, tt.wantSeverity, tt.wantAttack, tt.wantSnippet)
			}
		})
	}
}

func TestAnalyzeLargeFilesWithinDeadline(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		file string
		data string
		// expectations
		wantFindings []string
		wantSkip     string
	}{
		{
			name:         "multi-line string over 500k lines",
			file:         "pyproject.toml",
			data:         "[project]\ndescription = \"\"\"\n" + strings.Repeat("a\n", 500000) + "\"\"\"\ndependencies = [\"pkg @ https://dl.sinkhole.test/p.zip\"]\n",
			wantFindings: []string{"GAL-DEPS-002@500004"},
		},
		{
			name:         "open array over a million blank lines",
			file:         "pyproject.toml",
			data:         "[tool.x]\nv = [\n" + strings.Repeat("\n", 1000000) + "]\n[tool.uv.sources]\nhelper = { git = \"https://git.sinkhole.test/h.git\" }\n",
			wantFindings: []string{"GAL-DEPS-002@1000005"},
		},
		{
			name:     "long inline table key followed by many strings",
			file:     "pyproject.toml",
			data:     "[tool]\nx = {" + strings.Repeat("k", 500000) + "=[\"" + strings.Repeat("\",\"", 150000) + "\"]}\n",
			wantSkip: "depth",
		},
		{
			name:     "long table name followed by many keys",
			file:     "pyproject.toml",
			data:     "[" + strings.Repeat("t", 512<<10) + "]\n" + strings.Repeat("a=\"1\"\n", 87000) + "[tool.uv.sources]\nhelper = { git = \"https://git.sinkhole.test/h.git\" }\n",
			wantSkip: "depth",
		},
		{
			name:         "requirements index option after 340k lines",
			file:         "requirements.txt",
			data:         strings.Repeat("-q\n", 340000) + "--index-url https://pypi.sinkhole.test/simple\n",
			wantFindings: []string{"GAL-DEPS-004@340001"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// the reader is linear: a quadratic one runs for minutes, past this deadline
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			f := analyze.File{Path: tt.file, Name: tt.file, Data: []byte(tt.data)}

			out, err := deps.New().Analyze(ctx, f)

			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, fd := range out.Findings {
				got = append(got, fmt.Sprintf("%s@%d", fd.RuleID, fd.Evidence[0].Line))
			}
			if !slices.Equal(got, tt.wantFindings) {
				t.Errorf("findings = %q, want %q", got, tt.wantFindings)
			}
			gotSkip := ""
			if len(out.Skips) > 0 {
				gotSkip = out.Skips[0].Reason
			}
			if gotSkip != tt.wantSkip {
				t.Errorf("skip = %q, want %q", gotSkip, tt.wantSkip)
			}
		})
	}
}

func TestAnalyzeLinesCostAlike(t *testing.T) {
	const uvGit = "[tool.uv.sources]\nhelper = { git = \"https://git.sinkhole.test/h.git\" }\n"
	tests := []struct {
		name string
		// inputs
		file     string
		data     string // lines the reader handles one by one
		baseline string // as many lines, skipped before any work per line
		// expectations
		wantMaxRatio float64 // time for data over time for baseline: 1 to 2 when linear, 15 under heavy load, over 60 when quadratic
	}{
		{
			name:         "pyproject open array over blank lines",
			file:         "pyproject.toml",
			data:         "[tool.x]\nv = [\n" + strings.Repeat("\n", 1000000) + "]\n" + uvGit,
			baseline:     "[tool.x]\n\n" + strings.Repeat("\n", 1000000) + "\n" + uvGit,
			wantMaxRatio: 25,
		},
		{
			name:         "requirements option lines",
			file:         "requirements.txt",
			data:         strings.Repeat("-q\n", 340000) + "--index-url https://pypi.sinkhole.test/simple\n",
			baseline:     strings.Repeat("#q\n", 340000) + "--index-url https://pypi.sinkhole.test/simple\n",
			wantMaxRatio: 25,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := analyze.File{Path: tt.file, Name: tt.file, Data: []byte(tt.data)}
			baseline := analyze.File{Path: tt.file, Name: tt.file, Data: []byte(tt.baseline)}
			// the fastest of runs that take turns: both are long enough to share
			// the CPU alike under load, and a garbage collector pause does not
			// decide the ratio
			bestData, bestBaseline := time.Duration(math.MaxInt64), time.Duration(math.MaxInt64)
			for range 3 {
				bestData = min(bestData, timeAnalyze(t, data))
				bestBaseline = min(bestBaseline, timeAnalyze(t, baseline))
			}

			if ratio := float64(bestData) / float64(bestBaseline); ratio > tt.wantMaxRatio {
				t.Errorf("data took %.1fx the time of the baseline (%v, %v), want at most %.0fx", ratio, bestData, bestBaseline, tt.wantMaxRatio)
			}
		})
	}
}

// timeAnalyze runs the analyzer on f, which must give one finding, and returns how long it took.
func timeAnalyze(t *testing.T, f analyze.File) time.Duration {
	t.Helper()
	start := time.Now()
	out, err := deps.New().Analyze(context.Background(), f)
	took := time.Since(start)
	if err != nil || len(out.Findings) != 1 {
		t.Fatalf("err = %v, findings = %d, want 1 finding", err, len(out.Findings))
	}
	return took
}

func TestAnalyzeCancelled(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		file string
		data string
		// expectations
		wantErr bool
	}{
		{name: "cancelled context stops a line scan", file: "requirements.txt", data: "requests\nnumpy\n", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
			defer cancel()
			<-ctx.Done()
			f := analyze.File{Path: tt.file, Name: tt.file, Data: []byte(tt.data)}

			_, err := deps.New().Analyze(ctx, f)

			if (err != nil) != tt.wantErr {
				t.Errorf("err = %v, want error %v", err, tt.wantErr)
			}
		})
	}
}

func TestName(t *testing.T) {
	tests := []struct {
		name     string
		wantName string
	}{
		{name: "analyzer name", wantName: "deps"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := deps.New().Name(); got != tt.wantName {
				t.Errorf("Name = %q, want %q", got, tt.wantName)
			}
		})
	}
}
