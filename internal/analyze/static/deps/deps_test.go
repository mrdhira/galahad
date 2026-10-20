package deps_test

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mrdhira/galahad/internal/analyze"
	"github.com/mrdhira/galahad/internal/analyze/static/deps"
)

func TestAnalyze(t *testing.T) {
	filler := strings.Repeat("x", 3<<19) // 1.5 MiB, above MaxConfigSize
	deep := strings.Repeat(`{"a":`, 40) + "1" + strings.Repeat("}", 40)
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
			name:         "popular and scoped names are fine, a scoped typosquat is caught by its bare name",
			file:         "package.json",
			data:         "{\n\"dependencies\": {\n\"express\": \"1\",\n\"@types/react\": \"1\",\n\"@evil/lodahs\": \"1\",\n\"Ex_Press\": \"1\"\n}\n}",
			wantFindings: []string{"GAL-DEPS-001@5", "GAL-DEPS-001@6"},
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
			name:         "yarn lock resolved lines",
			file:         "yarn.lock",
			data:         "# yarn lockfile v1\n\na@^1:\n  version \"1.0.0\"\n  resolved \"https://registry.yarnpkg.com/a/-/a-1.0.0.tgz#abc\"\n\nb@^1:\n  version \"1.0.0\"\n  resolved \"https://npm.sinkhole.test/b/-/b-1.0.0.tgz#def\"\n",
			wantFindings: []string{"GAL-DEPS-003@9"},
		},
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
			data:         "{\n\"dependencies\": {\n\"x\": \"npm:expresss@1.0.0\",\n\"y\": \"npm:express@1.0.0\",\n\"z\": \"npm:@scope/lodahs\"\n}\n}",
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
