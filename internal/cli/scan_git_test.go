package cli_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mrdhira/galahad/internal/cli"
	"github.com/mrdhira/galahad/internal/job"
	"github.com/mrdhira/galahad/internal/sandbox"
)

func TestScanGitTarget(t *testing.T) {
	file := filepath.Join(t.TempDir(), "a.txt")
	if err := os.WriteFile(file, []byte("hello\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	broken := func() (sandbox.Backend, error) { return brokenBackend{}, nil }
	const started = "no kvm (job "
	tests := []struct {
		name string
		// inputs
		args []string
		// expectations
		wantCode   int
		wantStderr string // substring
		wantKind   string // the target kind in job.json, when a job starts
	}{
		{name: "a link that ends in .git", args: []string{"https://git.example.com/team/tools.git"}, wantCode: cli.ExitError, wantStderr: started, wantKind: "git"},
		{name: "--submodules with a repository", args: []string{"--submodules", "https://github.com/owner/repo"}, wantCode: cli.ExitError, wantStderr: started, wantKind: "git"},
		{name: "an ext address", args: []string{"ext::sh -c touch% /tmp/pwned"}, wantCode: cli.ExitUsage, wantStderr: "Git transport or ssh address"},
		{name: "another helper address", args: []string{"fd::17"}, wantCode: cli.ExitUsage, wantStderr: "Git transport or ssh address"},
		{name: "an scp-style address", args: []string{"git@github.com:owner/repo.git"}, wantCode: cli.ExitUsage, wantStderr: "Git transport or ssh address"},
		{name: "--git with a path", args: []string{"--git", file}, wantCode: cli.ExitUsage, wantStderr: "--git needs an https link"},
		{name: "an ssh URL", args: []string{"ssh://git@github.com/owner/repo.git"}, wantCode: cli.ExitUsage, wantStderr: "only http and https links are supported"},
		{name: "a git URL", args: []string{"git://github.com/owner/repo.git"}, wantCode: cli.ExitUsage, wantStderr: "only http and https links are supported"},
		{name: "a file URL", args: []string{"--git", "file:///tmp/repo"}, wantCode: cli.ExitUsage, wantStderr: "only http and https links are supported"},
		{name: "an http link that ends in .git", args: []string{"http://git.example.com/tools.git"}, wantCode: cli.ExitUsage, wantStderr: "a Git repository needs an https link"},
		{name: "--git with an http link", args: []string{"--git", "http://git.example.com/tools"}, wantCode: cli.ExitUsage, wantStderr: "a Git repository needs an https link"},
		{name: "--git forces any https link", args: []string{"--git", "https://git.example.com/team/tools"}, wantCode: cli.ExitError, wantStderr: started, wantKind: "git"},
		{name: "--git comes before the Drive check", args: []string{"--git", "https://drive.google.com/file/d/1AbCdEfGhIjKlMnOp/view"}, wantCode: cli.ExitError, wantStderr: started, wantKind: "git"},
		{name: "a link that ends in .git with a query is a plain link", args: []string{"https://git.example.com/tools.git?download=1"}, wantCode: cli.ExitError, wantStderr: started, wantKind: "url"},
		{name: "a GitHub repository", args: []string{"https://github.com/owner/repo"}, wantCode: cli.ExitError, wantStderr: started, wantKind: "git"},
		{name: "a GitHub repository with a slash and capitals", args: []string{"HTTPS://GitHub.com/owner/repo/"}, wantCode: cli.ExitError, wantStderr: started, wantKind: "git"},
		{name: "a GitHub page of a repository is a plain link", args: []string{"https://github.com/owner/repo/blob/main/a.txt"}, wantCode: cli.ExitError, wantStderr: started, wantKind: "url"},
		{name: "a GitHub owner is a plain link", args: []string{"https://github.com/owner"}, wantCode: cli.ExitError, wantStderr: started, wantKind: "url"},
		{name: "a GitHub repository with a query is a plain link", args: []string{"https://github.com/owner/repo?tab=readme"}, wantCode: cli.ExitError, wantStderr: started, wantKind: "url"},
		{name: "a GitLab repository in a subgroup", args: []string{"https://gitlab.com/group/sub/repo"}, wantCode: cli.ExitError, wantStderr: started, wantKind: "git"},
		{name: "a GitLab page of a repository is a plain link", args: []string{"https://gitlab.com/group/repo/-/blob/main/a.txt"}, wantCode: cli.ExitError, wantStderr: started, wantKind: "url"},
		{name: "a Bitbucket repository", args: []string{"https://bitbucket.org/owner/repo"}, wantCode: cli.ExitError, wantStderr: started, wantKind: "git"},
		{name: "a Codeberg repository", args: []string{"https://codeberg.org/owner/repo"}, wantCode: cli.ExitError, wantStderr: started, wantKind: "git"},
		{name: "a GitHub repository over http is a plain link", args: []string{"http://github.com/owner/repo"}, wantCode: cli.ExitError, wantStderr: started, wantKind: "url"},
		{name: "--submodules with a path", args: []string{"--submodules", file}, wantCode: cli.ExitUsage, wantStderr: "--submodules only applies to a Git repository"},
		{name: "--submodules with a plain link", args: []string{"--submodules", "https://example.com/a.pdf"}, wantCode: cli.ExitUsage, wantStderr: "--submodules only applies to a Git repository"},
		{name: "a repository without the network", args: []string{"--no-network", "https://github.com/owner/repo"}, wantCode: cli.ExitUsage, wantStderr: "a link needs the network"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home := t.TempDir()
			env := cli.Env{Home: home, Backend: broken, Now: time.Now}
			var out, errb bytes.Buffer

			got := cli.RunWithEnv(append([]string{"scan"}, tt.args...), &out, &errb, env)

			if got != tt.wantCode || !strings.Contains(errb.String(), tt.wantStderr) {
				t.Fatalf("exit = %d, want %d; stderr %q, want it to contain %q", got, tt.wantCode, errb.String(), tt.wantStderr)
			}
			entries, _ := os.ReadDir(filepath.Join(home, "jobs"))
			if (len(entries) > 0) != (tt.wantKind != "") {
				t.Fatalf("job directories = %v, want one: %v", entries, tt.wantKind != "")
			}
			if tt.wantKind != "" {
				saved, err := job.Load(filepath.Join(home, "jobs"), entries[0].Name())
				if err != nil {
					t.Fatal(err)
				}
				if saved.Target.Kind != tt.wantKind {
					t.Errorf("job.json target kind = %q, want %q", saved.Target.Kind, tt.wantKind)
				}
			}
		})
	}
}
