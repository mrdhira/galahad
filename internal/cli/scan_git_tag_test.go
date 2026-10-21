//go:build galahadtest

package cli_test

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/mrdhira/galahad/internal/cli"
	"github.com/mrdhira/galahad/internal/sandbox"
)

func TestScanGitHTTPInTestBuild(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		args []string
		// expectations
		wantCode   int
		wantStderr string
	}{
		{
			name: "a .test host over http that ends in .git is a repository", args: []string{"http://git.test/x.git"},
			wantCode: cli.ExitError, wantStderr: "no kvm (job ",
		},
		{
			name: "--git accepts a .test host over http", args: []string{"--git", "http://git.test/x"},
			wantCode: cli.ExitError, wantStderr: "no kvm (job ",
		},
		{
			name: "another host over http is refused", args: []string{"--git", "http://git.example.com/x"},
			wantCode: cli.ExitUsage, wantStderr: "a Git repository needs an https link",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := cli.Env{Home: t.TempDir(), Backend: func() (sandbox.Backend, error) { return brokenBackend{}, nil }, Now: time.Now}
			var out, errb bytes.Buffer

			got := cli.RunWithEnv(append([]string{"scan"}, tt.args...), &out, &errb, env)

			if got != tt.wantCode || !strings.Contains(errb.String(), tt.wantStderr) {
				t.Errorf("exit = %d, want %d; stderr %q, want it to contain %q", got, tt.wantCode, errb.String(), tt.wantStderr)
			}
		})
	}
}
