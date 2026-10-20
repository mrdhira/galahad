package agent_test

import (
	"bytes"
	"encoding/json"
	"runtime"
	"strings"
	"testing"

	"github.com/mrdhira/galahad/internal/agent"
)

func TestRun(t *testing.T) {
	tests := []struct {
		name         string
		args         []string
		wantCode     int
		wantStdout   string // substring; empty means stdout must be empty
		wantStderr   string // substring; empty means stderr must be empty
		wantPlatform bool   // stdout also names the Go version and GOOS/GOARCH
	}{
		{name: "version prints build info", args: []string{"version"}, wantCode: agent.ExitClean, wantStdout: "galahad-agent dev (", wantPlatform: true},
		{name: "no args prints usage", args: nil, wantCode: agent.ExitClean, wantStdout: "Usage: galahad-agent"},
		{name: "help prints usage", args: []string{"help"}, wantCode: agent.ExitClean, wantStdout: "Commands:"},
		{name: "-h prints usage", args: []string{"-h"}, wantCode: agent.ExitClean, wantStdout: "Commands:"},
		{name: "--help prints usage", args: []string{"--help"}, wantCode: agent.ExitClean, wantStdout: "Commands:"},
		{name: "unknown command", args: []string{"bogus"}, wantCode: agent.ExitUsage, wantStderr: `unknown command "bogus"`},
		{name: "version -h prints usage", args: []string{"version", "-h"}, wantCode: agent.ExitClean, wantStdout: "Commands:"},
		{name: "version bad flag", args: []string{"version", "--nope"}, wantCode: agent.ExitUsage, wantStderr: "flag provided but not defined"},
		{name: "version extra argument", args: []string{"version", "x"}, wantCode: agent.ExitUsage, wantStderr: "unexpected argument"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out, errb bytes.Buffer
			if got := agent.Run(tt.args, &out, &errb); got != tt.wantCode {
				t.Fatalf("exit = %d, want %d", got, tt.wantCode)
			}
			checkOutput(t, "stdout", out.String(), tt.wantStdout)
			checkOutput(t, "stderr", errb.String(), tt.wantStderr)
			if tt.wantPlatform {
				for _, want := range []string{runtime.Version(), runtime.GOOS + "/" + runtime.GOARCH} {
					if !strings.Contains(out.String(), want) {
						t.Errorf("stdout %q missing %q", out.String(), want)
					}
				}
			}
			if tt.wantCode == agent.ExitUsage && !strings.Contains(errb.String(), "Usage: galahad-agent") {
				t.Errorf("stderr lacks usage: %q", errb.String())
			}
		})
	}
}

func TestRunVersionJSON(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		wantCode    int
		wantKeys    []string
		wantVersion string
	}{
		{
			name:        "version --json prints build info",
			args:        []string{"version", "--json"},
			wantCode:    agent.ExitClean,
			wantKeys:    []string{"version", "commit", "go", "os", "arch"},
			wantVersion: "dev",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out, errb bytes.Buffer
			if got := agent.Run(tt.args, &out, &errb); got != tt.wantCode {
				t.Fatalf("exit = %d, want %d", got, tt.wantCode)
			}
			var m map[string]string
			if err := json.Unmarshal(out.Bytes(), &m); err != nil {
				t.Fatalf("invalid JSON %q: %v", out.String(), err)
			}
			if len(m) != len(tt.wantKeys) {
				t.Errorf("got %v, want keys %v", m, tt.wantKeys)
			}
			for _, k := range tt.wantKeys {
				if _, ok := m[k]; !ok {
					t.Errorf("missing key %q in %v", k, m)
				}
			}
			if m["version"] != tt.wantVersion {
				t.Errorf("version = %q, want %q", m["version"], tt.wantVersion)
			}
			if c := m["commit"]; c == "" || (c != "unknown" && len(c) > 12) {
				t.Errorf("commit = %q, want 1-12 chars or \"unknown\"", c)
			}
			if errb.Len() != 0 {
				t.Errorf("stderr = %q, want empty", errb.String())
			}
		})
	}
}

func checkOutput(t *testing.T, name, got, want string) {
	t.Helper()
	if want == "" {
		if got != "" {
			t.Errorf("%s = %q, want empty", name, got)
		}
		return
	}
	if !strings.Contains(got, want) {
		t.Errorf("%s %q missing %q", name, got, want)
	}
}
