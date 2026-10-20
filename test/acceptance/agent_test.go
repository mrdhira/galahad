package acceptance_test

import (
	"strings"
	"testing"
)

func TestAgentSmoke(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantStdout string // substring; empty means stdout must be empty
		wantStderr string // substring; empty means stderr must be empty
	}{
		{name: "version prints stamped build info", args: []string{"version"}, wantCode: 0, wantStdout: "galahad-agent " + stampedVersion + " (" + stampedCommit + ", "},
		{name: "no args prints usage", args: nil, wantCode: 0, wantStdout: "Usage: galahad-agent"},
		{name: "help prints usage", args: []string{"help"}, wantCode: 0, wantStdout: "Usage: galahad-agent"},
		{name: "unknown command", args: []string{"frobnicate"}, wantCode: 2, wantStderr: "frobnicate"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given the agent built with a stamped version
			// When running it with the case's arguments
			stdout, stderr, code := runAgent(t, tt.args...)
			// Then exit code, stdout and stderr match
			if code != tt.wantCode {
				t.Errorf("exit = %d, want %d", code, tt.wantCode)
			}
			checkOutput(t, "stdout", stdout, tt.wantStdout)
			checkOutput(t, "stderr", stderr, tt.wantStderr)
			if tt.wantCode == 2 && !strings.Contains(stderr, "Usage") {
				t.Errorf("stderr lacks usage: %q", stderr)
			}
		})
	}
}
