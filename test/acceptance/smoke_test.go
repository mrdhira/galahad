package acceptance_test

import (
	"encoding/json"
	"runtime"
	"strings"
	"testing"
)

func TestSmoke(t *testing.T) {
	platform := runtime.GOOS + "/" + runtime.GOARCH
	tests := []struct {
		name         string
		args         []string
		wantCode     int
		wantStdout   string // substring; empty means stdout must be empty
		wantStderr   string // substring; empty means stderr must be empty
		wantPlatform bool   // stdout also names GOOS/GOARCH
		wantKeys     []string
	}{
		{name: "version prints stamped build info", args: []string{"version"}, wantCode: 0, wantStdout: "galahad " + stampedVersion, wantPlatform: true},
		{name: "no args prints usage", args: nil, wantCode: 0, wantStdout: "Usage"},
		{name: "help prints usage", args: []string{"help"}, wantCode: 0, wantStdout: "Usage"},
		{name: "-h prints usage", args: []string{"-h"}, wantCode: 0, wantStdout: "Usage"},
		{name: "--help prints usage", args: []string{"--help"}, wantCode: 0, wantStdout: "Usage"},
		{name: "unknown command", args: []string{"frobnicate"}, wantCode: 2, wantStderr: "frobnicate"},
		{name: "version -h prints usage", args: []string{"version", "-h"}, wantCode: 0, wantStdout: "Usage"},
		{name: "version --help prints usage", args: []string{"version", "--help"}, wantCode: 0, wantStdout: "Usage"},
		{name: "version bad flag", args: []string{"version", "--nope"}, wantCode: 2, wantStderr: "flag provided but not defined"},
		{name: "version extra argument", args: []string{"version", "extra"}, wantCode: 2, wantStderr: "unexpected argument"},
		{name: "version --json prints stamped build info", args: []string{"version", "--json"}, wantCode: 0, wantStdout: `"version":"` + stampedVersion + `"`, wantKeys: []string{"version", "commit", "go", "os", "arch"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given the binary built with a stamped version
			// When running it with the case's arguments
			stdout, stderr, code := run(t, tt.args...)
			// Then exit code, stdout and stderr match
			if code != tt.wantCode {
				t.Errorf("exit = %d, want %d", code, tt.wantCode)
			}
			checkOutput(t, "stdout", stdout, tt.wantStdout)
			checkOutput(t, "stderr", stderr, tt.wantStderr)
			if tt.wantPlatform && !strings.Contains(stdout, platform) {
				t.Errorf("stdout %q missing %q", stdout, platform)
			}
			if tt.wantKeys != nil {
				var got map[string]any
				if err := json.Unmarshal([]byte(stdout), &got); err != nil {
					t.Fatalf("invalid JSON %q: %v", stdout, err)
				}
				for _, k := range tt.wantKeys {
					if _, ok := got[k]; !ok {
						t.Errorf("missing key %q in %v", k, got)
					}
				}
				if got["version"] != stampedVersion {
					t.Errorf("version = %v, want %s", got["version"], stampedVersion)
				}
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
