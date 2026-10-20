package acceptance

import (
	"encoding/json"
	"runtime"
	"strings"
	"testing"
)

func TestSmokeVersionText(t *testing.T) {
	// Given the binary built with a stamped version
	// When running `galahad version`
	stdout, _, code := run(t, "version")
	// Then it exits 0 and prints version and platform
	if code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	for _, want := range []string{"galahad " + stampedVersion, runtime.GOOS + "/" + runtime.GOARCH} {
		if !strings.Contains(stdout, want) {
			t.Errorf("stdout %q missing %q", stdout, want)
		}
	}
}

func TestSmokeVersionJSON(t *testing.T) {
	// Given the stamped binary
	// When running `galahad version --json`
	stdout, _, code := run(t, "version", "--json")
	// Then it exits 0 with a JSON object holding all five keys
	if code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("invalid JSON %q: %v", stdout, err)
	}
	for _, k := range []string{"version", "commit", "go", "os", "arch"} {
		if _, ok := got[k]; !ok {
			t.Errorf("missing key %q in %v", k, got)
		}
	}
	if got["version"] != stampedVersion {
		t.Errorf("version = %v, want %s", got["version"], stampedVersion)
	}
}

func TestSmokeHelp(t *testing.T) {
	for _, args := range [][]string{{"help"}, {"-h"}, {"--help"}, {}, {"version", "-h"}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			// Given a help request or no arguments
			// When running the binary
			stdout, stderr, code := run(t, args...)
			// Then usage goes to stdout, stderr is empty, exit 0
			if code != 0 {
				t.Errorf("exit = %d, want 0", code)
			}
			if !strings.Contains(stdout, "Usage") {
				t.Errorf("stdout %q lacks Usage", stdout)
			}
			if stderr != "" {
				t.Errorf("stderr = %q, want empty", stderr)
			}
		})
	}
}

func TestSmokeUsageErrors(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantStderr string
	}{
		{"unknown command", []string{"frobnicate"}, "frobnicate"},
		{"bad flag", []string{"version", "--nope"}, ""},
		{"extra arg", []string{"version", "extra"}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given invalid input
			// When running the binary
			stdout, stderr, code := run(t, tt.args...)
			// Then it exits 2 with a diagnostic on stderr and nothing on stdout
			if code != 2 {
				t.Errorf("exit = %d, want 2", code)
			}
			if stderr == "" || !strings.Contains(stderr, tt.wantStderr) {
				t.Errorf("stderr = %q, want it to mention %q", stderr, tt.wantStderr)
			}
			if stdout != "" {
				t.Errorf("stdout = %q, want empty", stdout)
			}
		})
	}
}
