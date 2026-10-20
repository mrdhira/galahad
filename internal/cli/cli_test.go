package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
	"testing"
)

func TestRun(t *testing.T) {
	tests := []struct {
		name   string
		args   []string
		code   int
		stdout string // substring expected on stdout; empty means stdout must be empty
		stderr string // substring expected on stderr; empty means stderr must be empty
	}{
		{"no args", nil, ExitClean, "Usage: galahad", ""},
		{"help", []string{"help"}, ExitClean, "Commands:", ""},
		{"-h", []string{"-h"}, ExitClean, "Commands:", ""},
		{"--help", []string{"--help"}, ExitClean, "Commands:", ""},
		{"unknown command", []string{"bogus"}, ExitUsage, "", `unknown command "bogus"`},
		{"bad flag", []string{"version", "--nope"}, ExitUsage, "", "flag provided but not defined"},
		{"extra arg", []string{"version", "x"}, ExitUsage, "", "unexpected argument"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out, errb bytes.Buffer
			if got := Run(tt.args, &out, &errb); got != tt.code {
				t.Fatalf("exit = %d, want %d", got, tt.code)
			}
			checkOutput(t, "stdout", out.String(), tt.stdout)
			checkOutput(t, "stderr", errb.String(), tt.stderr)
			if tt.code == ExitUsage && !strings.Contains(errb.String(), "Usage: galahad") {
				t.Errorf("stderr lacks usage: %q", errb.String())
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

func setVersion(t *testing.T) {
	t.Helper()
	oldV, oldC := version, commit
	t.Cleanup(func() { version, commit = oldV, oldC })
	version, commit = "1.2.3", "abc123"
}

func TestVersionText(t *testing.T) {
	setVersion(t)
	var out, errb bytes.Buffer
	if got := Run([]string{"version"}, &out, &errb); got != ExitClean {
		t.Fatalf("exit = %d", got)
	}
	want := fmt.Sprintf("galahad 1.2.3 (abc123, %s, %s/%s)\n", runtime.Version(), runtime.GOOS, runtime.GOARCH)
	if out.String() != want {
		t.Errorf("got %q, want %q", out.String(), want)
	}
	if errb.Len() != 0 {
		t.Errorf("stderr = %q", errb.String())
	}
}

func TestVersionJSON(t *testing.T) {
	setVersion(t)
	var out, errb bytes.Buffer
	if got := Run([]string{"version", "--json"}, &out, &errb); got != ExitClean {
		t.Fatalf("exit = %d", got)
	}
	var m map[string]string
	if err := json.Unmarshal(out.Bytes(), &m); err != nil {
		t.Fatalf("invalid JSON %q: %v", out.String(), err)
	}
	want := map[string]string{
		"version": "1.2.3",
		"commit":  "abc123",
		"go":      runtime.Version(),
		"os":      runtime.GOOS,
		"arch":    runtime.GOARCH,
	}
	if len(m) != len(want) {
		t.Errorf("got %v, want %v", m, want)
	}
	for k, v := range want {
		if m[k] != v {
			t.Errorf("%s = %q, want %q", k, m[k], v)
		}
	}
	if errb.Len() != 0 {
		t.Errorf("stderr = %q", errb.String())
	}
}

func TestBuildCommitFallback(t *testing.T) {
	old := commit
	t.Cleanup(func() { commit = old })
	commit = ""
	if buildCommit() == "" {
		t.Error("buildCommit returned empty string")
	}
}
