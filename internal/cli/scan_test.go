package cli_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mrdhira/galahad/internal/cli"
	"github.com/mrdhira/galahad/internal/sandbox"
)

// brokenBackend is a backend whose machine never starts.
type brokenBackend struct{}

func (brokenBackend) Name() string { return "broken" }

func (brokenBackend) Start(context.Context, sandbox.Spec) (sandbox.Machine, error) {
	return nil, errors.New("no kvm")
}

func TestRunScan(t *testing.T) {
	file := filepath.Join(t.TempDir(), "a.txt")
	if err := os.WriteFile(file, []byte("hello\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	broken := func() (sandbox.Backend, error) { return brokenBackend{}, nil }
	tests := []struct {
		name string
		// inputs
		args    []string
		backend func() (sandbox.Backend, error)
		// expectations
		wantCode   int
		wantStdout string // substring
		wantStderr string // substring
		wantJob    bool   // a job directory exists
	}{
		{name: "-h prints usage", args: []string{"-h"}, wantCode: cli.ExitClean, wantStdout: "Usage: galahad"},
		{name: "no path", wantCode: cli.ExitUsage, wantStderr: "want exactly one path, got 0"},
		{name: "two paths", args: []string{"a", "b"}, wantCode: cli.ExitUsage, wantStderr: "want exactly one path, got 2"},
		{name: "unknown flag", args: []string{"--nope", file}, wantCode: cli.ExitUsage, wantStderr: "flag provided but not defined"},
		{
			name: "no sandbox backend", args: []string{file}, wantCode: cli.ExitError, wantStderr: "sandbox not supported",
			backend: func() (sandbox.Backend, error) { return nil, sandbox.ErrUnsupported },
		},
		{name: "missing target", args: []string{filepath.Join(t.TempDir(), "missing")}, backend: broken, wantCode: cli.ExitError, wantStderr: "galahad scan:"},
		{name: "the machine does not start", args: []string{file}, backend: broken, wantCode: cli.ExitError, wantStderr: "no kvm (job ", wantJob: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home := t.TempDir()
			env := cli.Env{Home: home, Backend: tt.backend}
			var out, errb bytes.Buffer
			if got := cli.RunWithEnv(append([]string{"scan"}, tt.args...), &out, &errb, env); got != tt.wantCode {
				t.Fatalf("exit = %d, want %d\nstderr: %s", got, tt.wantCode, errb.String())
			}
			if !strings.Contains(out.String(), tt.wantStdout) {
				t.Errorf("stdout = %q, want it to contain %q", out.String(), tt.wantStdout)
			}
			if !strings.Contains(errb.String(), tt.wantStderr) {
				t.Errorf("stderr = %q, want it to contain %q", errb.String(), tt.wantStderr)
			}
			entries, _ := os.ReadDir(filepath.Join(home, "jobs"))
			if (len(entries) > 0) != tt.wantJob {
				t.Errorf("job directories = %v, want one: %v", entries, tt.wantJob)
			}
		})
	}
}
