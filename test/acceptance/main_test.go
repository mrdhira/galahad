// Package acceptance holds black-box tests that run the built galahad binary.
// It must not import any internal package.
package acceptance_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

const stampedVersion = "v0.0.0-acceptance"

var binPath string

func TestMain(m *testing.M) {
	os.Exit(testMain(m))
}

func testMain(m *testing.M) int {
	tmp, err := os.MkdirTemp("", "galahad-acceptance-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "mktemp:", err)
		return 1
	}
	defer func() { _ = os.RemoveAll(tmp) }() // best-effort cleanup of the temp build dir

	root, err := moduleRoot()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	name := "galahad"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	binPath = filepath.Join(tmp, name)

	build := exec.Command("go", "build",
		"-ldflags", "-X github.com/mrdhira/galahad/internal/cli.version="+stampedVersion,
		"-o", binPath, "./cmd/galahad")
	build.Dir = root
	if out, err := build.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "build failed: %v\n%s", err, out)
		return 1
	}
	return m.Run()
}

func moduleRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("go.mod not found")
		}
		dir = parent
	}
}

// run executes the built binary and returns stdout, stderr and the exit code.
func run(t *testing.T, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binPath, args...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	if ctx.Err() != nil {
		t.Fatalf("run %v: timed out after 30s", args)
	}
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			t.Fatalf("run %v: %v", args, err)
		}
		code = ee.ExitCode()
	}
	return out.String(), errb.String(), code
}
