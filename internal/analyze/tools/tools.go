// Package tools runs the signature scanners of the guest image, ClamAV and YARA, on the
// input and turns their hits into findings. The scanners are command line programs that the
// image installs; Galahad never links them. A scanner that is missing, has no signatures, runs
// out of time, crashes or prints something that does not parse is left out of the coverage and
// the reason goes to tools.log. It never counts as a clean scan.
//
// It reads the output of programs that scan untrusted input, so it belongs to the guest agent
// and must never be imported by the host.
package tools

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/mrdhira/galahad/internal/analyze"
	"github.com/mrdhira/galahad/internal/protocol"
)

// Limits on one tool run.
const (
	maxOutput = 4 << 20         // bytes of stdout; more kills the tool
	maxStderr = 4 << 10         // bytes of stderr kept for the log
	waitDelay = 2 * time.Second // how long a killed tool may keep its pipes open
	maxLog    = 32 << 10        // bytes of tools.log
)

// sigRoot is where the signatures drive is mounted in the guest.
var sigRoot = "/sig"

// Tool is a scanner that runs on the whole input after the Go engine.
type Tool interface {
	// Name is the analyzer name in the coverage.
	Name() string
	// Stage is the progress stage the guest reports while the tool runs.
	Stage() string
	// Run scans target, a file or a directory, within ctx. Evidence paths are relative to the
	// target and cleaned. An error means the tool did not scan, and says why.
	Run(ctx context.Context, target string) ([]protocol.Finding, error)
}

// registered holds one constructor per tool, so that a tool picks up sigRoot when All is
// called and not when the package starts.
var registered []func() Tool

// All returns the registered tools sorted by name.
func All() []Tool {
	all := make([]Tool, len(registered))
	for i, mk := range registered {
		all[i] = mk()
	}
	slices.SortFunc(all, func(a, b Tool) int { return strings.Compare(a.Name(), b.Name()) })
	return all
}

// Apply runs the tools one after the other within ctx, which holds what is left of the job
// time, and adds what they find to res. A tool that ran is added to res.Coverage.Analyzers.
// progress gets the stage of each tool before it runs. The returned bytes are tools.log, with
// one line per tool.
func Apply(ctx context.Context, ts []Tool, target string, res *protocol.Result, progress func(stage string) error) ([]byte, error) {
	var log bytes.Buffer
	for _, t := range ts {
		if err := progress(t.Stage()); err != nil {
			return log.Bytes(), err
		}
		fs, err := t.Run(ctx, target)
		if err != nil {
			fmt.Fprintf(&log, "%s: left out: %s\n", t.Name(), protocol.CleanPath(err.Error()))
			continue
		}
		analyze.AddFindings(res, t.Name(), fs)
		res.Coverage.Analyzers = append(res.Coverage.Analyzers, t.Name())
		slices.Sort(res.Coverage.Analyzers)
		fmt.Fprintf(&log, "%s: ok, %d findings\n", t.Name(), len(fs))
	}
	return log.Bytes()[:min(log.Len(), maxLog)], nil
}

// output is what a finished tool left.
type output struct {
	stdout []byte
	stderr string
	code   int
}

// execute runs the program at path with a limit and the output caps. A tool that is over its
// time or its output cap is killed and gives an error. A tool that exits non-zero is not an
// error here, since the exit code can mean a hit.
func execute(ctx context.Context, limit time.Duration, path string, args ...string) (output, error) {
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...) // #nosec G204 -- the program is found on PATH of the guest image and the arguments are fixed or absolute paths
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	cmd.WaitDelay = waitDelay
	out := &capped{max: maxOutput, stop: cancel}
	errb := &capped{max: maxStderr}
	cmd.Stdout, cmd.Stderr = out, errb
	err := cmd.Run()

	var ee *exec.ExitError
	switch {
	case out.over:
		return output{}, fmt.Errorf("output is over %d bytes", maxOutput)
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		return output{}, fmt.Errorf("timed out after %s", time.Since(start).Round(time.Second))
	case ctx.Err() != nil:
		return output{}, errors.New("stopped before it ended")
	case errors.As(err, &ee):
		return output{stdout: out.buf.Bytes(), stderr: errb.buf.String(), code: ee.ExitCode()}, nil
	case err != nil:
		return output{}, fmt.Errorf("cannot run: %w", err)
	}
	return output{stdout: out.buf.Bytes(), stderr: errb.buf.String()}, nil
}

// capped keeps the first max bytes written to it and swallows the rest. When more arrives it
// calls stop, which kills the tool, and sets over.
type capped struct {
	buf  bytes.Buffer
	max  int
	stop func()
	over bool
}

func (c *capped) Write(p []byte) (int, error) {
	room := c.max - c.buf.Len()
	if len(p) > room {
		c.over = true
		if c.stop != nil {
			c.stop()
		}
		p = p[:room]
	}
	c.buf.Write(p)
	return len(p), nil
}

// relPath makes path, which a tool printed for a file under root, relative to the target and
// cleaned. A file target gives its own name. ok is false for a path that is not under root.
func relPath(root, path string) (rel string, ok bool) {
	if path == root {
		return protocol.CleanPath(filepath.Base(root)), true
	}
	rest, ok := strings.CutPrefix(path, root+string(filepath.Separator))
	if !ok || rest == "" {
		return "", false
	}
	return protocol.CleanPath(filepath.ToSlash(rest)), true
}

// scanRoot returns the absolute, cleaned target, which is the prefix of every path the tools print.
func scanRoot(target string) (string, error) {
	abs, err := filepath.Abs(target)
	if err != nil {
		return "", err
	}
	return filepath.Clean(abs), nil
}
