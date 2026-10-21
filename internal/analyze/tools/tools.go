// Package tools runs the signature scanners of the guest image, ClamAV and YARA, on the
// input and turns their hits into findings. The scanners are command line programs that the
// image installs; Galahad never links them. capa runs only in the re image, and the OSV lookup
// reaches the network only through the relay of the guest. A scanner that is missing, has no signatures, runs
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
	Run(ctx context.Context, target string) (Result, error)
}

// Env is what a tool may need to know about the guest it runs in.
type Env struct {
	// Image is the guest image, protocol.ImageCore or protocol.ImageRE. The empty string means core.
	Image string
	// Scratch is a writable directory on the work disk, for the temporary files of a tool. Empty means
	// the system temporary directory.
	Scratch string
	// Relay is the host:port of the relay that reaches the host proxy. Empty means the job has no network.
	Relay string
}

// Result is what a tool that scanned found.
type Result struct {
	Findings []protocol.Finding
	// Partial is set when the tool did not cover all of its input, for example because it stopped at
	// a limit. Like a tool that is left out, it lowers the confidence of a clean verdict.
	Partial bool
	// Note is a problem that did not stop the scan, such as output that did not parse in full.
	// It goes to tools.log.
	Note string
}

// registered holds one constructor per tool, so that a tool picks up sigRoot when All is
// called and not when the package starts. A constructor returns nil for a tool that does not run in env.
var registered []func(Env) Tool

// All returns the registered tools that run in env, sorted by name, except that capa comes last: it is the
// slowest tool and the most likely to run out of time, so it must not starve the signature tools.
func All(env Env) []Tool {
	var all []Tool
	for _, mk := range registered {
		if t := mk(env); t != nil {
			all = append(all, t)
		}
	}
	slices.SortFunc(all, func(a, b Tool) int {
		if (a.Name() == "capa") != (b.Name() == "capa") {
			if a.Name() == "capa" {
				return 1
			}
			return -1
		}
		return strings.Compare(a.Name(), b.Name())
	})
	return all
}

// Apply runs the tools one after the other within ctx, which holds what is left of the job
// time, and adds what they find to res. A tool that ran is added to res.Coverage.Analyzers.
// A tool that is left out marks the coverage truncated, which lowers the confidence of a clean
// verdict without making it suspicious. progress gets the stage of each tool before it runs. The returned bytes are tools.log, with
// one line per tool.
func Apply(ctx context.Context, ts []Tool, target string, res *protocol.Result, progress func(stage string) error) ([]byte, error) {
	var log bytes.Buffer
	for _, t := range ts {
		if err := progress(t.Stage()); err != nil {
			return log.Bytes(), err
		}
		r, err := t.Run(ctx, target)
		if err != nil {
			fmt.Fprintf(&log, "%s: left out: %s\n", t.Name(), protocol.CleanPath(err.Error()))
			res.Coverage.Truncated = true
			continue
		}
		analyze.AddFindings(res, t.Name(), r.Findings)
		res.Coverage.Truncated = res.Coverage.Truncated || r.Partial
		res.Coverage.Analyzers = append(res.Coverage.Analyzers, t.Name())
		slices.Sort(res.Coverage.Analyzers)
		fmt.Fprintf(&log, "%s: ok, %d findings\n", t.Name(), len(r.Findings))
		if r.Note != "" {
			fmt.Fprintf(&log, "%s: note: %s\n", t.Name(), protocol.CleanPath(r.Note))
		}
	}
	return log.Bytes()[:min(log.Len(), maxLog)], nil
}

// errTimedOut is the error of a tool that was killed at its time limit.
var errTimedOut = errors.New("timed out")

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
	return executeMax(ctx, limit, maxOutput, nil, path, args...)
}

// executeMax is execute with a cap of maxOut bytes of stdout and extra variables for the environment of the tool.
func executeMax(ctx context.Context, limit time.Duration, maxOut int, env []string, path string, args ...string) (output, error) {
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...) // #nosec G204 -- the program is found on PATH of the guest image and the arguments are fixed or absolute paths
	cmd.Env = append(append(os.Environ(), "LC_ALL=C"), env...)
	cmd.WaitDelay = waitDelay
	ownGroup(cmd)
	out := &capped{max: maxOut, stop: cancel}
	errb := &capped{max: maxStderr}
	cmd.Stdout, cmd.Stderr = out, errb
	err := cmd.Run()

	var ee *exec.ExitError
	switch {
	case out.over:
		return output{}, fmt.Errorf("output is over %d bytes", maxOut)
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		return output{}, fmt.Errorf("%w after %s", errTimedOut, time.Since(start).Round(time.Second))
	case ctx.Err() != nil:
		return output{}, errors.New("stopped before it ended")
	case errors.As(err, &ee):
		return output{stdout: out.buf.Bytes(), stderr: errb.buf.String(), code: ee.ExitCode()}, nil
	case err != nil:
		return output{}, fmt.Errorf("cannot run: %w", err)
	}
	return output{stdout: out.buf.Bytes(), stderr: errb.buf.String()}, nil
}

// Exec runs the program called name, found on PATH, with the arguments args, under the time limit
// and the output caps of the scanners. It returns what the program wrote and its exit code, which
// is -1 when a signal ended it. A program that is missing, over its time or over its output cap is an
// error; one that exits non-zero is not.
func Exec(ctx context.Context, limit time.Duration, name string, args ...string) (stdout []byte, stderr string, code int, err error) {
	bin, err := exec.LookPath(name)
	if err != nil {
		return nil, "", 0, fmt.Errorf("%s is not installed: %w", name, err)
	}
	out, err := execute(ctx, limit, bin, args...)
	return out.stdout, out.stderr, out.code, err
}

// capped keeps the first max bytes written to it and drops the rest. It always reports the whole
// write as done, so the copy from the tool never stops early and the tool never gets a broken
// pipe. When more than max arrives and stop is set, it calls stop, which kills the tool, and
// sets over.
type capped struct {
	buf  bytes.Buffer
	max  int
	stop func()
	over bool
}

func (c *capped) Write(p []byte) (int, error) {
	n := len(p)
	room := c.max - c.buf.Len()
	if n > room {
		if c.stop != nil {
			c.over = true
			c.stop()
		}
		p = p[:room]
	}
	c.buf.Write(p)
	return n, nil
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
