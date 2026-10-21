package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/term"

	"github.com/mrdhira/galahad/internal/config"
	"github.com/mrdhira/galahad/internal/job"
	"github.com/mrdhira/galahad/internal/protocol"
	"github.com/mrdhira/galahad/internal/report"
)

// runScan scans a local file or folder in the sandbox and exits with the code of the verdict.
func runScan(args []string, stdout, stderr io.Writer, env Env) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(stdout, usage)
			return ExitClean
		}
		fmt.Fprintf(stderr, "galahad scan: %v\n\n%s", err, usage)
		return ExitUsage
	}
	if fs.NArg() != 1 {
		fmt.Fprintf(stderr, "galahad scan: want exactly one path, got %d arguments\n\n%s", fs.NArg(), usage)
		return ExitUsage
	}

	backend, err := env.Backend()
	if err != nil {
		fmt.Fprintf(stderr, "galahad scan: %v\n", err)
		return ExitError
	}
	home := env.Home
	if home == "" {
		if home, err = config.Home(); err != nil {
			fmt.Fprintf(stderr, "galahad scan: %v\n", err)
			return ExitError
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	out, err := job.Run(ctx, backend, job.Spec{
		JobsDir: config.JobsDir(home),
		Now:     env.Now,
		Version: version,
		Timeout: job.DefaultTimeout,
		Image:   "core",
		Progress: func(stage string) {
			fmt.Fprintf(stderr, "galahad: %s\n", stage)
		},
	}, fs.Arg(0))
	if err != nil {
		// The error can carry a file name from the target, which is untrusted text.
		msg := protocol.CleanPath(err.Error())
		if out.Job.ID != "" {
			fmt.Fprintf(stderr, "galahad scan: %s (job %s)\n", msg, out.Job.ID)
		} else {
			fmt.Fprintf(stderr, "galahad scan: %s\n", msg)
		}
		return ExitError
	}
	report.Terminal(stdout, out.Result, out.Paths, useColor(stdout))
	return out.Result.Verdict.ExitCode()
}

// useColor reports whether w is a terminal and NO_COLOR is unset.
func useColor(w io.Writer) bool {
	f, ok := w.(*os.File)
	return ok && os.Getenv("NO_COLOR") == "" && term.IsTerminal(int(f.Fd()))
}
