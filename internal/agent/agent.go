// Package agent implements the in-guest galahad-agent command line.
package agent

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"

	"github.com/mrdhira/galahad/internal/analyze"
	"github.com/mrdhira/galahad/internal/analyze/static"
	"github.com/mrdhira/galahad/internal/protocol"
	"github.com/mrdhira/galahad/internal/report"
	"github.com/mrdhira/galahad/internal/scoring"
	"github.com/mrdhira/galahad/internal/vmguard"
	"golang.org/x/term"
)

// Exit codes, matching the host CLI. A scan exits with the code of its verdict:
// ExitClean, ExitSuspicious or ExitMalicious.
const (
	ExitClean      = 0
	ExitError      = 1
	ExitUsage      = 2
	ExitSuspicious = 10
	ExitMalicious  = 20
)

// Set at build time with -ldflags "-X github.com/mrdhira/galahad/internal/agent.version=...".
var (
	version = "dev"
	commit  = ""
)

const usage = `Usage: galahad-agent <command> [flags]

Commands:
  analyze [-o dir] [-timeout d] [--memory-limit size] [--unsafe-host] <path>
            Analyze a file or directory and write report.json, summary.md and report.html to dir.
            --memory-limit sets the soft memory limit in bytes, with an optional KiB, MiB or GiB
            suffix; the default is 50% of the memory, at most 4 GiB, unless GOMEMLIMIT is set.
            Refuses to run outside a VM unless --unsafe-host is given.
  guest --control <addr> [--proxy <addr>] [--memory-limit size] [--unsafe-host]
            Run one job for the host: dial the host, take a job and its tar stream, analyze it and
            send back the result. The address is vsock:<cid>:<port>; tcp:<host:port> needs --unsafe-host.
            With --proxy it listens on 127.0.0.1 (port 3128, or any port with --unsafe-host) and sets
            http_proxy and https_proxy for the tools it runs; each request becomes a tunnel to that address.
            Refuses to run outside a VM unless --unsafe-host is given.
  version   Print version information
  help      Show this help
`

// Env holds the parts of the environment a command depends on, so tests can replace them.
type Env struct {
	// DetectVM reports whether the process runs inside a VM, and why. Nil means vmguard.Detect.
	DetectVM func() (inVM bool, reason string)
	// SetMemoryLimit sets the soft memory limit of the process. Nil means debug.SetMemoryLimit.
	SetMemoryLimit func(bytes int64)
	// Setenv sets an environment variable of the process, which the guest tools inherit. Nil means os.Setenv.
	Setenv func(key, value string)
}

// Run executes the command in args (without the program name) and returns the exit code.
func Run(args []string, stdout, stderr io.Writer) int {
	return RunWithEnv(args, stdout, stderr, Env{})
}

// RunWithEnv is Run with an explicit environment.
func RunWithEnv(args []string, stdout, stderr io.Writer, env Env) int {
	if env.DetectVM == nil {
		env.DetectVM = vmguard.Detect
	}
	if env.SetMemoryLimit == nil {
		env.SetMemoryLimit = func(n int64) { debug.SetMemoryLimit(n) }
	}
	if env.Setenv == nil {
		env.Setenv = func(k, v string) { _ = os.Setenv(k, v) }
	}
	if len(args) == 0 {
		fmt.Fprint(stdout, usage)
		return ExitClean
	}
	switch args[0] {
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return ExitClean
	case "analyze":
		return runAnalyze(args[1:], stdout, stderr, env)
	case "guest":
		return runGuest(args[1:], stdout, stderr, env)
	case "version":
		return runVersion(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "galahad-agent: unknown command %q\n\n%s", args[0], usage)
		return ExitUsage
	}
}

func runVersion(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("version", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	asJSON := fs.Bool("json", false, "print as JSON")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(stdout, usage)
			return ExitClean
		}
		fmt.Fprintf(stderr, "galahad-agent version: %v\n\n%s", err, usage)
		return ExitUsage
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "galahad-agent version: unexpected argument %q\n\n%s", fs.Arg(0), usage)
		return ExitUsage
	}

	c := buildCommit()
	if *asJSON {
		out := map[string]string{
			"version": version,
			"commit":  c,
			"go":      runtime.Version(),
			"os":      runtime.GOOS,
			"arch":    runtime.GOARCH,
		}
		if err := json.NewEncoder(stdout).Encode(out); err != nil {
			fmt.Fprintf(stderr, "galahad-agent version: %v\n", err)
			return ExitError
		}
		return ExitClean
	}
	fmt.Fprintf(stdout, "galahad-agent %s (%s, %s, %s/%s)\n", version, c, runtime.Version(), runtime.GOOS, runtime.GOARCH)
	return ExitClean
}

func buildCommit() string {
	if commit != "" {
		return commit
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, s := range info.Settings {
			if s.Key == "vcs.revision" && s.Value != "" {
				return s.Value[:min(len(s.Value), 12)]
			}
		}
	}
	return "unknown"
}

func runAnalyze(args []string, stdout, stderr io.Writer, env Env) int {
	fs := flag.NewFlagSet("analyze", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	outDir := fs.String("o", "", "output directory (default: a new temporary directory)")
	timeout := fs.Duration("timeout", analyze.DefaultJobTimeout, "time limit for the whole job")
	unsafeHost := fs.Bool("unsafe-host", false, "analyze on this host even though it is not a VM; you accept the risk")
	// Hidden from the usage text: the acceptance tests divide every job limit by it, so a
	// few small files cross the limits instead of tens of thousands.
	limitDivisor := fs.Int("limit-divisor", 1, "")
	var memoryLimit int64
	fs.Func("memory-limit", "soft memory limit in bytes, with an optional KiB, MiB or GiB suffix", func(s string) (err error) {
		memoryLimit, err = ParseSize(s)
		return err
	})
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(stdout, usage)
			return ExitClean
		}
		fmt.Fprintf(stderr, "galahad-agent analyze: %v\n\n%s", err, usage)
		return ExitUsage
	}
	if fs.NArg() != 1 {
		fmt.Fprintf(stderr, "galahad-agent analyze: want exactly one path, got %d arguments\n\n%s", fs.NArg(), usage)
		return ExitUsage
	}
	if *limitDivisor < 1 {
		fmt.Fprintf(stderr, "galahad-agent analyze: -limit-divisor must be at least 1, got %d\n", *limitDivisor)
		return ExitUsage
	}
	target := fs.Arg(0)

	if inVM, reason := env.DetectVM(); !inVM {
		if !*unsafeHost {
			fmt.Fprintf(stderr, "galahad-agent: refusing to analyze untrusted input outside a VM (%s). "+
				"Galahad runs analysis inside its VM; use `galahad scan` (coming in M2). "+
				"To run on this host anyway, pass --unsafe-host; you accept the risk.\n", reason)
			return ExitUsage
		}
		fmt.Fprintf(stderr, "galahad-agent: WARNING: --unsafe-host: analyzing untrusted input outside a VM (%s)\n", reason)
	}

	info, err := os.Stat(target)
	if err != nil {
		fmt.Fprintf(stderr, "galahad-agent analyze: %v\n", err)
		return ExitError
	}
	if *outDir != "" && info.IsDir() && inside(target, *outDir) {
		fmt.Fprintf(stderr, "galahad-agent analyze: output directory %q is inside the target\n", *outDir)
		return ExitUsage
	}

	applyMemoryLimit(env, memoryLimit)

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	res, err := analyze.Run(ctx, target, static.All(), analyze.WithLimits(dividedLimits(*limitDivisor)))
	if err != nil {
		fmt.Fprintf(stderr, "galahad-agent analyze: %v\n", err)
		return ExitError
	}
	res.Tool = protocol.Tool{Name: "galahad-agent", Version: version}
	scoring.Apply(&res)
	if err := res.Validate(); err != nil {
		fmt.Fprintf(stderr, "galahad-agent analyze: invalid result: %v\n", err)
		return ExitError
	}
	dir := *outDir
	if dir == "" {
		d, err := os.MkdirTemp("", "galahad-")
		if err != nil {
			fmt.Fprintf(stderr, "galahad-agent analyze: %v\n", err)
			return ExitError
		}
		dir = d
	}
	paths, err := report.Write(dir, &res)
	if err != nil {
		fmt.Fprintf(stderr, "galahad-agent analyze: %v\n", err)
		return ExitError
	}
	report.Terminal(stdout, &res, paths, useColor(stdout))
	return res.Verdict.ExitCode()
}

// applyMemoryLimit sets the soft memory limit: explicit when --memory-limit gave one, otherwise the default.
func applyMemoryLimit(env Env, explicit int64) {
	ram, _ := physicalMemory()                  // 0 when unknown
	gomemlimit := os.Getenv("GOMEMLIMIT") != "" // an empty value counts as unset
	if limit, ok := MemoryLimit(ram, gomemlimit, explicit); ok {
		env.SetMemoryLimit(limit)
	}
}

// dividedLimits returns the default job limits, each divided by d.
func dividedLimits(d int) analyze.Limits {
	l := analyze.DefaultLimits()
	n := int64(d)
	l.MaxFileSize /= n
	l.MaxTotalBytes /= n
	l.MaxFiles /= d
	l.MaxFilesSeen /= d
	l.MaxExtraFiles /= d
	l.MaxExtraBytes /= n
	return l
}

// useColor reports whether w is a terminal and NO_COLOR is unset.
func useColor(w io.Writer) bool {
	f, ok := w.(*os.File)
	return ok && os.Getenv("NO_COLOR") == "" && term.IsTerminal(int(f.Fd()))
}

// inside reports whether dir is target or below it, after resolving symlinks.
func inside(target, dir string) bool {
	rel, err := filepath.Rel(resolve(target), resolve(dir))
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// resolve makes p absolute and resolves symlinks in its longest existing prefix.
func resolve(p string) string {
	abs, err := filepath.Abs(p)
	if err != nil {
		return p
	}
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		return resolved
	}
	parent := filepath.Dir(abs)
	if parent == abs {
		return abs
	}
	return filepath.Join(resolve(parent), filepath.Base(abs))
}
