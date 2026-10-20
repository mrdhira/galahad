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
)

// Exit codes, matching the host CLI.
const (
	ExitClean = 0
	ExitError = 1
	ExitUsage = 2
)

// Set at build time with -ldflags "-X github.com/mrdhira/galahad/internal/agent.version=...".
var (
	version = "dev"
	commit  = ""
)

const usage = `Usage: galahad-agent <command> [flags]

Commands:
  analyze [-o dir] [-timeout d] <path>
            Analyze a file or directory and write dir/report.json
  version   Print version information
  help      Show this help
`

// Run executes the command in args (without the program name) and returns the exit code.
func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stdout, usage)
		return ExitClean
	}
	switch args[0] {
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return ExitClean
	case "analyze":
		return runAnalyze(args[1:], stdout, stderr)
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

func runAnalyze(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("analyze", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	outDir := fs.String("o", "", "output directory (default: a new temporary directory)")
	timeout := fs.Duration("timeout", analyze.DefaultJobTimeout, "time limit for the whole job")
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
	target := fs.Arg(0)

	info, err := os.Stat(target)
	if err != nil {
		fmt.Fprintf(stderr, "galahad-agent analyze: %v\n", err)
		return ExitError
	}
	if *outDir != "" && info.IsDir() && inside(target, *outDir) {
		fmt.Fprintf(stderr, "galahad-agent analyze: output directory %q is inside the target\n", *outDir)
		return ExitUsage
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	res, err := analyze.Run(ctx, target, static.All())
	if err != nil {
		fmt.Fprintf(stderr, "galahad-agent analyze: %v\n", err)
		return ExitError
	}
	res.Tool = protocol.Tool{Name: "galahad-agent", Version: version}
	if err := res.Validate(); err != nil {
		fmt.Fprintf(stderr, "galahad-agent analyze: invalid result: %v\n", err)
		return ExitError
	}
	path, err := writeReport(*outDir, &res)
	if err != nil {
		fmt.Fprintf(stderr, "galahad-agent analyze: %v\n", err)
		return ExitError
	}
	fmt.Fprintf(stdout, "report: %s\n", path)
	return ExitClean
}

// writeReport writes report.json into dir, or into a new temporary directory when dir is empty.
func writeReport(dir string, res *protocol.Result) (string, error) {
	if dir == "" {
		d, err := os.MkdirTemp("", "galahad-")
		if err != nil {
			return "", err
		}
		dir = d
	} else if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", err
	}
	b, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, "report.json")
	return path, os.WriteFile(path, append(b, '\n'), 0o600)
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
