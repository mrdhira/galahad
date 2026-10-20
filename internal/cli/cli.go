// Package cli implements the galahad command line.
package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"runtime"
	"runtime/debug"
)

// Exit codes. 10 and 20 are reserved for scan verdicts.
const (
	ExitClean      = 0
	ExitError      = 1
	ExitUsage      = 2
	ExitSuspicious = 10
	ExitMalicious  = 20
)

// Set at build time with -ldflags "-X github.com/mrdhira/galahad/internal/cli.version=...".
var (
	version = "dev"
	commit  = ""
)

const usage = `Usage: galahad <command> [flags]

Commands:
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
	case "version":
		return runVersion(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "galahad: unknown command %q\n\n%s", args[0], usage)
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
		fmt.Fprintf(stderr, "galahad version: %v\n\n%s", err, usage)
		return ExitUsage
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "galahad version: unexpected argument %q\n\n%s", fs.Arg(0), usage)
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
			fmt.Fprintf(stderr, "galahad version: %v\n", err)
			return ExitError
		}
		return ExitClean
	}
	fmt.Fprintf(stdout, "galahad %s (%s, %s, %s/%s)\n", version, c, runtime.Version(), runtime.GOOS, runtime.GOARCH)
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
