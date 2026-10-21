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
	"time"

	"github.com/mrdhira/galahad/internal/sandbox"
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
  scan      Scan a local file or folder in the sandbox: galahad scan [flags] <path>
              --image core|re  --timeout <duration>  --cpus <n>  --memory <MiB>  --no-network
  report    Show the report of a past scan: galahad report <id> [--json]
  jobs      List past scans, or remove them: galahad jobs [rm <id>...]
  version   Print version information
  help      Show this help
`

// Env holds the parts of the environment a command depends on, so tests can replace them.
type Env struct {
	// Home is the galahad state directory. Empty means config.Home, looked up when a
	// command needs it.
	Home string
	// Now returns the current time. Nil means time.Now.
	Now func() time.Time
	// Backend returns the sandbox backend. Nil means sandbox.Select.
	Backend func() (sandbox.Backend, error)
}

// Run executes the command in args (without the program name) and returns the exit code.
func Run(args []string, stdout, stderr io.Writer) int {
	return RunWithEnv(args, stdout, stderr, Env{})
}

// RunWithEnv is Run with an explicit environment.
func RunWithEnv(args []string, stdout, stderr io.Writer, env Env) int {
	if env.Now == nil {
		env.Now = time.Now
	}
	if env.Backend == nil {
		env.Backend = sandbox.Select
	}
	if len(args) == 0 {
		fmt.Fprint(stdout, usage)
		return ExitClean
	}
	switch args[0] {
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return ExitClean
	case "jobs":
		return runJobs(args[1:], stdout, stderr, env)
	case "report":
		return runReport(args[1:], stdout, stderr, env)
	case "scan":
		return runScan(args[1:], stdout, stderr, env)
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
