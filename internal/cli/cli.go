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

	"github.com/mrdhira/galahad/internal/config"
	"github.com/mrdhira/galahad/internal/images"
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
              --timeout 0, or no --timeout, means the default of the image: 10m for core, 20m for re
  setup     Download and verify the pinned Firecracker and guest images: galahad setup [--image core|re]
  doctor    Check that this host can run scans, and say how to fix what is wrong
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
	// Pins returns the pinned images and Firecracker for setup and doctor. Nil means images.Load.
	Pins func() (images.Pins, error)
	// Downloader fetches the assets for setup. Nil means images.NewDownloader.
	Downloader *images.Downloader
	// GOOS and GOARCH name the platform that setup and doctor check. Empty means the running one.
	GOOS, GOARCH string
	// KVM is the device doctor opens. Empty means /dev/kvm.
	KVM string
	// Exe is the path of this executable, next to which doctor looks for the agent. Empty means
	// os.Executable.
	Exe string
	// FreeBytes returns the space available to this user on the file system that holds dir. Nil
	// means the system call (Linux only).
	FreeBytes func(dir string) (uint64, error)
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
	case "doctor":
		return runDoctor(args[1:], stdout, stderr, env)
	case "jobs":
		return runJobs(args[1:], stdout, stderr, env)
	case "report":
		return runReport(args[1:], stdout, stderr, env)
	case "scan":
		return runScan(args[1:], stdout, stderr, env)
	case "setup":
		return runSetup(args[1:], stdout, stderr, env)
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

// home returns the galahad state directory.
func (e Env) home() (string, error) {
	if e.Home != "" {
		return e.Home, nil
	}
	return config.Home()
}

// pins returns the pinned images.
func (e Env) pins() (images.Pins, error) {
	if e.Pins != nil {
		return e.Pins()
	}
	return images.Load()
}

// platform returns the name of this system, and what is wrong with it when setup and doctor do
// not support it.
func (e Env) platform() (name, problem string) {
	goos, goarch := runtime.GOOS, runtime.GOARCH
	if e.GOOS != "" {
		goos = e.GOOS
	}
	if e.GOARCH != "" {
		goarch = e.GOARCH
	}
	name = goos + "/" + goarch
	switch {
	case goos != "linux":
		return name, "Linux only until M5"
	case goarch != "amd64":
		return name, "Linux amd64 only until M5"
	}
	return name, ""
}
