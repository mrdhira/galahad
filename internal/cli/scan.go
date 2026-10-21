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
	"time"

	"golang.org/x/term"

	"github.com/mrdhira/galahad/internal/config"
	"github.com/mrdhira/galahad/internal/job"
	"github.com/mrdhira/galahad/internal/protocol"
	"github.com/mrdhira/galahad/internal/proxy"
	"github.com/mrdhira/galahad/internal/report"
)

// Defaults and ranges of the scan flags. The memory range keeps room for the signature tools.
const (
	defaultCPUs      = 2
	maxCPUs          = 8
	defaultMemoryMiB = 3072
	minMemoryMiB     = 1024
	maxMemoryMiB     = 16384
	maxScanTimeout   = 24 * time.Hour
)

// runScan scans a local file or folder, or a link, in the sandbox and exits with the code of the verdict.
func runScan(args []string, stdout, stderr io.Writer, env Env) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	image := fs.String("image", "core", "guest image: core or re")
	timeout := fs.Duration("timeout", 0, "time limit of the whole scan; 0 means the default of the image (10m for core, 20m for re)")
	cpus := fs.Int("cpus", defaultCPUs, "virtual CPUs of the guest")
	memory := fs.Int("memory", defaultMemoryMiB, "memory of the guest in MiB")
	noNetwork := fs.Bool("no-network", false, "give the sandbox no network at all, not even through the proxy")
	forceGit := fs.Bool("git", false, "treat an https link as a Git repository and clone it")
	submodules := fs.Bool("submodules", false, "also fetch the submodules of a Git repository")
	var allowHosts []string
	fs.Func("allow-host", "let the sandbox reach this host as well; may be repeated", func(h string) error {
		// The proxy policy is the one that decides what a host name is.
		if _, err := proxy.NewPolicy(proxy.Input{Kind: protocol.KindScan, Source: protocol.SourceLocal, AllowHosts: []string{h}}); err != nil {
			return err
		}
		allowHosts = append(allowHosts, h)
		return nil
	})
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(stdout, usage)
			return ExitClean
		}
		fmt.Fprintf(stderr, "galahad scan: %v\n\n%s", err, usage)
		return ExitUsage
	}
	if fs.NArg() != 1 {
		fmt.Fprintf(stderr, "galahad scan: want exactly one path or link, got %d arguments\n\n%s", fs.NArg(), usage)
		return ExitUsage
	}
	tgt, err := classifyTarget(fs.Arg(0), *forceGit)
	if err != nil {
		fmt.Fprintf(stderr, "galahad scan: %v\n\n%s", err, usage)
		return ExitUsage
	}
	if *submodules && tgt.source != protocol.SourceGit {
		fmt.Fprintf(stderr, "galahad scan: --submodules only applies to a Git repository\n\n%s", usage)
		return ExitUsage
	}
	if tgt.source != protocol.SourceLocal && *noNetwork {
		fmt.Fprintf(stderr, "galahad scan: a link needs the network; drop --no-network, or download the file and scan it\n\n%s", usage)
		return ExitUsage
	}
	switch {
	case *timeout != 0:
	case *image == "re":
		*timeout = 2 * job.DefaultTimeout
	default:
		*timeout = job.DefaultTimeout
	}
	if err := checkLimits(*image, *timeout, *cpus, *memory); err != nil {
		fmt.Fprintf(stderr, "galahad scan: %v\n\n%s", err, usage)
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
		JobsDir:   config.JobsDir(home),
		Now:       env.Now,
		Version:   version,
		Timeout:   *timeout,
		Image:     *image,
		CPUs:      *cpus,
		MemoryMiB: *memory,
		// The sandbox reaches the network only through the host proxy; --no-network serves no proxy port.
		NoNetwork:  *noNetwork,
		Source:     tgt.source,
		AllowHosts: allowHosts,
		Submodules: *submodules,
		Progress: func(stage string) {
			fmt.Fprintf(stderr, "galahad: %s\n", stage)
		},
	}, tgt.value)
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

// checkLimits checks the values of the scan flags against their ranges.
func checkLimits(image string, timeout time.Duration, cpus, memory int) error {
	switch {
	case image != "core" && image != "re":
		return fmt.Errorf("--image %q: want core or re", protocol.CleanPath(image))
	case timeout < job.MinTimeout || timeout > maxScanTimeout:
		return fmt.Errorf("--timeout %s: want %s to %s", timeout, job.MinTimeout, maxScanTimeout)
	case cpus < 1 || cpus > maxCPUs:
		return fmt.Errorf("--cpus %d: want 1 to %d", cpus, maxCPUs)
	case memory < minMemoryMiB || memory > maxMemoryMiB:
		return fmt.Errorf("--memory %d: want %d to %d MiB", memory, minMemoryMiB, maxMemoryMiB)
	}
	return nil
}

// useColor reports whether w is a terminal and NO_COLOR is unset.
func useColor(w io.Writer) bool {
	f, ok := w.(*os.File)
	return ok && os.Getenv("NO_COLOR") == "" && term.IsTerminal(int(f.Fd()))
}
