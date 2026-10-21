package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/mrdhira/galahad/internal/config"
	"github.com/mrdhira/galahad/internal/images"
	"github.com/mrdhira/galahad/internal/job"
	"github.com/mrdhira/galahad/internal/protocol"
)

// runSetup installs the pinned Firecracker and the pinned guest image files, and then fills the
// signatures through the update VM. Everything downloaded here is checked against the pins, and a
// file that already verifies is left alone. The signatures are always fetched again, since they
// change daily; --skip-signatures leaves them out.
func runSetup(args []string, stdout, stderr io.Writer, env Env) int {
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	image := fs.String("image", "core", "guest image: core or re")
	skipSignatures := fs.Bool("skip-signatures", false, "install the images only, without the ClamAV and YARA signatures")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(stdout, usage)
			return ExitClean
		}
		fmt.Fprintf(stderr, "galahad setup: %v\n\n%s", err, usage)
		return ExitUsage
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "galahad setup: unexpected argument %q\n\n%s", protocol.CleanPath(fs.Arg(0)), usage)
		return ExitUsage
	}
	if *image != "core" && *image != "re" {
		fmt.Fprintf(stderr, "galahad setup: --image %q: want core or re\n\n%s", protocol.CleanPath(*image), usage)
		return ExitUsage
	}
	if name, problem := env.platform(); problem != "" {
		fmt.Fprintf(stderr, "galahad setup: %s: %s\n", name, problem)
		return ExitError
	}
	pins, err := env.pins()
	if err != nil {
		fmt.Fprintf(stderr, "galahad setup: %v\n", err)
		return ExitError
	}
	home, err := env.home()
	if err != nil {
		fmt.Fprintf(stderr, "galahad setup: %v\n", err)
		return ExitError
	}
	d := env.Downloader
	if d == nil {
		d = images.NewDownloader(pins)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := os.MkdirAll(home, 0o700); err != nil {
		fmt.Fprintf(stderr, "galahad setup: %s\n", protocol.CleanPath(err.Error()))
		return ExitError
	}

	installed, err := d.InstallFirecracker(ctx, config.BinDir(home), pins.Firecracker)
	if err != nil {
		return setupFailed(stderr, "firecracker", err, "")
	}
	fmt.Fprintf(stdout, "firecracker %s: %s\n", pins.Firecracker.Version, installedText(installed))

	dir := filepath.Join(config.ImagesDir(home), pins.Version)
	for _, a := range pins.Assets {
		if a.File != "vmlinux" && a.File != *image+".ext4" {
			continue
		}
		installed, err := d.InstallAsset(ctx, dir, a)
		if err != nil {
			return setupFailed(stderr, a.File, err, dir)
		}
		fmt.Fprintf(stdout, "%s: %s\n", a.File, installedText(installed))
	}
	if *skipSignatures {
		return ExitClean
	}
	return updateSignatures(ctx, *image, home, stdout, stderr, env)
}

// updateSignatures runs the update VM that fills signatures.img. A failure keeps the old image.
func updateSignatures(ctx context.Context, image, home string, stdout, stderr io.Writer, env Env) int {
	backend, err := env.Backend()
	if err != nil {
		fmt.Fprintf(stderr, "galahad setup: signatures: %s\n", protocol.CleanPath(err.Error()))
		return ExitError
	}
	fmt.Fprintln(stdout, "signatures: updating in a VM, this downloads about 300 MB")
	out, err := job.RunUpdate(ctx, backend, job.UpdateSpec{
		JobsDir:    config.JobsDir(home),
		Now:        env.Now,
		Version:    env.version(),
		Timeout:    job.UpdateTimeout,
		Image:      image,
		Signatures: config.SignaturesPath(home),
		Stamp:      config.SignaturesStamp(home),
		Progress: func(stage string) {
			switch stage {
			case protocol.StageClamAV:
				fmt.Fprintln(stdout, "signatures: ClamAV databases")
			case protocol.StageYARA:
				fmt.Fprintln(stdout, "signatures: YARA-Forge core rules")
			}
		},
	})
	if err != nil {
		// The error can carry text from the guest, which is untrusted.
		msg := protocol.CleanPath(err.Error())
		if out.Job.ID != "" {
			fmt.Fprintf(stderr, "galahad setup: signatures: %s (job %s; the previous signatures, if any, are kept)\n", msg, out.Job.ID)
		} else {
			fmt.Fprintf(stderr, "galahad setup: signatures: %s\n", msg)
		}
		return ExitError
	}
	fmt.Fprintln(stdout, "signatures: updated")
	return ExitClean
}

func installedText(installed bool) string {
	if installed {
		return "installed"
	}
	return "already installed"
}

// setupFailed prints the error of one download. The text can carry a URL from a redirect, which
// is not ours, so it is cleaned.
func setupFailed(stderr io.Writer, what string, err error, dir string) int {
	fmt.Fprintf(stderr, "galahad setup: %s: %s\n", what, protocol.CleanPath(err.Error()))
	if errors.Is(err, images.ErrNotPublished) && dir != "" {
		fmt.Fprintf(stderr, "The image release is not published yet. Until it is, build the files with images/linux/build.sh and\n"+
			"images/linux/kernel/build.sh from the source tree and install them with scripts/vm/images.sh into %s.\n", protocol.CleanPath(dir))
	}
	return ExitError
}
