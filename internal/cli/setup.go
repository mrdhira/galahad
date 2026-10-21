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
	"github.com/mrdhira/galahad/internal/protocol"
)

// runSetup installs the pinned Firecracker and the pinned guest image files. Everything is checked
// against the pins, and a file that already verifies is left alone.
func runSetup(args []string, stdout, stderr io.Writer, env Env) int {
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	image := fs.String("image", "core", "guest image: core or re")
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
