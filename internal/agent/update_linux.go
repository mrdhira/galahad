//go:build linux

package agent

import (
	"context"
	"fmt"
	"time"

	"golang.org/x/sys/unix"

	"github.com/mrdhira/galahad/internal/analyze/tools"
)

const (
	sigDevice = "/dev/vdd" // the signatures drive: after the root, scratch and agent drives
	sigMount  = "/sig"
)

// mountSignatures formats the new signatures drive and mounts it read-write at /sig. The init
// script could not mount the empty file, so nothing is mounted there yet. The returned function
// syncs and unmounts the drive. The file system has no journal and no orphan_file feature, which the
// 6.1 kernel of the guest cannot mount, as for the scratch drive.
func mountSignatures(ctx context.Context) (unmount func() error, err error) {
	_, stderr, code, err := tools.Exec(ctx, time.Minute, "mkfs.ext4", "-q", "-F", "-m", "0", "-O", "^has_journal,^orphan_file", "-L", "galahad-sig", sigDevice)
	if err != nil {
		return nil, fmt.Errorf("format the signatures drive: %w", err)
	}
	if code != 0 {
		return nil, fmt.Errorf("format the signatures drive: mkfs.ext4 exited with code %d: %s", code, lastLine(stderr))
	}
	if err := unix.Mount(sigDevice, sigMount, "ext4", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC|unix.MS_NOATIME, ""); err != nil {
		return nil, fmt.Errorf("mount the signatures drive: %w", err)
	}
	return func() error {
		unix.Sync()
		return unix.Unmount(sigMount, 0)
	}, nil
}
