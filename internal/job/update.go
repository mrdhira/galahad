package job

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/mrdhira/galahad/internal/sandbox"
)

const (
	// UpdateTimeout is the time limit of the update job. It downloads about 300 MiB of ClamAV databases.
	UpdateTimeout = 30 * time.Minute

	// signaturesBytes is the size of the sparse signatures image. The guest formats it on every update.
	signaturesBytes = 1 << 30
)

// UpdateSpec says how to run the signature update.
type UpdateSpec struct {
	JobsDir string
	// Now returns the current time.
	Now func() time.Time
	// Version is the version of this program. The agent must report the same one, unless it is "dev".
	Version string
	// Timeout is the time limit of the update job, at least MinTimeout.
	Timeout time.Duration
	// Image is the guest image the update VM boots: core or re.
	Image string
	// Signatures is the signatures image. The job fills Signatures+".new" and renames it to this name
	// when the update went through; a failed update leaves the old image where it is.
	Signatures string
	// Stamp gets the time of a good update.
	Stamp string
	// Progress is called with each stage the guest reports. It may be nil.
	Progress func(stage string)
}

// RunUpdate boots the update machine, which downloads the ClamAV databases and the YARA-Forge rules onto
// a new signatures image, and makes the image the current one when the guest reports success. The
// machine never gets a sample, and it reaches the network through the update policy of the host proxy
// only. The new image is the only drive it may write. The host never reads that image.
// The error says why the update failed; the job directory keeps the console and the logs.
func RunUpdate(ctx context.Context, backend sandbox.Backend, spec UpdateSpec) (Outcome, error) {
	if err := checkTimeout(spec.Timeout); err != nil {
		return Outcome{}, err
	}
	next := spec.Signatures + ".new"
	if err := makeSparse(next, signaturesBytes); err != nil {
		return Outcome{}, err
	}
	defer func() { _ = os.Remove(next) }() // gone after the rename; a failed update leaves nothing behind

	out, err := execute(ctx, backend, Spec{
		JobsDir: spec.JobsDir, Now: spec.Now, Version: spec.Version, Timeout: spec.Timeout, Image: spec.Image,
		Signatures: next, Progress: spec.Progress,
	}, &plan{update: true}, Target{Input: "signatures", Kind: "update"}, nil)
	if err != nil {
		return out, err
	}
	if err := os.Rename(next, spec.Signatures); err != nil {
		return out, fmt.Errorf("install the new signatures: %w", err)
	}
	if err := writeStamp(spec.Stamp, spec.Now()); err != nil {
		return out, fmt.Errorf("write the stamp: %w", err)
	}
	return out, nil
}

// makeSparse creates the empty file path of size bytes. A file left by an update that was cut short is replaced.
func makeSparse(path string, size int64) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("remove the old new signatures image: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create the signatures image: %w", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- the path is in the state directory of this program
	if err != nil {
		return fmt.Errorf("create the signatures image: %w", err)
	}
	if err := f.Truncate(size); err != nil {
		_ = f.Close() // the truncate error is the one to report
		return fmt.Errorf("size the signatures image: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("create the signatures image: %w", err)
	}
	return nil
}

// writeStamp replaces the file at path with the time t in one step.
func writeStamp(path string, t time.Time) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(t.UTC().Format(time.RFC3339)+"\n"), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp) // best effort; the rename error is the one to report
		return err
	}
	return nil
}
