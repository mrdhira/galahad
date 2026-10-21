// Package config locates the galahad state directory.
package config

import (
	"fmt"
	"os"
	"path/filepath"
)

// Home returns $GALAHAD_HOME, or ~/.galahad when it is not set.
func Home() (string, error) {
	if h := os.Getenv("GALAHAD_HOME"); h != "" {
		return h, nil
	}
	u, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("find the home directory: %w", err)
	}
	return filepath.Join(u, ".galahad"), nil
}

// JobsDir returns the directory that holds one subdirectory per job.
func JobsDir(home string) string { return filepath.Join(home, "jobs") }

// ImagesDir returns the directory that holds the guest images.
func ImagesDir(home string) string { return filepath.Join(home, "images") }

// BinDir returns the directory that holds downloaded helper binaries.
func BinDir(home string) string { return filepath.Join(home, "bin") }

// SignaturesPath returns the signatures image. Scan jobs attach it read-only, and only the update job writes it.
func SignaturesPath(home string) string { return filepath.Join(home, "signatures.img") }

// SignaturesStamp returns the file with the time of the last good update. The host writes it after
// the update job succeeded, and never reads the image the guest wrote.
func SignaturesStamp(home string) string { return filepath.Join(home, "signatures.stamp") }
