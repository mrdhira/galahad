package vmguard

import (
	"io"
	"os"
	"strings"
)

// exists reports whether path exists.
func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// readSmall returns at most 64 KiB of the file, trimmed, or "" when it cannot be read.
func readSmall(path string) string {
	f, err := os.Open(path) // #nosec G304 -- fixed system paths
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }() // read-only file
	b, _ := io.ReadAll(io.LimitReader(f, 64<<10))
	return strings.TrimSpace(string(b))
}
