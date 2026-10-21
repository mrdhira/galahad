//go:build unix

package job

import (
	"os"
	"syscall"
)

// readFlags open a file for reading without blocking. A file that was swapped for a FIFO would
// otherwise block the open until someone writes to it.
const readFlags = os.O_RDONLY | syscall.O_NONBLOCK

// openInput opens a file of the target for reading without blocking. A file that was swapped for
// a FIFO after the walk would otherwise block the open until someone writes to it.
func openInput(path string) (*os.File, error) {
	return os.OpenFile(path, readFlags, 0) // #nosec G304 -- the path comes from the walk of the target
}
