//go:build unix

package job

import (
	"os"
	"syscall"
)

// openInput opens a file of the target for reading without blocking. A file that was swapped for
// a FIFO after the walk would otherwise block the open until someone writes to it.
func openInput(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0) // #nosec G304 -- the path comes from the walk of the target
}
