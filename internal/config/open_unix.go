//go:build unix

package config

import (
	"os"
	"syscall"
)

// readFlags open a file for reading without blocking. A file that was swapped for a FIFO would
// otherwise block the open until someone writes to it.
const readFlags = os.O_RDONLY | syscall.O_NONBLOCK
