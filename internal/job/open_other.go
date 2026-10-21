//go:build !unix

package job

import "os"

// readFlags open a file for reading.
const readFlags = os.O_RDONLY

// openInput opens a file of the target for reading.
func openInput(path string) (*os.File, error) {
	return os.OpenFile(path, readFlags, 0) // #nosec G304 -- the path comes from the walk of the target
}
