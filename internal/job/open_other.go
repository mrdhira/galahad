//go:build !unix

package job

import "os"

// openInput opens a file of the target for reading.
func openInput(path string) (*os.File, error) {
	return os.Open(path) // #nosec G304 -- the path comes from the walk of the target
}
