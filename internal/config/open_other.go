//go:build !unix

package config

import "os"

// readFlags open a file for reading.
const readFlags = os.O_RDONLY
