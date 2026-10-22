//go:build !unix

package acceptance_test

import "os"

// maxRSS returns the peak resident set of an exited process in bytes, or -1 when the system does not say.
func maxRSS(*os.ProcessState) int64 { return -1 }
