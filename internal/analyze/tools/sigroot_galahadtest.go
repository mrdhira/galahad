//go:build galahadtest

package tools

import "os"

// The tests of the guest point the tools at a signatures directory of their own.
func init() {
	if d := os.Getenv("GALAHAD_TEST_SIG_DIR"); d != "" {
		sigRoot = d
	}
}
