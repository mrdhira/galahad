//go:build galahadtest

package agent

import "os"

// driveBase is the download address of Drive jobs. In galahadtest builds, GALAHAD_TEST_DRIVE_BASE
// replaces the real one, so that the tests can serve the Drive pages from a local server. The
// host proxy still applies its allowlist, so the test allows the host with --allow-host.
func driveBase() string { return os.Getenv("GALAHAD_TEST_DRIVE_BASE") }
