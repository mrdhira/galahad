//go:build !galahadtest

package agent

// driveBase is the download address of Drive jobs. Empty means the real one, which a release
// build always uses.
func driveBase() string { return "" }
