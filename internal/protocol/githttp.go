//go:build !galahadtest

package protocol

// GitHTTPHost reports whether a Git job may use plain http for host. A release build never does.
func GitHTTPHost(string) bool { return false }
