//go:build !galahadtest

package job

// netProbeURL is the address of the net-probe job. A release build has no such job.
func netProbeURL() string { return "" }
