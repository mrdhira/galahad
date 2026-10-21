//go:build galahadtest

package job

import "os"

// netProbeURL is the address of the net-probe job: in galahadtest builds, GALAHAD_TEST_NET_PROBE
// turns the scan into a job that also asks the proxy for this http URL. The job allows the host
// of the URL, as it does for the target of a URL job.
func netProbeURL() string { return os.Getenv("GALAHAD_TEST_NET_PROBE") }
