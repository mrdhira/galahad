//go:build galahadtest

package tools

import "os"

// In galahadtest builds the OSV tool asks the server named by GALAHAD_TEST_OSV_BASE, and no server
// when it is unset, so that a test never reaches the real API. The host proxy still applies its
// policy, which allows api.osv.dev only: the test serves plain HTTP at http://api.osv.dev:443 and
// points the name at its server with GALAHAD_TEST_RESOLVE and GALAHAD_TEST_SINKHOLE.
func init() { osvBase = os.Getenv("GALAHAD_TEST_OSV_BASE") }
