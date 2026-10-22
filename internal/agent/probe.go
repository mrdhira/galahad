//go:build !galahadtest

package agent

import "errors"

// probeEnabled says whether this build runs P8 probe jobs. A release build does not.
const probeEnabled = false

func probeBeforeInput(string) bool { return false }

func runProbe(*hostConn, string, *guestRelay, string, bool) error {
	return errors.New("probe jobs are not available in this build")
}
