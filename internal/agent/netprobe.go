//go:build !galahadtest

package agent

import "errors"

// netProbeEnabled says whether this build runs net-probe jobs. A release build does not.
const netProbeEnabled = false

func runNetProbe(*hostConn, *guestRelay, string) error {
	return errors.New("net-probe jobs are not available in this build")
}
