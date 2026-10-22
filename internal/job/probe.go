//go:build !galahadtest

package job

import "errors"

// newProbePlan plans a P8 probe job. A release build has no such job.
func newProbePlan(string, string) (*plan, error) {
	return nil, errors.New("probe jobs are not available in this build")
}
