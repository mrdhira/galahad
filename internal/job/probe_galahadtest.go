//go:build galahadtest

package job

import "github.com/mrdhira/galahad/internal/protocol"

// newProbePlan plans a P8 probe job named name. Without a target the job has no input. A target is
// sent like the input of a scan, which lets a probe act before the guest has read it.
func newProbePlan(name, target string) (*plan, error) {
	if target == "" {
		return &plan{source: protocol.SourceLocal, p8: name}, nil
	}
	p, err := newLocalPlan(target)
	if err != nil {
		return nil, err
	}
	p.p8 = name
	return p, nil
}
