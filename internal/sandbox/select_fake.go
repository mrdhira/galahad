//go:build galahadtest

package sandbox

import (
	"context"
	"os"

	"github.com/mrdhira/galahad/internal/sandbox/fake"
)

func init() {
	testBackend = func() (Backend, bool) {
		if os.Getenv("GALAHAD_SANDBOX") != "fake" {
			return nil, false
		}
		return fakeBackend{}, true
	}
}

// fakeBackend adapts the fake package, which cannot import sandbox, to Backend.
type fakeBackend struct{}

func (fakeBackend) Name() string { return "fake" }

func (fakeBackend) Start(ctx context.Context, s Spec) (Machine, error) {
	m, err := fake.Start(ctx, s.JobDir, s.Ports)
	if err != nil {
		return nil, err
	}
	return m, nil
}
