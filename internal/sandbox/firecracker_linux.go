package sandbox

import (
	"context"

	"github.com/mrdhira/galahad/internal/sandbox/firecracker"
)

func newFirecracker() (Backend, error) {
	b, err := firecracker.New()
	if err != nil {
		return nil, err
	}
	return firecrackerBackend{b}, nil
}

// firecrackerBackend adapts the firecracker package, which cannot import sandbox, to Backend.
type firecrackerBackend struct{ b *firecracker.Backend }

func (firecrackerBackend) Name() string { return "firecracker" }

func (f firecrackerBackend) Start(ctx context.Context, s Spec) (Machine, error) {
	m, err := f.b.Start(ctx, firecracker.Params(s))
	if err != nil {
		return nil, err
	}
	return m, nil
}
