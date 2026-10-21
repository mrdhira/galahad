//go:build !linux

package sandbox

import (
	"fmt"

	"github.com/mrdhira/galahad/internal/sandbox/firecracker"
)

func newFirecracker() (Backend, error) {
	_, err := firecracker.New()
	return nil, fmt.Errorf("%w: %w", ErrUnsupported, err)
}
