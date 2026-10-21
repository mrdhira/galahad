//go:build !linux

package agent

import (
	"context"
	"errors"
)

const sigMount = "/sig"

// mountSignatures is for the VM, which is Linux.
func mountSignatures(context.Context) (func() error, error) {
	return nil, errors.New("the signatures drive can only be mounted on Linux")
}
