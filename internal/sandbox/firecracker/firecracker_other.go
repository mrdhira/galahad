//go:build !linux

// Package firecracker runs the guest in a Firecracker microVM, which exists on Linux only.
package firecracker

import "errors"

// ErrUnsupported is what New returns on every system but Linux.
var ErrUnsupported = errors.New("Linux only until M5")

// Backend does not exist here; New never returns one.
type Backend struct{}

// New returns ErrUnsupported.
func New() (*Backend, error) { return nil, ErrUnsupported }
