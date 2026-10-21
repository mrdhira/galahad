//go:build !linux

package cli

import "errors"

// freeBytes is not needed off Linux: doctor stops at its platform check there.
func freeBytes(string) (uint64, error) { return 0, errors.New("Linux only until M5") }
