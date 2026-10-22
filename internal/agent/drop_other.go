//go:build !linux

package agent

import "errors"

// dropPrivileges is for the VM, which is Linux.
func dropPrivileges() error {
	return errors.New("dropping privileges is only supported on Linux")
}
