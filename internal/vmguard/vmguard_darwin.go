//go:build darwin

package vmguard

import "golang.org/x/sys/unix"

func gather() Signals {
	v, err := unix.SysctlUint32("kern.hv_vmm_present")
	return Signals{CPUHypervisor: err == nil && v == 1}
}
