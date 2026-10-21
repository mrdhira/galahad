//go:build darwin

package agent

import "golang.org/x/sys/unix"

// physicalMemory returns the memory of the machine in bytes, from sysctl hw.memsize.
func physicalMemory() (uint64, bool) {
	n, err := unix.SysctlUint64("hw.memsize")
	return n, err == nil && n > 0
}
