//go:build !linux && !darwin && !windows

package agent

// physicalMemory is not known on this platform.
func physicalMemory() (uint64, bool) { return 0, false }
