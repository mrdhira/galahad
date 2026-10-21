//go:build linux

package agent

import (
	"io"
	"os"
)

// physicalMemory returns the memory of the machine in bytes, from /proc/meminfo.
func physicalMemory() (uint64, bool) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, false
	}
	defer func() { _ = f.Close() }() // read-only file
	b, err := io.ReadAll(io.LimitReader(f, 64<<10))
	if err != nil {
		return 0, false
	}
	return ParseMemInfo(string(b))
}
