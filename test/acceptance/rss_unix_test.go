//go:build unix

package acceptance_test

import (
	"os"
	"runtime"
	"syscall"
)

// maxRSS returns the peak resident set of an exited process in bytes, or -1 when the system does not say.
func maxRSS(ps *os.ProcessState) int64 {
	ru, ok := ps.SysUsage().(*syscall.Rusage)
	if !ok {
		return -1
	}
	if runtime.GOOS == "darwin" { // bytes there, KiB elsewhere
		return int64(ru.Maxrss)
	}
	return int64(ru.Maxrss) * 1024
}
