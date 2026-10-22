//go:build linux

package acceptance_test

import (
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// watchRSS polls the peak resident set (VmHWM) of the process pid every 20 ms until the returned function is
// called, and returns the largest value it saw, in bytes. It reads only this process. The rusage of a wait
// status would add the children the process reaped, and Firecracker holds the memory of the guest.
func watchRSS(pid int) (stop func() int64) {
	var peak int64
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		tick := time.NewTicker(20 * time.Millisecond)
		defer tick.Stop()
		for {
			peak = max(peak, vmHWM(pid))
			select {
			case <-done:
				return
			case <-tick.C:
			}
		}
	}()
	return func() int64 {
		close(done)
		wg.Wait()
		return peak
	}
}

// vmHWM returns the VmHWM line of /proc/pid/status in bytes, or 0 when the process is gone.
func vmHWM(pid int) int64 {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/status") // #nosec G304 -- /proc
	if err != nil {
		return 0
	}
	for line := range strings.Lines(string(data)) {
		if rest, ok := strings.CutPrefix(line, "VmHWM:"); ok {
			if f := strings.Fields(rest); len(f) == 2 && f[1] == "kB" {
				kb, _ := strconv.ParseInt(f[0], 10, 64)
				return kb << 10
			}
		}
	}
	return 0
}
