//go:build linux

package vmguard

import "strings"

func gather() Signals {
	return Signals{
		CPUHypervisor:  cpuHasHypervisor(readSmall("/proc/cpuinfo")),
		HypervisorType: readSmall("/sys/hypervisor/type"),
		Vendor:         readSmall("/sys/class/dmi/id/sys_vendor"),
		Product:        readSmall("/sys/class/dmi/id/product_name"),
		Container:      exists("/.dockerenv") || exists("/run/.containerenv"),
	}
}

// cpuHasHypervisor reports whether a "flags" line of cpuinfo lists the hypervisor flag.
func cpuHasHypervisor(cpuinfo string) bool {
	for line := range strings.SplitSeq(cpuinfo, "\n") {
		key, val, ok := strings.Cut(line, ":")
		if ok && strings.TrimSpace(key) == "flags" {
			for _, f := range strings.Fields(val) {
				if f == "hypervisor" {
					return true
				}
			}
		}
	}
	return false
}
