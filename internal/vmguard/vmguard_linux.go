//go:build linux

package vmguard

import (
	"os"
	"path/filepath"
	"strings"
)

func gather() Signals {
	return Signals{
		CPUHypervisor:  cpuHasHypervisor(readSmall("/proc/cpuinfo")),
		HypervisorType: readSmall("/sys/hypervisor/type"),
		DeviceTreeHV:   deviceTreeHypervisor(),
		KernelRelease:  readSmall("/proc/sys/kernel/osrelease"),
		WSLEnv:         os.Getenv("WSL_DISTRO_NAME") != "" || os.Getenv("WSL_INTEROP") != "",
		WSLInterop:     wslInterop(),
		WindowsMounts:  procMountsHaveWindows(),
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

// deviceTreeHypervisor returns the hypervisor/compatible property of the device tree, or "" when absent.
// The property is a list of NUL-separated strings; they are joined with commas.
func deviceTreeHypervisor() string {
	for _, p := range []string{
		"/proc/device-tree/hypervisor/compatible",
		"/sys/firmware/devicetree/base/hypervisor/compatible",
	} {
		if v := strings.ReplaceAll(strings.Trim(readSmall(p), "\x00"), "\x00", ","); v != "" {
			return v
		}
	}
	return ""
}

// wslInterop reports whether WSL interop is present: a WSLInterop binfmt_misc entry, enabled or not,
// or an interop socket. The socket stays even when the binfmt entry is off.
func wslInterop() bool {
	for _, pattern := range []string{"/proc/sys/fs/binfmt_misc/WSLInterop*", "/run/WSL/*_interop"} {
		if entries, _ := filepath.Glob(pattern); len(entries) > 0 {
			return true
		}
	}
	return false
}

// procMountsHaveWindows reports whether /proc/mounts lists a Windows drive. An unreadable file means false.
func procMountsHaveWindows() bool {
	f, err := os.Open("/proc/mounts")
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }() // read-only file
	return WindowsMounts(f)
}
