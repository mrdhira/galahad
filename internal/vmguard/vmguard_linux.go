//go:build linux

package vmguard

import (
	"os"
	"path/filepath"
	"strings"
)

func gather() Signals {
	interop, interopOn := wslInterop()
	return Signals{
		CPUHypervisor:  cpuHasHypervisor(readSmall("/proc/cpuinfo")),
		HypervisorType: readSmall("/sys/hypervisor/type"),
		DeviceTreeHV:   deviceTreeHypervisor(),
		KernelRelease:  readSmall("/proc/sys/kernel/osrelease"),
		WSLEnv:         os.Getenv("WSL_DISTRO_NAME") != "" || os.Getenv("WSL_INTEROP") != "",
		WSLInterop:     interop,
		InteropEnabled: interopOn,
		WindowsMounts:  hasWindowsMount(readSmall("/proc/mounts")),
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

// wslInterop reports whether a WSLInterop binfmt_misc entry exists and whether it is enabled.
func wslInterop() (exists, enabled bool) {
	entries, _ := filepath.Glob("/proc/sys/fs/binfmt_misc/WSLInterop*")
	for _, e := range entries {
		exists = true
		if strings.HasPrefix(readSmall(e), "enabled") {
			enabled = true
		}
	}
	return exists, enabled
}

// hasWindowsMount reports whether /proc/mounts lists a drvfs mount or a 9p mount of a Windows drive.
func hasWindowsMount(mounts string) bool {
	for line := range strings.SplitSeq(mounts, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		point, fstype, opts := f[1], f[2], f[3]
		if fstype == "drvfs" || (fstype == "9p" && (strings.Contains(opts, "aname=drvfs") || isDriveMount(point))) {
			return true
		}
	}
	return false
}

// isDriveMount reports whether point is /mnt/<letter>.
func isDriveMount(point string) bool {
	letter, ok := strings.CutPrefix(point, "/mnt/")
	return ok && len(letter) == 1 && strings.ToLower(letter) != strings.ToUpper(letter)
}
