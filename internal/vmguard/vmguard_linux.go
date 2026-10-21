//go:build linux

package vmguard

import (
	"io"
	"os"
	"path/filepath"
	"strings"
)

func gather() Signals {
	mounts, truncated := readLimited("/proc/mounts", 16<<20)
	return Signals{
		CPUHypervisor:  cpuHasHypervisor(readSmall("/proc/cpuinfo")),
		HypervisorType: readSmall("/sys/hypervisor/type"),
		DeviceTreeHV:   deviceTreeHypervisor(),
		KernelRelease:  readSmall("/proc/sys/kernel/osrelease"),
		WSLEnv:         os.Getenv("WSL_DISTRO_NAME") != "" || os.Getenv("WSL_INTEROP") != "",
		WSLInterop:     wslInterop(),
		WindowsMounts:  truncated || hasWindowsMount(mounts),
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

// readLimited returns at most limit bytes of a trusted kernel file and whether the file was longer.
func readLimited(path string, limit int64) (content string, truncated bool) {
	f, err := os.Open(path) // #nosec G304 -- fixed system paths
	if err != nil {
		return "", false
	}
	defer func() { _ = f.Close() }() // read-only file
	b, _ := io.ReadAll(io.LimitReader(f, limit+1))
	if int64(len(b)) > limit {
		return "", true
	}
	return string(b), false
}

// hasWindowsMount reports whether /proc/mounts lists a mount of a Windows drive: a source such as C:\
// (shown as C:\134), drvfs, 9p with aname=drvfs, or 9p or virtiofs at /mnt/<letter>.
func hasWindowsMount(mounts string) bool {
	for line := range strings.SplitSeq(mounts, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		source, point, fstype, opts := f[0], f[1], f[2], f[3]
		if isDriveSource(source) || fstype == "drvfs" ||
			(fstype == "9p" && strings.Contains(opts, "aname=drvfs")) ||
			((fstype == "9p" || fstype == "virtiofs") && isDriveMount(point)) {
			return true
		}
	}
	return false
}

// isDriveSource reports whether source starts with a drive letter and a colon.
func isDriveSource(source string) bool {
	return len(source) >= 2 && source[1] == ':' && (source[0]|0x20 >= 'a' && source[0]|0x20 <= 'z')
}

// isDriveMount reports whether point is /mnt/<letter>.
func isDriveMount(point string) bool {
	letter, ok := strings.CutPrefix(point, "/mnt/")
	return ok && len(letter) == 1 && letter[0]|0x20 >= 'a' && letter[0]|0x20 <= 'z'
}
