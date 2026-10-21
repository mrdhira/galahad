// Package vmguard tells whether the process runs inside a virtual machine. It reads a few
// small system facts and never parses untrusted input, so it is safe on the host.
package vmguard

import "strings"

// guestMarker is created by the Galahad guest image.
const guestMarker = "/etc/galahad-guest"

// Signals are the raw facts Detect gathers on the current OS.
type Signals struct {
	GalahadGuest   bool   // the Galahad guest marker file exists
	CPUHypervisor  bool   // the CPU reports a hypervisor (cpuinfo flag, kern.hv_vmm_present)
	HypervisorType string // /sys/hypervisor/type, trimmed
	DeviceTreeHV   string // device tree hypervisor/compatible (arm64 guests without DMI), trimmed
	KernelRelease  string // kernel release string, for example /proc/sys/kernel/osrelease
	WSLEnv         bool   // WSL_DISTRO_NAME or WSL_INTEROP is set
	WSLInterop     bool   // a WSLInterop binfmt_misc entry or a /run/WSL/*_interop socket exists
	WindowsMounts  bool   // a mount of a Windows drive exists
	Vendor         string // DMI sys_vendor, or the BIOS system manufacturer
	Product        string // DMI product_name, or the BIOS system product name
	Container      bool   // a container marker file exists; containers share the host kernel
}

// vmVendors are lower-case fragments of DMI and BIOS vendor and product strings of virtual machines.
var vmVendors = []string{
	"qemu", "kvm", "vmware", "virtualbox", "innotek", "xen", "amazon ec2",
	"google compute engine", "firecracker", "parallels", "apple virtualization", "bhyve",
	"openstack", "digitalocean", "bochs", "oracle cloud", "alibaba cloud", "nutanix ahv",
}

// wslKernel is a lower-case fragment of the kernel release of WSL1 and WSL2.
const wslKernel = "microsoft"

// FromSignals decides from the raw signals whether the process is in a VM and why.
func FromSignals(s Signals) (inVM bool, reason string) {
	if s.GalahadGuest {
		return true, "galahad guest"
	}
	// WSL never counts as a VM, even on x86 where it reports the hypervisor flag below.
	if s.WSLEnv || s.WSLInterop || s.WindowsMounts || strings.Contains(strings.ToLower(s.KernelRelease), wslKernel) {
		return false, "WSL shares a kernel with the other distributions and Docker Desktop, " +
			"and can reach Windows files and programs; use a real VM"
	}
	switch {
	case s.CPUHypervisor:
		return true, "cpu reports a hypervisor"
	case s.HypervisorType != "":
		return true, "hypervisor type " + s.HypervisorType
	case s.DeviceTreeHV != "":
		return true, "device tree hypervisor " + s.DeviceTreeHV
	}
	id := strings.ToLower(s.Vendor + " " + s.Product)
	vendor := "vm vendor " + strings.TrimSpace(s.Vendor+" "+s.Product)
	for _, v := range vmVendors {
		if strings.Contains(id, v) {
			return true, vendor
		}
	}
	if strings.Contains(id, "microsoft corporation") && strings.Contains(id, "virtual machine") {
		return true, vendor
	}
	if s.Container {
		return false, "container detected; a container shares the host kernel and is not a VM"
	}
	return false, "no virtualization detected"
}

// Detect gathers the signals of the current OS and decides with FromSignals.
func Detect() (inVM bool, reason string) {
	s := gather()
	s.GalahadGuest = exists(guestMarker)
	return FromSignals(s)
}
