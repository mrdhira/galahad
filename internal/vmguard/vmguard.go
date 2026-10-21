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
	Vendor         string // DMI sys_vendor, or the BIOS system manufacturer
	Product        string // DMI product_name, or the BIOS system product name
	Container      bool   // a container marker file exists; containers share the host kernel
}

// vmVendors are lower-case fragments of DMI and BIOS vendor and product strings of virtual machines.
var vmVendors = []string{
	"qemu", "kvm", "vmware", "virtualbox", "innotek", "xen", "amazon ec2",
	"google compute engine", "firecracker", "parallels", "apple virtualization", "bhyve",
	"openstack", "digitalocean", "bochs", "oracle cloud", "alibaba cloud", "nutanix",
}

// wsl2Kernel is a lower-case fragment of the kernel release of WSL2, which runs in a Hyper-V utility VM.
// The WSL1 release has no such fragment and WSL1 is not a VM.
const wsl2Kernel = "microsoft-standard-wsl2"

// FromSignals decides from the raw signals whether the process is in a VM and why.
func FromSignals(s Signals) (inVM bool, reason string) {
	switch {
	case s.GalahadGuest:
		return true, "galahad guest"
	case s.CPUHypervisor:
		return true, "cpu reports a hypervisor"
	case s.HypervisorType != "":
		return true, "hypervisor type " + s.HypervisorType
	case s.DeviceTreeHV != "":
		return true, "device tree hypervisor " + s.DeviceTreeHV
	case strings.Contains(strings.ToLower(s.KernelRelease), wsl2Kernel):
		return true, "wsl2 kernel " + s.KernelRelease
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
