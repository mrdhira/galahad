package vmguard_test

import (
	"strings"
	"testing"

	"github.com/mrdhira/galahad/internal/vmguard"
)

func TestFromSignals(t *testing.T) {
	tests := []struct {
		name       string
		signals    vmguard.Signals
		wantInVM   bool
		wantReason string // substring
	}{
		{name: "galahad guest marker", signals: vmguard.Signals{GalahadGuest: true}, wantInVM: true, wantReason: "galahad guest"},
		{name: "guest marker wins over container", signals: vmguard.Signals{GalahadGuest: true, Container: true}, wantInVM: true, wantReason: "galahad guest"},
		{name: "wsl2 default shares windows files", signals: vmguard.Signals{KernelRelease: "5.15.153.1-microsoft-standard-WSL2", CPUHypervisor: true, WSLEnv: true, WSLInterop: true, InteropEnabled: true, WindowsMounts: true}, wantInVM: false, wantReason: "shares the Windows host's files"},
		{name: "wsl2 with interop only", signals: vmguard.Signals{KernelRelease: "5.15.153.1-microsoft-standard-WSL2", CPUHypervisor: true, WSLInterop: true, InteropEnabled: true}, wantInVM: false, wantReason: "shares the Windows host's files"},
		{name: "wsl2 with windows drives only", signals: vmguard.Signals{KernelRelease: "5.15.153.1-microsoft-standard-WSL2", CPUHypervisor: true, WindowsMounts: true}, wantInVM: false, wantReason: "shares the Windows host's files"},
		{name: "wsl2 locked down", signals: vmguard.Signals{KernelRelease: "5.15.153.1-microsoft-standard-WSL2", CPUHypervisor: true, WSLEnv: true}, wantInVM: true, wantReason: "wsl2 kernel"},
		{name: "wsl2 locked down in lower case", signals: vmguard.Signals{KernelRelease: "6.6.36.3-microsoft-standard-wsl2+"}, wantInVM: true, wantReason: "wsl2 kernel"},
		{name: "wsl1 is not a vm", signals: vmguard.Signals{KernelRelease: "4.4.0-19041-Microsoft"}, wantInVM: false, wantReason: "WSL1"},
		{name: "wsl found by interop entry is not a vm", signals: vmguard.Signals{WSLInterop: true}, wantInVM: false, wantReason: "WSL1"},
		{name: "wsl found by environment is not a vm", signals: vmguard.Signals{WSLEnv: true, Container: true}, wantInVM: false, wantReason: "WSL1"},
		{name: "cpu hypervisor flag", signals: vmguard.Signals{CPUHypervisor: true}, wantInVM: true, wantReason: "hypervisor"},
		{name: "sys hypervisor type", signals: vmguard.Signals{HypervisorType: "xen"}, wantInVM: true, wantReason: "hypervisor type xen"},
		{name: "device tree hypervisor", signals: vmguard.Signals{DeviceTreeHV: "linux,kvm,xen"}, wantInVM: true, wantReason: "device tree hypervisor linux,kvm,xen"},
		{name: "qemu vendor", signals: vmguard.Signals{Vendor: "QEMU", Product: "Standard PC"}, wantInVM: true, wantReason: "QEMU"},
		{name: "vmware vendor", signals: vmguard.Signals{Vendor: "VMware, Inc.", Product: "VMware7,1"}, wantInVM: true, wantReason: "VMware"},
		{name: "virtualbox product", signals: vmguard.Signals{Vendor: "innotek GmbH", Product: "VirtualBox"}, wantInVM: true, wantReason: "VirtualBox"},
		{name: "hyper-v", signals: vmguard.Signals{Vendor: "Microsoft Corporation", Product: "Virtual Machine"}, wantInVM: true, wantReason: "Virtual Machine"},
		{name: "amazon ec2", signals: vmguard.Signals{Vendor: "Amazon EC2", Product: "t3.micro"}, wantInVM: true, wantReason: "Amazon EC2"},
		{name: "google compute engine", signals: vmguard.Signals{Vendor: "Google", Product: "Google Compute Engine"}, wantInVM: true, wantReason: "Google Compute Engine"},
		{name: "firecracker", signals: vmguard.Signals{Vendor: "Amazon", Product: "Firecracker"}, wantInVM: true, wantReason: "Firecracker"},
		{name: "openstack", signals: vmguard.Signals{Vendor: "OpenStack Foundation", Product: "OpenStack Nova"}, wantInVM: true, wantReason: "OpenStack"},
		{name: "digitalocean", signals: vmguard.Signals{Vendor: "DigitalOcean", Product: "Droplet"}, wantInVM: true, wantReason: "DigitalOcean"},
		{name: "bochs", signals: vmguard.Signals{Vendor: "Bochs", Product: "Bochs"}, wantInVM: true, wantReason: "Bochs"},
		{name: "oracle cloud", signals: vmguard.Signals{Vendor: "Oracle Cloud", Product: "Compute"}, wantInVM: true, wantReason: "Oracle Cloud"},
		{name: "alibaba cloud", signals: vmguard.Signals{Vendor: "Alibaba Cloud", Product: "Alibaba Cloud ECS"}, wantInVM: true, wantReason: "Alibaba Cloud"},
		{name: "nutanix", signals: vmguard.Signals{Vendor: "Nutanix", Product: "AHV"}, wantInVM: true, wantReason: "Nutanix"},
		{name: "microsoft laptop is not a vm", signals: vmguard.Signals{Vendor: "Microsoft Corporation", Product: "Surface Laptop 5"}, wantInVM: false, wantReason: "no virtualization"},
		{name: "oracle hardware is not a vm", signals: vmguard.Signals{Vendor: "Oracle Corporation", Product: "SUN FIRE X4170"}, wantInVM: false, wantReason: "no virtualization"},
		{name: "nutanix hardware is not a vm", signals: vmguard.Signals{Vendor: "Nutanix", Product: "NX-3060-G6"}, wantInVM: false, wantReason: "no virtualization"},
		{name: "plain linux vm is unaffected", signals: vmguard.Signals{KernelRelease: "6.8.0-45-generic", CPUHypervisor: true}, wantInVM: true, wantReason: "hypervisor"},
		{name: "bare metal", signals: vmguard.Signals{Vendor: "LENOVO", Product: "ThinkPad X1 Extreme"}, wantInVM: false, wantReason: "no virtualization"},
		{name: "container only is not a vm", signals: vmguard.Signals{Container: true}, wantInVM: false, wantReason: "not a VM"},
		{name: "no signals", signals: vmguard.Signals{}, wantInVM: false, wantReason: "no virtualization"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inVM, reason := vmguard.FromSignals(tt.signals)
			if inVM != tt.wantInVM {
				t.Errorf("inVM = %v, want %v (reason %q)", inVM, tt.wantInVM, reason)
			}
			if !strings.Contains(reason, tt.wantReason) {
				t.Errorf("reason %q missing %q", reason, tt.wantReason)
			}
		})
	}
}

func TestDetect(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "explains itself on any machine"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// The verdict depends on the machine; only the reason is always set.
			if _, reason := vmguard.Detect(); reason == "" {
				t.Error("empty reason")
			}
		})
	}
}
