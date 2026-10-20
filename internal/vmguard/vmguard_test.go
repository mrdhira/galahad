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
		{name: "cpu hypervisor flag", signals: vmguard.Signals{CPUHypervisor: true}, wantInVM: true, wantReason: "hypervisor"},
		{name: "sys hypervisor type", signals: vmguard.Signals{HypervisorType: "xen"}, wantInVM: true, wantReason: "hypervisor type xen"},
		{name: "qemu vendor", signals: vmguard.Signals{Vendor: "QEMU", Product: "Standard PC"}, wantInVM: true, wantReason: "QEMU"},
		{name: "vmware vendor", signals: vmguard.Signals{Vendor: "VMware, Inc.", Product: "VMware7,1"}, wantInVM: true, wantReason: "VMware"},
		{name: "virtualbox product", signals: vmguard.Signals{Vendor: "innotek GmbH", Product: "VirtualBox"}, wantInVM: true, wantReason: "VirtualBox"},
		{name: "hyper-v", signals: vmguard.Signals{Vendor: "Microsoft Corporation", Product: "Virtual Machine"}, wantInVM: true, wantReason: "Virtual Machine"},
		{name: "amazon ec2", signals: vmguard.Signals{Vendor: "Amazon EC2", Product: "t3.micro"}, wantInVM: true, wantReason: "Amazon EC2"},
		{name: "google compute engine", signals: vmguard.Signals{Vendor: "Google", Product: "Google Compute Engine"}, wantInVM: true, wantReason: "Google Compute Engine"},
		{name: "firecracker", signals: vmguard.Signals{Vendor: "Amazon", Product: "Firecracker"}, wantInVM: true, wantReason: "Firecracker"},
		{name: "microsoft laptop is not a vm", signals: vmguard.Signals{Vendor: "Microsoft Corporation", Product: "Surface Laptop 5"}, wantInVM: false, wantReason: "no virtualization"},
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
