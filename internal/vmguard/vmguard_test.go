package vmguard_test

import (
	"io"
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
		{name: "wsl env only", signals: vmguard.Signals{WSLEnv: true, CPUHypervisor: true}, wantInVM: false, wantReason: "WSL shares a kernel"},
		{name: "wsl interop entry only", signals: vmguard.Signals{WSLInterop: true, CPUHypervisor: true}, wantInVM: false, wantReason: "WSL shares a kernel"},
		{name: "windows mount only", signals: vmguard.Signals{WindowsMounts: true}, wantInVM: false, wantReason: "WSL shares a kernel"},
		{name: "custom kernel with a windows mount", signals: vmguard.Signals{KernelRelease: "6.6.0-custom", CPUHypervisor: true, WindowsMounts: true}, wantInVM: false, wantReason: "WSL shares a kernel"},
		{name: "wsl2 locked down is still not a vm", signals: vmguard.Signals{KernelRelease: "5.15.153.1-microsoft-standard-WSL2", CPUHypervisor: true}, wantInVM: false, wantReason: "WSL shares a kernel"},
		{name: "wsl1 kernel", signals: vmguard.Signals{KernelRelease: "4.4.0-19041-Microsoft"}, wantInVM: false, wantReason: "WSL shares a kernel"},
		{name: "cpu hypervisor flag", signals: vmguard.Signals{CPUHypervisor: true}, wantInVM: true, wantReason: "hypervisor"},
		{name: "plain linux vm is unaffected", signals: vmguard.Signals{KernelRelease: "6.8.0-45-generic", CPUHypervisor: true}, wantInVM: true, wantReason: "hypervisor"},
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

// newlines yields endless newline bytes, so a test can build input over the limit without storing it.
type newlines struct{}

func (newlines) Read(p []byte) (int, error) {
	return copy(p, newlineBlock), nil
}

var newlineBlock = []byte(strings.Repeat("\n", 64<<10))

func TestWindowsMounts(t *testing.T) {
	const limit = 16 << 20
	tests := []struct {
		name string
		// inputs
		mounts string
		extra  int // newline bytes appended after mounts
		// expectations
		want bool
	}{
		{name: "wsl 9p drvfs mount at /mnt/c", mounts: `C:\134 /mnt/c 9p rw,noatime,dirsync,aname=drvfs;path=C:\;uid=1000 0 0`, want: true},
		{name: "input over the limit", extra: limit + 1, want: true},
		{name: "short line is skipped", mounts: "C:\\134 /mnt/c\n\nnonsense\n", want: false},
		{name: "drive letter source", mounts: `C:\134 /data fuseblk rw 0 0`, want: true},
		{name: "drive letter source with a space in the path", mounts: `D:\134My\040Files /data fuseblk rw 0 0`, want: true},
		{name: "type drvfs", mounts: "drvfs /data drvfs rw 0 0", want: true},
		{name: "9p with aname drvfs outside /mnt", mounts: "share /srv/win 9p rw,aname=drvfs;path=E:\\ 0 0", want: true},
		{name: "9p at /mnt/x", mounts: "share /mnt/x 9p rw 0 0", want: true},
		{name: "virtiofs at /mnt/c", mounts: "share /mnt/c virtiofs rw 0 0", want: true},
		{name: "9p drivers share stays false", mounts: "drivers /usr/lib/wsl/drivers 9p ro,aname=drivers 0 0", want: false},
		{name: "virtiofs at /mnt/data stays false", mounts: "share /mnt/data virtiofs rw 0 0", want: false},
		{name: "plain ext4 stays false", mounts: "/dev/vda1 / ext4 rw 0 0", want: false},
		{name: "nfs export stays false", mounts: "host:/export /mnt/nfs nfs4 rw 0 0", want: false},
		{name: "empty input", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := io.MultiReader(strings.NewReader(tt.mounts), io.LimitReader(newlines{}, int64(tt.extra)))
			if got := vmguard.WindowsMounts(r); got != tt.want {
				t.Errorf("WindowsMounts() = %v, want %v", got, tt.want)
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
