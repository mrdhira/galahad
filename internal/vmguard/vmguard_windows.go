//go:build windows

package vmguard

import "golang.org/x/sys/windows/registry"

func gather() Signals {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `HARDWARE\DESCRIPTION\System\BIOS`, registry.QUERY_VALUE)
	if err != nil {
		return Signals{}
	}
	defer func() { _ = k.Close() }() // read-only key
	vendor, _, _ := k.GetStringValue("SystemManufacturer")
	product, _, _ := k.GetStringValue("SystemProductName")
	return Signals{Vendor: vendor, Product: product}
}
