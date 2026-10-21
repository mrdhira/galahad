//go:build windows

package agent

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// memoryStatusEx is the MEMORYSTATUSEX structure of the Windows API.
type memoryStatusEx struct {
	Length               uint32
	MemoryLoad           uint32
	TotalPhys            uint64
	AvailPhys            uint64
	TotalPageFile        uint64
	AvailPageFile        uint64
	TotalVirtual         uint64
	AvailVirtual         uint64
	AvailExtendedVirtual uint64
}

var globalMemoryStatusEx = windows.NewLazySystemDLL("kernel32.dll").NewProc("GlobalMemoryStatusEx")

// physicalMemory returns the memory of the machine in bytes, from GlobalMemoryStatusEx.
func physicalMemory() (uint64, bool) {
	if globalMemoryStatusEx.Find() != nil {
		return 0, false
	}
	m := memoryStatusEx{Length: uint32(unsafe.Sizeof(memoryStatusEx{}))}
	// #nosec G103 -- the API fills a structure that this process owns
	r, _, _ := globalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&m)))
	return m.TotalPhys, r != 0 && m.TotalPhys > 0
}
