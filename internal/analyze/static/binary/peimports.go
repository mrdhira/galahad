package binary

import (
	"context"
	"debug/pe"
	"encoding/binary"
	"errors"
)

const (
	maxImportDescriptors = 1024
	maxImportNameLen     = 256
)

// peImports lists imported function names. It replaces pe.File.ImportedSymbols,
// which copies the import section per descriptor and walks every thunk array
// without a limit. Here the section is read once, descriptors that repeat a
// thunk array are skipped, and the work stops at maxImportDescriptors
// descriptors and maxImports names. A damaged table gives the names found so
// far and an error.
func peImports(ctx context.Context, f *pe.File) ([]string, error) {
	var dirs []pe.DataDirectory
	var pe64 bool
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader64:
		dirs, pe64 = oh.DataDirectory[:min(uint32(len(oh.DataDirectory)), oh.NumberOfRvaAndSizes)], true
	case *pe.OptionalHeader32:
		dirs = oh.DataDirectory[:min(uint32(len(oh.DataDirectory)), oh.NumberOfRvaAndSizes)]
	default:
		return nil, nil
	}
	if len(dirs) <= pe.IMAGE_DIRECTORY_ENTRY_IMPORT {
		return nil, nil
	}
	idd := dirs[pe.IMAGE_DIRECTORY_ENTRY_IMPORT]
	var ds *pe.Section
	for _, s := range f.Sections {
		if s.Offset != 0 && s.VirtualAddress <= idd.VirtualAddress && idd.VirtualAddress-s.VirtualAddress < s.VirtualSize {
			ds = s
			break
		}
	}
	if ds == nil {
		return nil, nil
	}
	data, err := ds.Data()
	if err != nil {
		return nil, err
	}
	// rva turns a relative address into an offset in data, or -1.
	rva := func(v uint32) int {
		if v < ds.VirtualAddress || uint64(v-ds.VirtualAddress) >= uint64(len(data)) {
			return -1
		}
		return int(v - ds.VirtualAddress)
	}
	step := 4
	if pe64 {
		step = 8
	}

	var names []string
	seen := map[uint32]bool{}
	thunks := 0 // thunks walked, named or not
	pos := rva(idd.VirtualAddress)
	if pos < 0 {
		return nil, errors.New("import directory outside its section")
	}
	for n := 0; n < maxImportDescriptors && pos+20 <= len(data); n, pos = n+1, pos+20 {
		if err := ctx.Err(); err != nil {
			return names, err
		}
		first := binary.LittleEndian.Uint32(data[pos:])
		if first == 0 {
			break
		}
		if seen[first] {
			continue
		}
		seen[first] = true
		t := rva(first)
		if t < 0 {
			return names, errors.New("import thunk outside its section")
		}
		for ; t+step <= len(data) && thunks < maxImports; t, thunks = t+step, thunks+1 {
			var va uint64
			var ordinal bool
			if pe64 {
				va = binary.LittleEndian.Uint64(data[t:])
				ordinal = va&(1<<63) != 0
			} else {
				va = uint64(binary.LittleEndian.Uint32(data[t:]))
				ordinal = va&(1<<31) != 0
			}
			if va == 0 {
				break
			}
			if ordinal || va > 0xffffffff {
				continue
			}
			if o := rva(uint32(va)); o >= 0 && o+2 < len(data) { // skip the 2-byte hint
				names = append(names, cString(data[o+2:]))
			}
		}
		if thunks >= maxImports {
			break
		}
	}
	return names, nil
}

// cString returns the bytes up to the first NUL, at most maxImportNameLen.
func cString(b []byte) string {
	b = b[:min(len(b), maxImportNameLen)]
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
