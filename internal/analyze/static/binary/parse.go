package binary

import (
	"bytes"
	"context"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/mrdhira/galahad/internal/analyze/ident"
)

const (
	vmProtExecute         = 4
	sAttrPureInstructions = 0x80000000
	sAttrSomeInstructions = 0x400
	shfCompressed         = 0x800
	machoFat              = 0xcafebabe
	lcSegment             = 0x1
	lcSymtab              = 0x2
	lcDysymtab            = 0xb
	lcSegment64           = 0x19
)

var errHeader = errors.New("binary header out of bounds or over limits")

// Parse reads the sections and imports of a PE, ELF or Mach-O file. Malformed
// input returns an error, including when the standard library panics. The
// debug packages allocate from header counts before any check of their own, so
// the headers are checked first with encoding/binary.
func Parse(ctx context.Context, data []byte) (ft Features, err error) {
	defer func() {
		if r := recover(); r != nil {
			ft, err = Features{}, fmt.Errorf("binary parse panic: %v", r)
		}
	}()
	rd := &budgetReader{ctx: ctx, left: int64(len(data))}
	switch ident.Identify("", data) {
	case ident.PE:
		return parsePE(rd, data)
	case ident.ELF:
		return parseELF(rd, data)
	case ident.MachO:
		return parseMachO(rd, data)
	}
	return Features{}, errors.New("not a PE, ELF or Mach-O file")
}

// budgetReader limits the section bytes read for entropy: 16 MiB per section
// and no more than the file size in total, so overlapping sections cannot
// multiply the work. It also stops on a cancelled context.
type budgetReader struct {
	ctx  context.Context
	left int64
}

func (b *budgetReader) entropy(r io.Reader) (float64, error) {
	if err := b.ctx.Err(); err != nil {
		return 0, err
	}
	data, err := io.ReadAll(io.LimitReader(r, min(maxSectionBytes, b.left)))
	b.left -= int64(len(data))
	if err != nil {
		return 0, nil // unreadable section data counts as no entropy
	}
	return ident.Entropy(data), nil
}

// hdr reads fixed-size fields; any read outside the data sets bad.
type hdr struct {
	d   []byte
	o   binary.ByteOrder
	bad bool
}

func (h *hdr) u(off uint64, size int) uint64 {
	if off > uint64(len(h.d)) || uint64(size) > uint64(len(h.d))-off {
		h.bad = true
		return 0
	}
	b := h.d[off : off+uint64(size)]
	switch size {
	case 2:
		return uint64(h.o.Uint16(b))
	case 4:
		return uint64(h.o.Uint32(b))
	}
	return h.o.Uint64(b)
}

func checkPE(data []byte) error {
	h := &hdr{d: data, o: binary.LittleEndian}
	pe := h.u(0x3c, 4)
	if h.bad || pe > uint64(len(data)) || !bytes.HasPrefix(data[pe:], []byte("PE\x00\x00")) {
		return errHeader
	}
	nsec, nsym, optSize := h.u(pe+6, 2), h.u(pe+12, 4), h.u(pe+20, 2)
	if nsec > maxSections || nsym*18 > uint64(len(data)) {
		return errHeader
	}
	var relocs uint64
	for i := range nsec {
		relocs += h.u(pe+24+optSize+i*40+32, 2) * 10
	}
	if h.bad || relocs > uint64(len(data)) {
		return errHeader
	}
	return nil
}

func parsePE(rd *budgetReader, data []byte) (Features, error) {
	if err := checkPE(data); err != nil {
		return Features{}, err
	}
	f, err := pe.NewFile(bytes.NewReader(data))
	if err != nil {
		return Features{}, err
	}
	ft := Features{Format: "pe"}
	for _, s := range f.Sections {
		e, err := rd.entropy(s.Open())
		if err != nil {
			return Features{}, err
		}
		ft.Sections = append(ft.Sections, Section{
			Name:       s.Name,
			Size:       uint64(s.Size),
			Executable: s.Characteristics&(pe.IMAGE_SCN_MEM_EXECUTE|pe.IMAGE_SCN_CNT_CODE) != 0,
			Entropy:    e,
		})
	}
	syms, _ := f.ImportedSymbols() // "Func:dll"; an unreadable import table is just empty
	for _, s := range syms[:min(len(syms), maxImports)] {
		name, _, _ := strings.Cut(s, ":")
		ft.Imports = append(ft.Imports, name)
	}
	return ft, nil
}

func checkELF(data []byte) error {
	if len(data) < 64 {
		return errHeader
	}
	h := &hdr{d: data}
	switch data[5] {
	case 1:
		h.o = binary.LittleEndian
	case 2:
		h.o = binary.BigEndian
	default:
		return errHeader
	}
	// Field offsets: header (section table offset, entry size, count) and
	// section entry (type, flags, file offset, size), plus the compression header.
	var shoff, entsize, num, offAt, sizeAt, chdrSizeAt, chdrLen, minEnt uint64
	var word int
	if data[4] == 2 {
		shoff, entsize, num = h.u(0x28, 8), h.u(0x3a, 2), h.u(0x3c, 2)
		offAt, sizeAt, chdrSizeAt, chdrLen, minEnt, word = 24, 32, 8, 24, 64, 8
	} else {
		shoff, entsize, num = h.u(0x20, 4), h.u(0x2e, 2), h.u(0x30, 2)
		offAt, sizeAt, chdrSizeAt, chdrLen, minEnt, word = 16, 20, 4, 12, 40, 4
	}
	if h.bad {
		return errHeader
	}
	if shoff == 0 {
		return nil // no section headers
	}
	if entsize < minEnt {
		return errHeader
	}
	if num == 0 { // the extended count is the size of section 0
		num = h.u(shoff+sizeAt, word)
	}
	if h.bad || num > maxSections || shoff > uint64(len(data)) || num*entsize > uint64(len(data))-shoff {
		return errHeader
	}
	for i := range num {
		e := shoff + i*entsize
		typ, flags := h.u(e+4, 4), h.u(e+8, word)
		if flags&shfCompressed == 0 || typ == uint64(elf.SHT_NOBITS) {
			continue
		}
		off := h.u(e+offAt, word)
		if h.bad || off > uint64(len(data)) || chdrLen > uint64(len(data))-off || h.u(off+chdrSizeAt, word) > maxSectionBytes {
			return errHeader
		}
	}
	if h.bad {
		return errHeader
	}
	return nil
}

func parseELF(rd *budgetReader, data []byte) (Features, error) {
	if err := checkELF(data); err != nil {
		return Features{}, err
	}
	f, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return Features{}, err
	}
	ft := Features{Format: "elf"}
	for _, s := range f.Sections {
		sec := Section{Name: s.Name, Size: s.Size, Executable: s.Flags&elf.SHF_EXECINSTR != 0}
		if s.Type != elf.SHT_NOBITS {
			e, err := rd.entropy(s.Open())
			if err != nil {
				return Features{}, err
			}
			sec.Entropy = e
		}
		ft.Sections = append(ft.Sections, sec)
	}
	syms, _ := f.ImportedSymbols()
	for _, s := range syms[:min(len(syms), maxImports)] {
		ft.Imports = append(ft.Imports, s.Name)
	}
	// shortcut: a UPX-packed ELF without section headers is not detected; checking PT_LOAD with PF_X is a follow-up.
	return ft, nil
}

// machoSlice returns the Mach-O bytes to parse: the data itself, or the first
// architecture of a fat file. The fat header is read here because
// macho.NewFatFile parses every architecture.
func machoSlice(data []byte) ([]byte, error) {
	h := &hdr{d: data, o: binary.BigEndian}
	if h.u(0, 4) != machoFat {
		return data, nil
	}
	n, off, size := h.u(4, 4), h.u(16, 4), h.u(20, 4)
	if h.bad || n == 0 || off > uint64(len(data)) || size > uint64(len(data))-off {
		return nil, errHeader
	}
	return data[off : off+size], nil
}

func checkMachO(data []byte) error {
	h := &hdr{d: data}
	for _, o := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		h.o = o
		switch h.u(0, 4) {
		case 0xfeedface:
			return checkMachOLoads(h, false)
		case 0xfeedfacf:
			return checkMachOLoads(h, true)
		}
	}
	return errHeader
}

func checkMachOLoads(h *hdr, is64 bool) error {
	size := uint64(len(h.d))
	off, secSize, nrelocAt, nsectsAt, secAt, symSize := uint64(28), uint64(68), uint64(52), uint64(48), uint64(56), uint64(12)
	segCmd := uint64(lcSegment)
	if is64 {
		off, secSize, nrelocAt, nsectsAt, secAt, symSize, segCmd = 32, 80, 60, 64, 72, 16, lcSegment64
	}
	ncmd := h.u(16, 4)
	if h.bad || ncmd > size/8 {
		return errHeader
	}
	var sections, relocs uint64
	for range ncmd {
		cmd, cmdsize := h.u(off, 4), h.u(off+4, 4)
		if h.bad || cmdsize < 8 || cmdsize > size-off {
			return errHeader
		}
		switch cmd {
		case segCmd:
			n := h.u(off+nsectsAt, 4)
			sections += n
			if h.bad || sections > maxSections || secAt+n*secSize > cmdsize {
				return errHeader
			}
			for i := range n {
				relocs += h.u(off+secAt+i*secSize+nrelocAt, 4) * 8
			}
		case lcSymtab:
			if h.u(off+12, 4)*symSize > size { // nsyms
				return errHeader
			}
		case lcDysymtab:
			if h.u(off+60, 4)*4 > size { // nindirectsyms
				return errHeader
			}
		}
		off += cmdsize
	}
	if h.bad || relocs > size {
		return errHeader
	}
	return nil
}

func parseMachO(rd *budgetReader, data []byte) (Features, error) {
	data, err := machoSlice(data)
	if err != nil {
		return Features{}, err
	}
	if err := checkMachO(data); err != nil {
		return Features{}, err
	}
	f, err := macho.NewFile(bytes.NewReader(data))
	if err != nil {
		return Features{}, err
	}
	execSeg := map[string]bool{}
	for _, l := range f.Loads {
		if seg, ok := l.(*macho.Segment); ok && seg.Prot&vmProtExecute != 0 {
			execSeg[seg.Name] = true
		}
	}
	ft := Features{Format: "macho"}
	for _, s := range f.Sections {
		e, err := rd.entropy(s.Open())
		if err != nil {
			return Features{}, err
		}
		ft.Sections = append(ft.Sections, Section{
			Name:       s.Name,
			Size:       s.Size,
			Executable: execSeg[s.Seg] || s.Flags&(sAttrPureInstructions|sAttrSomeInstructions) != 0,
			Entropy:    e,
		})
	}
	syms, _ := f.ImportedSymbols()
	for _, s := range syms[:min(len(syms), maxImports)] {
		ft.Imports = append(ft.Imports, strings.TrimPrefix(s, "_"))
	}
	return ft, nil
}
