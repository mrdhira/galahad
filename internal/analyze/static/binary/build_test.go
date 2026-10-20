package binary_test

import (
	"bytes"
	"encoding/binary"
	"math/rand/v2"
)

// Builders for tiny hand-made PE, ELF and Mach-O files. Nothing is committed;
// every input is made at test time.

var (
	le = binary.LittleEndian
	be = binary.BigEndian
)

func noise(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.NewChaCha8([32]byte{1}).Read(b) // ChaCha8 never fails
	return b
}

type peSection struct {
	name   string
	chars  uint32
	data   []byte
	nreloc uint16
}

const (
	peExec = 0x60000020 // CNT_CODE | MEM_EXECUTE | MEM_READ
	peData = 0x40000040
)

// buildPE makes a PE with no optional header. count overrides the section
// count in the header when not negative.
func buildPE(secs []peSection, count int) []byte {
	n := len(secs)
	if count >= 0 {
		n = count
	}
	var b bytes.Buffer
	dos := make([]byte, 0x40)
	copy(dos, "MZ")
	le.PutUint32(dos[0x3c:], 0x40)
	b.Write(dos)
	coff := make([]byte, 24)
	copy(coff, "PE\x00\x00")
	le.PutUint16(coff[4:], 0x14c)
	le.PutUint16(coff[6:], uint16(n))
	b.Write(coff)
	raw := b.Len() + 40*len(secs)
	var body bytes.Buffer
	for _, s := range secs {
		h := make([]byte, 40)
		copy(h, s.name)
		le.PutUint32(h[8:], uint32(len(s.data)))
		le.PutUint32(h[16:], uint32(len(s.data)))
		le.PutUint32(h[20:], uint32(raw+body.Len()))
		le.PutUint16(h[32:], s.nreloc)
		le.PutUint32(h[36:], s.chars)
		b.Write(h)
		body.Write(s.data)
	}
	b.Write(body.Bytes())
	return b.Bytes()
}

// withSymbols sets the COFF symbol table pointer and count of a buildPE file
// and appends an empty string table, the way Go-built Windows binaries end.
func withSymbols(pe []byte, count uint32) []byte {
	out := append(bytes.Clone(pe), 0, 0, 0, 0)
	le.PutUint32(out[0x40+12:], uint32(len(pe)))
	le.PutUint32(out[0x40+16:], count)
	return out
}

type elfSection struct {
	name  string
	typ   uint32
	flags uint64
	data  []byte
}

// buildELF makes a 64-bit little-endian ELF. The section string table is added
// last, with flags shstrFlags and, if shstrData is not nil, that content.
// It returns the file and the offset of the section header table.
func buildELF(secs []elfSection, shstrFlags uint64, shstrData []byte) ([]byte, int) {
	all := append([]elfSection{{}}, secs...)
	var names bytes.Buffer
	names.WriteByte(0)
	nameOff := make([]uint32, len(all)+1)
	for i := 1; i < len(all); i++ {
		nameOff[i] = uint32(names.Len())
		names.WriteString(all[i].name + "\x00")
	}
	nameOff[len(all)] = uint32(names.Len())
	names.WriteString(".shstrtab\x00")
	str := names.Bytes()
	if shstrData != nil {
		str = shstrData
	}
	all = append(all, elfSection{typ: 3, flags: shstrFlags, data: str})

	var b bytes.Buffer
	b.Write(make([]byte, 64))
	offs := make([]int, len(all))
	for i, s := range all {
		offs[i] = b.Len()
		b.Write(s.data)
	}
	for b.Len()%8 != 0 {
		b.WriteByte(0)
	}
	shoff := b.Len()
	for i, s := range all {
		h := make([]byte, 64)
		le.PutUint32(h[0:], nameOff[i])
		le.PutUint32(h[4:], s.typ)
		le.PutUint64(h[8:], s.flags)
		le.PutUint64(h[24:], uint64(offs[i]))
		le.PutUint64(h[32:], uint64(len(s.data)))
		b.Write(h)
	}
	out := b.Bytes()
	copy(out, "\x7fELF\x02\x01\x01")
	le.PutUint16(out[16:], 3)
	le.PutUint16(out[18:], 62)
	le.PutUint32(out[20:], 1)
	le.PutUint64(out[40:], uint64(shoff))
	le.PutUint16(out[52:], 64)
	le.PutUint16(out[58:], 64)
	le.PutUint16(out[60:], uint16(len(all)))
	le.PutUint16(out[62:], uint16(len(all)-1))
	return out, shoff
}

func chdr(size uint64) []byte {
	h := make([]byte, 24)
	le.PutUint32(h, 1) // ELFCOMPRESS_ZLIB
	le.PutUint64(h[8:], size)
	le.PutUint64(h[16:], 1)
	return append(h, 0x78, 0x9c, 0x03, 0x00, 0, 0, 0, 1) // an empty zlib stream
}

type machoSection struct {
	name, seg string
	data      []byte
	nreloc    uint32
	flags     uint32
}

// buildMachO makes a 64-bit little-endian Mach-O with one segment per
// distinct section group: all sections go into a single segment segName whose
// initial protection is prot.
func buildMachO(segName string, prot uint32, secs []machoSection) []byte {
	cmdSize := 72 + 80*len(secs)
	var b bytes.Buffer
	h := make([]byte, 32)
	le.PutUint32(h[0:], 0xfeedfacf)
	le.PutUint32(h[4:], 0x01000007)
	le.PutUint32(h[12:], 2)
	le.PutUint32(h[16:], 1)
	le.PutUint32(h[20:], uint32(cmdSize))
	b.Write(h)
	seg := make([]byte, 72)
	le.PutUint32(seg[0:], 0x19)
	le.PutUint32(seg[4:], uint32(cmdSize))
	copy(seg[8:], segName)
	var body bytes.Buffer
	base := 32 + cmdSize
	le.PutUint64(seg[40:], uint64(base)) // fileoff
	le.PutUint32(seg[56:], 7)            // maxprot
	le.PutUint32(seg[60:], prot)
	le.PutUint32(seg[64:], uint32(len(secs)))
	var sh bytes.Buffer
	for _, s := range secs {
		x := make([]byte, 80)
		copy(x[0:], s.name)
		copy(x[16:], s.seg)
		le.PutUint64(x[40:], uint64(len(s.data)))
		le.PutUint32(x[48:], uint32(base+body.Len()))
		le.PutUint32(x[60:], s.nreloc)
		le.PutUint32(x[64:], s.flags)
		sh.Write(x)
		body.Write(s.data)
	}
	le.PutUint64(seg[48:], uint64(body.Len())) // filesize
	b.Write(seg)
	b.Write(sh.Bytes())
	b.Write(body.Bytes())
	return b.Bytes()
}

// buildFat wraps archs in a fat header; each declared arch points at arch 0's
// bytes when it has no content of its own.
func buildFat(first []byte, archs int) []byte {
	var b bytes.Buffer
	h := make([]byte, 8+20*archs)
	be.PutUint32(h[0:], 0xcafebabe)
	be.PutUint32(h[4:], uint32(archs))
	for i := range archs {
		e := h[8+20*i:]
		be.PutUint32(e[0:], 0x01000007)
		be.PutUint32(e[8:], uint32(len(h)))
		be.PutUint32(e[12:], uint32(len(first)))
	}
	b.Write(h)
	b.Write(first)
	return b.Bytes()
}

// buildPEImports makes a PE32 whose import directory has the given number of
// descriptors, all pointing at one thunk array that names funcs.
func buildPEImports(funcs []string, descriptors int) []byte {
	const base = 0x1000
	thunkOff := (descriptors + 1) * 20
	namesOff := thunkOff + (len(funcs)+1)*4
	sec := make([]byte, namesOff)
	for i := range descriptors {
		le.PutUint32(sec[i*20:], base+uint32(thunkOff))
		le.PutUint32(sec[i*20+16:], base+uint32(thunkOff))
	}
	for i, f := range funcs {
		le.PutUint32(sec[thunkOff+i*4:], base+uint32(len(sec)))
		sec = append(sec, 0, 0)
		sec = append(sec, f...)
		sec = append(sec, 0)
	}
	var b bytes.Buffer
	dos := make([]byte, 0x40)
	copy(dos, "MZ")
	le.PutUint32(dos[0x3c:], 0x40)
	b.Write(dos)
	coff := make([]byte, 24)
	copy(coff, "PE\x00\x00")
	le.PutUint16(coff[4:], 0x14c)
	le.PutUint16(coff[6:], 1)
	le.PutUint16(coff[20:], 224)
	b.Write(coff)
	opt := make([]byte, 224)
	le.PutUint16(opt[0:], 0x10b)
	le.PutUint32(opt[92:], 16)
	le.PutUint32(opt[96+8:], base) // import directory
	b.Write(opt)
	h := make([]byte, 40)
	copy(h, ".idata")
	le.PutUint32(h[8:], uint32(len(sec)))
	le.PutUint32(h[12:], base)
	le.PutUint32(h[16:], uint32(len(sec)))
	le.PutUint32(h[20:], uint32(b.Len()+40))
	le.PutUint32(h[36:], peData)
	b.Write(h)
	b.Write(sec)
	return b.Bytes()
}
