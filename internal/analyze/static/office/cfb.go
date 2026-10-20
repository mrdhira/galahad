package office

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"unicode/utf16"

	"github.com/mrdhira/galahad/internal/protocol"
)

// Limits of one compound file.
const (
	maxStream  = 16 << 20 // bytes of one stream
	dirEntryLn = 128
	maxDepth   = 32 // nesting of storages
)

const (
	maxRegSect = 0xFFFFFFFA // sector numbers from here are markers
	noStream   = 0xFFFFFFFF
	headerLen  = 512
	miniSecLen = 64
	difatInHdr = 109
)

const (
	typeStorage = 1
	typeStream  = 2
)

var cfbMagic = []byte{0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1}

var (
	errCFB      = errors.New("office: invalid compound file")
	errTooLarge = errors.New("office: stream too large")
)

// cfb is a read-only view of an OLE compound file held in memory. Every sector
// chain is bounded by the size of its table, so a looping chain ends in an error.
type cfb struct {
	data       []byte
	secSize    int
	nSectors   int
	fat        []uint32
	miniFAT    []uint32
	mini       []byte
	miniLoaded bool
	miniCutoff uint32
	entries    []dirEntry
}

type dirEntry struct {
	name              string
	typ               byte
	left, right, kids uint32
	start             uint32
	size              uint64
}

// member is a stream with its slash-separated path from the root.
type member struct {
	path string
	e    dirEntry
}

func openCFB(data []byte) (*cfb, error) {
	if len(data) < headerLen || !bytes.HasPrefix(data, cfbMagic) {
		return nil, errCFB
	}
	le := binary.LittleEndian
	shift := le.Uint16(data[30:])
	if le.Uint16(data[28:]) != 0xFFFE || (shift != 9 && shift != 12) || le.Uint16(data[32:]) != 6 {
		return nil, errCFB
	}
	secSize := 1 << shift
	if len(data) < secSize {
		return nil, errCFB
	}
	c := &cfb{
		data:       data,
		secSize:    secSize,
		nSectors:   (len(data) - secSize + secSize - 1) / secSize,
		miniCutoff: le.Uint32(data[56:]),
	}
	numFAT, dirStart := int(le.Uint32(data[44:])), le.Uint32(data[48:])
	miniStart, numDifat := le.Uint32(data[60:]), int(le.Uint32(data[72:]))
	if numFAT > c.nSectors || numDifat > c.nSectors {
		return nil, errCFB
	}
	if err := c.loadFAT(numFAT, le.Uint32(data[68:]), numDifat); err != nil {
		return nil, err
	}
	if miniStart < maxRegSect {
		b, err := c.readChain(miniStart, c.fat, 0)
		if err != nil {
			return nil, err
		}
		c.miniFAT = words(b)
	}
	dir, err := c.readChain(dirStart, c.fat, 0)
	if err != nil {
		return nil, err
	}
	c.parseDir(dir)
	if len(c.entries) == 0 {
		return nil, errCFB
	}
	return c, nil
}

// loadFAT collects the FAT sectors named by the header and the DIFAT chain.
func (c *cfb) loadFAT(numFAT int, difStart uint32, numDifat int) error {
	le := binary.LittleEndian
	var secs []uint32
	for i := 0; i < difatInHdr && len(secs) < numFAT; i++ {
		if v := le.Uint32(c.data[76+4*i:]); v < maxRegSect {
			secs = append(secs, v)
		}
	}
	for s, i := difStart, 0; len(secs) < numFAT && i < numDifat && s < maxRegSect; i++ {
		sec, err := c.sector(s)
		if err != nil {
			return err
		}
		n := len(sec)/4 - 1
		for j := 0; j < n && len(secs) < numFAT; j++ {
			if v := le.Uint32(sec[4*j:]); v < maxRegSect {
				secs = append(secs, v)
			}
		}
		s = le.Uint32(sec[4*n:])
	}
	for _, s := range secs {
		sec, err := c.sector(s)
		if err != nil {
			return err
		}
		c.fat = append(c.fat, words(sec)...)
	}
	return nil
}

func words(b []byte) []uint32 {
	out := make([]uint32, len(b)/4)
	for i := range out {
		out[i] = binary.LittleEndian.Uint32(b[4*i:])
	}
	return out
}

// sector returns the bytes of sector n; the last sector of a truncated file may be short.
func (c *cfb) sector(n uint32) ([]byte, error) {
	if uint64(n) >= uint64(c.nSectors) {
		return nil, errCFB
	}
	off := (int(n) + 1) * c.secSize
	return c.data[off:min(off+c.secSize, len(c.data))], nil
}

// readChain concatenates the sectors of the chain starting at start. A chain
// longer than its table is a cycle. A non-zero size cuts the result and makes
// a chain too short for it an error.
func (c *cfb) readChain(start uint32, table []uint32, size uint64) ([]byte, error) {
	var out []byte
	hops := 0
	for s := start; s < maxRegSect; s = table[s] {
		if int(s) >= len(table) || hops >= len(table) || len(out) > maxStream {
			return nil, errCFB
		}
		hops++
		sec, err := c.sector(s)
		if err != nil {
			return nil, err
		}
		out = append(out, sec...)
		if size > 0 && uint64(len(out)) >= size {
			break
		}
	}
	if size > 0 {
		if uint64(len(out)) < size {
			return nil, errCFB
		}
		out = out[:size]
	}
	return out, nil
}

func (c *cfb) parseDir(dir []byte) {
	n := min(len(dir)/dirEntryLn, maxStream/dirEntryLn)
	le := binary.LittleEndian
	for i := range n {
		e := dir[i*dirEntryLn : (i+1)*dirEntryLn]
		nameLen := min(int(le.Uint16(e[64:])), 64)
		var name []uint16
		for j := 0; j+1 < nameLen-1; j += 2 {
			name = append(name, le.Uint16(e[j:]))
		}
		size := le.Uint64(e[120:])
		if c.secSize == 512 {
			size &= 0xFFFFFFFF
		}
		c.entries = append(c.entries, dirEntry{
			name: string(utf16.Decode(name)), typ: e[66],
			left: le.Uint32(e[68:]), right: le.Uint32(e[72:]), kids: le.Uint32(e[76:]),
			start: le.Uint32(e[116:]), size: size,
		})
	}
}

// streams lists every stream with its path. The tree is walked with an explicit
// stack and a visited set, so a looping tree ends. Storages nested deeper than
// maxDepth, or whose path would pass protocol.MaxPath, are not entered and
// shallow is false.
func (c *cfb) streams(ctx context.Context) (out []member, complete bool, err error) {
	type item struct {
		idx    uint32
		prefix string
		depth  int
	}
	complete = true
	seen := make([]bool, len(c.entries))
	stack := []item{{c.entries[0].kids, "", 0}}
	for len(stack) > 0 {
		if err := ctx.Err(); err != nil {
			return nil, false, err
		}
		it := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if it.idx == noStream || int(it.idx) >= len(c.entries) || seen[it.idx] {
			continue
		}
		seen[it.idx] = true
		e := c.entries[it.idx]
		stack = append(stack, item{e.left, it.prefix, it.depth}, item{e.right, it.prefix, it.depth})
		switch e.typ {
		case typeStream:
			if len(it.prefix)+len(e.name) <= protocol.MaxPath {
				out = append(out, member{it.prefix + e.name, e})
			} else {
				complete = false
			}
		case typeStorage:
			if it.depth+1 > maxDepth || len(it.prefix)+len(e.name)+1 > protocol.MaxPath {
				complete = false
				continue
			}
			stack = append(stack, item{e.kids, it.prefix + e.name + "/", it.depth + 1})
		}
	}
	return out, complete, nil
}

// read returns the content of a stream, from the mini stream when it is small.
func (c *cfb) read(e dirEntry) ([]byte, error) {
	switch {
	case e.size > maxStream:
		return nil, errTooLarge
	case e.size == 0:
		return nil, nil
	case e.size >= uint64(c.miniCutoff):
		return c.readChain(e.start, c.fat, e.size)
	}
	if !c.miniLoaded {
		root := c.entries[0]
		if root.size > maxStream {
			return nil, errTooLarge
		}
		if root.size > 0 {
			var err error
			if c.mini, err = c.readChain(root.start, c.fat, root.size); err != nil {
				return nil, err
			}
		}
		c.miniLoaded = true
	}
	var out []byte
	hops := 0
	for s := e.start; s < maxRegSect; s = c.miniFAT[s] {
		off := int(s) * miniSecLen
		if int(s) >= len(c.miniFAT) || hops >= len(c.miniFAT) || off+miniSecLen > len(c.mini) {
			return nil, errCFB
		}
		hops++
		out = append(out, c.mini[off:off+miniSecLen]...)
		if uint64(len(out)) >= e.size {
			return out[:e.size], nil
		}
	}
	return nil, errCFB
}
