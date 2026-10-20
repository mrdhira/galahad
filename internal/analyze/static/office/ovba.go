package office

import (
	"context"
	"encoding/binary"
	"errors"
	"math/bits"
	"strings"
)

// Limits of one VBA project.
const (
	maxModules    = 1000
	maxDirStreams = 16
	maxDirRecords = 100000
	maxVBABytes   = 16 << 20 // decompressed bytes over a whole project
)

const chunkLen = 4096 // decompressed bytes of one MS-OVBA chunk

// MS-OVBA dir stream record ids.
const (
	recVersion    = 0x0009
	recTerminator = 0x0010
	recStreamName = 0x001A
	recOffset     = 0x0031
	recModuleEnd  = 0x002B
)

var errOVBA = errors.New("office: invalid MS-OVBA data")

// decompress expands an MS-OVBA compressed container. The output never exceeds limit bytes.
func decompress(data []byte, limit int) ([]byte, error) {
	if len(data) == 0 || data[0] != 1 {
		return nil, errOVBA
	}
	var out []byte
	for pos := 1; pos+2 <= len(data); {
		hdr := int(binary.LittleEndian.Uint16(data[pos:]))
		end := pos + (hdr & 0x0FFF) + 3
		if (hdr>>12)&7 != 3 || end > len(data) {
			return nil, errOVBA
		}
		chunk := data[pos+2 : end]
		pos = end
		start := len(out)
		if hdr&0x8000 == 0 {
			out = append(out, chunk...)
		} else if err := expandChunk(&out, chunk, start); err != nil {
			return nil, err
		}
		if len(out)-start > chunkLen || len(out) > limit {
			return nil, errOVBA
		}
	}
	return out, nil
}

// expandChunk decodes the tokens of one compressed chunk and appends them to out.
func expandChunk(out *[]byte, chunk []byte, start int) error {
	for i := 0; i < len(chunk); {
		flags := chunk[i]
		i++
		for bit := 0; bit < 8 && i < len(chunk); bit++ {
			if flags&(1<<bit) == 0 {
				*out = append(*out, chunk[i])
				i++
				continue
			}
			if i+2 > len(chunk) {
				return errOVBA
			}
			token := int(binary.LittleEndian.Uint16(chunk[i:]))
			i += 2
			diff := len(*out) - start
			if diff == 0 {
				return errOVBA
			}
			bitCount := max(bits.Len(uint(diff-1)), 4)
			length := token&(0xFFFF>>bitCount) + 3
			offset := token>>(16-bitCount) + 1
			if len(*out)-start < offset || len(*out)-start+length > chunkLen {
				return errOVBA
			}
			for range length {
				*out = append(*out, (*out)[len(*out)-offset])
			}
		}
	}
	return nil
}

// module is the decompressed source of one VBA module and its stream path.
type module struct {
	path   string
	source []byte
}

// project reads the modules of the VBA projects in one compound file under a
// shared byte budget.
type project struct {
	c      *cfb
	byPath map[string]dirEntry
	raw    map[string][]byte // streams already read, by lower-case path
	budget int               // bytes still allowed, raw and decompressed
	mods   int               // module records seen
}

// vbaModules finds the VBA projects in c and decompresses their modules. found
// is true when a VBA dir stream exists, even if its modules could not be read;
// complete is false when the storage tree was too deep to list fully.
func vbaModules(ctx context.Context, c *cfb) (mods []module, found, complete bool, err error) {
	all, complete, err := c.streams(ctx)
	if err != nil {
		return nil, false, complete, err
	}
	p := &project{c: c, byPath: make(map[string]dirEntry, len(all)), raw: map[string][]byte{}, budget: maxVBABytes}
	for _, m := range all {
		p.byPath[strings.ToLower(m.path)] = m.e
	}
	dirs := 0
	for _, m := range all {
		lower := strings.ToLower(m.path)
		lp, ok := strings.CutSuffix(lower, "dir")
		if !ok || (lp != "vba/" && !strings.HasSuffix(lp, "/vba/")) {
			continue
		}
		found = true
		if dirs++; dirs > maxDirStreams {
			return mods, found, complete, errOVBA
		}
		prefix := m.path[:len(lp)]
		dir, err := p.read(lower, 0)
		if err != nil {
			return mods, found, complete, err
		}
		for _, info := range parseDir(dir) {
			if err := ctx.Err(); err != nil {
				return mods, found, complete, err
			}
			if p.mods++; p.mods > maxModules {
				return mods, found, complete, errOVBA
			}
			src, err := p.source(prefix+info.stream, info.offset)
			if err != nil {
				return mods, found, complete, err
			}
			if src != nil {
				mods = append(mods, module{path: prefix + info.stream, source: src})
			}
		}
	}
	return mods, found, complete, nil
}

// read returns a stream decompressed from offset, reading and charging the
// stream's bytes only the first time it is used.
func (p *project) read(lowerPath string, offset uint32) ([]byte, error) {
	raw, ok := p.raw[lowerPath]
	if !ok {
		e := p.byPath[lowerPath]
		if uint64(p.budget) < e.size {
			return nil, errOVBA
		}
		var err error
		if raw, err = p.c.read(e); err != nil {
			return nil, errOVBA
		}
		p.budget -= len(raw)
		p.raw[lowerPath] = raw
	}
	if uint64(offset) > uint64(len(raw)) {
		return nil, errOVBA
	}
	src, err := decompress(raw[offset:], p.budget)
	if err != nil {
		return nil, err
	}
	p.budget -= len(src)
	return src, nil
}

// source reads and decompresses the module stream with the given path. A
// stream that does not exist gives nil.
func (p *project) source(path string, offset uint32) ([]byte, error) {
	lower := strings.ToLower(path)
	if _, ok := p.byPath[lower]; !ok {
		return nil, nil
	}
	return p.read(lower, offset)
}

type moduleInfo struct {
	stream string
	offset uint32
}

// parseDir reads the module records of a decompressed VBA dir stream. A
// truncated or odd stream yields the modules read so far.
func parseDir(d []byte) []moduleInfo {
	var mods []moduleInfo
	var cur moduleInfo
	pos := 0
	for n := 0; n < maxDirRecords && pos+6 <= len(d); n++ {
		id := binary.LittleEndian.Uint16(d[pos:])
		size := int(binary.LittleEndian.Uint32(d[pos+2:]))
		pos += 6
		if id == recVersion {
			size = 6 // the size field is a constant; major and minor version follow
		}
		if size < 0 || size > len(d)-pos {
			break
		}
		data := d[pos : pos+size]
		pos += size
		switch {
		case id == recTerminator:
			return mods
		case id == recStreamName:
			cur.stream = string(data)
		case id == recOffset && size == 4:
			cur.offset = binary.LittleEndian.Uint32(data)
		case id == recModuleEnd:
			if cur.stream != "" {
				mods = append(mods, cur)
			}
			cur = moduleInfo{}
		}
	}
	return mods
}
