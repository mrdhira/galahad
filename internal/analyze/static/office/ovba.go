package office

import (
	"encoding/binary"
	"errors"
	"math/bits"
	"strings"
)

// Limits of one VBA project.
const (
	maxModules    = 1000
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

// vbaModules finds the VBA project in c and decompresses its modules. found is
// true when a VBA dir stream exists, even if its modules could not be read.
func vbaModules(c *cfb) (mods []module, found bool, err error) {
	all := c.streams()
	byPath := make(map[string]dirEntry, len(all))
	for _, m := range all {
		byPath[strings.ToLower(m.path)] = m.e
	}
	budget := maxVBABytes
	for _, m := range all {
		prefix, ok := strings.CutSuffix(m.path, "dir")
		if !ok || (prefix != "VBA/" && !strings.HasSuffix(prefix, "/VBA/")) {
			continue
		}
		found = true
		raw, err := c.read(m.e)
		if err != nil {
			return mods, found, err
		}
		dir, err := decompress(raw, maxVBABytes)
		if err != nil {
			return mods, found, err
		}
		for _, info := range parseDir(dir) {
			if len(mods) >= maxModules {
				return mods, found, nil
			}
			src, err := moduleSource(c, byPath, prefix+info.stream, info.offset, &budget)
			if err != nil {
				return mods, found, err
			}
			if src != nil {
				mods = append(mods, module{path: prefix + info.stream, source: src})
			}
		}
	}
	return mods, found, nil
}

// moduleSource reads and decompresses the module stream with the given path.
func moduleSource(c *cfb, byPath map[string]dirEntry, path string, offset uint32, budget *int) ([]byte, error) {
	e, ok := byPath[strings.ToLower(path)]
	if !ok {
		return nil, nil
	}
	raw, err := c.read(e)
	if err != nil || uint64(offset) > uint64(len(raw)) {
		return nil, errOVBA
	}
	src, err := decompress(raw[offset:], *budget)
	if err != nil {
		return nil, err
	}
	*budget -= len(src)
	return src, nil
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
