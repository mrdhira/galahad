package protocol

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
)

// FrameType is the first byte of a frame.
type FrameType byte

// Frame types. Job, Data and End go from the host to the guest; Hello, Progress,
// Artifact, Result and Error go from the guest to the host; Connect and
// ConnectReply belong to the proxy channel.
const (
	FrameHello FrameType = iota + 1
	FrameJob
	FrameData
	FrameEnd
	FrameProgress
	FrameArtifact
	FrameResult
	FrameError
	FrameConnect
	FrameConnectReply
)

var frameNames = map[FrameType]string{
	FrameHello: "hello", FrameJob: "job", FrameData: "data", FrameEnd: "end",
	FrameProgress: "progress", FrameArtifact: "artifact", FrameResult: "result",
	FrameError: "error", FrameConnect: "connect", FrameConnectReply: "connect_reply",
}

func (t FrameType) String() string {
	if n, ok := frameNames[t]; ok {
		return n
	}
	return fmt.Sprintf("unknown(%d)", byte(t))
}

// frameLimits is the largest payload of each frame type, in bytes.
var frameLimits = map[FrameType]int{
	FrameHello:        1 << 10,
	FrameJob:          64 << 10,
	FrameData:         1 << 20,
	FrameEnd:          1 << 10,
	FrameProgress:     256,
	FrameArtifact:     1 << 20,
	FrameResult:       64 << 20,
	FrameError:        4 << 10,
	FrameConnect:      1 << 10,
	FrameConnectReply: 1 << 10,
}

const headerSize = 5

// checkLen returns the limit error for a payload of n bytes, or an error for an unknown type.
func checkLen(t FrameType, n uint64) error {
	limit, ok := frameLimits[t]
	if !ok {
		return fmt.Errorf("unknown frame type %d", byte(t))
	}
	if n > uint64(limit) {
		return fmt.Errorf("%s frame is %d bytes, max %d", t, n, limit)
	}
	return nil
}

// WriteFrame writes one frame. It refuses an unknown type and a payload over the limit of its type.
func WriteFrame(w io.Writer, t FrameType, payload []byte) error {
	if err := checkLen(t, uint64(len(payload))); err != nil {
		return err
	}
	var h [headerSize]byte
	h[0] = byte(t)
	binary.BigEndian.PutUint32(h[1:], uint32(len(payload))) // #nosec G115 -- checkLen bounds it by 64 MiB
	if _, err := w.Write(h[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// ReadFrame reads one frame of any type. It rejects an unknown type and a length
// over the limit of its type before it allocates the payload. At a clean end of the
// stream, before any header byte, it returns io.EOF.
func ReadFrame(r io.Reader) (FrameType, []byte, error) {
	return ReadFrameOf(r, allTypes...)
}

// allTypes lists every type in frameLimits, so a new type cannot be forgotten.
var allTypes = func() []FrameType {
	out := make([]FrameType, 0, len(frameLimits))
	for t := range frameLimits {
		out = append(out, t)
	}
	return out
}()

// ReadFrameOf is ReadFrame for a reader that expects only some types. It rejects
// a type that is not in allowed, and a length over the limit of its type, on the
// header alone, so a peer cannot make it allocate for a frame it never wanted.
func ReadFrameOf(r io.Reader, allowed ...FrameType) (FrameType, []byte, error) {
	var h [headerSize]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return 0, nil, err
	}
	t := FrameType(h[0])
	n := binary.BigEndian.Uint32(h[1:])
	if _, known := frameLimits[t]; !known {
		return 0, nil, checkLen(t, uint64(n))
	}
	if !slices.Contains(allowed, t) {
		return 0, nil, fmt.Errorf("unexpected %s frame", t)
	}
	if err := checkLen(t, uint64(n)); err != nil {
		return 0, nil, err
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
		return 0, nil, err
	}
	return t, payload, nil
}

// Order checks that the frames of one direction come in the allowed sequence.
type Order struct {
	last FrameType // 0 before the first frame
	next map[FrameType][]FrameType
}

// NewHostOrder allows the frames the host sends: Job, Data*, End.
func NewHostOrder() *Order {
	return &Order{next: map[FrameType][]FrameType{
		0:         {FrameJob},
		FrameJob:  {FrameData, FrameEnd},
		FrameData: {FrameData, FrameEnd},
	}}
}

// NewGuestOrder allows the frames the guest sends: Hello, (Progress | Artifact)*, then Result or Error.
func NewGuestOrder() *Order {
	more := []FrameType{FrameProgress, FrameArtifact, FrameResult, FrameError}
	return &Order{next: map[FrameType][]FrameType{
		0:             {FrameHello},
		FrameHello:    more,
		FrameProgress: more,
		FrameArtifact: more,
	}}
}

// Accept records t as the next frame. It returns an error, and records nothing,
// if t may not follow the frames seen so far.
func (o *Order) Accept(t FrameType) error {
	for _, ok := range o.next[o.last] {
		if t == ok {
			o.last = t
			return nil
		}
	}
	if o.last == 0 {
		return fmt.Errorf("%s frame first, want %v", t, o.next[0])
	}
	return fmt.Errorf("%s frame after %s", t, o.last)
}

// Complete reports whether the sequence has ended: no frame may follow the last one.
func (o *Order) Complete() bool {
	return o.last != 0 && len(o.next[o.last]) == 0
}

// DecodeStrict decodes one JSON value into v. It rejects unknown fields and any
// data after the value.
func DecodeStrict(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing data after JSON value")
	}
	return nil
}
