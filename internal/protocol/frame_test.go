package protocol_test

import (
	"bytes"
	"errors"
	"io"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/mrdhira/galahad/internal/protocol"
)

func TestFrameRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		typ     protocol.FrameType
		payload []byte
		// expectations
		wantHeader []byte
	}{
		{name: "job", typ: protocol.FrameJob, payload: []byte(`{"id":"x"}`), wantHeader: []byte{2, 0, 0, 0, 10}},
		{name: "empty payload", typ: protocol.FrameData, payload: []byte{}, wantHeader: []byte{3, 0, 0, 0, 0}},
		{name: "payload at the limit", typ: protocol.FrameProgress, payload: bytes.Repeat([]byte("a"), 256), wantHeader: []byte{5, 0, 0, 1, 0}},
		{name: "binary data", typ: protocol.FrameArtifact, payload: []byte{1, 0, 0xff, '\n'}, wantHeader: []byte{6, 0, 0, 0, 4}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := protocol.WriteFrame(&buf, tt.typ, tt.payload); err != nil {
				t.Fatalf("WriteFrame: %v", err)
			}
			if got := buf.Bytes()[:5]; !bytes.Equal(got, tt.wantHeader) {
				t.Errorf("header = %v, want %v", got, tt.wantHeader)
			}
			typ, payload, err := protocol.ReadFrame(&buf)
			if err != nil {
				t.Fatalf("ReadFrame: %v", err)
			}
			if typ != tt.typ || !bytes.Equal(payload, tt.payload) {
				t.Errorf("ReadFrame = %v, %q, want %v, %q", typ, payload, tt.typ, tt.payload)
			}
			if _, _, err := protocol.ReadFrame(&buf); err != io.EOF {
				t.Errorf("ReadFrame at the end = %v, want io.EOF", err)
			}
		})
	}
}

func TestWriteFrameRejects(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		typ     protocol.FrameType
		payload []byte
		// expectations
		wantErr string
	}{
		{name: "unknown type", typ: 0, payload: nil, wantErr: "unknown frame type 0"},
		{name: "type past the last", typ: 11, payload: nil, wantErr: "unknown frame type 11"},
		{name: "oversize progress", typ: protocol.FrameProgress, payload: make([]byte, 257), wantErr: "progress frame is 257 bytes, max 256"},
		{name: "oversize hello", typ: protocol.FrameHello, payload: make([]byte, 1025), wantErr: "max 1024"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			err := protocol.WriteFrame(&buf, tt.typ, tt.payload)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("WriteFrame = %v, want error containing %q", err, tt.wantErr)
			}
			if buf.Len() != 0 {
				t.Errorf("wrote %d bytes before the error", buf.Len())
			}
		})
	}
}

func TestReadFrameLimits(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		typ protocol.FrameType
		// expectations
		wantMax int
	}{
		{name: "hello", typ: protocol.FrameHello, wantMax: 1 << 10},
		{name: "job", typ: protocol.FrameJob, wantMax: 64 << 10},
		{name: "data", typ: protocol.FrameData, wantMax: 1 << 20},
		{name: "end", typ: protocol.FrameEnd, wantMax: 1 << 10},
		{name: "progress", typ: protocol.FrameProgress, wantMax: 256},
		{name: "artifact", typ: protocol.FrameArtifact, wantMax: 1 << 20},
		{name: "result", typ: protocol.FrameResult, wantMax: 64 << 20},
		{name: "error", typ: protocol.FrameError, wantMax: 4 << 10},
		{name: "connect", typ: protocol.FrameConnect, wantMax: 1 << 10},
		{name: "connect reply", typ: protocol.FrameConnectReply, wantMax: 1 << 10},
	}
	header := func(typ protocol.FrameType, n int) []byte {
		return []byte{byte(typ), byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// One byte over the limit fails on the header alone, before any payload is read.
			_, _, err := protocol.ReadFrame(bytes.NewReader(header(tt.typ, tt.wantMax+1)))
			if err == nil || !strings.Contains(err.Error(), "max") {
				t.Errorf("ReadFrame over the limit = %v, want a limit error", err)
			}
			// At the limit the header is accepted, so the missing payload is what fails.
			_, _, err = protocol.ReadFrame(bytes.NewReader(header(tt.typ, tt.wantMax)))
			if !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Errorf("ReadFrame at the limit = %v, want io.ErrUnexpectedEOF", err)
			}
		})
	}
}

func TestReadFrameRejects(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		stream []byte
		// expectations
		wantErr string
		wantIs  error
	}{
		{name: "empty stream", stream: nil, wantIs: io.EOF},
		{name: "short header", stream: []byte{2, 0, 0}, wantIs: io.ErrUnexpectedEOF},
		{name: "unknown type", stream: []byte{0, 0, 0, 0, 0}, wantErr: "unknown frame type 0"},
		{name: "type past the last", stream: []byte{99, 0, 0, 0, 1, 'x'}, wantErr: "unknown frame type 99"},
		{name: "oversize length", stream: []byte{5, 0, 0, 1, 1}, wantErr: "progress frame is 257 bytes, max 256"},
		{name: "huge length", stream: []byte{7, 0xff, 0xff, 0xff, 0xff}, wantErr: "max 67108864"},
		{name: "short payload", stream: []byte{2, 0, 0, 0, 4, 'a', 'b'}, wantIs: io.ErrUnexpectedEOF},
		{name: "payload missing", stream: []byte{2, 0, 0, 0, 4}, wantIs: io.ErrUnexpectedEOF},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := protocol.ReadFrame(bytes.NewReader(tt.stream))
			switch {
			case tt.wantIs != nil:
				if !errors.Is(err, tt.wantIs) {
					t.Errorf("ReadFrame = %v, want %v", err, tt.wantIs)
				}
			case err == nil || !strings.Contains(err.Error(), tt.wantErr):
				t.Errorf("ReadFrame = %v, want error containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestReadFrameOf(t *testing.T) {
	// A refused header claims 64 MiB and carries nothing else.
	huge := func(typ protocol.FrameType) []byte {
		return []byte{byte(typ), 0x04, 0, 0, 0}
	}
	tests := []struct {
		name string
		// inputs
		stream  []byte
		allowed []protocol.FrameType
		// expectations
		wantType    protocol.FrameType
		wantPayload string
		wantErr     string
		wantIs      error
	}{
		{name: "allowed type", stream: []byte{byte(protocol.FrameConnect), 0, 0, 0, 2, '{', '}'}, allowed: []protocol.FrameType{protocol.FrameConnect}, wantType: protocol.FrameConnect, wantPayload: "{}"},
		{name: "one of several allowed", stream: []byte{byte(protocol.FrameEnd), 0, 0, 0, 0}, allowed: []protocol.FrameType{protocol.FrameData, protocol.FrameEnd}, wantType: protocol.FrameEnd},
		{name: "empty stream", stream: nil, allowed: []protocol.FrameType{protocol.FrameConnect}, wantIs: io.EOF},
		{name: "unknown type", stream: []byte{99, 0, 0, 0, 1}, allowed: []protocol.FrameType{protocol.FrameConnect}, wantErr: "unknown frame type 99"},
		{name: "type not allowed", stream: huge(protocol.FrameResult), allowed: []protocol.FrameType{protocol.FrameConnect}, wantErr: "unexpected result frame"},
		{name: "nothing allowed", stream: []byte{byte(protocol.FrameEnd), 0, 0, 0, 0}, wantErr: "unexpected end frame"},
		{name: "allowed type over its limit", stream: huge(protocol.FrameConnect), allowed: []protocol.FrameType{protocol.FrameConnect}, wantErr: "max 1024"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			typ, payload, err := protocol.ReadFrameOf(bytes.NewReader(tt.stream), tt.allowed...)
			switch {
			case tt.wantIs != nil:
				if !errors.Is(err, tt.wantIs) {
					t.Fatalf("ReadFrameOf = %v, want %v", err, tt.wantIs)
				}
			case tt.wantErr != "":
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("ReadFrameOf = %v, want error containing %q", err, tt.wantErr)
				}
			case err != nil:
				t.Fatalf("ReadFrameOf: %v", err)
			case typ != tt.wantType || string(payload) != tt.wantPayload:
				t.Errorf("ReadFrameOf = %v, %q; want %v, %q", typ, payload, tt.wantType, tt.wantPayload)
			}
		})
	}
}

func TestReadFrameOfAllocation(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		typ protocol.FrameType
		// expectations
		wantMaxBytes uint64
	}{
		{name: "refused result header of 64 MiB", typ: protocol.FrameResult, wantMaxBytes: 1 << 20},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stream := []byte{byte(tt.typ), 0x04, 0, 0, 0}
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			for range 100 {
				if _, _, err := protocol.ReadFrameOf(bytes.NewReader(stream), protocol.FrameConnect); err == nil {
					t.Fatal("ReadFrameOf accepted a refused type")
				}
			}
			runtime.ReadMemStats(&after)
			// Allocating the payload 100 times would be 6.4 GB.
			if got := after.TotalAlloc - before.TotalAlloc; got > tt.wantMaxBytes {
				t.Errorf("allocated %d bytes for 100 refused frames, want at most %d", got, tt.wantMaxBytes)
			}
		})
	}
}

func TestFrameTypeString(t *testing.T) {
	tests := []struct {
		name string
		typ  protocol.FrameType
		want string
	}{
		{name: "hello", typ: protocol.FrameHello, want: "hello"},
		{name: "job", typ: protocol.FrameJob, want: "job"},
		{name: "data", typ: protocol.FrameData, want: "data"},
		{name: "end", typ: protocol.FrameEnd, want: "end"},
		{name: "progress", typ: protocol.FrameProgress, want: "progress"},
		{name: "artifact", typ: protocol.FrameArtifact, want: "artifact"},
		{name: "result", typ: protocol.FrameResult, want: "result"},
		{name: "error", typ: protocol.FrameError, want: "error"},
		{name: "connect", typ: protocol.FrameConnect, want: "connect"},
		{name: "connect reply", typ: protocol.FrameConnectReply, want: "connect_reply"},
		{name: "unknown", typ: 42, want: "unknown(42)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.typ.String(); got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestOrder(t *testing.T) {
	const (
		hello = protocol.FrameHello
		job   = protocol.FrameJob
		data  = protocol.FrameData
		end   = protocol.FrameEnd
		prog  = protocol.FrameProgress
		art   = protocol.FrameArtifact
		res   = protocol.FrameResult
		fail  = protocol.FrameError
	)
	tests := []struct {
		name string
		// inputs
		guest  bool
		frames []protocol.FrameType
		// expectations
		wantErrAt    int // index of the first rejected frame; -1 means all accepted
		wantErr      string
		wantComplete bool
	}{
		{name: "host: job, data, end", frames: []protocol.FrameType{job, data, data, end}, wantErrAt: -1, wantComplete: true},
		{name: "host: job, end without data", frames: []protocol.FrameType{job, end}, wantErrAt: -1, wantComplete: true},
		{name: "host: job only is not complete", frames: []protocol.FrameType{job}, wantErrAt: -1},
		{name: "host: data first", frames: []protocol.FrameType{data}, wantErrAt: 0, wantErr: "data frame first"},
		{name: "host: job twice", frames: []protocol.FrameType{job, job}, wantErrAt: 1, wantErr: "job frame after job"},
		{name: "host: end before job", frames: []protocol.FrameType{end, job}, wantErrAt: 0, wantErr: "end frame first"},
		{name: "host: data after end", frames: []protocol.FrameType{job, end, data}, wantErrAt: 2, wantErr: "data frame after end"},
		{name: "host: a guest frame", frames: []protocol.FrameType{job, res}, wantErrAt: 1, wantErr: "result frame after job"},
		{name: "guest: hello, result", guest: true, frames: []protocol.FrameType{hello, res}, wantErrAt: -1, wantComplete: true},
		{name: "guest: hello, progress and artifacts, result", guest: true, frames: []protocol.FrameType{hello, prog, art, prog, art, res}, wantErrAt: -1, wantComplete: true},
		{name: "guest: hello, error", guest: true, frames: []protocol.FrameType{hello, prog, fail}, wantErrAt: -1, wantComplete: true},
		{name: "guest: hello only is not complete", guest: true, frames: []protocol.FrameType{hello, prog}, wantErrAt: -1},
		{name: "guest: progress before hello", guest: true, frames: []protocol.FrameType{prog}, wantErrAt: 0, wantErr: "progress frame first"},
		{name: "guest: hello twice", guest: true, frames: []protocol.FrameType{hello, hello}, wantErrAt: 1, wantErr: "hello frame after hello"},
		{name: "guest: result before hello", guest: true, frames: []protocol.FrameType{res}, wantErrAt: 0, wantErr: "result frame first"},
		{name: "guest: progress after result", guest: true, frames: []protocol.FrameType{hello, res, prog}, wantErrAt: 2, wantErr: "progress frame after result"},
		{name: "guest: error after result", guest: true, frames: []protocol.FrameType{hello, res, fail}, wantErrAt: 2, wantErr: "error frame after result"},
		{name: "guest: a host frame", guest: true, frames: []protocol.FrameType{hello, data}, wantErrAt: 1, wantErr: "data frame after hello"},
		{name: "guest: unknown type", guest: true, frames: []protocol.FrameType{hello, 99}, wantErrAt: 1, wantErr: "unknown(99) frame after hello"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := protocol.NewHostOrder()
			if tt.guest {
				o = protocol.NewGuestOrder()
			}
			gotErrAt := -1
			var err error
			for i, f := range tt.frames {
				if err = o.Accept(f); err != nil {
					gotErrAt = i
					break
				}
			}
			if gotErrAt != tt.wantErrAt {
				t.Fatalf("first rejected frame = %d (%v), want %d", gotErrAt, err, tt.wantErrAt)
			}
			if err != nil && !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Accept error = %v, want it to contain %q", err, tt.wantErr)
			}
			if err == nil && o.Complete() != tt.wantComplete {
				t.Errorf("Complete() = %v, want %v", o.Complete(), tt.wantComplete)
			}
		})
	}
}

func TestOrderNothingSeenIsNotComplete(t *testing.T) {
	tests := []struct {
		name  string
		order *protocol.Order
	}{
		{name: "host", order: protocol.NewHostOrder()},
		{name: "guest", order: protocol.NewGuestOrder()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.order.Complete() {
				t.Error("Complete() = true before any frame")
			}
		})
	}
}

func TestDecodeStrict(t *testing.T) {
	type msg struct {
		A int    `json:"a"`
		B string `json:"b"`
	}
	tests := []struct {
		name string
		// inputs
		data string
		// expectations
		want    msg
		wantErr string
	}{
		{name: "valid", data: `{"a":1,"b":"x"}`, want: msg{A: 1, B: "x"}},
		{name: "trailing whitespace is fine", data: "{\"a\":1}\n \t", want: msg{A: 1}},
		{name: "empty input", data: ``, wantErr: "EOF"},
		{name: "syntax error", data: `{"a":`, wantErr: "unexpected EOF"},
		{name: "unknown field", data: `{"a":1,"c":2}`, wantErr: `unknown field "c"`},
		{name: "wrong type", data: `{"a":"1"}`, wantErr: "cannot unmarshal"},
		{name: "trailing value", data: `{"a":1}{"a":2}`, wantErr: "trailing data"},
		{name: "trailing garbage", data: `{"a":1} x`, wantErr: "trailing data"},
		{name: "trailing brace", data: `{"a":1}}`, wantErr: "trailing data"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got msg
			err := protocol.DecodeStrict([]byte(tt.data), &got)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("DecodeStrict = %v, want error containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil || got != tt.want {
				t.Errorf("DecodeStrict = %+v, %v, want %+v", got, err, tt.want)
			}
		})
	}
}

func TestOrderAllowed(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		order  *protocol.Order
		frames []protocol.FrameType
		// expectations
		wantAllowed []protocol.FrameType
	}{
		{name: "guest start", order: protocol.NewGuestOrder(), wantAllowed: []protocol.FrameType{protocol.FrameHello}},
		{
			name: "guest after hello", order: protocol.NewGuestOrder(), frames: []protocol.FrameType{protocol.FrameHello},
			wantAllowed: []protocol.FrameType{protocol.FrameProgress, protocol.FrameArtifact, protocol.FrameResult, protocol.FrameError},
		},
		{name: "guest after result", order: protocol.NewGuestOrder(), frames: []protocol.FrameType{protocol.FrameHello, protocol.FrameResult}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, f := range tt.frames {
				if err := tt.order.Accept(f); err != nil {
					t.Fatal(err)
				}
			}
			if got := tt.order.Allowed(); !slices.Equal(got, tt.wantAllowed) {
				t.Errorf("Allowed() = %v, want %v", got, tt.wantAllowed)
			}
		})
	}
}
