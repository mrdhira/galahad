package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/mrdhira/galahad/internal/protocol"
)

// frameIdle is how long the guest waits for the next frame of the host, or for the host to take one.
const frameIdle = 60 * time.Second

// drainTime is how long close waits for the host to finish sending.
const drainTime = 2 * time.Second

// codeError is a failure that has its own Error code for the host.
type codeError struct {
	code string
	err  error
}

func (e *codeError) Error() string { return e.err.Error() }
func (e *codeError) Unwrap() error { return e.err }

func fail(code, format string, args ...any) error {
	return &codeError{code: code, err: fmt.Errorf(format, args...)}
}

// hostConn is the control connection seen from the guest.
type hostConn struct {
	conn     net.Conn
	order    *protocol.Order
	deadline time.Time // end of the job; zero until the Job frame has come
}

func newHostConn(conn net.Conn) *hostConn {
	return &hostConn{conn: conn, order: protocol.NewHostOrder()}
}

// next reads one frame of the host. Each read has the idle deadline, cut short by the job deadline.
// A frame that may not come at this point in the sequence is a protocol error.
func (h *hostConn) next() (protocol.FrameType, []byte, error) {
	d := time.Now().Add(frameIdle)
	if !h.deadline.IsZero() && h.deadline.Before(d) {
		d = h.deadline
	}
	if err := h.conn.SetReadDeadline(d); err != nil {
		return 0, nil, err
	}
	t, payload, err := protocol.ReadFrame(h.conn)
	switch {
	case errors.Is(err, os.ErrDeadlineExceeded):
		return 0, nil, fail(protocol.CodeTimeout, "timed out waiting for the host")
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return 0, nil, fail(protocol.CodeProtocol, "the host closed the connection before the end frame")
	case err != nil:
		return 0, nil, fail(protocol.CodeProtocol, "read frame: %v", err)
	}
	if err := h.order.Accept(t); err != nil {
		return 0, nil, fail(protocol.CodeProtocol, "%v", err)
	}
	return t, payload, nil
}

// send writes one frame with the idle deadline.
func (h *hostConn) send(t protocol.FrameType, payload []byte) error {
	if err := h.conn.SetWriteDeadline(time.Now().Add(frameIdle)); err != nil {
		return err
	}
	return protocol.WriteFrame(h.conn, t, payload)
}

// close ends the session after the last frame. Closing a connection with unread input
// resets it on some systems, and the peer then drops what it had not read yet, which
// can be the last frame. So the guest first shuts down its sending side, then reads what
// the host still sends until EOF or a short deadline, and only then closes.
func (h *hostConn) close() {
	if cw, ok := h.conn.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite() // best effort; the drain below still runs
	}
	if err := h.conn.SetReadDeadline(time.Now().Add(drainTime)); err == nil {
		_, _ = io.Copy(io.Discard, h.conn) // ends at EOF, an error or the deadline
	}
	_ = h.conn.Close() // nothing is left to flush
}

// sendJSON writes a small message, which is not a Result, as one frame.
func (h *hostConn) sendJSON(t protocol.FrameType, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return h.send(t, data)
}

// inputReader is the tar stream in the Data frames. It ends at the End frame, which it keeps.
type inputReader struct {
	host *hostConn
	buf  []byte
	end  *protocol.End
}

func (r *inputReader) Read(p []byte) (int, error) {
	for len(r.buf) == 0 {
		if r.end != nil {
			return 0, io.EOF
		}
		t, payload, err := r.host.next()
		if err != nil {
			return 0, err
		}
		switch t {
		case protocol.FrameData:
			r.buf = payload
		case protocol.FrameEnd:
			var end protocol.End
			if err := protocol.DecodeStrict(payload, &end); err != nil {
				return 0, fail(protocol.CodeProtocol, "end frame: %v", err)
			}
			if err := end.Validate(); err != nil {
				return 0, fail(protocol.CodeProtocol, "end frame: %v", err)
			}
			r.end = &end
		}
	}
	n := copy(p, r.buf)
	r.buf = r.buf[n:]
	return n, nil
}
