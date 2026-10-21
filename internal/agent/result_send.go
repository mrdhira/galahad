//go:build !galahadtest

package agent

import "github.com/mrdhira/galahad/internal/protocol"

// sendResult sends the encoded Result to the host.
func sendResult(h *hostConn, data []byte) error {
	return h.send(protocol.FrameResult, data)
}
