//go:build !linux

package agent

import (
	"errors"
	"net"
)

func dialVsock(uint32, uint32) (net.Conn, error) {
	return nil, errors.New("vsock is only available on Linux")
}
