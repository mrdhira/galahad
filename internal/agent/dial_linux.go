package agent

import (
	"net"

	"github.com/mrdhira/galahad/internal/vsock"
)

func dialVsock(cid, port uint32) (net.Conn, error) { return vsock.Dial(cid, port) }
