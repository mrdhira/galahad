//go:build linux

// Package vsock dials the host over AF_VSOCK. It is for the guest agent only: the guest
// always dials the host, so there is no listener.
package vsock

import (
	"fmt"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

// Addr is a vsock address.
type Addr struct {
	CID  uint32
	Port uint32
}

// Network returns "vsock".
func (Addr) Network() string { return "vsock" }

func (a Addr) String() string { return fmt.Sprintf("%d:%d", a.CID, a.Port) }

// conn is a stream socket. The standard library cannot wrap an AF_VSOCK socket with
// net.FileConn (it does not know the address family), so the file is the connection:
// a non-blocking socket in an os.File is pollable and supports deadlines.
type conn struct {
	*os.File
	local, remote Addr
}

// LocalAddr returns the guest address of the connection.
func (c *conn) LocalAddr() net.Addr { return c.local }

// RemoteAddr returns the peer address of the connection.
func (c *conn) RemoteAddr() net.Addr { return c.remote }

// Dial connects to the given context ID and port. The kernel gives up on a connect
// that gets no answer after a few seconds.
func Dial(cid, port uint32) (net.Conn, error) {
	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("vsock socket: %w", err)
	}
	remote := Addr{CID: cid, Port: port}
	if err := unix.Connect(fd, &unix.SockaddrVM{CID: cid, Port: port}); err != nil {
		_ = unix.Close(fd) // the connect error is the one to report
		return nil, fmt.Errorf("vsock connect %s: %w", remote, err)
	}
	local := Addr{}
	if sa, err := unix.Getsockname(fd); err == nil {
		if vm, ok := sa.(*unix.SockaddrVM); ok {
			local = Addr{CID: vm.CID, Port: vm.Port}
		}
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		_ = unix.Close(fd) // the SetNonblock error is the one to report
		return nil, fmt.Errorf("vsock set non-blocking: %w", err)
	}
	return &conn{File: os.NewFile(uintptr(fd), "vsock:"+remote.String()), local: local, remote: remote}, nil
}
