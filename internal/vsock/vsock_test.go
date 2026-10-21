//go:build linux

package vsock_test

import (
	"errors"
	"io"
	"os"
	"testing"
	"time"

	"github.com/mrdhira/galahad/internal/vsock"
	"golang.org/x/sys/unix"
)

// listen returns a vsock listener on the loopback address and its port, or skips the
// test when the kernel has no vsock loopback.
func listen(t *testing.T) (fd int, port uint32) {
	t.Helper()
	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Skipf("no vsock: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	if err := unix.Bind(fd, &unix.SockaddrVM{CID: unix.VMADDR_CID_ANY, Port: unix.VMADDR_PORT_ANY}); err != nil {
		t.Skipf("no vsock bind: %v", err)
	}
	if err := unix.Listen(fd, 1); err != nil {
		t.Skipf("no vsock listen: %v", err)
	}
	sa, err := unix.Getsockname(fd)
	if err != nil {
		t.Skipf("no vsock name: %v", err)
	}
	return fd, sa.(*unix.SockaddrVM).Port
}

func TestDial(t *testing.T) {
	tests := []struct {
		name    string
		loop    bool // dial the listener of this test on the loopback CID
		cid     uint32
		port    uint32
		wantErr bool
	}{
		{name: "loopback listener", loop: true, cid: unix.VMADDR_CID_LOCAL},
		{name: "nothing listens", cid: unix.VMADDR_CID_LOCAL, port: 1, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			port := tt.port
			var lfd int
			if tt.loop {
				lfd, port = listen(t)
			}
			c, err := vsock.Dial(tt.cid, port)
			if tt.wantErr {
				if err == nil {
					_ = c.Close()
					t.Fatal("Dial succeeded, want an error")
				}
				return
			}
			if err != nil {
				t.Skipf("no vsock loopback: %v", err)
			}
			defer func() { _ = c.Close() }()
			nfd, _, err := unix.Accept(lfd)
			if err != nil {
				t.Fatalf("accept: %v", err)
			}
			peer := os.NewFile(uintptr(nfd), "peer")
			defer func() { _ = peer.Close() }()

			if got := c.RemoteAddr().Network(); got != "vsock" {
				t.Errorf("network = %q, want vsock", got)
			}
			if _, err := c.Write([]byte("ping")); err != nil {
				t.Fatalf("write: %v", err)
			}
			buf := make([]byte, 4)
			if _, err := io.ReadFull(peer, buf); err != nil || string(buf) != "ping" {
				t.Fatalf("peer read = %q, %v", buf, err)
			}
			// A read deadline works, so the guest can bound a silent host.
			if err := c.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
				t.Fatalf("SetReadDeadline: %v", err)
			}
			if _, err := c.Read(buf); !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Errorf("read error = %v, want a deadline error", err)
			}
		})
	}
}
