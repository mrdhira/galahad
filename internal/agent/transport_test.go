package agent_test

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/mrdhira/galahad/internal/agent"
)

func TestParseTransport(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	tcp := "tcp:" + l.Addr().String()

	tests := []struct {
		name string
		// inputs
		value      string
		unsafeHost bool
		// want*
		wantDial bool // dialing reaches the listener
		wantErr  string
	}{
		{name: "tcp with --unsafe-host", value: tcp, unsafeHost: true, wantDial: true},
		{name: "vsock", value: "vsock:2:1024"},
		{name: "vsock with the largest values", value: "vsock:4294967295:4294967295"},
		{name: "no colon", value: "nocolon", unsafeHost: true, wantErr: "want vsock:<cid>:<port> or tcp:<host:port>"},
		{name: "unknown kind", value: "unix:/tmp/x", unsafeHost: true, wantErr: `unknown kind "unix"`},
		{name: "vsock without a port", value: "vsock:2", wantErr: "want vsock:<cid>:<port>"},
		{name: "vsock bad cid", value: "vsock:two:1024", wantErr: "bad cid"},
		{name: "vsock cid out of range", value: "vsock:4294967296:1024", wantErr: "bad cid"},
		{name: "vsock bad port", value: "vsock:2:-1", wantErr: "bad port"},
		{name: "tcp without --unsafe-host", value: tcp, wantErr: "only allowed together with --unsafe-host"},
		{name: "tcp without a port", value: "tcp:localhost", unsafeHost: true, wantErr: "want tcp:<host:port>"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dial, err := agent.ParseTransport(tt.value, tt.unsafeHost)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want one containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseTransport: %v", err)
			}
			if !tt.wantDial {
				return // a vsock dialer needs a VM; the dial itself is tested in internal/vsock
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			c, err := dial(ctx)
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			_ = c.Close()
		})
	}
}
