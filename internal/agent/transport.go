package agent

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// Dialer opens one connection to the host.
type Dialer func(ctx context.Context) (net.Conn, error)

// dialTimeout bounds a TCP connect. A vsock connect is bounded by the kernel.
const dialTimeout = 10 * time.Second

// ParseTransport turns the value of --control or --proxy into a Dialer. The value is
// vsock:<cid>:<port>, which is what the guest uses, or tcp:<host:port>, which only the
// test backend uses and which needs unsafeHost.
func ParseTransport(value string, unsafeHost bool) (Dialer, error) {
	kind, addr, ok := strings.Cut(value, ":")
	if !ok {
		return nil, fmt.Errorf("transport %q: want vsock:<cid>:<port> or tcp:<host:port>", value)
	}
	switch kind {
	case "vsock":
		cidText, portText, ok := strings.Cut(addr, ":")
		if !ok {
			return nil, fmt.Errorf("transport %q: want vsock:<cid>:<port>", value)
		}
		cid, err := strconv.ParseUint(cidText, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("transport %q: bad cid: %w", value, err)
		}
		port, err := strconv.ParseUint(portText, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("transport %q: bad port: %w", value, err)
		}
		return func(context.Context) (net.Conn, error) { return dialVsock(uint32(cid), uint32(port)) }, nil // #nosec G115 -- ParseUint bounds both by 32 bits
	case "tcp":
		if !unsafeHost {
			return nil, fmt.Errorf("transport %q: tcp is only allowed together with --unsafe-host", value)
		}
		if _, _, err := net.SplitHostPort(addr); err != nil {
			return nil, fmt.Errorf("transport %q: want tcp:<host:port>", value)
		}
		return func(ctx context.Context) (net.Conn, error) {
			d := net.Dialer{Timeout: dialTimeout}
			return d.DialContext(ctx, "tcp", addr)
		}, nil
	}
	return nil, fmt.Errorf("transport %q: unknown kind %q, want vsock or tcp", value, kind)
}
