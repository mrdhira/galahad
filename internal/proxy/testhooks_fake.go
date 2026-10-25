//go:build galahadtest

package proxy

import (
	"net/netip"
	"os"
	"strings"
)

// The hooks read the environment on each call, so a test can change it.
func init() {
	hookResolve = func(host string) ([]netip.Addr, bool) {
		// GALAHAD_TEST_RESOLVE=name=ip,name=ip. A name may repeat to give several addresses. name=fail
		// makes the lookup of name fail, as it does on a computer without a network.
		var out []netip.Addr
		for _, kv := range strings.Split(os.Getenv("GALAHAD_TEST_RESOLVE"), ",") {
			name, ip, ok := strings.Cut(kv, "=")
			if ok && name == host && ip == "fail" {
				return nil, true
			}
			if a, err := netip.ParseAddr(ip); ok && name == host && err == nil {
				out = append(out, a)
			}
		}
		return out, len(out) > 0
	}
	// GALAHAD_TEST_SINKHOLE=127.0.0.1:port is the one loopback address the block list lets through.
	hookSinkhole = func() (netip.AddrPort, bool) {
		s, err := netip.ParseAddrPort(os.Getenv("GALAHAD_TEST_SINKHOLE"))
		return s, err == nil && s.Addr().IsLoopback()
	}
	// Port 80 is open for .test hosts that are on the allowlist.
	hookHTTPHost = func(host string) bool { return strings.HasSuffix(host, ".test") }
}
