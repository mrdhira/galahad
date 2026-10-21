package proxy_test

import (
	"net/netip"
	"testing"

	"github.com/mrdhira/galahad/internal/proxy"
)

func TestBlockReason(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		// expectations
		wantReason string
	}{
		{name: "public IPv4", ip: "93.184.216.34", wantReason: ""},
		{name: "IPv4 just below 172.16/12", ip: "172.15.255.255", wantReason: ""},
		{name: "IPv4 just above 172.16/12", ip: "172.32.0.0", wantReason: ""},
		{name: "IPv4 just above 100.64/10", ip: "100.128.0.0", wantReason: ""},
		{name: "mapped public", ip: "::ffff:93.184.216.34", wantReason: ""},
		{name: "NAT64 with public address", ip: "64:ff9b::5db8:d822", wantReason: ""},
		{name: "public IPv6", ip: "2606:2800:220:1:248:1893:25c8:1946", wantReason: ""},
		{name: "metadata", ip: "169.254.169.254", wantReason: "metadata"},
		{name: "broadcast", ip: "255.255.255.255", wantReason: "broadcast"},
		{name: "this network", ip: "0.1.2.3", wantReason: "this network"},
		{name: "RFC 1918 10/8", ip: "10.1.2.3", wantReason: "private"},
		{name: "shared address space", ip: "100.64.0.1", wantReason: "shared address space"},
		{name: "loopback", ip: "127.0.0.1", wantReason: "loopback"},
		{name: "link-local", ip: "169.254.1.1", wantReason: "link-local"},
		{name: "RFC 1918 172.16/12", ip: "172.31.255.255", wantReason: "private"},
		{name: "protocol assignments", ip: "192.0.0.8", wantReason: "protocol assignments"},
		{name: "documentation 192.0.2/24", ip: "192.0.2.1", wantReason: "documentation"},
		{name: "RFC 1918 192.168/16", ip: "192.168.0.1", wantReason: "private"},
		{name: "benchmarking", ip: "198.19.255.255", wantReason: "benchmarking"},
		{name: "documentation 198.51.100/24", ip: "198.51.100.7", wantReason: "documentation"},
		{name: "documentation 203.0.113/24", ip: "203.0.113.7", wantReason: "documentation"},
		{name: "multicast", ip: "239.1.1.1", wantReason: "multicast"},
		{name: "reserved 240/4", ip: "250.0.0.1", wantReason: "reserved"},
		{name: "mapped loopback", ip: "::ffff:127.0.0.1", wantReason: "loopback"},
		{name: "mapped private", ip: "::ffff:10.0.0.1", wantReason: "private"},
		{name: "mapped metadata", ip: "::ffff:169.254.169.254", wantReason: "metadata"},
		{name: "mapped broadcast", ip: "::ffff:255.255.255.255", wantReason: "broadcast"},
		{name: "NAT64 with private address", ip: "64:ff9b::a00:1", wantReason: "nat64 private"},
		{name: "NAT64 with metadata address", ip: "64:ff9b::a9fe:a9fe", wantReason: "nat64 metadata"},
		{name: "IPv6 unspecified", ip: "::", wantReason: "unspecified"},
		{name: "IPv6 loopback", ip: "::1", wantReason: "loopback"},
		{name: "IPv4-compatible loopback", ip: "::127.0.0.1", wantReason: "ipv4-compatible"},
		{name: "IPv4-compatible public", ip: "::93.184.216.34", wantReason: "ipv4-compatible"},
		{name: "IPv6 unique local", ip: "fd12:3456::1", wantReason: "unique local"},
		{name: "IPv6 link-local", ip: "fe80::1", wantReason: "link-local"},
		{name: "IPv6 link-local with zone", ip: "fe80::1%eth0", wantReason: "link-local"},
		{name: "IPv6 multicast", ip: "ff02::1", wantReason: "multicast"},
		{name: "Teredo", ip: "2001:0:4136:e378:8000:63bf:3fff:fdd2", wantReason: "teredo"},
		{name: "IPv6 documentation", ip: "2001:db8::1", wantReason: "documentation"},
		{name: "6to4", ip: "2002:5db8:d822::1", wantReason: "6to4"},
		{name: "local-use NAT64", ip: "64:ff9b:1::5db8:d822", wantReason: "local-use nat64"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := proxy.BlockReason(netip.MustParseAddr(tt.ip)); got != tt.wantReason {
				t.Errorf("BlockReason(%s) = %q, want %q", tt.ip, got, tt.wantReason)
			}
		})
	}
}
