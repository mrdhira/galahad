package proxy

import "net/netip"

type blockedRange struct {
	prefix netip.Prefix
	reason string
}

func ranges(rs ...[2]string) []blockedRange {
	out := make([]blockedRange, len(rs))
	for i, r := range rs {
		out[i] = blockedRange{netip.MustParsePrefix(r[0]), r[1]}
	}
	return out
}

// Order matters: the first match gives the reason, so the narrow ranges come first.
var blockedV4 = ranges(
	[2]string{"169.254.169.254/32", "metadata"},
	[2]string{"255.255.255.255/32", "broadcast"},
	[2]string{"0.0.0.0/8", "this network"},
	[2]string{"10.0.0.0/8", "private"},
	[2]string{"100.64.0.0/10", "shared address space"},
	[2]string{"127.0.0.0/8", "loopback"},
	[2]string{"169.254.0.0/16", "link-local"},
	[2]string{"172.16.0.0/12", "private"},
	[2]string{"192.0.0.0/24", "protocol assignments"},
	[2]string{"192.0.2.0/24", "documentation"},
	[2]string{"192.168.0.0/16", "private"},
	[2]string{"198.18.0.0/15", "benchmarking"},
	[2]string{"198.51.100.0/24", "documentation"},
	[2]string{"203.0.113.0/24", "documentation"},
	[2]string{"224.0.0.0/4", "multicast"},
	[2]string{"240.0.0.0/4", "reserved"},
)

var blockedV6 = ranges(
	[2]string{"::/128", "unspecified"},
	[2]string{"::1/128", "loopback"},
	[2]string{"fc00::/7", "unique local"},
	[2]string{"fe80::/10", "link-local"},
	[2]string{"ff00::/8", "multicast"},
	[2]string{"2001:db8::/32", "documentation"},
	[2]string{"2002::/16", "6to4"},
)

var nat64 = netip.MustParsePrefix("64:ff9b::/96")

// BlockReason returns why ip may not be dialed, or "" when it is a public address.
// An IPv4-mapped IPv6 address is checked as IPv4, and a 64:ff9b::/96 address is
// checked through the IPv4 address it embeds.
func BlockReason(ip netip.Addr) string {
	ip = ip.WithZone("").Unmap()
	if ip.Is4() {
		return match(blockedV4, ip)
	}
	if nat64.Contains(ip) {
		b := ip.As16()
		if r := match(blockedV4, netip.AddrFrom4([4]byte(b[12:]))); r != "" {
			return "nat64 " + r
		}
		return ""
	}
	return match(blockedV6, ip)
}

func match(rs []blockedRange, ip netip.Addr) string {
	for _, r := range rs {
		if r.prefix.Contains(ip) {
			return r.reason
		}
	}
	return ""
}
