// Package ioc extracts URLs, domains, IP addresses and email addresses from
// text and flags risky URLs.
package ioc

import (
	"bytes"
	"context"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/mrdhira/galahad/internal/analyze"
	"github.com/mrdhira/galahad/internal/analyze/ident"
	"github.com/mrdhira/galahad/internal/protocol"
)

var (
	ruleRawIP   = protocol.Rule{ID: "GAL-IOC-001", Severity: protocol.SeverityLow, Title: "URL uses a raw public IP address as host", Attack: "T1071.001"}
	ruleService = protocol.Rule{ID: "GAL-IOC-002", Severity: protocol.SeverityMedium, Title: "URL points to a paste, tunnel or webhook service", Attack: "T1567"}
)

// Indicator types, as in protocol.IOC.
const (
	TypeURL    = "url"
	TypeDomain = "domain"
	TypeIP     = "ip"
	TypeEmail  = "email"
)

// Match is one indicator found in text. Offset is the byte offset where the
// URL, email address or IP address starts; a domain taken from a URL or email
// address has the offset of that URL or email address. Line is 1-based.
type Match struct {
	Type   string
	Value  string // raw, not defanged
	Offset int
	Line   int
}

var (
	urlRe   = regexp.MustCompile(`(?i)\b(?:https?|ftp)://[^\s<>"'` + "`" + `\\^{}|]+`)
	emailRe = regexp.MustCompile(`(?i)[a-z0-9._%+-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,}`)
	ipRe    = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
)

// Extract returns the URLs, email addresses, bare IPv4 addresses and the
// domains and IPs of URL hosts in text, ordered by offset. Domains come only
// from URLs and email addresses. Private, loopback, link-local and
// documentation IPs are not listed as ip matches. Values with control or bidi
// characters or invalid UTF-8 are dropped.
func Extract(text []byte) []Match {
	type span struct{ start, end int }
	var ms []Match
	var taken []span
	add := func(typ, value string, off int) {
		if safe(value) {
			ms = append(ms, Match{Type: typ, Value: value, Offset: off})
		}
	}
	covered := func(start int) bool {
		for _, s := range taken {
			if start >= s.start && start < s.end {
				return true
			}
		}
		return false
	}

	for _, m := range urlRe.FindAllIndex(text, -1) {
		end := m[0] + len(bytes.TrimRight(text[m[0]:m[1]], ".,;:!?)]"))
		raw := string(text[m[0]:end])
		taken = append(taken, span{m[0], end})
		if !safe(raw) {
			continue
		}
		add(TypeURL, raw, m[0])
		u, err := url.Parse(raw)
		if err != nil {
			continue
		}
		host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
		if addr, err := netip.ParseAddr(host); err == nil {
			if isPublic(addr) {
				add(TypeIP, addr.String(), m[0])
			}
		} else if strings.Contains(host, ".") {
			add(TypeDomain, host, m[0])
		}
	}
	for _, m := range emailRe.FindAllIndex(text, -1) {
		if covered(m[0]) {
			continue
		}
		taken = append(taken, span{m[0], m[1]})
		raw := string(text[m[0]:m[1]])
		add(TypeEmail, raw, m[0])
		add(TypeDomain, strings.ToLower(raw[strings.LastIndexByte(raw, '@')+1:]), m[0])
	}
	for _, m := range ipRe.FindAllIndex(text, -1) {
		if covered(m[0]) || inDottedRun(text, m[0], m[1]) {
			continue
		}
		if addr, err := netip.ParseAddr(string(text[m[0]:m[1]])); err == nil && isPublic(addr) {
			add(TypeIP, addr.String(), m[0])
		}
	}

	sort.SliceStable(ms, func(a, b int) bool { return ms[a].Offset < ms[b].Offset })
	line, prev := 1, 0
	for i := range ms {
		line += bytes.Count(text[prev:ms[i].Offset], []byte{'\n'})
		prev = ms[i].Offset
		ms[i].Line = line
	}
	return ms
}

// inDottedRun reports an address that is part of a longer dotted number such as 1.2.3.4.5.
func inDottedRun(text []byte, start, end int) bool {
	digit := func(c byte) bool { return c >= '0' && c <= '9' }
	return (end+1 < len(text) && text[end] == '.' && digit(text[end+1])) ||
		(start >= 2 && text[start-1] == '.' && digit(text[start-2]))
}

// safe reports a value that is valid UTF-8 without control or bidi characters.
func safe(s string) bool {
	return utf8.ValidString(s) && !strings.ContainsFunc(s, func(r rune) bool {
		return unicode.IsControl(r) || r == 0x061C || r == 0x200E || r == 0x200F ||
			(r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069)
	})
}

// nonPublic lists address ranges that are not on the public internet, beyond
// what netip reports as private, loopback and link-local.
var nonPublic = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001:db8::/32"),
}

func isPublic(a netip.Addr) bool {
	a = a.Unmap().WithZone("")
	if !a.IsGlobalUnicast() || a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() {
		return false
	}
	for _, p := range nonPublic {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

// service is a paste, tunnel or webhook service. A host matches itself and its
// subdomains; a non-empty path restricts the match to URLs under that path.
type service struct{ host, path string }

var services = []service{
	{"pastebin.com", ""}, {"paste.ee", ""}, {"ngrok.io", ""}, {"ngrok-free.app", ""},
	{"webhook.site", ""}, {"transfer.sh", ""},
	{"discord.com", "/api/webhooks"}, {"discordapp.com", "/api/webhooks"},
	{"api.telegram.org", "/bot"},
}

func isService(u *url.URL) bool {
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	p := strings.ToLower(u.Path)
	for _, s := range services {
		if (host == s.host || strings.HasSuffix(host, "."+s.host)) && strings.HasPrefix(p, s.path) {
			return true
		}
	}
	return false
}

type analyzer struct{}

// New returns the IOC analyzer. It reads text files only.
func New() analyze.Analyzer { return analyzer{} }

func (analyzer) Name() string { return "ioc" }

func (analyzer) Analyze(ctx context.Context, f analyze.File) (analyze.Output, error) {
	var out analyze.Output
	if f.Kind != ident.Text {
		return out, nil
	}
	seen := map[string]bool{}
	for lineNo, start := 1, 0; start <= len(f.Data); lineNo++ {
		if err := ctx.Err(); err != nil {
			return analyze.Output{}, err
		}
		end := len(f.Data)
		if i := bytes.IndexByte(f.Data[start:], '\n'); i >= 0 {
			end = start + i
		}
		line := f.Data[start:min(end, start+analyze.MaxLineScan)]
		for _, m := range Extract(line) {
			key := m.Type + "\x00" + m.Value
			if seen[key] {
				continue
			}
			seen[key] = true
			if len(out.IOCs) < protocol.MaxIOCs {
				out.IOCs = append(out.IOCs, protocol.IOC{Type: m.Type, Value: m.Value, Path: f.Path, Line: lineNo})
			}
			if m.Type == TypeURL {
				out.Findings = append(out.Findings, risks(f, start+m.Offset, m.Value)...)
			}
		}
		start = end + 1
	}
	return out, nil
}

// risks returns the findings for one URL found at the byte offset in f.
func risks(f analyze.File, off int, raw string) []protocol.Finding {
	u, err := url.Parse(raw)
	if err != nil {
		return nil
	}
	var fs []protocol.Finding
	if addr, err := netip.ParseAddr(u.Hostname()); err == nil && isPublic(addr) {
		fs = append(fs, ruleRawIP.Finding(analyze.EvidenceAt(f, off)))
	}
	if isService(u) {
		fs = append(fs, ruleService.Finding(analyze.EvidenceAt(f, off)))
	}
	return fs
}
