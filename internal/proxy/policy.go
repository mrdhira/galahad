package proxy

import (
	"fmt"
	"net/netip"
	"net/url"
	"strings"

	"github.com/mrdhira/galahad/internal/protocol"
)

// Hosts of the policy rows in docs/milestones/M2.md.
var (
	driveHosts    = []string{"drive.google.com", "drive.usercontent.google.com", "docs.google.com"}
	redirectHosts = []string{"objects.githubusercontent.com", "release-assets.githubusercontent.com", "raw.githubusercontent.com", "codeload.github.com"}
	updateHosts   = []string{"database.clamav.net", "github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com"}
)

const osvHost = "api.osv.dev"

// IsInfraHost reports whether host is the fixed infrastructure host that the guest contacts by itself on
// every scan, which is api.osv.dev. The match is exact: no subdomain and no address counts.
func IsInfraHost(host string) bool { return host == osvHost }

// ReasonHostNotAllowed is the reason of a denial for a host that is not on the allowlist.
const ReasonHostNotAllowed = "host not allowed"

// Input describes a job for NewPolicy.
type Input struct {
	Kind       string   // protocol.Kind*
	Source     string   // protocol.Source*, for scan jobs
	Target     string   // http or https URL, used by the url and git sources
	AllowHosts []string // --allow-host values
}

// Policy is the set of host and port pairs one job may reach. The zero Policy allows nothing.
type Policy struct {
	hosts    map[string]bool
	httpHost string // the host allowed on port 80
}

// NewPolicy builds the policy for a job. It fails on a target or --allow-host
// value that is not a valid host name. An IP literal can only be the target.
func NewPolicy(in Input) (Policy, error) {
	p := Policy{hosts: map[string]bool{}}
	if in.Kind == protocol.KindUpdate {
		p.add(updateHosts...)
		return p, nil
	}
	p.add(osvHost)
	for _, h := range in.AllowHosts {
		h = strings.ToLower(h)
		if !validHost(h) || isIP(h) {
			return Policy{}, fmt.Errorf("--allow-host %q is not a host name", h)
		}
		p.add(h)
	}
	switch in.Source {
	case protocol.SourceDrive:
		p.add(driveHosts...)
	case protocol.SourceURL, protocol.SourceGit:
		u, err := url.Parse(in.Target)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			return Policy{}, fmt.Errorf("target %q is not an http or https URL", in.Target)
		}
		h := strings.ToLower(u.Hostname())
		if !validHost(h) {
			return Policy{}, fmt.Errorf("target host %q is not a valid host name", h)
		}
		p.add(h)
		if u.Scheme == "http" {
			p.httpHost = h
		}
		if in.Source == protocol.SourceURL {
			p.add(redirectHosts...)
		}
	}
	return p, nil
}

func (p *Policy) add(hosts ...string) {
	for _, h := range hosts {
		p.hosts[h] = true
	}
}

// Allows reports whether the job may connect to host and port. Port 443 is open
// for every listed host. Port 80 is open only for the host of an http target.
// When it says no, reason tells why.
func (p Policy) Allows(host string, port int) (ok bool, reason string) {
	if !p.hosts[host] {
		return false, ReasonHostNotAllowed
	}
	switch {
	case port == 443:
		return true, ""
	case port == 80 && (host == p.httpHost || (hookHTTPHost != nil && hookHTTPHost(host))):
		return true, ""
	}
	return false, "port not allowed"
}

func isIP(h string) bool {
	_, err := netip.ParseAddr(h)
	return err == nil
}

// validHost checks a lowercase host name or IPv4 literal, tighter than protocol.Connect.Validate:
// no empty label, no leading or trailing "-" or ".", no label over 63 bytes, and no
// all-digit last label unless the whole host is an IPv4 literal (a resolver may read
// "127.1" or "2130706433" as an address).
func validHost(h string) bool {
	if len(h) < 1 || len(h) > 253 {
		return false
	}
	labels := strings.Split(h, ".")
	for _, l := range labels {
		if len(l) < 1 || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for i := 0; i < len(l); i++ {
			if c := l[i]; (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
	}
	if a, err := netip.ParseAddr(h); err == nil {
		return a.Is4()
	}
	last := labels[len(labels)-1]
	return strings.Trim(last, "0123456789") != ""
}
