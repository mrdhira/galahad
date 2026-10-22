package proxy_test

import (
	"strings"
	"testing"

	"github.com/mrdhira/galahad/internal/protocol"
	"github.com/mrdhira/galahad/internal/proxy"
)

func TestPolicy(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		in   proxy.Input
		host string
		port int
		// expectations
		wantOK     bool
		wantReason string
	}{
		{name: "allowed host on 443", in: proxy.Input{Kind: protocol.KindScan, Source: protocol.SourceLocal, AllowHosts: []string{"files.example.com"}}, host: "files.example.com", port: 443, wantOK: true},
		{name: "scan reaches the OSV API", in: proxy.Input{Kind: protocol.KindScan, Source: protocol.SourceLocal}, host: "api.osv.dev", port: 443, wantOK: true},
		{name: "allow-host is lowercased", in: proxy.Input{Kind: protocol.KindScan, Source: protocol.SourceLocal, AllowHosts: []string{"Files.Example.COM"}}, host: "files.example.com", port: 443, wantOK: true},
		{name: "host not listed", in: proxy.Input{Kind: protocol.KindScan, Source: protocol.SourceLocal}, host: "example.com", port: 443, wantReason: "host not allowed"},
		{name: "wrong port on a listed host", in: proxy.Input{Kind: protocol.KindScan, Source: protocol.SourceLocal}, host: "api.osv.dev", port: 8443, wantReason: "port not allowed"},
		{name: "port 80 on a host of no http target", in: proxy.Input{Kind: protocol.KindScan, Source: protocol.SourceLocal}, host: "api.osv.dev", port: 80, wantReason: "port not allowed"},
		{name: "drive host", in: proxy.Input{Kind: protocol.KindScan, Source: protocol.SourceDrive}, host: "drive.usercontent.google.com", port: 443, wantOK: true},
		{name: "drive hosts are not open to a local scan", in: proxy.Input{Kind: protocol.KindScan, Source: protocol.SourceLocal}, host: "drive.google.com", port: 443, wantReason: "host not allowed"},
		{name: "url target on 443", in: proxy.Input{Kind: protocol.KindScan, Source: protocol.SourceURL, Target: "https://Dl.Example.com/a.zip"}, host: "dl.example.com", port: 443, wantOK: true},
		{name: "url redirect host", in: proxy.Input{Kind: protocol.KindScan, Source: protocol.SourceURL, Target: "https://dl.example.com/a.zip"}, host: "objects.githubusercontent.com", port: 443, wantOK: true},
		{name: "url https target on 80", in: proxy.Input{Kind: protocol.KindScan, Source: protocol.SourceURL, Target: "https://dl.example.com/a.zip"}, host: "dl.example.com", port: 80, wantReason: "port not allowed"},
		{name: "url http target on 80", in: proxy.Input{Kind: protocol.KindScan, Source: protocol.SourceURL, Target: "http://dl.example.com/a.zip"}, host: "dl.example.com", port: 80, wantOK: true},
		{name: "port 80 is for the http target only", in: proxy.Input{Kind: protocol.KindScan, Source: protocol.SourceURL, Target: "http://dl.example.com/a.zip"}, host: "raw.githubusercontent.com", port: 80, wantReason: "port not allowed"},
		{name: "git target", in: proxy.Input{Kind: protocol.KindScan, Source: protocol.SourceGit, Target: "https://github.com/a/b"}, host: "github.com", port: 443, wantOK: true},
		{name: "git has no redirect hosts", in: proxy.Input{Kind: protocol.KindScan, Source: protocol.SourceGit, Target: "https://github.com/a/b"}, host: "raw.githubusercontent.com", port: 443, wantReason: "host not allowed"},
		{name: "IP literal target", in: proxy.Input{Kind: protocol.KindScan, Source: protocol.SourceURL, Target: "http://93.184.216.34:8080/x"}, host: "93.184.216.34", port: 80, wantOK: true},
		{name: "IP literal that is not the target", in: proxy.Input{Kind: protocol.KindScan, Source: protocol.SourceURL, Target: "http://93.184.216.34/x"}, host: "93.184.216.35", port: 80, wantReason: "host not allowed"},
		{name: "update host", in: proxy.Input{Kind: protocol.KindUpdate}, host: "database.clamav.net", port: 443, wantOK: true},
		{name: "update has no OSV", in: proxy.Input{Kind: protocol.KindUpdate}, host: "api.osv.dev", port: 443, wantReason: "host not allowed"},
		{name: "update ignores allow-host", in: proxy.Input{Kind: protocol.KindUpdate, AllowHosts: []string{"example.com"}}, host: "example.com", port: 443, wantReason: "host not allowed"},
		{name: "scan has no update hosts", in: proxy.Input{Kind: protocol.KindScan, Source: protocol.SourceLocal}, host: "database.clamav.net", port: 443, wantReason: "host not allowed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := proxy.NewPolicy(tt.in)
			if err != nil {
				t.Fatalf("NewPolicy: %v", err)
			}
			ok, reason := p.Allows(tt.host, tt.port)
			if ok != tt.wantOK || reason != tt.wantReason {
				t.Errorf("Allows(%q, %d) = %v, %q; want %v, %q", tt.host, tt.port, ok, reason, tt.wantOK, tt.wantReason)
			}
		})
	}
}

func TestIsInfraHost(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		host string
		// expectations
		want bool
	}{
		{name: "the OSV API", host: "api.osv.dev", want: true},
		{name: "a subdomain of it", host: "evil.api.osv.dev"},
		{name: "a parent domain of it", host: "osv.dev"},
		{name: "a host that ends with it", host: "notapi.osv.dev"},
		{name: "a different case", host: "API.osv.dev"},
		{name: "a trailing dot", host: "api.osv.dev."},
		{name: "an address", host: "198.18.0.5"},
		{name: "another allowed host", host: "github.com"},
		{name: "empty", host: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := proxy.IsInfraHost(tt.host); got != tt.want {
				t.Errorf("IsInfraHost(%q) = %v, want %v", tt.host, got, tt.want)
			}
		})
	}
}

func TestZeroPolicyAllowsNothing(t *testing.T) {
	tests := []struct {
		name string
		host string
		port int
		// expectations
		wantOK bool
	}{
		{name: "OSV on 443", host: "api.osv.dev", port: 443, wantOK: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var p proxy.Policy
			if ok, _ := p.Allows(tt.host, tt.port); ok != tt.wantOK {
				t.Errorf("zero Policy Allows(%q, %d) = %v, want %v", tt.host, tt.port, ok, tt.wantOK)
			}
		})
	}
}

func TestNewPolicyErrors(t *testing.T) {
	tests := []struct {
		name string
		in   proxy.Input
		// expectations
		wantErr string
	}{
		{name: "allow-host is an IP literal", in: proxy.Input{Kind: protocol.KindScan, Source: protocol.SourceLocal, AllowHosts: []string{"93.184.216.34"}}, wantErr: "--allow-host"},
		{name: "allow-host has an empty label", in: proxy.Input{Kind: protocol.KindScan, Source: protocol.SourceLocal, AllowHosts: []string{"a..example.com"}}, wantErr: "--allow-host"},
		{name: "allow-host starts with a dash", in: proxy.Input{Kind: protocol.KindScan, Source: protocol.SourceLocal, AllowHosts: []string{"-a.example.com"}}, wantErr: "--allow-host"},
		{name: "allow-host label ends with a dash", in: proxy.Input{Kind: protocol.KindScan, Source: protocol.SourceLocal, AllowHosts: []string{"a-.example.com"}}, wantErr: "--allow-host"},
		{name: "allow-host ends with a dot", in: proxy.Input{Kind: protocol.KindScan, Source: protocol.SourceLocal, AllowHosts: []string{"example.com."}}, wantErr: "--allow-host"},
		{name: "allow-host label over 63 bytes", in: proxy.Input{Kind: protocol.KindScan, Source: protocol.SourceLocal, AllowHosts: []string{strings.Repeat("a", 64) + ".com"}}, wantErr: "--allow-host"},
		{name: "allow-host over 253 bytes", in: proxy.Input{Kind: protocol.KindScan, Source: protocol.SourceLocal, AllowHosts: []string{strings.Repeat("a.", 127) + "com"}}, wantErr: "--allow-host"},
		{name: "allow-host has a bad character", in: proxy.Input{Kind: protocol.KindScan, Source: protocol.SourceLocal, AllowHosts: []string{"a_b.example.com"}}, wantErr: "--allow-host"},
		{name: "allow-host is a short IP form", in: proxy.Input{Kind: protocol.KindScan, Source: protocol.SourceLocal, AllowHosts: []string{"127.1"}}, wantErr: "--allow-host"},
		{name: "allow-host is empty", in: proxy.Input{Kind: protocol.KindScan, Source: protocol.SourceLocal, AllowHosts: []string{""}}, wantErr: "--allow-host"},
		{name: "url job without a target", in: proxy.Input{Kind: protocol.KindScan, Source: protocol.SourceURL}, wantErr: "target"},
		{name: "target is not http", in: proxy.Input{Kind: protocol.KindScan, Source: protocol.SourceGit, Target: "ftp://example.com/x"}, wantErr: "target"},
		{name: "target is an IPv6 literal", in: proxy.Input{Kind: protocol.KindScan, Source: protocol.SourceURL, Target: "http://[::1]/x"}, wantErr: "target host"},
		{name: "target is a decimal IP", in: proxy.Input{Kind: protocol.KindScan, Source: protocol.SourceURL, Target: "http://2130706433/x"}, wantErr: "target host"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := proxy.NewPolicy(tt.in)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("NewPolicy error = %v, want one containing %q", err, tt.wantErr)
			}
		})
	}
}
