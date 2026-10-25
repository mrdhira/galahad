//go:build galahadtest

package proxy_test

import (
	"io"
	"strings"
	"testing"

	"github.com/mrdhira/galahad/internal/protocol"
	"github.com/mrdhira/galahad/internal/proxy"
)

func TestTestHooks(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		resolve  string // GALAHAD_TEST_RESOLVE
		sinkhole bool   // GALAHAD_TEST_SINKHOLE points at the backend
		host     string
		port     int
		// expectations
		wantOK     bool
		wantReason string
	}{
		{name: "resolved name reaches the sinkhole on port 443", resolve: "ok.test=127.0.0.1", sinkhole: true, host: "ok.test", port: 443, wantOK: true},
		{name: "a .test host may use port 80", resolve: "ok.test=127.0.0.1", sinkhole: true, host: "ok.test", port: 80, wantOK: true},
		{name: "several addresses for one name", resolve: "ok.test=127.0.0.1,ok.test=127.0.0.1", sinkhole: true, host: "ok.test", port: 443, wantOK: true},
		{name: "the block list still applies to resolved names", resolve: "rebind.test=10.0.0.1", host: "rebind.test", port: 443, wantReason: "private"},
		{name: "loopback is blocked without a sinkhole", resolve: "ok.test=127.0.0.1", host: "ok.test", port: 443, wantReason: "loopback"},
		{name: "the sinkhole is the only loopback address", resolve: "ok.test=127.0.0.2", sinkhole: true, host: "ok.test", port: 443, wantReason: "loopback"},
		{name: "the sinkhole does not hide a second address", resolve: "ok.test=127.0.0.1,ok.test=10.0.0.1", sinkhole: true, host: "ok.test", port: 443, wantReason: "private"},
		{name: "a name set to fail does not resolve", resolve: "off.test=fail", host: "off.test", port: 443, wantReason: "dns lookup failed"},
		{name: "port 80 needs a .test host", resolve: "ok.example.com=127.0.0.1", sinkhole: true, host: "ok.example.com", port: 80, wantReason: "port not allowed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("GALAHAD_TEST_RESOLVE", tt.resolve)
			t.Setenv("GALAHAD_TEST_SINKHOLE", "")
			if tt.sinkhole {
				t.Setenv("GALAHAD_TEST_SINKHOLE", newBackend(t))
			}
			pol := policy(t, proxy.Input{Kind: protocol.KindScan, Source: protocol.SourceLocal, AllowHosts: []string{tt.host}})
			addr, _, _ := start(t, pol, nil)
			c, reply, err := open(t, addr, tt.host, tt.port)
			if err != nil {
				t.Fatalf("reading the reply: %v", err)
			}
			if reply.OK != tt.wantOK || reply.Reason != tt.wantReason {
				t.Fatalf("reply = %+v, want ok=%v reason=%q", reply, tt.wantOK, tt.wantReason)
			}
			if tt.wantOK {
				if _, err := io.WriteString(c, "GET / HTTP/1.0\r\n\r\n"); err != nil {
					t.Fatal(err)
				}
				body, _ := io.ReadAll(c)
				if !strings.Contains(string(body), "hello from backend") {
					t.Errorf("relayed response = %q", body)
				}
			}
		})
	}
}
