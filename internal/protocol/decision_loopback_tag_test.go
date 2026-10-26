//go:build galahadtest

package protocol_test

import (
	"testing"

	"github.com/mrdhira/galahad/internal/protocol"
)

func TestDecisionLoopback(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		host string
		// expectations
		want bool
	}{
		{name: "the IPv4 loopback address", host: "127.0.0.1", want: true},
		{name: "the IPv6 loopback address", host: "::1", want: true},
		{name: "localhost by name", host: "localhost", want: false},
		{name: "another address", host: "10.0.0.1", want: false},
		{name: "another host", host: "api.example.com", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := protocol.DecisionLoopback(tt.host); got != tt.want {
				t.Errorf("DecisionLoopback(%q) = %v, want %v", tt.host, got, tt.want)
			}
		})
	}
}

func TestDecisionValidateLoopbackURL(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		url string
		// expectations
		wantErr bool
	}{
		{name: "IPv4 loopback with a port", url: "http://127.0.0.1:8080"},
		{name: "IPv6 loopback with a port", url: "http://[::1]:8080"},
		{name: "loopback without a port", url: "http://127.0.0.1", wantErr: true},
		{name: "plain http to another address", url: "http://10.0.0.1:8080", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := skippedDecision()
			d.URL = tt.url
			if err := d.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("Validate() = %v, want error: %v", err, tt.wantErr)
			}
		})
	}
}
