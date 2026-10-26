//go:build !galahadtest

package config_test

import (
	"testing"

	"github.com/mrdhira/galahad/internal/config"
)

func TestProviderRefusesLoopbackInRelease(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		url string
	}{
		{name: "IPv4 loopback with a port", url: "http://127.0.0.1:8080"},
		{name: "IPv6 loopback with a port", url: "http://[::1]:8080"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := config.Provider{Name: "mock", URL: tt.url, Model: "m", TimeoutSeconds: 5}
			if err := p.Validate(); err == nil {
				t.Error("Validate() = nil, want an error for plain http")
			}
		})
	}
}
