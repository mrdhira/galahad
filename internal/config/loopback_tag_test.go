//go:build galahadtest

package config_test

import (
	"testing"

	"github.com/mrdhira/galahad/internal/config"
)

func TestProviderLoopbackURL(t *testing.T) {
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
			p := config.Provider{Name: "mock", URL: tt.url, Model: "m", TimeoutSeconds: 5}
			if err := p.Validate(); (err != nil) != tt.wantErr {
				t.Errorf("Validate() = %v, want error: %v", err, tt.wantErr)
			}
		})
	}
}
