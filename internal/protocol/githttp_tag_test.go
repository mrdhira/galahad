//go:build galahadtest

package protocol_test

import (
	"testing"

	"github.com/mrdhira/galahad/internal/protocol"
)

func TestGitHTTPHost(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		host string
		// expectations
		want bool
	}{
		{name: "a .test host", host: "git.test", want: true},
		{name: "a .test host in capitals", host: "Git.TEST", want: true},
		{name: "another host", host: "github.com", want: false},
		{name: "a host that only contains test", host: "test.example.com", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := protocol.GitHTTPHost(tt.host); got != tt.want {
				t.Errorf("GitHTTPHost(%q) = %v, want %v", tt.host, got, tt.want)
			}
		})
	}
}
