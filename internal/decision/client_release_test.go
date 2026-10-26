//go:build !galahadtest

package decision_test

import (
	"context"
	"testing"

	"github.com/mrdhira/galahad/internal/config"
	"github.com/mrdhira/galahad/internal/decision"
	"github.com/mrdhira/galahad/internal/protocol"
)

func TestSendRefusesLoopbackInRelease(t *testing.T) {
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
			p := config.Provider{Name: "mock", URL: tt.url, Model: "test/model-1", TimeoutSeconds: 5}
			reply := decision.Send(context.Background(), p, "", "v1", validRequest())
			if reply.Error == nil || reply.Error.Code != protocol.DecisionErrInvalid {
				t.Errorf("reply = %+v, want invalid", reply)
			}
		})
	}
}
