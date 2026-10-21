package protocol_test

import (
	"strings"
	"testing"

	"github.com/mrdhira/galahad/internal/protocol"
)

func TestNetworkValidate(t *testing.T) {
	event := func(mutate func(e *protocol.NetEvent)) protocol.NetEvent {
		e := protocol.NetEvent{Host: "169.254.169.254", Port: 443, Decision: protocol.DecisionDenied, Reason: "metadata", Blocked: true, Count: 2}
		mutate(&e)
		return e
	}
	tests := []struct {
		name string
		// inputs
		network protocol.Network
		// expectations
		wantErr string // substring; empty means valid
	}{
		{name: "no events", network: protocol.Network{}},
		{name: "a blocked denial", network: protocol.Network{Events: []protocol.NetEvent{event(func(*protocol.NetEvent) {})}}},
		{name: "an allowed request", network: protocol.Network{Events: []protocol.NetEvent{
			event(func(e *protocol.NetEvent) {
				e.Host, e.Decision, e.Reason, e.Blocked = "api.osv.dev", protocol.DecisionAllowed, "", false
			}),
		}}},
		{name: "events at the limit", network: protocol.Network{Events: repeatEvent(event(func(*protocol.NetEvent) {}), protocol.MaxNetEvents)}},
		{name: "too many events", network: protocol.Network{Events: repeatEvent(event(func(*protocol.NetEvent) {}), protocol.MaxNetEvents+1)}, wantErr: "201 events, max 200"},
		{name: "host with upper case", network: protocol.Network{Events: []protocol.NetEvent{event(func(e *protocol.NetEvent) { e.Host = "Evil.test" })}}, wantErr: "events[0]: host"},
		{name: "host with a control character", network: protocol.Network{Events: []protocol.NetEvent{event(func(e *protocol.NetEvent) { e.Host = "a\x1b.test" })}}, wantErr: "events[0]: host"},
		{name: "port zero", network: protocol.Network{Events: []protocol.NetEvent{event(func(e *protocol.NetEvent) { e.Port = 0 })}}, wantErr: "port 0"},
		{name: "port too high", network: protocol.Network{Events: []protocol.NetEvent{event(func(e *protocol.NetEvent) { e.Port = 65536 })}}, wantErr: "port 65536"},
		{name: "unknown decision", network: protocol.Network{Events: []protocol.NetEvent{event(func(e *protocol.NetEvent) { e.Decision = "maybe" })}}, wantErr: `decision "maybe" not allowed`},
		{name: "reason too long", network: protocol.Network{Events: []protocol.NetEvent{event(func(e *protocol.NetEvent) { e.Reason = strings.Repeat("a", protocol.MaxReply+1) })}}, wantErr: "reason has 129 runes"},
		{name: "reason with a control character", network: protocol.Network{Events: []protocol.NetEvent{event(func(e *protocol.NetEvent) { e.Reason = "a\nb" })}}, wantErr: "reason has control"},
		{name: "count zero", network: protocol.Network{Events: []protocol.NetEvent{event(func(e *protocol.NetEvent) { e.Count = 0 })}}, wantErr: "count 0"},
		{name: "an allowed request cannot be blocked", network: protocol.Network{Events: []protocol.NetEvent{event(func(e *protocol.NetEvent) { e.Decision = protocol.DecisionAllowed })}}, wantErr: "cannot be blocked"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.network.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Validate() = %v, want error containing %q", err, tt.wantErr)
			}
		})
	}
}

func repeatEvent(e protocol.NetEvent, n int) []protocol.NetEvent {
	out := make([]protocol.NetEvent, n)
	for i := range out {
		out[i] = e
	}
	return out
}
