package protocol

import (
	"fmt"
	"unicode/utf8"
)

// Proxy decisions, as in NetEvent.Decision and the proxy log.
const (
	DecisionAllowed = "allowed"
	DecisionDenied  = "denied"
)

// MaxNetEvents is the most entries of Network.Events.
const MaxNetEvents = 200

// NetEvent is the aggregate of the proxy's decisions for one host, port and decision. Reason is
// the reason of the first one. Blocked is set when the host was, or resolved to, an address that
// is not public.
type NetEvent struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Decision string `json:"decision"`
	Reason   string `json:"reason"`
	Blocked  bool   `json:"blocked"`
	Count    int    `json:"count"`
}

// Validate checks the host name format, the port range, the decision enum, the reason text, the
// count, and that only a denial is blocked.
func (e NetEvent) Validate() error {
	if !hostRe.MatchString(e.Host) {
		return fmt.Errorf("host %q does not match %s", e.Host, hostRe)
	}
	if e.Port < 1 || e.Port > 65535 {
		return fmt.Errorf("port %d out of range 1-65535", e.Port)
	}
	if err := oneOf("decision", e.Decision, DecisionAllowed, DecisionDenied); err != nil {
		return err
	}
	if n := utf8.RuneCountInString(e.Reason); n > MaxReply {
		return fmt.Errorf("reason has %d runes, max %d", n, MaxReply)
	}
	if err := checkText("reason", e.Reason); err != nil {
		return err
	}
	if e.Count < 1 {
		return fmt.Errorf("count %d, want at least 1", e.Count)
	}
	if e.Blocked && e.Decision != DecisionDenied {
		return fmt.Errorf("a %s request cannot be blocked", e.Decision)
	}
	return nil
}

// Network is what the guest asked the host proxy for. Only the host writes it: the host takes it
// from its own proxy and rejects a Result from the guest that has it.
type Network struct {
	Events []NetEvent `json:"events"`
}

// Validate checks the number of events and each event.
func (n Network) Validate() error {
	if len(n.Events) > MaxNetEvents {
		return fmt.Errorf("%d events, max %d", len(n.Events), MaxNetEvents)
	}
	for i, e := range n.Events {
		if err := e.Validate(); err != nil {
			return fmt.Errorf("events[%d]: %w", i, err)
		}
	}
	return nil
}
