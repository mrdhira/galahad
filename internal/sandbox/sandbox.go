// Package sandbox is the interface between a job and the machine that runs the guest agent.
package sandbox

import (
	"context"
	"errors"
	"net"
)

// ErrUnsupported means no sandbox backend is available on this system.
var ErrUnsupported = errors.New("sandbox not supported")

// Spec describes the machine to start.
type Spec struct {
	JobDir             string
	Image              string // core | re
	CPUs               int
	MemoryMiB          int
	ScratchMiB         int64
	AgentPath          string
	Signatures         string // "" = none
	SignaturesWritable bool   // update job only
	Ports              []uint32
}

// Backend starts machines.
type Backend interface {
	Name() string
	// Start boots a machine. The listeners for s.Ports exist before it boots.
	Start(ctx context.Context, s Spec) (Machine, error)
}

// Machine is a running guest.
type Machine interface {
	// Listener returns the guest-to-host connections on a port.
	Listener(port uint32) net.Listener
	// Wait returns when the machine exits.
	Wait() error
	// Kill is idempotent: it kills the machine, then removes its transient files.
	Kill() error
}
