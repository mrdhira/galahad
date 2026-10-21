// Package job manages the job directory of one galahad scan: its ID, its job.json
// and the list of past jobs.
package job

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"regexp"
	"sync"
	"time"
)

// State is the lifecycle state of a job.
type State string

// The states of job.json. StateUnreadable is never written: List reports it for a
// job directory whose job.json cannot be read.
const (
	StateCreated    State = "created"
	StateBooting    State = "booting"
	StateRunning    State = "running"
	StateDone       State = "done"
	StateFailed     State = "failed"
	StateTimeout    State = "timeout"
	StateCanceled   State = "canceled"
	StateUnreadable State = "unreadable"
)

func (s State) valid() bool {
	switch s {
	case StateCreated, StateBooting, StateRunning, StateDone, StateFailed, StateTimeout, StateCanceled:
		return true
	}
	return false
}

// Target is what a job scans.
type Target struct {
	Input string `json:"input"` // the cleaned target as the user gave it
	Kind  string `json:"kind"`
}

// Job is the content of job.json.
type Job struct {
	ID         string     `json:"id"`
	CreatedAt  time.Time  `json:"created_at"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
	Target     Target     `json:"target"`
	Image      string     `json:"image"`
	Backend    string     `json:"backend"`
	State      State      `json:"state"`
	ExitCode   int        `json:"exit_code"`
	Verdict    string     `json:"verdict,omitempty"`
	Score      int        `json:"score"`
	Error      string     `json:"error,omitempty"`
	Blocked    bool       `json:"blocked"`
}

// idPattern is the format of a job ID: UTC time, then 3 random bytes in hex.
var idPattern = regexp.MustCompile(`^[0-9]{8}-[0-9]{6}-[0-9a-f]{6}$`)

// ValidID reports whether id has the format NewID produces.
func ValidID(id string) bool { return idPattern.MatchString(id) }

var (
	idMu   sync.Mutex
	idUsed = map[string]struct{}{}
)

// NewID returns a job ID of the form YYYYMMDD-HHMMSS-<6 hex>. IDs sort by time, and the
// process never returns the same ID twice.
func NewID(now time.Time) (string, error) {
	idMu.Lock()
	defer idMu.Unlock()
	prefix := now.UTC().Format("20060102-150405")
	for {
		var b [3]byte
		if _, err := rand.Read(b[:]); err != nil {
			return "", fmt.Errorf("new job id: %w", err)
		}
		id := prefix + "-" + hex.EncodeToString(b[:])
		if _, dup := idUsed[id]; !dup {
			idUsed[id] = struct{}{}
			return id, nil
		}
	}
}
