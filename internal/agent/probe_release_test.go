//go:build !galahadtest

package agent_test

import (
	"strings"
	"testing"

	"github.com/mrdhira/galahad/internal/agent"
	"github.com/mrdhira/galahad/internal/protocol"
)

func TestGuestProbeIsNotInRelease(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		probe string
		// expectations
		wantErrCode string
		wantMessage string
	}{
		{name: "a probe job is refused", probe: "proxy", wantErrCode: protocol.CodeProtocol, wantMessage: "not supported"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			job := testJob(tt.probe, 300)
			job.Kind, job.Source = protocol.KindProbe, ""

			c, exit := startGuest(t)
			go func() { _ = writeJSON(c, protocol.FrameJob, job) }()
			got := readGuest(t, c)

			if ex := <-exit; ex.code != agent.ExitError {
				t.Errorf("exit = %d, want %d; stderr %q", ex.code, agent.ExitError, ex.stderr)
			}
			if got.errMsg == nil || got.errMsg.Code != tt.wantErrCode || !strings.Contains(got.errMsg.Message, tt.wantMessage) {
				t.Errorf("error frame = %+v, want code %q and a message with %q", got.errMsg, tt.wantErrCode, tt.wantMessage)
			}
		})
	}
}
