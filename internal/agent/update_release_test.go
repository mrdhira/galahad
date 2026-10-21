//go:build !galahadtest

package agent_test

import (
	"net"
	"strings"
	"testing"

	"github.com/mrdhira/galahad/internal/agent"
	"github.com/mrdhira/galahad/internal/protocol"
)

func TestGuestUpdateNeedsTheVM(t *testing.T) {
	tests := []struct {
		name string
		// expectations
		wantErrCode string
		wantMessage string
	}{
		{name: "an update outside the VM has no signatures drive and does nothing", wantErrCode: protocol.CodeInternal, wantMessage: "needs the signatures drive of the VM"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			job := protocol.Job{ID: "20261021-153012-a1b2c3", Kind: protocol.KindUpdate, Timeouts: protocol.Timeouts{Job: 300}, Now: testJob("", 1).Now}
			proxy := fakeProxyAt(t, func(net.Conn) {})

			c, exit := startGuestWith(t, agent.Env{Setenv: func(string, string) {}}, "--proxy", "tcp:"+proxy)
			go func() {
				if writeJSON(c, protocol.FrameJob, job) == nil {
					_ = writeJSON(c, protocol.FrameEnd, endOf(nil))
				}
			}()
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
