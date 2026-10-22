//go:build galahadtest

package agent_test

import (
	"encoding/json"
	"net"
	"strings"
	"testing"

	"github.com/mrdhira/galahad/internal/agent"
	"github.com/mrdhira/galahad/internal/protocol"
)

func TestGuestProbe(t *testing.T) {
	type observation struct {
		Form   string `json:"form"`
		Status int    `json:"status"`
		Body   string `json:"body"`
	}
	type report struct {
		Probe        string                 `json:"probe"`
		Observations map[string]observation `json:"observations"`
	}
	denied := observation{Form: "connect", Status: 403, Body: "denied: private"}
	tests := []struct {
		name string
		// inputs
		probe   string
		noProxy bool // no --proxy
		noInput bool // the host sends the Job and nothing more
		// expectations
		wantErrCode string // an Error frame instead of a Result
		wantMessage string
		wantReport  *report
	}{
		{
			name:  "the proxy probe asks for four tunnels and the host proxy denies each",
			probe: "proxy",
			wantReport: &report{Probe: "proxy", Observations: map[string]observation{
				"169.254.169.254:443": denied, "10.1.2.3:443": denied, "localhost:443": denied, "rebind.test:443": denied,
			}},
		},
		{
			name:  "a result probe that acts before the input sends its Result without reading it",
			probe: "result-early", noInput: true,
		},
		{
			name:  "an unknown probe fails the job",
			probe: "no-such-probe", wantErrCode: protocol.CodeProtocol, wantMessage: "unknown probe",
		},
		{
			name:  "a probe that pushes at the machine is refused on a host that is not a VM",
			probe: "fork-bomb", wantErrCode: protocol.CodeInternal, wantMessage: "only in a VM",
		},
		{
			name:  "the proxy probe without a proxy channel fails the job",
			probe: "proxy", noProxy: true, wantErrCode: protocol.CodeInternal, wantMessage: "needs the proxy",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given a probe job and a host proxy that refuses every tunnel as "private"
			var args []string
			if !tt.noProxy {
				addr := fakeProxyAt(t, func(c net.Conn) {
					readConnectFrame(c)
					writeReply(c, protocol.FrameConnectReply, `{"ok":false,"reason":"private"}`)
				})
				args = []string{"--proxy", "tcp:" + addr}
			}
			job := testJob(tt.probe, 300)
			job.Kind, job.Source = protocol.KindProbe, ""

			// When the guest runs it
			c, exit := startGuestWith(t, agent.Env{Setenv: func(string, string) {}}, args...)
			go func() {
				if writeJSON(c, protocol.FrameJob, job) == nil && !tt.noInput {
					_ = sendInput(c, nil, endOf(nil))
				}
			}()
			got := readGuest(t, c)
			ex := <-exit

			// Then the observations are the probe artifact and the job ends with a Result, or an Error
			if tt.wantErrCode != "" {
				if got.errMsg == nil || got.errMsg.Code != tt.wantErrCode || !strings.Contains(got.errMsg.Message, tt.wantMessage) || ex.code != agent.ExitError {
					t.Fatalf("error frame = %+v, exit = %d, want code %q with %q and exit %d", got.errMsg, ex.code, tt.wantErrCode, tt.wantMessage, agent.ExitError)
				}
				return
			}
			if got.result == nil || ex.code != agent.ExitClean {
				t.Fatalf("result = %v, error = %+v, exit = %d; stderr %q", got.result, got.errMsg, ex.code, ex.stderr)
			}
			if tt.wantReport == nil {
				return
			}
			var rep report
			if err := json.Unmarshal(got.probe, &rep); err != nil {
				t.Fatalf("probe.json %q: %v", got.probe, err)
			}
			if rep.Probe != tt.wantReport.Probe || len(rep.Observations) != len(tt.wantReport.Observations) {
				t.Fatalf("probe.json = %+v, want %+v", rep, *tt.wantReport)
			}
			for k, want := range tt.wantReport.Observations {
				if rep.Observations[k] != want {
					t.Errorf("observation %s = %+v, want %+v", k, rep.Observations[k], want)
				}
			}
		})
	}
}
