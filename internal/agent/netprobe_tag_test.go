//go:build galahadtest

package agent_test

import (
	"archive/tar"
	"encoding/json"
	"net"
	"testing"

	"github.com/mrdhira/galahad/internal/agent"
	"github.com/mrdhira/galahad/internal/protocol"
)

func TestGuestNetProbe(t *testing.T) {
	type result struct {
		Form   string `json:"form"`
		Status int    `json:"status"`
		Body   string `json:"body"`
		Error  string `json:"error"`
	}
	tests := []struct {
		name string
		// inputs
		url     string
		refuse  bool // the host proxy refuses every tunnel with "private"
		noProxy bool // no --proxy
		// expectations
		wantErrCode string // an Error frame instead of a Result
		wantResults []result
	}{
		{
			name: "both request forms reach the allowed backend",
			url:  "http://allowed.example.com/hello",
			wantResults: []result{
				{Form: "absolute", Status: 200, Body: "hello from backend"},
				{Form: "connect", Status: 200, Body: "hello from backend"},
			},
		},
		{
			name: "both request forms are refused",
			url:  "http://rebind.test/", refuse: true,
			wantResults: []result{
				{Form: "absolute", Status: 403, Body: "denied: private"},
				{Form: "connect", Status: 403, Body: "denied: private"},
			},
		},
		{
			name: "a URL that is not http fails the job",
			url:  "ftp://allowed.example.com/", wantErrCode: protocol.CodeInternal,
		},
		{
			name: "without a proxy channel the job fails",
			url:  "http://allowed.example.com/", noProxy: true, wantErrCode: protocol.CodeInternal,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given a net-probe job and a host proxy
			backend, _ := newBackend(t)
			var args []string
			if !tt.noProxy {
				dialAddr := ""
				if tt.refuse {
					dialAddr = fakeProxyAt(t, func(c net.Conn) {
						readConnectFrame(c)
						writeReply(c, protocol.FrameConnectReply, `{"ok":false,"reason":"private"}`)
					})
				} else {
					dialAddr = hostProxyAt(t, backend)
				}
				args = []string{"--proxy", "tcp:" + dialAddr}
			}
			job := testJob("proj", 300)
			job.Kind, job.Source, job.URL = protocol.KindNetProbe, "", tt.url
			data := buildTar(t, tarEntry{name: "proj/", typ: tar.TypeDir}, tarEntry{name: "proj/a.txt", body: "a\n"})

			// When the guest runs it
			c, exit := startGuestWith(t, agent.Env{Setenv: func(string, string) {}}, args...)
			go func() {
				if writeJSON(c, protocol.FrameJob, job) == nil {
					_ = sendInput(c, data, endOf(data))
				}
			}()
			got := readGuest(t, c)
			ex := <-exit

			// Then the artifact has one result per form, and the job goes on to a Result
			if tt.wantErrCode != "" {
				if got.errMsg == nil || got.errMsg.Code != tt.wantErrCode || ex.code != agent.ExitError {
					t.Fatalf("error frame = %+v, exit = %d, want code %q and exit %d", got.errMsg, ex.code, tt.wantErrCode, agent.ExitError)
				}
				return
			}
			if got.result == nil || ex.code != agent.ExitClean {
				t.Fatalf("result = %v, error = %+v, exit = %d; stderr %q", got.result, got.errMsg, ex.code, ex.stderr)
			}
			var results []result
			if err := json.Unmarshal(got.probe, &results); err != nil {
				t.Fatalf("probe.json %q: %v", got.probe, err)
			}
			if len(results) != len(tt.wantResults) {
				t.Fatalf("results = %+v, want %+v", results, tt.wantResults)
			}
			for i, want := range tt.wantResults {
				if results[i] != want {
					t.Errorf("result %d = %+v, want %+v", i, results[i], want)
				}
			}
		})
	}
}
