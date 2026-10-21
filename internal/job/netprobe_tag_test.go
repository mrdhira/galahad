//go:build galahadtest

package job_test

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/mrdhira/galahad/internal/job"
	"github.com/mrdhira/galahad/internal/protocol"
)

func TestRunNetProbe(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		url     string // GALAHAD_TEST_NET_PROBE
		resolve string // GALAHAD_TEST_RESOLVE
		request string // host the guest asks for, on port 80
		// expectations
		wantKind   string
		wantURL    string
		wantReply  protocol.ConnectReply
		wantEvents []protocol.NetEvent
	}{
		{
			name: "the job asks for the URL and the proxy allows its host on port 80",
			url:  "http://rebind.test/", resolve: "rebind.test=10.0.0.1", request: "rebind.test",
			wantKind: protocol.KindNetProbe, wantURL: "http://rebind.test/",
			wantReply: protocol.ConnectReply{Reason: "private"},
			wantEvents: []protocol.NetEvent{
				{Host: "rebind.test", Port: 80, Decision: protocol.DecisionDenied, Reason: "private", Blocked: true, Count: 1},
			},
		},
		{
			name: "another host is not allowed",
			url:  "http://rebind.test/", resolve: "rebind.test=10.0.0.1", request: "other.test",
			wantKind: protocol.KindNetProbe, wantURL: "http://rebind.test/",
			wantReply: protocol.ConnectReply{Reason: "host not allowed"},
			wantEvents: []protocol.NetEvent{
				{Host: "other.test", Port: 80, Decision: protocol.DecisionDenied, Reason: "host not allowed", Count: 1},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given a net-probe job and a guest that makes one request
			t.Setenv("GALAHAD_TEST_NET_PROBE", tt.url)
			t.Setenv("GALAHAD_TEST_RESOLVE", tt.resolve)
			var reply protocol.ConnectReply
			var jobSeen protocol.Job
			b := &fakeBackend{}
			b.script = serveNet(func(g *guest) {
				jobSeen = g.job
				reply = g.connectRetry(tt.request, 80)
			}, nil)
			spec := job.Spec{
				JobsDir: t.TempDir(),
				Now:     func() time.Time { return time.Date(2026, 10, 21, 15, 30, 12, 0, time.UTC) },
				Version: hostVersion,
				Timeout: job.MinTimeout,
				Image:   "core",
			}

			// When it runs
			out, err := job.Run(context.Background(), b, spec, dirTarget(t))
			if err != nil {
				t.Fatal(err)
			}
			<-b.done

			// Then the guest got a net-probe job and the proxy's answer, and the Result has the events
			if jobSeen.Kind != tt.wantKind || jobSeen.URL != tt.wantURL || jobSeen.Source != "" {
				t.Errorf("job = %+v, want kind %s, url %s, no source", jobSeen, tt.wantKind, tt.wantURL)
			}
			if reply != tt.wantReply {
				t.Errorf("reply = %+v, want %+v", reply, tt.wantReply)
			}
			if !slices.Equal(out.Result.Network.Events, tt.wantEvents) {
				t.Errorf("events = %+v, want %+v", out.Result.Network.Events, tt.wantEvents)
			}
		})
	}
}
