//go:build galahadtest

package job_test

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mrdhira/galahad/internal/job"
	"github.com/mrdhira/galahad/internal/protocol"
)

// A block for api.osv.dev comes from the DNS of the computer that runs Galahad, not from the input, so it
// must not make a benign scan suspicious.
func TestRunInfraHostBlocked(t *testing.T) {
	osvBlocked := func(reason string) protocol.NetEvent {
		return protocol.NetEvent{Host: "api.osv.dev", Port: 443, Decision: protocol.DecisionDenied, Reason: reason, Blocked: true, Count: 1}
	}
	tests := []struct {
		name string
		// inputs
		resolve    string   // GALAHAD_TEST_RESOLVE
		allowHosts []string // --allow-host
		requests   []string // hosts the guest asks for on port 443, in order
		// expectations
		wantEvents   []protocol.NetEvent
		wantEvidence []string // snippets of GAL-NET-001; empty means no such finding
		wantVerdict  protocol.Verdict
		wantBlocked  bool   // job.json says blocked
		wantReason   string // substring of a reason; empty means no reason about OSV
	}{
		{
			name:    "OSV that resolves to a fake-IP address is blocked without a finding and the report says why",
			resolve: "api.osv.dev=198.18.0.5", requests: []string{"api.osv.dev"},
			wantEvents: []protocol.NetEvent{osvBlocked("benchmarking")}, wantVerdict: protocol.VerdictClean,
			wantReason: "the OSV lookup was blocked: api.osv.dev resolved to an address that is not public (benchmarking)",
		},
		{
			name:    "OSV that a Pi-hole answers with 0.0.0.0 is blocked without a finding",
			resolve: "api.osv.dev=0.0.0.0", requests: []string{"api.osv.dev"},
			wantEvents: []protocol.NetEvent{osvBlocked("this network")}, wantVerdict: protocol.VerdictClean,
			wantReason: "(this network)",
		},
		{
			name:    "OSV that split-horizon DNS resolves to a private address is blocked without a finding",
			resolve: "api.osv.dev=10.1.2.3", requests: []string{"api.osv.dev"},
			wantEvents: []protocol.NetEvent{osvBlocked("private")}, wantVerdict: protocol.VerdictClean,
			wantReason: "(private)",
		},
		{
			name:     "a request the input caused still gives GAL-NET-001",
			resolve:  "files.example.com=198.18.0.5",
			requests: []string{"files.example.com"}, allowHosts: []string{"files.example.com"},
			wantEvents: []protocol.NetEvent{
				{Host: "files.example.com", Port: 443, Decision: protocol.DecisionDenied, Reason: "benchmarking", Blocked: true, Count: 1},
			},
			wantEvidence: []string{"CONNECT files.example.com:443 denied: benchmarking"}, wantVerdict: protocol.VerdictSuspicious, wantBlocked: true,
		},
		{
			name:     "a subdomain of the OSV host is not exempt",
			resolve:  "evil.api.osv.dev=198.18.0.5",
			requests: []string{"evil.api.osv.dev"}, allowHosts: []string{"evil.api.osv.dev"},
			wantEvents: []protocol.NetEvent{
				{Host: "evil.api.osv.dev", Port: 443, Decision: protocol.DecisionDenied, Reason: "benchmarking", Blocked: true, Count: 1},
			},
			wantEvidence: []string{"CONNECT evil.api.osv.dev:443 denied: benchmarking"}, wantVerdict: protocol.VerdictSuspicious, wantBlocked: true,
		},
		{
			name:     "an address literal is not exempt",
			requests: []string{"198.18.0.5"},
			wantEvents: []protocol.NetEvent{
				{Host: "198.18.0.5", Port: 443, Decision: protocol.DecisionDenied, Reason: "benchmarking", Blocked: true, Count: 1},
			},
			wantEvidence: []string{"CONNECT 198.18.0.5:443 denied: benchmarking"}, wantVerdict: protocol.VerdictSuspicious, wantBlocked: true,
		},
		{
			name:     "a blocked request of the input next to a blocked OSV lookup gives a finding for the input only",
			resolve:  "api.osv.dev=198.18.0.5",
			requests: []string{"api.osv.dev", "169.254.169.254"},
			wantEvents: []protocol.NetEvent{
				osvBlocked("benchmarking"),
				{Host: "169.254.169.254", Port: 443, Decision: protocol.DecisionDenied, Reason: "metadata", Blocked: true, Count: 1},
			},
			wantEvidence: []string{"CONNECT 169.254.169.254:443 denied: metadata"}, wantVerdict: protocol.VerdictSuspicious, wantBlocked: true,
			wantReason: "the OSV lookup was blocked",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given a guest that asks the proxy for hosts
			t.Setenv("GALAHAD_TEST_RESOLVE", tt.resolve)
			b := &fakeBackend{}
			b.script = serveNet(func(g *guest) {
				for _, h := range tt.requests {
					g.connectRetry(h, 443)
				}
			}, nil)
			spec := job.Spec{
				JobsDir:    t.TempDir(),
				Now:        func() time.Time { return time.Date(2026, 10, 21, 15, 30, 12, 0, time.UTC) },
				Version:    hostVersion,
				Timeout:    job.MinTimeout,
				Image:      "core",
				AllowHosts: tt.allowHosts,
			}

			// When it runs
			out, err := job.Run(context.Background(), b, spec, dirTarget(t))
			if err != nil {
				t.Fatal(err)
			}
			<-b.done

			// Then the events are reported as the proxy saw them, and only the blocks of the input are findings
			res := out.Result
			if !slices.Equal(res.Network.Events, tt.wantEvents) {
				t.Errorf("events = %+v, want %+v", res.Network.Events, tt.wantEvents)
			}
			var evidence []string
			for _, f := range res.Findings {
				if f.RuleID == "GAL-NET-001" {
					for _, e := range f.Evidence {
						evidence = append(evidence, e.Snippet)
					}
				}
			}
			if !slices.Equal(evidence, tt.wantEvidence) {
				t.Errorf("GAL-NET-001 evidence = %q, want %q", evidence, tt.wantEvidence)
			}
			if res.Verdict != tt.wantVerdict {
				t.Errorf("verdict = %s, want %s", res.Verdict, tt.wantVerdict)
			}
			if out.Job.Blocked != tt.wantBlocked {
				t.Errorf("job blocked = %v, want %v", out.Job.Blocked, tt.wantBlocked)
			}
			hasReason := slices.ContainsFunc(res.Reasons, func(r string) bool { return strings.Contains(r, "the OSV lookup was blocked") })
			if hasReason != (tt.wantReason != "") || (tt.wantReason != "" && !slices.ContainsFunc(res.Reasons, func(r string) bool { return strings.Contains(r, tt.wantReason) })) {
				t.Errorf("reasons = %q, want one containing %q", res.Reasons, tt.wantReason)
			}
		})
	}
}
