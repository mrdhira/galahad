package job_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mrdhira/galahad/internal/job"
	"github.com/mrdhira/galahad/internal/protocol"
)

// connect opens a tunnel through the proxy listener as the guest does, and returns the reply of the host.
// It reports false when the proxy closed the connection without a reply, as it does over the tunnel cap.
func (g *guest) connect(host string, port int) (protocol.ConnectReply, bool) {
	hostEnd, guestEnd := net.Pipe()
	defer func() { _ = guestEnd.Close() }() // the guest hangs up after the reply, so the proxy does not drain
	g.b.proxyL.conns <- hostEnd
	data, err := json.Marshal(protocol.Connect{Host: host, Port: port})
	if err != nil {
		panic(err)
	}
	var reply protocol.ConnectReply
	if err := protocol.WriteFrame(guestEnd, protocol.FrameConnect, data); err != nil {
		return reply, false
	}
	t, payload, err := protocol.ReadFrame(guestEnd)
	if err != nil || t != protocol.FrameConnectReply || protocol.DecodeStrict(payload, &reply) != nil {
		return reply, false
	}
	return reply, true
}

// connectRetry is connect, tried again while the proxy is over its tunnel cap.
func (g *guest) connectRetry(host string, port int) protocol.ConnectReply {
	for range 5000 {
		if reply, ok := g.connect(host, port); ok {
			return reply
		}
		time.Sleep(time.Millisecond)
	}
	runtime.Goexit()
	return protocol.ConnectReply{}
}

// serveNet is a well-behaved guest that makes the requests in requests before it sends the result that edit changes.
func serveNet(requests func(g *guest), edit func(res *protocol.Result)) func(g *guest) {
	return func(g *guest) {
		g.dial()
		g.hello(hostVersion)
		g.readJob()
		g.readInput()
		if requests != nil {
			requests(g)
		}
		res := g.result(hostVersion)
		if edit != nil {
			edit(&res)
		}
		g.send(protocol.FrameResult, res)
	}
}

func TestRunNetwork(t *testing.T) {
	metadata := protocol.NetEvent{Host: "169.254.169.254", Port: 443, Decision: protocol.DecisionDenied, Reason: "metadata", Blocked: true, Count: 1}
	metadataSnippet := "CONNECT 169.254.169.254:443 denied: metadata"
	tests := []struct {
		name string
		// inputs
		noNetwork       bool
		noProxyListener bool
		script          func(g *guest) // instead of a guest that follows the protocol
		requests        func(g *guest)
		edit            func(res *protocol.Result)
		// expectations
		wantErr      string // substring; empty means success
		wantPorts    []uint32
		wantEvents   []protocol.NetEvent // nil means the section is not checked
		wantEvidence []string            // snippets of GAL-NET-001; empty means no such finding
		wantVerdict  protocol.Verdict
		wantLog      bool     // proxy.log exists
		wantLogLines []string // substrings, each in some line
		wantMaxLines int      // proxy.log has at most this many lines, when not zero
		wantFindings int      // the number of findings, when not zero
	}{
		{
			name:      "a blocked request is reported and becomes GAL-NET-001",
			requests:  func(g *guest) { g.connectRetry("169.254.169.254", 443) },
			wantPorts: []uint32{1024, 1025}, wantEvents: []protocol.NetEvent{metadata},
			wantEvidence: []string{metadataSnippet}, wantVerdict: protocol.VerdictSuspicious,
			wantLog: true, wantLogLines: []string{`"host":"169.254.169.254"`, `"reason":"metadata"`, `"decision":"denied"`},
		},
		{
			name: "a blocked request is still reported after other requests filled the log and the events",
			requests: func(g *guest) {
				for i := range 10100 {
					g.connectRetry(fmt.Sprintf("h%d.example.com", i), 443)
				}
				g.connectRetry("169.254.169.254", 443)
			},
			wantPorts: []uint32{1024, 1025}, wantEvidence: []string{metadataSnippet}, wantVerdict: protocol.VerdictSuspicious,
			wantLog: true, wantLogLines: []string{`"reason":"metadata"`}, wantMaxLines: 10000,
		},
		{
			name:      "a request that is not blocked is reported and makes no finding",
			requests:  func(g *guest) { g.connectRetry("evil.example.com", 443) },
			wantPorts: []uint32{1024, 1025},
			wantEvents: []protocol.NetEvent{
				{Host: "evil.example.com", Port: 443, Decision: protocol.DecisionDenied, Reason: "host not allowed", Count: 1},
			},
			wantVerdict: protocol.VerdictClean, wantLog: true, wantLogLines: []string{`"host":"evil.example.com"`},
		},
		{
			name:      "no requests leave an empty network section",
			wantPorts: []uint32{1024, 1025}, wantEvents: []protocol.NetEvent{}, wantVerdict: protocol.VerdictClean, wantLog: true,
		},
		{
			name: "the finding has at most eight evidence entries",
			requests: func(g *guest) {
				for i := range 10 {
					g.connectRetry(fmt.Sprintf("10.0.0.%d", i), 443)
				}
			},
			wantPorts: []uint32{1024, 1025}, wantVerdict: protocol.VerdictSuspicious, wantLog: true,
			wantEvidence: []string{
				"CONNECT 10.0.0.0:443 denied: private", "CONNECT 10.0.0.1:443 denied: private", "CONNECT 10.0.0.2:443 denied: private", "CONNECT 10.0.0.3:443 denied: private",
				"CONNECT 10.0.0.4:443 denied: private", "CONNECT 10.0.0.5:443 denied: private", "CONNECT 10.0.0.6:443 denied: private", "CONNECT 10.0.0.7:443 denied: private",
			},
		},
		{
			name:     "the finding takes the place of the last one when the guest sent the most findings",
			requests: func(g *guest) { g.connectRetry("169.254.169.254", 443) },
			edit: func(res *protocol.Result) {
				for i := range protocol.MaxFindings {
					f := protocol.Rule{ID: "GAL-X-001", Severity: protocol.SeverityLow, Title: "x"}.Finding(protocol.Evidence{Path: fmt.Sprintf("f%d", i)})
					f.Analyzer = "x"
					res.Findings = append(res.Findings, f)
				}
			},
			wantPorts: []uint32{1024, 1025}, wantEvidence: []string{metadataSnippet}, wantVerdict: protocol.VerdictSuspicious,
			wantLog: true, wantFindings: protocol.MaxFindings,
		},
		{
			name:      "no network serves no proxy port",
			noNetwork: true,
			wantPorts: []uint32{1024}, wantEvents: []protocol.NetEvent{}, wantVerdict: protocol.VerdictClean,
		},
		{
			name:      "the result has network data of the guest",
			edit:      func(res *protocol.Result) { res.Network = &protocol.Network{Events: []protocol.NetEvent{}} },
			wantErr:   "the result has network data",
			wantLog:   true,
			wantPorts: []uint32{1024, 1025},
		},
		{
			name:            "the sandbox has no proxy listener",
			noProxyListener: true, script: func(*guest) {},
			wantErr:   "the sandbox has no proxy listener",
			wantPorts: []uint32{1024, 1025},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given a guest that makes requests through the proxy port
			jobs := t.TempDir()
			b := &fakeBackend{script: serveNet(tt.requests, tt.edit), noProxyListener: tt.noProxyListener}
			if tt.script != nil {
				b.script = tt.script
			}
			spec := job.Spec{
				JobsDir:   jobs,
				Now:       func() time.Time { return time.Date(2026, 10, 21, 15, 30, 12, 0, time.UTC) },
				Version:   hostVersion,
				Timeout:   job.MinTimeout,
				Image:     "core",
				NoNetwork: tt.noNetwork,
			}

			// When it runs
			out, err := job.Run(context.Background(), b, spec, dirTarget(t))
			if b.done != nil {
				<-b.done
			}

			// Then the ports, the error, the log and the Result are as expected
			if !slices.Equal(b.ports, tt.wantPorts) {
				t.Errorf("ports = %v, want %v", b.ports, tt.wantPorts)
			}
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("Run error = %v, want one containing %q", err, tt.wantErr)
				}
			} else if err != nil {
				t.Fatalf("Run: %v", err)
			}
			logPath := filepath.Join(jobs, out.Job.ID, "proxy.log")
			logData, statErr := os.ReadFile(logPath)
			if (statErr == nil) != tt.wantLog && !tt.noProxyListener {
				t.Errorf("proxy.log exists = %v, want %v", statErr == nil, tt.wantLog)
			}
			lines := strings.Split(strings.TrimSpace(string(logData)), "\n")
			for _, want := range tt.wantLogLines {
				if !slices.ContainsFunc(lines, func(l string) bool { return strings.Contains(l, want) }) {
					t.Errorf("proxy.log has no line with %s", want)
				}
			}
			if tt.wantMaxLines > 0 && len(lines) > tt.wantMaxLines {
				t.Errorf("proxy.log has %d lines, want at most %d", len(lines), tt.wantMaxLines)
			}
			if tt.wantErr != "" {
				return
			}
			res := out.Result
			if res.Network == nil {
				t.Fatal("Result.Network is nil")
			}
			if tt.wantEvents != nil && !slices.Equal(res.Network.Events, tt.wantEvents) {
				t.Errorf("Network.Events = %+v, want %+v", res.Network.Events, tt.wantEvents)
			}
			if res.Network.Events == nil {
				t.Error("Network.Events is nil, want an empty list")
			}
			if res.Verdict != tt.wantVerdict {
				t.Errorf("verdict = %s, want %s", res.Verdict, tt.wantVerdict)
			}
			if tt.wantFindings > 0 && len(res.Findings) != tt.wantFindings {
				t.Errorf("%d findings, want %d", len(res.Findings), tt.wantFindings)
			}
			var evidence []string
			for _, f := range res.Findings {
				if f.RuleID != "GAL-NET-001" {
					continue
				}
				if f.Severity != protocol.SeverityHigh {
					t.Errorf("GAL-NET-001 severity = %s, want high", f.Severity)
				}
				for _, e := range f.Evidence {
					if e.Path != "(network)" {
						t.Errorf("evidence path = %q, want (network)", e.Path)
					}
					evidence = append(evidence, e.Snippet)
				}
			}
			if !slices.Equal(evidence, tt.wantEvidence) {
				t.Errorf("GAL-NET-001 evidence = %q, want %q", evidence, tt.wantEvidence)
			}
			if err := res.Validate(); err != nil {
				t.Errorf("Result does not validate: %v", err)
			}
		})
	}
}
