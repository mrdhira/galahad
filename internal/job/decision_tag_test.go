//go:build galahadtest

package job_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mrdhira/galahad/internal/config"
	"github.com/mrdhira/galahad/internal/decision"
	"github.com/mrdhira/galahad/internal/job"
	"github.com/mrdhira/galahad/internal/protocol"
)

const decisionModel = "fake-model/v1"

func lowFinding() protocol.Finding {
	return protocol.Rule{ID: "GAL-AUTOEXEC-006", Severity: protocol.SeverityLow, Title: "Runs a hook", Attack: "T1204"}.
		Finding(protocol.Evidence{Path: "main.go", Line: 1, Snippet: "x"})
}

// mockDecision is a valid Decision of the provider "mock" for res, with the status and the answer asked for.
func mockDecision(t *testing.T, res protocol.Result, status string, pMalicious float64) protocol.Decision {
	t.Helper()
	d := protocol.Decision{Provider: "mock", URL: "https://api.mock.test", Model: decisionModel, Status: status}
	if status == protocol.DecisionSkipped {
		d.Reason = protocol.DecisionSkipNoFindings
		return d
	}
	req, ok, err := decision.Select(res, decisionModel)
	if err != nil || !ok {
		t.Fatalf("Select = %v, %v", ok, err)
	}
	d.Sent, d.LatencyMS, d.Attempts = &req, 12, 1
	if status == protocol.DecisionFailed {
		d.Error = &protocol.DecisionError{Code: protocol.DecisionErrNetwork, Message: "could not reach the provider"}
		return d
	}
	score := 1.5
	d.Answers = &protocol.DecisionAnswers{Model: decisionModel, Questions: map[string]protocol.DecisionAnswer{
		protocol.QuestionVerdict: {Type: protocol.QuestionChoice, LabelMass: 0.5, Choice: protocol.LabelMalicious,
			Probabilities: map[string]float64{"clean": 1 - pMalicious, "suspicious": 0, "malicious": pMalicious}},
		protocol.QuestionRisk: {Type: protocol.QuestionScore, LabelMass: 0.5, Score: &score,
			Probabilities: map[string]float64{"0": 0.25, "1": 0.25, "2": 0.25, "3": 0.25}},
		protocol.QuestionStealsSecrets: {Type: protocol.QuestionYesNo, LabelMass: 0.5, Probabilities: map[string]float64{"yes": 0.5, "no": 0.5}},
	}}
	d.Usage = &protocol.DecisionUsage{PromptTokens: 100, TotalTokens: 100}
	return d
}

func TestRunDecision(t *testing.T) {
	osvBlocked := serveNet(func(g *guest) { g.connectRetry("api.osv.dev", 443) }, func(res *protocol.Result) {
		res.Findings = []protocol.Finding{lowFinding()}
	})
	mock := config.Provider{Name: "mock", URL: "https://api.mock.test", Model: decisionModel, TimeoutSeconds: 5}
	tests := []struct {
		name string
		// inputs
		script  func(g *guest)
		source  string // protocol.SourceLocal when empty
		target  string // the dir target when empty
		resolve string // GALAHAD_TEST_RESOLVE
		ask     func(t *testing.T, res protocol.Result) protocol.Decision
		askErr  error
		cancel  bool // the caller cancels during the call
		// expectations
		wantState   job.State
		wantErr     string // substring
		wantExit    int
		wantVerdict protocol.Verdict
		wantScore   int
		wantStatus  string   // status of the Decision in the report; empty means no report
		wantReasons []string // each is a substring of a reason
		wantCalls   int
	}{
		{
			name:   "an opinion that counts raises a clean scan",
			script: serve(hostVersion, func(res *protocol.Result) { res.Findings = []protocol.Finding{lowFinding()} }),
			ask: func(t *testing.T, res protocol.Result) protocol.Decision {
				return mockDecision(t, res, protocol.DecisionOK, 0.95)
			},
			wantState: job.StateDone, wantExit: 10, wantVerdict: protocol.VerdictSuspicious, wantScore: 20, wantStatus: protocol.DecisionOK,
			wantReasons: []string{"AI opinion (mock): malicious 95%, raised to suspicious"}, wantCalls: 1,
		},
		{
			name:   "an opinion never lowers a malicious scan",
			script: serve(hostVersion, func(res *protocol.Result) { res.Findings = []protocol.Finding{criticalFinding()} }),
			ask: func(t *testing.T, res protocol.Result) protocol.Decision {
				return mockDecision(t, res, protocol.DecisionOK, 0)
			},
			wantState: job.StateDone, wantExit: 20, wantVerdict: protocol.VerdictMalicious, wantScore: 100, wantStatus: protocol.DecisionOK, wantCalls: 1,
		},
		{
			name:   "a provider that fails leaves the static verdict and exit code",
			script: serve(hostVersion, func(res *protocol.Result) { res.Findings = []protocol.Finding{criticalFinding()} }),
			ask: func(t *testing.T, res protocol.Result) protocol.Decision {
				return mockDecision(t, res, protocol.DecisionFailed, 0)
			},
			wantState: job.StateDone, wantExit: 20, wantVerdict: protocol.VerdictMalicious, wantScore: 100, wantStatus: protocol.DecisionFailed, wantCalls: 1,
		},
		{
			name:   "a scan with nothing to send is skipped",
			script: serve(hostVersion, nil),
			ask: func(t *testing.T, res protocol.Result) protocol.Decision {
				return mockDecision(t, res, protocol.DecisionSkipped, 0)
			},
			wantState: job.StateDone, wantVerdict: protocol.VerdictClean, wantStatus: protocol.DecisionSkipped, wantCalls: 1,
		},
		{
			name:    "the note about a blocked infrastructure host survives the second scoring",
			script:  osvBlocked,
			resolve: "api.osv.dev=198.18.0.5",
			ask: func(t *testing.T, res protocol.Result) protocol.Decision {
				return mockDecision(t, res, protocol.DecisionOK, 0.95)
			},
			wantState: job.StateDone, wantExit: 10, wantVerdict: protocol.VerdictSuspicious, wantScore: 20, wantStatus: protocol.DecisionOK,
			wantReasons: []string{"AI opinion (mock): malicious 95%", "the OSV lookup was blocked: api.osv.dev resolved to an address that is not public (benchmarking)"},
			wantCalls:   1,
		},
		{
			name:   "the note that a link could not be downloaded survives the second scoring, and the link is skipped",
			source: protocol.SourceURL,
			script: failLink(func(g *guest) { g.connectRetry("169.254.169.254", 443) }, protocol.Error{Code: protocol.CodeNotAllowed, Message: "x"}),
			ask: func(t *testing.T, res protocol.Result) protocol.Decision {
				d, err := decision.Ask(context.Background(), mock, "", "dev", res)
				if err != nil {
					t.Fatal(err)
				}
				return d
			},
			wantState: job.StateDone, wantExit: 10, wantVerdict: protocol.VerdictSuspicious, wantScore: 35, wantStatus: protocol.DecisionSkipped,
			wantReasons: []string{"the input could not be downloaded, so only the network requests were examined"}, wantCalls: 1,
		},
		{
			name:   "Ctrl-C during the call ends the job canceled",
			script: serve(hostVersion, func(res *protocol.Result) { res.Findings = []protocol.Finding{lowFinding()} }),
			ask: func(t *testing.T, res protocol.Result) protocol.Decision {
				return mockDecision(t, res, protocol.DecisionFailed, 0)
			},
			cancel:    true,
			wantState: job.StateCanceled, wantErr: "canceled", wantExit: 1, wantCalls: 1,
		},
		{
			name:   "a request that cannot be built fails the job",
			script: serve(hostVersion, nil),
			ask: func(t *testing.T, res protocol.Result) protocol.Decision {
				return protocol.Decision{}
			},
			askErr:    errors.New("decision request: model is wrong"),
			wantState: job.StateFailed, wantErr: "the decision step: decision request: model is wrong", wantExit: 1, wantCalls: 1,
		},
		{
			name:   "a guest that fails is not asked about",
			script: func(g *guest) { g.dial(); g.hello("v0.0.1"); g.readJob() },
			ask: func(t *testing.T, res protocol.Result) protocol.Decision {
				return mockDecision(t, res, protocol.DecisionOK, 0.95)
			},
			wantState: job.StateFailed, wantErr: "the agent is version", wantExit: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given a scripted guest and a decision step that records when it is called
			t.Setenv("GALAHAD_TEST_RESOLVE", tt.resolve)
			jobs := t.TempDir()
			b := &fakeBackend{script: tt.script}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls, killsAtCall := 0, 0
			spec := job.Spec{
				JobsDir: jobs,
				Now:     func() time.Time { return time.Date(2026, 10, 21, 15, 30, 12, 0, time.UTC) },
				Version: hostVersion,
				Timeout: job.MinTimeout,
				Image:   "core",
				Source:  tt.source,
				Decide: func(_ context.Context, res protocol.Result) (protocol.Decision, error) {
					calls++
					b.mu.Lock()
					killsAtCall = b.kills
					b.mu.Unlock()
					if res.Decision != nil {
						t.Errorf("the Result already has a Decision: %+v", res.Decision)
					}
					if tt.cancel {
						cancel()
					}
					return tt.ask(t, res), tt.askErr
				},
			}
			target := tt.target
			if target == "" && tt.source == "" {
				target = dirTarget(t)
			}
			if target == "" {
				target = "https://files.example.com/a.pdf"
			}

			// When it runs
			out, err := job.Run(ctx, b, spec, target)
			if b.done != nil {
				<-b.done
			}

			// Then the call came after the machine was killed, and the job ends as expected
			if calls != tt.wantCalls {
				t.Fatalf("decision step called %d times, want %d", calls, tt.wantCalls)
			}
			if calls > 0 && killsAtCall < 1 {
				t.Errorf("the machine had been killed %d times when the decision step started, want at least 1", killsAtCall)
			}
			if tt.wantErr == "" && err != nil {
				t.Fatalf("Run: %v", err)
			}
			if tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)) {
				t.Fatalf("Run error = %v, want one containing %q", err, tt.wantErr)
			}
			saved, err := job.Load(jobs, out.Job.ID)
			if err != nil {
				t.Fatal(err)
			}
			if saved.State != tt.wantState || saved.ExitCode != tt.wantExit {
				t.Errorf("job.json = state %s, exit %d, want %s, %d", saved.State, saved.ExitCode, tt.wantState, tt.wantExit)
			}
			_, statErr := os.Stat(filepath.Join(jobs, out.Job.ID, "report.json"))
			if tt.wantStatus == "" {
				if statErr == nil || out.Result != nil {
					t.Errorf("report.json exists or the outcome has a Result, want neither (stat error %v)", statErr)
				}
				return
			}
			if statErr != nil {
				t.Fatalf("report.json: %v", statErr)
			}
			res := out.Result
			if res == nil || res.Decision == nil || res.Decision.Status != tt.wantStatus {
				t.Fatalf("Result = %+v, want a Decision of status %s", res, tt.wantStatus)
			}
			if res.Verdict != tt.wantVerdict || res.Score != tt.wantScore || saved.Verdict != string(tt.wantVerdict) || saved.Score != tt.wantScore {
				t.Errorf("verdict %s score %d (job.json %s %d), want %s %d", res.Verdict, res.Score, saved.Verdict, saved.Score, tt.wantVerdict, tt.wantScore)
			}
			for _, want := range tt.wantReasons {
				if !slices.ContainsFunc(res.Reasons, func(r string) bool { return strings.Contains(r, want) }) {
					t.Errorf("reasons = %q, want one containing %q", res.Reasons, want)
				}
			}
			if err := res.Validate(); err != nil {
				t.Errorf("the Result does not validate: %v", err)
			}
		})
	}
}
