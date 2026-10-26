package scoring_test

import (
	"fmt"
	"slices"
	"testing"

	"github.com/mrdhira/galahad/internal/protocol"
	"github.com/mrdhira/galahad/internal/scoring"
)

// opinion returns a Decision of the given status. An ok one answers the verdict question with the
// given probability of malicious.
func opinion(status string, malicious float64) *protocol.Decision {
	d := &protocol.Decision{Provider: "netra", Status: status}
	if status == protocol.DecisionOK {
		d.Answers = &protocol.DecisionAnswers{Questions: map[string]protocol.DecisionAnswer{
			protocol.QuestionVerdict: {Probabilities: map[string]float64{
				string(protocol.VerdictClean): 1 - malicious, string(protocol.VerdictSuspicious): 0, protocol.LabelMalicious: malicious,
			}},
		}}
	}
	return d
}

func verdictRank(v protocol.Verdict) int {
	switch v {
	case protocol.VerdictMalicious:
		return 2
	case protocol.VerdictSuspicious:
		return 1
	default:
		return 0
	}
}

func TestApplyDecisionIgnored(t *testing.T) {
	failedMalicious := opinion(protocol.DecisionOK, 1)
	failedMalicious.Status = protocol.DecisionFailed
	tests := []struct {
		name string
		// inputs
		decision *protocol.Decision
	}{
		{name: "no decision", decision: nil},
		{name: "failed decision", decision: &protocol.Decision{Provider: "netra", Status: protocol.DecisionFailed}},
		{name: "skipped decision", decision: &protocol.Decision{Provider: "netra", Status: protocol.DecisionSkipped}},
		{name: "failed decision that holds malicious 1.0", decision: failedMalicious},
		{name: "ok decision without answers", decision: &protocol.Decision{Provider: "netra", Status: protocol.DecisionOK}},
		{name: "ok decision without the verdict answer", decision: &protocol.Decision{Provider: "netra", Status: protocol.DecisionOK,
			Answers: &protocol.DecisionAnswers{Questions: map[string]protocol.DecisionAnswer{}}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := protocol.Result{
				Findings: []protocol.Finding{finding("GAL-A-001", protocol.SeverityMedium, "a", "f", 1)},
				Coverage: protocol.Coverage{FilesSeen: 1, FilesAnalyzed: 1},
				Decision: tt.decision,
			}

			scoring.Apply(&res)

			if res.Verdict != protocol.VerdictSuspicious || res.Score != 15 || res.Confidence != 75 {
				t.Errorf("verdict/score/confidence = %s/%d/%d, want suspicious/15/75", res.Verdict, res.Score, res.Confidence)
			}
			if want := []string{"score 15 >= 15"}; !slices.Equal(res.Reasons, want) {
				t.Errorf("reasons = %q, want %q", res.Reasons, want)
			}
		})
	}
}

func TestApplyDecisionCap(t *testing.T) {
	cov := func(seen, analyzed int) protocol.Coverage {
		return protocol.Coverage{FilesSeen: seen, FilesAnalyzed: analyzed}
	}
	const aiReason = "AI opinion (netra): malicious %s%%, raised to suspicious; an AI opinion never makes a verdict malicious"
	answers := []struct {
		name      string
		malicious float64
		wantPct   string // empty when the opinion does not count
	}{
		{name: "clean 1.0", malicious: 0},
		{name: "malicious 0.79", malicious: 0.79},
		{name: "malicious 0.80", malicious: 0.80, wantPct: "80"},
		{name: "malicious 1.0", malicious: 1, wantPct: "100"},
	}
	tests := []struct {
		name string
		// inputs
		findings []protocol.Finding
		coverage protocol.Coverage
		// expectations: S is what Apply gives without an opinion, "raised" is the result of a
		// counting opinion on a case whose S is not malicious
		wantVerdict       protocol.Verdict
		wantScore         int
		wantReasons       []string
		wantRaisedVerdict protocol.Verdict
		wantRaisedScore   int
		wantConf          int
		wantLevel         string
	}{
		{
			name:        "clean without findings",
			coverage:    cov(2, 2),
			wantVerdict: protocol.VerdictClean, wantScore: 0, wantReasons: []string{"no findings"},
			wantRaisedVerdict: protocol.VerdictSuspicious, wantRaisedScore: 15,
			wantConf: 100, wantLevel: "high",
		},
		{
			name:        "clean with a low finding",
			findings:    []protocol.Finding{finding("GAL-A-001", protocol.SeverityLow, "a", "f", 1)},
			coverage:    cov(2, 2),
			wantVerdict: protocol.VerdictClean, wantScore: 5, wantReasons: []string{"score 5 < 15"},
			wantRaisedVerdict: protocol.VerdictSuspicious, wantRaisedScore: 20,
			wantConf: 90, wantLevel: "high",
		},
		{
			name:        "clean at low coverage",
			coverage:    cov(10, 4),
			wantVerdict: protocol.VerdictSuspicious, wantScore: 0,
			wantReasons:       []string{"no findings", "coverage 40% < 50%", "less than half of the files could be analyzed"},
			wantRaisedVerdict: protocol.VerdictSuspicious, wantRaisedScore: 15,
			wantConf: 30, wantLevel: "low",
		},
		{
			name:        "suspicious at 15",
			findings:    []protocol.Finding{finding("GAL-A-001", protocol.SeverityMedium, "a", "f", 1)},
			coverage:    cov(1, 1),
			wantVerdict: protocol.VerdictSuspicious, wantScore: 15, wantReasons: []string{"score 15 >= 15"},
			wantRaisedVerdict: protocol.VerdictSuspicious, wantRaisedScore: 30,
			wantConf: 75, wantLevel: "medium",
		},
		{
			name: "suspicious at 65 is raised to 69, not 80",
			findings: []protocol.Finding{
				finding("GAL-A-001", protocol.SeverityHigh, "a", "f", 1),
				finding("GAL-A-002", protocol.SeverityMedium, "a", "f", 2),
				finding("GAL-A-003", protocol.SeverityMedium, "a", "f", 3),
			},
			coverage:    cov(1, 1),
			wantVerdict: protocol.VerdictSuspicious, wantScore: 65, wantReasons: []string{"score 65 >= 15"},
			wantRaisedVerdict: protocol.VerdictSuspicious, wantRaisedScore: 69,
			wantConf: 75, wantLevel: "medium",
		},
		{
			name: "malicious by score",
			findings: []protocol.Finding{
				finding("GAL-A-001", protocol.SeverityHigh, "a", "f", 1),
				finding("GAL-A-002", protocol.SeverityHigh, "a", "f", 2),
			},
			coverage:    cov(1, 1),
			wantVerdict: protocol.VerdictMalicious, wantScore: 70, wantReasons: []string{"score 70 >= 70"},
			wantRaisedVerdict: protocol.VerdictMalicious, wantRaisedScore: 70,
			wantConf: 75, wantLevel: "medium",
		},
		{
			name:        "malicious by a hard trigger",
			findings:    []protocol.Finding{finding("GAL-SIG-001", protocol.SeverityCritical, "sig", "eicar.txt", 1)},
			coverage:    cov(1, 1),
			wantVerdict: protocol.VerdictMalicious, wantScore: 100, wantReasons: []string{"hard trigger GAL-SIG-001 (critical) at eicar.txt:1"},
			wantRaisedVerdict: protocol.VerdictMalicious, wantRaisedScore: 100,
			wantConf: 90, wantLevel: "high",
		},
		{
			name: "fake-interview-repo stays malicious at its score",
			findings: []protocol.Finding{
				finding("GAL-AUTOEXEC-001", protocol.SeverityHigh, "autoexec", ".vscode/tasks.json", 7),
				finding("GAL-AUTOEXEC-010", protocol.SeverityHigh, "autoexec", ".vscode/tasks.json", 7),
				finding("GAL-AUTOEXEC-005", protocol.SeverityMedium, "autoexec", "package.json", 6),
				finding("GAL-EXFIL-001", protocol.SeverityCritical, "script", "scripts/setup.js", 3),
			},
			coverage:    cov(4, 4),
			wantVerdict: protocol.VerdictMalicious, wantScore: 100,
			wantReasons:       []string{"hard trigger GAL-EXFIL-001 (critical) at scripts/setup.js:3", "agreement: autoexec, script"},
			wantRaisedVerdict: protocol.VerdictMalicious, wantRaisedScore: 100,
			wantConf: 100, wantLevel: "high",
		},
	}
	for _, tt := range tests {
		for _, a := range answers {
			t.Run(tt.name+"/"+a.name, func(t *testing.T) {
				res := protocol.Result{
					SchemaVersion: protocol.SchemaVersion,
					Tool:          protocol.Tool{Name: "t", Version: "v"},
					Target:        protocol.Target{Name: "x", Kind: protocol.TargetDir},
					Findings:      slices.Clone(tt.findings),
					Coverage:      tt.coverage,
					Decision:      opinion(protocol.DecisionOK, a.malicious),
				}
				wantVerdict, wantScore, wantReasons := tt.wantVerdict, tt.wantScore, tt.wantReasons
				if a.wantPct != "" && tt.wantVerdict != protocol.VerdictMalicious {
					wantVerdict, wantScore = tt.wantRaisedVerdict, tt.wantRaisedScore
					wantReasons = append(slices.Clone(tt.wantReasons), fmt.Sprintf(aiReason, a.wantPct))
				}

				scoring.Apply(&res)

				if res.Verdict != wantVerdict || res.Score != wantScore {
					t.Errorf("verdict/score = %s/%d, want %s/%d", res.Verdict, res.Score, wantVerdict, wantScore)
				}
				if !slices.Equal(res.Reasons, wantReasons) {
					t.Errorf("reasons = %q, want %q", res.Reasons, wantReasons)
				}
				if res.Confidence != tt.wantConf || res.ConfidenceLevel != tt.wantLevel {
					t.Errorf("confidence/level = %d/%s, want %d/%s", res.Confidence, res.ConfidenceLevel, tt.wantConf, tt.wantLevel)
				}
				// The invariants of the cap, against S.
				if verdictRank(res.Verdict) < verdictRank(tt.wantVerdict) || res.Verdict == protocol.VerdictMalicious && tt.wantVerdict != protocol.VerdictMalicious {
					t.Errorf("verdict %s breaks the cap for S = %s", res.Verdict, tt.wantVerdict)
				}
				if res.Score < tt.wantScore || res.Score > tt.wantScore+15 {
					t.Errorf("score %d outside [%d, %d]", res.Score, tt.wantScore, tt.wantScore+15)
				}
				if len(res.Findings) != len(tt.findings) || !slices.EqualFunc(res.Findings, tt.findings, func(a, b protocol.Finding) bool { return a.RuleID == b.RuleID && a.Severity == b.Severity }) {
					t.Errorf("findings changed: %v", res.Findings)
				}
				res.Findings, res.Decision = nil, nil // only the scored fields must validate
				if err := res.Validate(); err != nil {
					t.Errorf("scored result does not validate: %v", err)
				}
			})
		}
	}
}
