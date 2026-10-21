package scoring_test

import (
	"strings"
	"testing"

	"github.com/mrdhira/galahad/internal/protocol"
	"github.com/mrdhira/galahad/internal/scoring"
)

func finding(rule string, sev protocol.Severity, analyzer, path string, line int) protocol.Finding {
	return protocol.Finding{
		RuleID: rule, Severity: sev, Title: "t", Analyzer: analyzer,
		Evidence: []protocol.Evidence{{Path: path, Line: line, Snippet: "x"}},
	}
}

func TestApply(t *testing.T) {
	cov := func(seen, analyzed int) protocol.Coverage {
		return protocol.Coverage{FilesSeen: seen, FilesAnalyzed: analyzed}
	}
	skipped := func(seen, analyzed int, reason string) protocol.Coverage {
		return protocol.Coverage{FilesSeen: seen, FilesAnalyzed: analyzed, Skipped: []protocol.Skip{{Path: "a.zip!/x", Reason: reason}}}
	}
	tests := []struct {
		name string
		// inputs
		findings []protocol.Finding
		coverage protocol.Coverage
		// expectations
		wantVerdict protocol.Verdict
		wantScore   int
		wantConf    int
		wantLevel   string
		wantReasons []string // exact reasons, in order
	}{
		{
			name: "hard trigger with agreement",
			findings: []protocol.Finding{
				finding("GAL-EXFIL-001", protocol.SeverityCritical, "script", "scripts/setup.js", 3),
				finding("GAL-AUTOEXEC-001", protocol.SeverityHigh, "autoexec", ".vscode/tasks.json", 7),
			},
			coverage:    cov(4, 1),
			wantVerdict: protocol.VerdictMalicious,
			wantScore:   100,
			wantConf:    100,
			wantLevel:   "high",
			wantReasons: []string{"hard trigger GAL-EXFIL-001 (critical) at scripts/setup.js:3", "agreement: autoexec, script"},
		},
		{
			name: "same rule twice counts once",
			findings: []protocol.Finding{
				finding("GAL-A-001", protocol.SeverityHigh, "a", "f", 1),
				finding("GAL-A-001", protocol.SeverityHigh, "a", "g", 2),
			},
			coverage:    cov(2, 2),
			wantVerdict: protocol.VerdictSuspicious,
			wantScore:   35,
			wantConf:    75,
			wantLevel:   "medium",
			wantReasons: []string{"score 35 >= 15"},
		},
		{
			name: "same rule counts at its highest severity",
			findings: []protocol.Finding{
				finding("GAL-A-001", protocol.SeverityLow, "a", "f", 1),
				finding("GAL-A-001", protocol.SeverityHigh, "a", "g", 2),
				finding("GAL-A-001", protocol.SeverityMedium, "a", "h", 3),
			},
			coverage:    cov(3, 3),
			wantVerdict: protocol.VerdictSuspicious,
			wantScore:   35,
			wantConf:    75,
			wantLevel:   "medium",
			wantReasons: []string{"score 35 >= 15"},
		},
		{
			name: "score is capped at 100",
			findings: []protocol.Finding{
				finding("GAL-A-001", protocol.SeverityHigh, "a", "f", 1),
				finding("GAL-A-002", protocol.SeverityHigh, "a", "f", 2),
				finding("GAL-A-003", protocol.SeverityHigh, "a", "f", 3),
				finding("GAL-A-004", protocol.SeverityHigh, "a", "f", 4),
			},
			coverage:    cov(1, 1),
			wantVerdict: protocol.VerdictMalicious,
			wantScore:   100,
			wantConf:    75,
			wantLevel:   "medium",
			wantReasons: []string{"score 100 >= 70"},
		},
		{
			name: "any critical is malicious with rule and evidence in the reasons",
			findings: []protocol.Finding{
				finding("GAL-SIG-001", protocol.SeverityCritical, "sig", "eicar.txt", 1),
			},
			coverage:    cov(1, 1),
			wantVerdict: protocol.VerdictMalicious,
			wantScore:   100,
			wantConf:    90,
			wantLevel:   "high",
			wantReasons: []string{"hard trigger GAL-SIG-001 (critical) at eicar.txt:1"},
		},
		{
			name: "hard trigger ignores coverage",
			findings: []protocol.Finding{
				finding("GAL-SIG-001", protocol.SeverityCritical, "sig", "a!/b", 0),
			},
			coverage:    cov(10, 1),
			wantVerdict: protocol.VerdictMalicious,
			wantScore:   100,
			wantConf:    90,
			wantLevel:   "high",
			wantReasons: []string{"hard trigger GAL-SIG-001 (critical) at a!/b"},
		},
		{
			name: "evidence path is cleaned in reasons",
			findings: []protocol.Finding{
				finding("GAL-SIG-001", protocol.SeverityCritical, "sig", "a\x1b[31m", 2),
			},
			coverage:    cov(1, 1),
			wantVerdict: protocol.VerdictMalicious,
			wantScore:   100,
			wantConf:    90,
			wantLevel:   "high",
			wantReasons: []string{`hard trigger GAL-SIG-001 (critical) at a\u001b[31m:2`},
		},
		{
			name: "two highs are malicious",
			findings: []protocol.Finding{
				finding("GAL-A-001", protocol.SeverityHigh, "a", "f", 1),
				finding("GAL-A-002", protocol.SeverityHigh, "a", "f", 2),
			},
			coverage:    cov(1, 1),
			wantVerdict: protocol.VerdictMalicious,
			wantScore:   70,
			wantConf:    75,
			wantLevel:   "medium",
			wantReasons: []string{"score 70 >= 70"},
		},
		{
			name: "three lows are suspicious",
			findings: []protocol.Finding{
				finding("GAL-A-001", protocol.SeverityLow, "a", "f", 1),
				finding("GAL-A-002", protocol.SeverityLow, "a", "f", 2),
				finding("GAL-A-003", protocol.SeverityLow, "a", "f", 3),
			},
			coverage:    cov(4, 4),
			wantVerdict: protocol.VerdictSuspicious,
			wantScore:   15,
			wantConf:    75,
			wantLevel:   "medium",
			wantReasons: []string{"score 15 >= 15"},
		},
		{
			name: "one medium is suspicious",
			findings: []protocol.Finding{
				finding("GAL-A-001", protocol.SeverityMedium, "a", "f", 1),
			},
			coverage:    cov(1, 1),
			wantVerdict: protocol.VerdictSuspicious,
			wantScore:   15,
			wantConf:    75,
			wantLevel:   "medium",
			wantReasons: []string{"score 15 >= 15"},
		},
		{
			name: "one high is suspicious",
			findings: []protocol.Finding{
				finding("GAL-A-001", protocol.SeverityHigh, "a", "f", 1),
			},
			coverage:    cov(1, 1),
			wantVerdict: protocol.VerdictSuspicious,
			wantScore:   35,
			wantConf:    75,
			wantLevel:   "medium",
			wantReasons: []string{"score 35 >= 15"},
		},
		{
			name:        "no findings is clean",
			coverage:    cov(10, 10),
			wantVerdict: protocol.VerdictClean,
			wantConf:    100,
			wantLevel:   "high",
			wantReasons: []string{"no findings"},
		},
		{
			name: "one low is clean with reduced confidence",
			findings: []protocol.Finding{
				finding("GAL-A-001", protocol.SeverityLow, "a", "f", 1),
			},
			coverage:    cov(10, 10),
			wantVerdict: protocol.VerdictClean,
			wantScore:   5,
			wantConf:    90,
			wantLevel:   "high",
			wantReasons: []string{"score 5 < 15"},
		},
		{
			name: "info findings weigh nothing",
			findings: []protocol.Finding{
				finding("GAL-A-001", protocol.SeverityInfo, "a", "f", 1),
			},
			coverage:    cov(2, 2),
			wantVerdict: protocol.VerdictClean,
			wantConf:    100,
			wantLevel:   "high",
			wantReasons: []string{"score 0 < 15"},
		},
		{
			name:        "coverage under 50 percent with no findings is suspicious",
			coverage:    cov(10, 4),
			wantVerdict: protocol.VerdictSuspicious,
			wantConf:    30,
			wantLevel:   "low",
			wantReasons: []string{"no findings", "coverage 40% < 50%", "less than half of the files could be analyzed"},
		},
		{
			name:        "nothing seen is suspicious",
			coverage:    cov(0, 0),
			wantVerdict: protocol.VerdictSuspicious,
			wantConf:    0,
			wantLevel:   "low",
			wantReasons: []string{"no findings", "coverage 0% < 50%", "no files were found to analyze"},
		},
		{
			name:        "exactly 50 percent coverage passes the guard",
			coverage:    cov(10, 5),
			wantVerdict: protocol.VerdictClean,
			wantConf:    50,
			wantLevel:   "medium",
			wantReasons: []string{"no findings"},
		},
		{
			name:        "a depth skip makes a clean result suspicious",
			coverage:    skipped(10, 8, protocol.SkipDepth),
			wantVerdict: protocol.VerdictSuspicious,
			wantConf:    60,
			wantLevel:   "medium",
			wantReasons: []string{"no findings", "part of the input could not be analyzed"},
		},
		{
			name:        "a budget skip makes a clean result suspicious",
			coverage:    skipped(10, 8, protocol.SkipBudget),
			wantVerdict: protocol.VerdictSuspicious,
			wantConf:    60,
			wantLevel:   "medium",
			wantReasons: []string{"no findings", "part of the input could not be analyzed"},
		},
		{
			name:        "a encrypted skip makes a clean result suspicious",
			coverage:    skipped(10, 8, protocol.SkipEncrypted),
			wantVerdict: protocol.VerdictSuspicious,
			wantConf:    60,
			wantLevel:   "medium",
			wantReasons: []string{"no findings", "part of the input could not be analyzed"},
		},
		{
			name:        "a too large skip makes a clean result suspicious",
			coverage:    skipped(10, 8, protocol.SkipTooLarge),
			wantVerdict: protocol.VerdictSuspicious,
			wantConf:    60,
			wantLevel:   "medium",
			wantReasons: []string{"no findings", "part of the input could not be analyzed"},
		},
		{
			name:        "low coverage and a skip give both reasons",
			coverage:    skipped(10, 4, protocol.SkipDepth),
			wantVerdict: protocol.VerdictSuspicious,
			wantConf:    30,
			wantLevel:   "low",
			wantReasons: []string{"no findings", "coverage 40% < 50%", "less than half of the files could be analyzed", "part of the input could not be analyzed"},
		},
		{
			name:        "a skip that hides nothing keeps a clean result",
			coverage:    skipped(10, 10, protocol.SkipUnsupported),
			wantVerdict: protocol.VerdictClean,
			wantConf:    100,
			wantLevel:   "high",
			wantReasons: []string{"no findings"},
		},
		{
			name: "a skip does not change a suspicious verdict",
			findings: []protocol.Finding{
				finding("GAL-A-001", protocol.SeverityMedium, "a", "f", 1),
			},
			coverage:    skipped(10, 10, protocol.SkipDepth),
			wantVerdict: protocol.VerdictSuspicious,
			wantScore:   15,
			wantConf:    75,
			wantLevel:   "medium",
			wantReasons: []string{"score 15 >= 15"},
		},
		{
			name: "low coverage does not change a suspicious verdict",
			findings: []protocol.Finding{
				finding("GAL-A-001", protocol.SeverityMedium, "a", "f", 1),
			},
			coverage:    cov(10, 4),
			wantVerdict: protocol.VerdictSuspicious,
			wantScore:   15,
			wantConf:    30,
			wantLevel:   "low",
			wantReasons: []string{"score 15 >= 15"},
		},
		{
			name: "score verdict with agreement uses factor 1.0",
			findings: []protocol.Finding{
				finding("GAL-A-001", protocol.SeverityMedium, "autoexec", "f", 1),
				finding("GAL-B-001", protocol.SeverityMedium, "script", "g", 1),
			},
			coverage:    cov(5, 4),
			wantVerdict: protocol.VerdictSuspicious,
			wantScore:   30,
			wantConf:    80,
			wantLevel:   "high",
			wantReasons: []string{"score 30 >= 15", "agreement: autoexec, script"},
		},
		{
			name: "low findings from two analyzers are not agreement",
			findings: []protocol.Finding{
				finding("GAL-A-001", protocol.SeverityMedium, "a", "f", 1),
				finding("GAL-B-001", protocol.SeverityLow, "b", "g", 1),
			},
			coverage:    cov(1, 1),
			wantVerdict: protocol.VerdictSuspicious,
			wantScore:   20,
			wantConf:    75,
			wantLevel:   "medium",
			wantReasons: []string{"score 20 >= 15"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := protocol.Result{
				SchemaVersion: protocol.SchemaVersion,
				Tool:          protocol.Tool{Name: "t", Version: "v"},
				Target:        protocol.Target{Name: "x", Kind: protocol.TargetDir},
				Findings:      tt.findings,
				Coverage:      tt.coverage,
			}

			scoring.Apply(&res)

			if res.Verdict != tt.wantVerdict || res.Score != tt.wantScore || res.Confidence != tt.wantConf || res.ConfidenceLevel != tt.wantLevel {
				t.Errorf("verdict/score/confidence/level = %s/%d/%d/%s, want %s/%d/%d/%s",
					res.Verdict, res.Score, res.Confidence, res.ConfidenceLevel,
					tt.wantVerdict, tt.wantScore, tt.wantConf, tt.wantLevel)
			}
			if got, want := strings.Join(res.Reasons, "\n"), strings.Join(tt.wantReasons, "\n"); got != want {
				t.Errorf("reasons = %q, want %q", res.Reasons, tt.wantReasons)
			}
			res.Findings = nil // some cases use deliberately unclean evidence paths; only the scored fields must validate
			if err := res.Validate(); err != nil {
				t.Errorf("scored result does not validate: %v", err)
			}
		})
	}
}

func TestApplyLevels(t *testing.T) {
	tests := []struct {
		name      string
		analyzed  int
		wantConf  int
		wantLevel string
	}{
		{name: "80 is high", analyzed: 80, wantConf: 80, wantLevel: "high"},
		{name: "79 is medium", analyzed: 79, wantConf: 79, wantLevel: "medium"},
		{name: "50 is medium", analyzed: 50, wantConf: 50, wantLevel: "medium"},
		{name: "49 percent coverage is suspicious and low", analyzed: 49, wantConf: 37, wantLevel: "low"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := protocol.Result{Coverage: protocol.Coverage{FilesSeen: 100, FilesAnalyzed: tt.analyzed}}

			scoring.Apply(&res)

			if res.Confidence != tt.wantConf || res.ConfidenceLevel != tt.wantLevel {
				t.Errorf("confidence/level = %d/%s, want %d/%s", res.Confidence, res.ConfidenceLevel, tt.wantConf, tt.wantLevel)
			}
		})
	}
}

func TestApplyReasonLength(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantMax int
	}{
		{name: "long path is cut to the reason limit", path: strings.Repeat("é", 1000), wantMax: protocol.MaxReason},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := protocol.Result{
				SchemaVersion: protocol.SchemaVersion,
				Tool:          protocol.Tool{Name: "t", Version: "v"},
				Target:        protocol.Target{Name: "x", Kind: protocol.TargetDir},
				Findings:      []protocol.Finding{finding("GAL-SIG-001", protocol.SeverityCritical, "sig", tt.path, 1)},
				Coverage:      protocol.Coverage{FilesSeen: 1, FilesAnalyzed: 1},
			}

			scoring.Apply(&res)

			if n := len([]rune(res.Reasons[0])); n != tt.wantMax {
				t.Errorf("reason has %d runes, want %d", n, tt.wantMax)
			}
			res.Findings = nil // the test path is deliberately unclean; only the reasons must validate
			if err := res.Validate(); err != nil {
				t.Errorf("does not validate: %v", err)
			}
		})
	}
}
