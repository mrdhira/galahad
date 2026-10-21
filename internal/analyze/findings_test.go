package analyze_test

import (
	"fmt"
	"testing"

	"github.com/mrdhira/galahad/internal/analyze"
	"github.com/mrdhira/galahad/internal/protocol"
)

func ruleFinding(rule string, sev protocol.Severity, path string) protocol.Finding {
	return protocol.Finding{RuleID: rule, Severity: sev, Title: "t", Evidence: []protocol.Evidence{{Path: path}}}
}

func TestAddFindings(t *testing.T) {
	full := func() []protocol.Finding {
		fs := make([]protocol.Finding, protocol.MaxFindings)
		for i := range fs {
			fs[i] = ruleFinding("GAL-LOW-001", protocol.SeverityLow, fmt.Sprintf("f%d", i))
		}
		return fs
	}
	perFile := make([]protocol.Finding, protocol.MaxFindingsPerRulePerFile+3)
	for i := range perFile {
		perFile[i] = ruleFinding("GAL-AV-001", protocol.SeverityHigh, "a")
	}
	tests := []struct {
		name string
		// inputs
		have []protocol.Finding
		add  []protocol.Finding
		// expectations
		wantCount     int
		wantFirstRule string
		wantFirstBy   string // analyzer of the first finding
		wantTruncated bool
	}{
		{
			name:      "added findings are marked and sorted by severity",
			have:      []protocol.Finding{ruleFinding("GAL-LOW-001", protocol.SeverityLow, "a")},
			add:       []protocol.Finding{ruleFinding("GAL-AV-001", protocol.SeverityHigh, "b")},
			wantCount: 2, wantFirstRule: "GAL-AV-001", wantFirstBy: "clamav",
		},
		{
			name: "a finding without evidence is dropped",
			add:  []protocol.Finding{{RuleID: "GAL-AV-001", Severity: protocol.SeverityHigh}},
		},
		{
			name: "one rule is capped per file", add: perFile,
			wantCount: protocol.MaxFindingsPerRulePerFile, wantFirstRule: "GAL-AV-001", wantFirstBy: "clamav",
		},
		{
			name: "a full list gives room to a more severe finding", have: full(),
			add:       []protocol.Finding{ruleFinding("GAL-AV-001", protocol.SeverityHigh, "b")},
			wantCount: protocol.MaxFindings, wantFirstRule: "GAL-AV-001", wantFirstBy: "clamav", wantTruncated: true,
		},
		{
			name: "a full list drops a less severe finding", have: full(),
			add:       []protocol.Finding{ruleFinding("GAL-INFO-001", protocol.SeverityInfo, "b")},
			wantCount: protocol.MaxFindings, wantFirstRule: "GAL-LOW-001", wantTruncated: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := protocol.Result{Findings: tt.have}

			analyze.AddFindings(&res, "clamav", tt.add)

			if len(res.Findings) != tt.wantCount || res.Coverage.Truncated != tt.wantTruncated {
				t.Fatalf("findings = %d, truncated = %v, want %d, %v", len(res.Findings), res.Coverage.Truncated, tt.wantCount, tt.wantTruncated)
			}
			if tt.wantCount == 0 {
				return
			}
			if got := res.Findings[0]; got.RuleID != tt.wantFirstRule || got.Analyzer != tt.wantFirstBy {
				t.Errorf("first finding = %s by %q, want %s by %q", got.RuleID, got.Analyzer, tt.wantFirstRule, tt.wantFirstBy)
			}
		})
	}
}
