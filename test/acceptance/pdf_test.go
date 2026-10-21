package acceptance_test

import (
	"path/filepath"
	"testing"
)

func TestPDF(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		fixture string
		// expectations
		wantCode     int
		wantVerdict  string
		wantFindings []string // "RULE path:line" that must be present
		wantAbsent   []string // rule IDs that must not be present
	}{
		{
			name:        "OpenAction to JavaScript, Launch and a URI is malicious",
			fixture:     "p4-pdf-launch",
			wantCode:    20,
			wantVerdict: "malicious",
			wantFindings: []string{
				"GAL-PDF-001 invoice.pdf:12",
				"GAL-PDF-002 invoice.pdf:3",
				"GAL-PDF-003 invoice.pdf:15",
				"GAL-PDF-005 invoice.pdf:21",
			},
		},
		{
			name:         "OpenAction to a URI action is suspicious",
			fixture:      "p4-pdf-openaction-uri",
			wantCode:     10,
			wantVerdict:  "suspicious",
			wantFindings: []string{"GAL-PDF-002 statement.pdf:3", "GAL-PDF-005 statement.pdf:12"},
			wantAbsent:   []string{"GAL-PDF-001", "GAL-PDF-003"},
		},
		{
			name:         "benign twin with a destination OpenAction and one link is clean",
			fixture:      "benign-pdf",
			wantCode:     0,
			wantVerdict:  "clean",
			wantFindings: []string{"GAL-PDF-005 report.pdf:12"},
			wantAbsent:   []string{"GAL-PDF-001", "GAL-PDF-002", "GAL-PDF-003", "GAL-PDF-004", "GAL-PDF-006", "GAL-PDF-007"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given a PDF fixture
			root, err := moduleRoot()
			if err != nil {
				t.Fatal(err)
			}
			// When the agent analyzes it
			rep := analyze(t, filepath.Join(root, "testdata", "corpus", tt.fixture), tt.wantCode)
			// Then the verdict, the findings with their lines and the coverage match
			if rep.Verdict != tt.wantVerdict {
				t.Errorf("verdict = %q, want %q", rep.Verdict, tt.wantVerdict)
			}
			for _, want := range tt.wantFindings {
				var rule, at string
				for i := range want {
					if want[i] == ' ' {
						rule, at = want[:i], want[i+1:]
					}
				}
				if !hasFinding(rep, rule, at) {
					t.Errorf("no %s at %s in %+v", rule, at, rep.Findings)
				}
			}
			for _, f := range rep.Findings {
				for _, id := range tt.wantAbsent {
					if f.RuleID == id {
						t.Errorf("unexpected finding %s", id)
					}
				}
			}
			if rep.Coverage.FilesAnalyzed != rep.Coverage.FilesSeen || len(rep.Coverage.Skipped) != 0 {
				t.Errorf("coverage = %d/%d skipped %v, want all analyzed", rep.Coverage.FilesAnalyzed, rep.Coverage.FilesSeen, rep.Coverage.Skipped)
			}
		})
	}
}
