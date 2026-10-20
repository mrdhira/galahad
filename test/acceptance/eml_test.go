package acceptance_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAgentAnalyzeEML(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		fixture string
		// expectations
		wantMinCode  int      // exit code must be at least this; 0 means exactly 0
		wantFindings []string // "RULE path:line" that must be present
		wantFiles    []string // paths that must be in files
		wantNone     []string // rules that must be absent
	}{
		{
			name:         "lure email: sender, reply-to, link mismatch and the attachment as a child",
			fixture:      "p6-eml-lure",
			wantMinCode:  10,
			wantFindings: []string{"GAL-EML-001 lure.eml:1", "GAL-EML-002 lure.eml:2", "GAL-EML-003 lure.eml:15"},
			wantFiles:    []string{"lure.eml", "lure.eml!/setup.js"},
		},
		{
			name:      "benign newsletter has no findings and is fully analyzed",
			fixture:   "benign-eml-newsletter",
			wantFiles: []string{"newsletter.eml"},
			wantNone:  []string{"GAL-EML-002", "GAL-EML-003"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given a committed email fixture
			root, err := moduleRoot()
			if err != nil {
				t.Fatal(err)
			}
			out := filepath.Join(t.TempDir(), "out")
			// When the agent analyzes it
			stdout, stderr, code := runAgent(t, "analyze", "-o", out, filepath.Join(root, "testdata", "corpus", tt.fixture))
			// Then the exit code, findings and files match
			if (tt.wantMinCode == 0 && code != 0) || code < tt.wantMinCode || code > 20 {
				t.Fatalf("exit = %d, want >= %d\nstdout: %s\nstderr: %s", code, tt.wantMinCode, stdout, stderr)
			}
			b, err := os.ReadFile(filepath.Join(out, "report.json"))
			if err != nil {
				t.Fatal(err)
			}
			var rep report
			if err := json.Unmarshal(b, &rep); err != nil {
				t.Fatal(err)
			}
			for _, want := range tt.wantFindings {
				rule, at, _ := strings.Cut(want, " ")
				if !hasFinding(rep, rule, at) {
					t.Errorf("no %s at %s in %+v", rule, at, rep.Findings)
				}
			}
			for _, rule := range tt.wantNone {
				for _, f := range rep.Findings {
					if f.RuleID == rule {
						t.Errorf("unexpected finding %s", rule)
					}
				}
			}
			for _, want := range tt.wantFiles {
				found := false
				for _, f := range rep.Files {
					found = found || f.Path == want
				}
				if !found {
					t.Errorf("file %q not in %+v", want, rep.Files)
				}
			}
			if rep.Coverage.FilesAnalyzed != rep.Coverage.FilesSeen {
				t.Errorf("files_analyzed = %d, files_seen = %d", rep.Coverage.FilesAnalyzed, rep.Coverage.FilesSeen)
			}
		})
	}
}
