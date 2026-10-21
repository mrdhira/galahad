package acceptance_test

import (
	"path/filepath"
	"testing"
)

// P2: a repository pulls dependencies that are typosquats or come from outside the default registries.
func TestAgentDependencyChecks(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		fixture string
		// expectations
		wantCode  int
		wantRules map[string]string // rule -> "path:line" that must be present
		wantClean bool              // no findings at all
	}{
		{
			name:     "typosquatted names and a github dependency",
			fixture:  "p2-typosquat",
			wantCode: 10,
			wantRules: map[string]string{
				"GAL-DEPS-001": "package.json:6",
				"GAL-DEPS-002": "package.json:8",
			},
		},
		{
			name:     "custom python index and a typosquatted requirement",
			fixture:  "p2-pip-index",
			wantCode: 10,
			wantRules: map[string]string{
				"GAL-DEPS-004": "requirements.txt:2",
				"GAL-DEPS-001": "requirements.txt:3",
			},
		},
		{name: "benign npm project with a registry lockfile", fixture: "benign-npm-deps", wantCode: 0, wantClean: true},
		{name: "benign npm project with local path dependencies", fixture: "benign-local-deps", wantCode: 0, wantClean: true},
		{name: "benign python library", fixture: "benign-python-lib", wantCode: 0, wantClean: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given a fixture
			root, err := moduleRoot()
			if err != nil {
				t.Fatal(err)
			}
			// When the agent analyzes it
			rep := analyze(t, filepath.Join(root, "testdata", "corpus", tt.fixture), tt.wantCode)
			// Then the dependency findings point at the right lines, or there are none
			for rule, at := range tt.wantRules {
				if !hasFinding(rep, rule, at) {
					t.Errorf("no %s at %s in %+v", rule, at, rep.Findings)
				}
			}
			if got := otherFindings(rep); tt.wantClean && len(got) != 0 {
				t.Errorf("findings = %v, want none besides inventory", got)
			}
			if rep.Coverage.FilesAnalyzed != rep.Coverage.FilesSeen || len(rep.Coverage.Skipped) != 0 {
				t.Errorf("coverage seen/analyzed/skipped = %d/%d/%v, want all analyzed", rep.Coverage.FilesSeen, rep.Coverage.FilesAnalyzed, rep.Coverage.Skipped)
			}
		})
	}
}
