package acceptance_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBinaryAnalyze(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		target func(t *testing.T) string
		// expectations
		wantCode int
		wantKind map[string]bool
	}{
		{
			name:     "built galahad binary is a clean native executable",
			target:   func(*testing.T) string { return binPath },
			wantCode: 0,
			wantKind: map[string]bool{"elf": true, "pe": true, "macho": true},
		},
		{
			name: "text file is not treated as a binary",
			target: func(t *testing.T) string {
				p := filepath.Join(t.TempDir(), "notes.txt")
				if err := os.WriteFile(p, []byte("hello\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				return p
			},
			wantCode: 0,
			wantKind: map[string]bool{"text": true},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "out")
			stdout, stderr, code := runAgent(t, "analyze", "--unsafe-host", "-o", out, tt.target(t))
			if code != tt.wantCode {
				t.Fatalf("exit = %d, want %d\nstdout: %s\nstderr: %s", code, tt.wantCode, stdout, stderr)
			}
			b, err := os.ReadFile(filepath.Join(out, "report.json"))
			if err != nil {
				t.Fatal(err)
			}
			var rep struct {
				Files []struct {
					Kind string `json:"kind"`
				} `json:"files"`
				Findings []struct {
					RuleID string `json:"rule_id"`
				} `json:"findings"`
			}
			if err := json.Unmarshal(b, &rep); err != nil {
				t.Fatal(err)
			}
			if len(rep.Files) != 1 || !tt.wantKind[rep.Files[0].Kind] {
				t.Errorf("files = %+v, want one file with kind in %v", rep.Files, tt.wantKind)
			}
			for _, f := range rep.Findings {
				if strings.HasPrefix(f.RuleID, "GAL-BIN-") {
					t.Errorf("unexpected binary finding %s", f.RuleID)
				}
			}
		})
	}
}
