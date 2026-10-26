package acceptance_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// TestReportAIOpinions covers the "AI opinions" report section (T3.4c, P9) from the user's side.
// Each case scans a fixture through the fake sandbox and then puts a fixed decision from
// testdata/corpus/ai-opinions into the job's report.json, so every status can be shown without a provider
// (TestScanDecision covers the real decision step). "galahad report <id>" must show it. summary.md and report.html only come out of a scan, so
// their Decision cases are in internal/report/ai_test.go.
func TestReportAIOpinions(t *testing.T) {
	const reasonRaised = "AI opinion (mock): malicious 92%, raised to suspicious; an AI opinion never makes a verdict malicious"
	tests := []struct {
		name string
		// inputs
		target   string // fixture in testdata/corpus
		decision string // file in testdata/corpus/ai-opinions, or "" for none
		raise    bool   // the scan was capped: verdict suspicious, score 20 and the AI reason, as scoring writes them
		corrupt  bool   // the decision says status ok but has no answers
		args     []string
		// expectations
		wantCode         int
		wantStdout       []string
		wantStdoutAbsent []string
		wantStderr       string
		wantDecision     bool // --json holds the decision of the fixture, unchanged
		wantNoDecision   bool // --json has no decision key
	}{
		{
			name:   "a capped scan shows raised to suspicious and keeps the provider text off the terminal",
			target: "benign-husky-lint", decision: "ok-raised", raise: true, args: []string{"report", "{id}"},
			wantCode:         10,
			wantStdout:       []string{"Verdict: SUSPICIOUS", "AI opinion (mock): malicious 92%, raised to suspicious"},
			wantStdoutAbsent: []string{"fake-model", "req_123", "api.mock.test", "hxxps://api"},
		},
		{
			name:   "report --json holds decision.sent as the fixture wrote it",
			target: "benign-husky-lint", decision: "ok-raised", raise: true, args: []string{"report", "{id}", "--json"},
			wantCode: 10, wantDecision: true,
		},
		{
			name:   "a malicious static verdict stays malicious: no change",
			target: "fake-interview-repo", decision: "ok-raised", args: []string{"report", "{id}"},
			wantCode:         20,
			wantStdout:       []string{"Verdict: MALICIOUS", "AI opinion (mock): malicious 92%, no change", "tasks.json:7"},
			wantStdoutAbsent: []string{"raised to suspicious"},
		},
		{
			name:   "a low opinion changes nothing",
			target: "benign-husky-lint", decision: "ok-nochange", args: []string{"report", "{id}"},
			wantCode:         0,
			wantStdout:       []string{"Verdict: CLEAN", "AI opinion (mock): malicious 10%, no change"},
			wantStdoutAbsent: []string{"raised to suspicious"},
		},
		{
			name:   "a provider that timed out leaves a malicious verdict as it was",
			target: "fake-interview-repo", decision: "failed-timeout", args: []string{"report", "{id}"},
			wantCode:         20,
			wantStdout:       []string{"Verdict: MALICIOUS", "AI opinion (mock): unavailable (timeout: the provider did not answer in time)"},
			wantStdoutAbsent: []string{"raised to suspicious"},
		},
		{
			name:   "a provider that answered 402 leaves a clean verdict as it was",
			target: "benign-husky-lint", decision: "failed-402", args: []string{"report", "{id}"},
			wantCode:         0,
			wantStdout:       []string{"Verdict: CLEAN", "AI opinion (mock): unavailable (status 402: insufficient credit)"},
			wantStdoutAbsent: []string{"raised to suspicious"},
		},
		{
			name:   "nothing to judge is skipped",
			target: "benign-go-cli", decision: "skipped", args: []string{"report", "{id}"},
			wantCode:   0,
			wantStdout: []string{"Verdict: CLEAN", "AI opinion (mock): skipped: no findings to send"},
		},
		{
			name:   "hostile provider text does not reach the terminal",
			target: "fake-interview-repo", decision: "hostile", args: []string{"report", "{id}"},
			wantCode:         20,
			wantStdout:       []string{"AI opinion (mock): malicious 92%, no change"},
			wantStdoutAbsent: []string{"<script", "<img", "click", "javascript:", "https://e.test", "onerror"},
		},
		{
			name:   "hostile error text is defanged on the terminal",
			target: "fake-interview-repo", decision: "hostile-error", args: []string{"report", "{id}"},
			wantCode:         20,
			wantStdout:       []string{"AI opinion (mock): unavailable (invalid: "},
			wantStdoutAbsent: []string{"https://e.test", "<script>alert(1)</script>[click](https"},
		},
		{
			name:   "a scan without a decision has no AI line and no decision key",
			target: "fake-interview-repo", args: []string{"report", "{id}", "--json"},
			wantCode: 20, wantNoDecision: true,
		},
		{
			name:   "a scan without a decision prints no AI line",
			target: "fake-interview-repo", args: []string{"report", "{id}"},
			wantCode:         20,
			wantStdout:       []string{"Verdict: MALICIOUS"},
			wantStdoutAbsent: []string{"AI opinion"},
		},
		{
			name:   "a decision that does not fit its status is an error",
			target: "benign-husky-lint", decision: "ok-raised", corrupt: true, args: []string{"report", "{id}"},
			wantCode: 1, wantStderr: "decision",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given a scanned job whose report.json holds the decision
			home := t.TempDir()
			if _, stderr, code := scan(t, home, corpus(t, tt.target)); code == 1 || code == 2 {
				t.Fatalf("scan exit = %d\n%s", code, stderr)
			}
			dir := onlyJob(t, home)
			id := filepath.Base(dir)
			var want any
			if tt.decision != "" {
				path := filepath.Join(dir, "report.json")
				var res map[string]any
				if err := json.Unmarshal([]byte(readFile(t, path)), &res); err != nil {
					t.Fatal(err)
				}
				if err := json.Unmarshal([]byte(readFile(t, corpus(t, "ai-opinions")+"/"+tt.decision+".json")), &want); err != nil {
					t.Fatal(err)
				}
				d := want.(map[string]any)
				if tt.corrupt {
					d = map[string]any{}
					for k, v := range want.(map[string]any) {
						d[k] = v
					}
					delete(d, "answers")
				}
				res["decision"] = d
				if tt.raise {
					res["verdict"], res["score"] = "suspicious", 20
					res["reasons"] = append(res["reasons"].([]any), reasonRaised)
				}
				out, err := json.MarshalIndent(res, "", "  ")
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, out, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			args := make([]string, len(tt.args))
			for i, a := range tt.args {
				args[i] = strings.ReplaceAll(a, "{id}", id)
			}

			// When the report is printed
			stdout, stderr, code := run(t, args...)

			// Then the exit code is the verdict's, and the section matches
			if code != tt.wantCode {
				t.Fatalf("exit = %d, want %d\nstdout: %s\nstderr: %s", code, tt.wantCode, stdout, stderr)
			}
			for _, w := range tt.wantStdout {
				if !strings.Contains(stdout, w) {
					t.Errorf("stdout lacks %q:\n%s", w, stdout)
				}
			}
			for _, a := range tt.wantStdoutAbsent {
				if strings.Contains(stdout, a) {
					t.Errorf("stdout has %q:\n%s", a, stdout)
				}
			}
			if !strings.Contains(stderr, tt.wantStderr) {
				t.Errorf("stderr lacks %q:\n%s", tt.wantStderr, stderr)
			}
			if tt.wantDecision || tt.wantNoDecision {
				var got map[string]any
				if err := json.Unmarshal([]byte(stdout), &got); err != nil {
					t.Fatalf("stdout is not JSON: %v\n%s", err, stdout)
				}
				if tt.wantNoDecision {
					if _, ok := got["decision"]; ok {
						t.Errorf("--json has a decision key without a decision")
					}
				}
				if tt.wantDecision && !reflect.DeepEqual(got["decision"], want) {
					t.Errorf("--json decision differs from the fixture:\n%v\nwant:\n%v", got["decision"], want)
				}
			}
		})
	}
}
