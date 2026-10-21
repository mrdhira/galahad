package protocol_test

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/mrdhira/galahad/internal/protocol"
)

var testRule = protocol.Rule{ID: "GAL-EXEC-001", Severity: protocol.SeverityHigh, Title: "Auto execution", Attack: "T1204.002"}

func validResult() protocol.Result {
	start := time.Date(2026, 10, 20, 12, 0, 0, 123456789, time.UTC)
	f := testRule.Finding(protocol.Evidence{Path: "lure.eml!/invoice.pdf.lnk", Line: 3, Snippet: "cmd /c calc"})
	f.Analyzer = "autoexec"
	return protocol.Result{
		SchemaVersion: protocol.SchemaVersion,
		Tool:          protocol.Tool{Name: "galahad-agent", Version: "dev"},
		Target:        protocol.Target{Name: "lure.eml", Kind: "file", Size: 10, SHA256: "ab", FileCount: 1},
		StartedAt:     start,
		FinishedAt:    start.Add(time.Second),
		Files:         []protocol.FileInfo{{Path: "lure.eml", Size: 10, Kind: "text", SHA256: "ab", Entropy: 4.5}},
		Findings:      []protocol.Finding{f},
		IOCs:          []protocol.IOC{{Type: "url", Value: "http://example.com/x", Path: "lure.eml", Line: 2}},
		Coverage: protocol.Coverage{
			FilesSeen: 1, FilesAnalyzed: 1,
			Skipped:   []protocol.Skip{{Path: "big.bin", Reason: "too_large"}},
			Analyzers: []string{"autoexec"},
		},
		Verdict: protocol.VerdictSuspicious, Score: 40, Confidence: 70, ConfidenceLevel: "medium",
		Reasons: []string{"auto execution"},
	}
}

func TestVerdictExitCode(t *testing.T) {
	tests := []struct {
		name     string
		verdict  protocol.Verdict
		wantCode int
	}{
		{name: "clean", verdict: protocol.VerdictClean, wantCode: 0},
		{name: "suspicious", verdict: protocol.VerdictSuspicious, wantCode: 10},
		{name: "malicious", verdict: protocol.VerdictMalicious, wantCode: 20},
		{name: "not scored", verdict: "", wantCode: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.verdict.ExitCode(); got != tt.wantCode {
				t.Errorf("ExitCode(%q) = %d, want %d", tt.verdict, got, tt.wantCode)
			}
		})
	}
}

func TestRuleFinding(t *testing.T) {
	ev := []protocol.Evidence{{Path: "a", Line: 1, Snippet: "x"}, {Path: "b"}}
	tests := []struct {
		name string
		ev   []protocol.Evidence
		want protocol.Finding
	}{
		{
			name: "copies rule fields and keeps evidence order",
			ev:   ev,
			want: protocol.Finding{RuleID: "GAL-EXEC-001", Severity: protocol.SeverityHigh, Title: "Auto execution", Attack: "T1204.002", Evidence: ev},
		},
		{name: "no evidence", ev: nil, want: protocol.Finding{RuleID: "GAL-EXEC-001", Severity: protocol.SeverityHigh, Title: "Auto execution", Attack: "T1204.002"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := testRule.Finding(tt.ev...); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Finding = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestValidate(t *testing.T) {
	manyFindings := func(r *protocol.Result, n int) {
		f := r.Findings[0]
		r.Findings = nil
		for i := range n {
			g := f
			g.Evidence = []protocol.Evidence{{Path: "f" + strings.Repeat("x", i%1000) + string(rune('a'+i/1000))}}
			r.Findings = append(r.Findings, g)
		}
	}
	tests := []struct {
		name    string
		mutate  func(r *protocol.Result)
		wantErr string // substring; empty means valid
	}{
		{name: "complete valid result", mutate: func(r *protocol.Result) {}},
		{name: "not yet scored result", mutate: func(r *protocol.Result) { r.Verdict, r.ConfidenceLevel = "", "" }},
		{name: "wrong schema version", mutate: func(r *protocol.Result) { r.SchemaVersion = 2 }, wantErr: "schema_version"},
		{name: "tool name has control character", mutate: func(r *protocol.Result) { r.Tool.Name = "a\x1b" }, wantErr: "tool.name"},
		{name: "tool version has invalid UTF-8", mutate: func(r *protocol.Result) { r.Tool.Version = "\xff" }, wantErr: "tool.version"},
		{name: "target name too long", mutate: func(r *protocol.Result) { r.Target.Name = strings.Repeat("a", protocol.MaxPath+1) }, wantErr: "target.name is"},
		{name: "target name has bidi character", mutate: func(r *protocol.Result) { r.Target.Name = "a\u202eb" }, wantErr: "target.name has"},
		{name: "target kind unknown", mutate: func(r *protocol.Result) { r.Target.Kind = "repo" }, wantErr: "target.kind"},
		{name: "target kind dir", mutate: func(r *protocol.Result) { r.Target.Kind = protocol.TargetDir }},
		{name: "unknown verdict", mutate: func(r *protocol.Result) { r.Verdict = "evil" }, wantErr: "verdict"},
		{name: "unknown confidence level", mutate: func(r *protocol.Result) { r.ConfidenceLevel = "huge" }, wantErr: "confidence_level"},
		{name: "score below 0", mutate: func(r *protocol.Result) { r.Score = -1 }, wantErr: "score"},
		{name: "score above 100", mutate: func(r *protocol.Result) { r.Score = 101 }, wantErr: "score"},
		{name: "confidence below 0", mutate: func(r *protocol.Result) { r.Confidence = -1 }, wantErr: "confidence "},
		{name: "confidence above 100", mutate: func(r *protocol.Result) { r.Confidence = 101 }, wantErr: "confidence "},
		{name: "too many findings", mutate: func(r *protocol.Result) { manyFindings(r, protocol.MaxFindings+1) }, wantErr: "findings, max"},
		{name: "too many iocs", mutate: func(r *protocol.Result) { r.IOCs = make([]protocol.IOC, protocol.MaxIOCs+1) }, wantErr: "iocs, max"},
		{name: "file path empty", mutate: func(r *protocol.Result) { r.Files[0].Path = "" }, wantErr: "files[0]: path is empty"},
		{name: "file kind has control character", mutate: func(r *protocol.Result) { r.Files[0].Kind = "a\x1b" }, wantErr: "files[0]: kind"},
		{name: "rule id malformed", mutate: func(r *protocol.Result) { r.Findings[0].RuleID = "gal-exec-1" }, wantErr: "rule_id"},
		{name: "severity unknown", mutate: func(r *protocol.Result) { r.Findings[0].Severity = "huge" }, wantErr: "severity"},
		{name: "attack malformed", mutate: func(r *protocol.Result) { r.Findings[0].Attack = "T12" }, wantErr: "attack"},
		{name: "attack empty is allowed", mutate: func(r *protocol.Result) { r.Findings[0].Attack = "" }},
		{name: "attack without sub-technique is allowed", mutate: func(r *protocol.Result) { r.Findings[0].Attack = "T1204" }},
		{name: "analyzer has control character", mutate: func(r *protocol.Result) { r.Findings[0].Analyzer = "a\x1b" }, wantErr: "analyzer"},
		{name: "title has invalid UTF-8", mutate: func(r *protocol.Result) { r.Findings[0].Title = "\xff" }, wantErr: "title"},
		{name: "title has control character", mutate: func(r *protocol.Result) { r.Findings[0].Title = "a\x1bb" }, wantErr: "title"},
		{name: "title has bidi character", mutate: func(r *protocol.Result) { r.Findings[0].Title = "a\u202eb" }, wantErr: "title"},
		{name: "no evidence", mutate: func(r *protocol.Result) { r.Findings[0].Evidence = nil }, wantErr: "no evidence"},
		{name: "evidence path empty", mutate: func(r *protocol.Result) { r.Findings[0].Evidence[0].Path = "" }, wantErr: "path is empty"},
		{name: "evidence path too long", mutate: func(r *protocol.Result) { r.Findings[0].Evidence[0].Path = strings.Repeat("a", protocol.MaxPath+1) }, wantErr: "max 1024"},
		{name: "evidence path has NUL", mutate: func(r *protocol.Result) { r.Findings[0].Evidence[0].Path = "a\x00b" }, wantErr: "NUL"},
		{name: "evidence path is absolute", mutate: func(r *protocol.Result) { r.Findings[0].Evidence[0].Path = "/etc/passwd" }, wantErr: "starts with /"},
		{name: "evidence path has control character", mutate: func(r *protocol.Result) { r.Findings[0].Evidence[0].Path = "a\x1bb" }, wantErr: "path has control"},
		{name: "evidence path has bidi character", mutate: func(r *protocol.Result) { r.Findings[0].Evidence[0].Path = "a\u202eb" }, wantErr: "path has control"},
		{name: "evidence path has 8-bit CSI byte", mutate: func(r *protocol.Result) { r.Findings[0].Evidence[0].Path = "a\x9b[2J" }, wantErr: "path has control"},
		{name: "snippet too long", mutate: func(r *protocol.Result) {
			r.Findings[0].Evidence[0].Snippet = strings.Repeat("é", protocol.MaxSnippet+1)
		}, wantErr: "snippet has 201 runes"},
		{name: "snippet at the limit", mutate: func(r *protocol.Result) {
			r.Findings[0].Evidence[0].Snippet = strings.Repeat("é", protocol.MaxSnippet)
		}},
		{name: "snippet has control character", mutate: func(r *protocol.Result) { r.Findings[0].Evidence[0].Snippet = "a\nb" }, wantErr: "snippet has control"},
		{name: "snippet has bidi character", mutate: func(r *protocol.Result) { r.Findings[0].Evidence[0].Snippet = "a\u2067b" }, wantErr: "snippet has control"},
		{name: "too many findings of one rule in one file", mutate: func(r *protocol.Result) {
			for range protocol.MaxFindingsPerRulePerFile {
				r.Findings = append(r.Findings, r.Findings[0])
			}
		}, wantErr: "more than 20 findings"},
		{name: "findings of one rule at the per-file limit", mutate: func(r *protocol.Result) {
			for range protocol.MaxFindingsPerRulePerFile - 1 {
				r.Findings = append(r.Findings, r.Findings[0])
			}
		}},
		{name: "ioc type unknown", mutate: func(r *protocol.Result) { r.IOCs[0].Type = "hash" }, wantErr: "iocs[0]: type"},
		{name: "ioc value has control character", mutate: func(r *protocol.Result) { r.IOCs[0].Value = "http://a\x1b" }, wantErr: "value has control"},
		{name: "ioc value has bidi character", mutate: func(r *protocol.Result) { r.IOCs[0].Value = "http://a\u202e" }, wantErr: "value has control"},
		{name: "ioc path is absolute", mutate: func(r *protocol.Result) { r.IOCs[0].Path = "/x" }, wantErr: "iocs[0]: path"},
		{name: "skip path is absolute", mutate: func(r *protocol.Result) { r.Coverage.Skipped[0].Path = "/x" }, wantErr: "coverage.skipped[0]: path"},
		{name: "skip reason unknown", mutate: func(r *protocol.Result) { r.Coverage.Skipped[0].Reason = "lazy" }, wantErr: "reason"},
		{name: "coverage analyzer has control character", mutate: func(r *protocol.Result) { r.Coverage.Analyzers[0] = "a\x1b" }, wantErr: "coverage.analyzers[0]"},
		{name: "reason too long", mutate: func(r *protocol.Result) { r.Reasons[0] = strings.Repeat("a", protocol.MaxReason+1) }, wantErr: "reasons[0]: 401 runes"},
		{name: "reason has control character", mutate: func(r *protocol.Result) { r.Reasons[0] = "a\nb" }, wantErr: "reasons[0]: text"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := validResult()
			tt.mutate(&r)
			err := r.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Validate() = %v, want error containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestResultJSON(t *testing.T) {
	tests := []struct {
		name     string
		result   protocol.Result
		wantKeys []string
	}{
		{
			name:     "round trip is lossless with snake_case keys",
			result:   validResult(),
			wantKeys: []string{"schema_version", "started_at", "finished_at", "confidence_level", "tool", "target", "files", "findings", "iocs", "coverage", "verdict", "score", "confidence", "reasons"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.result)
			if err != nil {
				t.Fatal(err)
			}
			var raw map[string]json.RawMessage
			if err := json.Unmarshal(data, &raw); err != nil {
				t.Fatal(err)
			}
			for _, k := range tt.wantKeys {
				if _, ok := raw[k]; !ok {
					t.Errorf("missing key %q", k)
				}
			}
			var got protocol.Result
			if err := json.Unmarshal(data, &got); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tt.result) {
				t.Errorf("round trip changed result:\n got %+v\nwant %+v", got, tt.result)
			}
		})
	}
}

func TestSkipHidesContent(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		reason string
		// expectations
		wantHides bool
	}{
		{name: "too large", reason: protocol.SkipTooLarge, wantHides: true},
		{name: "budget", reason: protocol.SkipBudget, wantHides: true},
		{name: "depth", reason: protocol.SkipDepth, wantHides: true},
		{name: "encrypted", reason: protocol.SkipEncrypted, wantHides: true},
		{name: "unsupported", reason: protocol.SkipUnsupported},
		{name: "parse error", reason: protocol.SkipParseError},
		{name: "timeout", reason: protocol.SkipTimeout},
		{name: "panic", reason: protocol.SkipPanic},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := (protocol.Skip{Path: "a", Reason: tt.reason}).HidesContent(); got != tt.wantHides {
				t.Errorf("HidesContent() = %v, want %v", got, tt.wantHides)
			}
		})
	}
}
