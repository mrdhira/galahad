package protocol_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"slices"
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
		{name: "tool name too long", mutate: func(r *protocol.Result) { r.Tool.Name = strings.Repeat("a", protocol.MaxName+1) }, wantErr: "tool.name is 65 bytes"},
		{name: "tool version too long", mutate: func(r *protocol.Result) { r.Tool.Version = strings.Repeat("a", protocol.MaxName+1) }, wantErr: "tool.version is 65 bytes"},
		{name: "target name too long", mutate: func(r *protocol.Result) { r.Target.Name = strings.Repeat("a", protocol.MaxPath+1) }, wantErr: "target.name is"},
		{name: "target name has bidi character", mutate: func(r *protocol.Result) { r.Target.Name = "a\u202eb" }, wantErr: "target.name has"},
		{name: "target sha256 too long", mutate: func(r *protocol.Result) { r.Target.SHA256 = strings.Repeat("a", protocol.MaxName+1) }, wantErr: "target.sha256 is 65 bytes"},
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
		{name: "too many files", mutate: func(r *protocol.Result) { r.Files = make([]protocol.FileInfo, protocol.MaxFiles+1) }, wantErr: "files, max"},
		{name: "too many skipped", mutate: func(r *protocol.Result) { r.Coverage.Skipped = make([]protocol.Skip, protocol.MaxSkipped+1) }, wantErr: "skipped, max"},
		{name: "too many analyzers", mutate: func(r *protocol.Result) { r.Coverage.Analyzers = make([]string, protocol.MaxAnalyzers+1) }, wantErr: "analyzers, max"},
		{name: "too many reasons", mutate: func(r *protocol.Result) { r.Reasons = make([]string, protocol.MaxReasonCount+1) }, wantErr: "reasons, max"},
		{name: "files at the limit", mutate: func(r *protocol.Result) {
			r.Files = slices.Repeat(r.Files, protocol.MaxFiles)
			r.Coverage.Skipped = slices.Repeat(r.Coverage.Skipped, protocol.MaxSkipped)
			r.Coverage.Analyzers = slices.Repeat(r.Coverage.Analyzers, protocol.MaxAnalyzers)
			r.Reasons = slices.Repeat(r.Reasons, protocol.MaxReasonCount)
		}},
		{name: "network set by the host", mutate: func(r *protocol.Result) {
			r.Network = &protocol.Network{Events: []protocol.NetEvent{{Host: "api.osv.dev", Port: 443, Decision: protocol.DecisionAllowed, Count: 1}}}
		}},
		{name: "network invalid", mutate: func(r *protocol.Result) {
			r.Network = &protocol.Network{Events: []protocol.NetEvent{{Host: "api.osv.dev", Port: 0, Decision: protocol.DecisionAllowed, Count: 1}}}
		}, wantErr: "network: events[0]: port 0"},
		{name: "file path empty", mutate: func(r *protocol.Result) { r.Files[0].Path = "" }, wantErr: "files[0]: path is empty"},
		{name: "file kind has control character", mutate: func(r *protocol.Result) { r.Files[0].Kind = "a\x1b" }, wantErr: "files[0]: kind"},
		{name: "file kind too long", mutate: func(r *protocol.Result) { r.Files[0].Kind = strings.Repeat("a", protocol.MaxName+1) }, wantErr: "files[0]: kind is 65 bytes"},
		{name: "file sha256 has control character", mutate: func(r *protocol.Result) { r.Files[0].SHA256 = "a\x1b" }, wantErr: "files[0]: sha256 has control"},
		{name: "file sha256 too long", mutate: func(r *protocol.Result) { r.Files[0].SHA256 = strings.Repeat("a", protocol.MaxName+1) }, wantErr: "files[0]: sha256 is 65 bytes"},
		{name: "file entropy is not a number", mutate: func(r *protocol.Result) { r.Files[0].Entropy = math.NaN() }, wantErr: "entropy is not a finite number"},
		{name: "file entropy is infinite", mutate: func(r *protocol.Result) { r.Files[0].Entropy = math.Inf(1) }, wantErr: "entropy is not a finite number"},
		{name: "rule id malformed", mutate: func(r *protocol.Result) { r.Findings[0].RuleID = "gal-exec-1" }, wantErr: "rule_id"},
		{name: "rule id category too long", mutate: func(r *protocol.Result) { r.Findings[0].RuleID = "GAL-" + strings.Repeat("A", 17) + "-001" }, wantErr: "rule_id"},
		{name: "severity unknown", mutate: func(r *protocol.Result) { r.Findings[0].Severity = "huge" }, wantErr: "severity"},
		{name: "attack malformed", mutate: func(r *protocol.Result) { r.Findings[0].Attack = "T12" }, wantErr: "attack"},
		{name: "attack empty is allowed", mutate: func(r *protocol.Result) { r.Findings[0].Attack = "" }},
		{name: "attack without sub-technique is allowed", mutate: func(r *protocol.Result) { r.Findings[0].Attack = "T1204" }},
		{name: "analyzer has control character", mutate: func(r *protocol.Result) { r.Findings[0].Analyzer = "a\x1b" }, wantErr: "analyzer"},
		{name: "analyzer too long", mutate: func(r *protocol.Result) { r.Findings[0].Analyzer = strings.Repeat("a", protocol.MaxName+1) }, wantErr: "analyzer is 65 bytes"},
		{name: "title has invalid UTF-8", mutate: func(r *protocol.Result) { r.Findings[0].Title = "\xff" }, wantErr: "title"},
		{name: "title too long", mutate: func(r *protocol.Result) { r.Findings[0].Title = strings.Repeat("é", protocol.MaxTitle+1) }, wantErr: "title has 201 runes"},
		{name: "title at the limit", mutate: func(r *protocol.Result) { r.Findings[0].Title = strings.Repeat("é", protocol.MaxTitle) }},
		{name: "title has control character", mutate: func(r *protocol.Result) { r.Findings[0].Title = "a\x1bb" }, wantErr: "title"},
		{name: "title has bidi character", mutate: func(r *protocol.Result) { r.Findings[0].Title = "a\u202eb" }, wantErr: "title"},
		{name: "no evidence", mutate: func(r *protocol.Result) { r.Findings[0].Evidence = nil }, wantErr: "no evidence"},
		{name: "evidence at the limit", mutate: func(r *protocol.Result) {
			r.Findings[0].Evidence = slices.Repeat(r.Findings[0].Evidence, protocol.MaxEvidence)
		}},
		{name: "too many evidence entries", mutate: func(r *protocol.Result) {
			r.Findings[0].Evidence = slices.Repeat(r.Findings[0].Evidence, protocol.MaxEvidence+1)
		}, wantErr: "9 evidence entries, max 8"},
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
		{name: "ioc value as long as a pdf link target", mutate: func(r *protocol.Result) { r.IOCs[0].Value = "http://a.test/" + strings.Repeat("a", 1222) }},
		{name: "ioc value too long", mutate: func(r *protocol.Result) { r.IOCs[0].Value = strings.Repeat("a", protocol.MaxIOCValue+1) }, wantErr: "value is 2049 bytes"},
		{name: "ioc path is absolute", mutate: func(r *protocol.Result) { r.IOCs[0].Path = "/x" }, wantErr: "iocs[0]: path"},
		{name: "skip path is absolute", mutate: func(r *protocol.Result) { r.Coverage.Skipped[0].Path = "/x" }, wantErr: "coverage.skipped[0]: path"},
		{name: "skip reason unknown", mutate: func(r *protocol.Result) { r.Coverage.Skipped[0].Reason = "lazy" }, wantErr: "reason"},
		{name: "coverage analyzer has control character", mutate: func(r *protocol.Result) { r.Coverage.Analyzers[0] = "a\x1b" }, wantErr: "coverage.analyzers[0]"},
		{name: "coverage analyzer too long", mutate: func(r *protocol.Result) { r.Coverage.Analyzers[0] = strings.Repeat("a", protocol.MaxName+1) }, wantErr: "coverage.analyzers[0]: name is 65 bytes"},
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

func TestSkipUnreadAndHidesContent(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		path   string
		reason string
		// expectations
		wantUnread bool
		wantHides  bool
	}{
		{name: "too large is unread but hides nothing", path: "a", reason: protocol.SkipTooLarge, wantUnread: true},
		{name: "budget", path: "a", reason: protocol.SkipBudget, wantUnread: true, wantHides: true},
		{name: "depth", path: "a", reason: protocol.SkipDepth, wantUnread: true, wantHides: true},
		{name: "encrypted", path: "a", reason: protocol.SkipEncrypted, wantUnread: true, wantHides: true},
		{name: "unsupported top-level file", path: "a", reason: protocol.SkipUnsupported},
		{name: "unsupported container member", path: "a.zip!/b", reason: protocol.SkipUnsupported},
		{name: "parse error in a top-level file", path: "a", reason: protocol.SkipParseError},
		{name: "parse error in a container member", path: "a.zip!/b", reason: protocol.SkipParseError},
		{name: "member that could not be extracted", path: "a.zip!/b", reason: protocol.SkipUnreadable, wantUnread: true, wantHides: true},
		{name: "timeout", path: "a", reason: protocol.SkipTimeout, wantUnread: true, wantHides: true},
		{name: "panic", path: "a", reason: protocol.SkipPanic, wantUnread: true, wantHides: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := protocol.Skip{Path: tt.path, Reason: tt.reason}
			if s.Unread() != tt.wantUnread || s.HidesContent() != tt.wantHides {
				t.Errorf("Unread() = %v, HidesContent() = %v, want %v, %v", s.Unread(), s.HidesContent(), tt.wantUnread, tt.wantHides)
			}
		})
	}
}

func TestEncodeResult(t *testing.T) {
	// Text at its worst: a quote or backslash takes 2 bytes, U+2028 takes 6 (3 raw), and
	// EncodeResult does not escape HTML. Paths are capped in bytes, so quotes are their worst.
	quotes := func(n int) string { return strings.Repeat(`"`, n) }
	worstPath := quotes(protocol.MaxPath)
	worstName := quotes(protocol.MaxName)
	worstSnippet := strings.Repeat("\u2028", protocol.MaxSnippet)
	worstTitle := strings.Repeat("\u2028", protocol.MaxTitle)
	worstReason := strings.Repeat("\u2028", protocol.MaxReason)
	// Equal strings share their memory, which keeps the test cheap without changing the encoded
	// size. 100 rules with 20 findings each stay within the per-rule, per-file limit.
	worst := func() protocol.Result {
		r := validResult()
		r.Tool = protocol.Tool{Name: worstName, Version: worstName}
		r.Target.Name = quotes(protocol.MaxPath)
		r.Target.SHA256 = worstName
		r.Files = make([]protocol.FileInfo, protocol.MaxFiles)
		for i := range r.Files {
			r.Files[i] = protocol.FileInfo{Path: worstPath, Size: -1 << 62, Kind: worstName, SHA256: worstName, Entropy: -1.2345678901234567e-300}
		}
		ev := slices.Repeat([]protocol.Evidence{{Path: worstPath, Line: -1 << 62, Snippet: worstSnippet}}, protocol.MaxEvidence)
		r.Findings = make([]protocol.Finding, protocol.MaxFindings)
		for i := range r.Findings {
			r.Findings[i] = protocol.Finding{
				RuleID: fmt.Sprintf("GAL-%s-%03d", strings.Repeat("A", 16), i%100), Severity: protocol.SeverityCritical,
				Title: worstTitle, Attack: "T1204.002", Analyzer: worstName, Evidence: ev,
			}
		}
		r.IOCs = slices.Repeat([]protocol.IOC{{Type: "url", Value: quotes(protocol.MaxIOCValue), Path: worstPath, Line: -1 << 62}}, protocol.MaxIOCs)
		r.Coverage.Skipped = slices.Repeat([]protocol.Skip{{Path: worstPath, Reason: protocol.SkipUnsupported}}, protocol.MaxSkipped)
		r.Coverage.Analyzers = slices.Repeat([]string{worstName}, protocol.MaxAnalyzers)
		r.Reasons = slices.Repeat([]string{worstReason}, protocol.MaxReasonCount)
		return r
	}
	// lean is a small valid result with one IOC and one evidence entry, no files and no skips.
	// The cases below add one oversize list to it, beyond the caps, to reach each shrink step.
	const big = 23 << 20 // three of these do not fit in the 64 MiB frame
	bigText := strings.Repeat("a", big)
	lean := func() protocol.Result {
		r := validResult()
		r.Files = nil
		r.Coverage.Skipped = nil
		return r
	}
	tests := []struct {
		name string
		// inputs
		build   func() protocol.Result
		measure bool // log the size before shrinking
		// expectations
		wantErr       string
		wantPlain     bool // the output is the plain encoding of the result
		wantValid     bool
		wantTruncated bool
		wantFiles     int
		wantSkipped   int
		wantEvidence  int // of the first finding
		wantIOCs      int
	}{
		{
			name:      "a result that fits is encoded as it is",
			build:     validResult,
			wantPlain: true, wantValid: true,
			wantFiles: 1, wantSkipped: 1, wantEvidence: 1, wantIOCs: 1,
		},
		{
			name:  "every cap at its maximum with the worst text still fits after shrinking",
			build: worst, measure: true,
			wantValid: true, wantTruncated: true,
			wantFiles: 0, wantSkipped: 1, wantEvidence: protocol.MaxEvidence, wantIOCs: protocol.MaxIOCs,
		},
		{
			// What no step cuts, at its worst, is far under the limit, so the error below is
			// unreachable for a result within the caps.
			name: "the part that is never cut fits with room to spare",
			build: func() protocol.Result {
				r := worst()
				r.Files, r.Coverage.Skipped, r.IOCs = nil, nil, nil
				for i := range r.Findings {
					r.Findings[i].Evidence = r.Findings[i].Evidence[:1]
				}
				return r
			},
			measure:   true,
			wantPlain: true, wantValid: true,
			wantFiles: 0, wantSkipped: 0, wantEvidence: 1, wantIOCs: 0,
		},
		{
			name: "the files go first and the skipped list gets the budget skip",
			build: func() protocol.Result {
				r := lean()
				r.Files = slices.Repeat([]protocol.FileInfo{{Path: bigText}}, 3)
				return r
			},
			wantTruncated: true,
			wantFiles:     0, wantSkipped: 1, wantEvidence: 1, wantIOCs: 1,
		},
		{
			name: "the skipped list goes second",
			build: func() protocol.Result {
				r := lean()
				r.Coverage.Skipped = slices.Repeat([]protocol.Skip{{Path: bigText, Reason: protocol.SkipTimeout}}, 3)
				return r
			},
			wantTruncated: true,
			wantFiles:     0, wantSkipped: 1, wantEvidence: 1, wantIOCs: 1,
		},
		{
			name: "the evidence past the first entry goes third",
			build: func() protocol.Result {
				r := lean()
				r.Findings[0].Evidence = slices.Repeat([]protocol.Evidence{{Path: "a", Snippet: bigText}}, 3)
				return r
			},
			wantTruncated: true,
			wantFiles:     0, wantSkipped: 1, wantEvidence: 1, wantIOCs: 1,
		},
		{
			name: "the IOCs go last",
			build: func() protocol.Result {
				r := lean()
				r.IOCs = slices.Repeat([]protocol.IOC{{Type: "url", Value: bigText, Path: "a"}}, 3)
				return r
			},
			wantTruncated: true,
			wantFiles:     0, wantSkipped: 1, wantEvidence: 1, wantIOCs: 0,
		},
		{
			name: "findings are never cut, so an oversize finding is an error",
			build: func() protocol.Result {
				r := lean()
				r.Findings[0].Title = strings.Repeat("a", 65<<20)
				return r
			},
			wantErr: "after shrinking",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := tt.build()
			files, skipped := len(res.Files), len(res.Coverage.Skipped)

			data, err := protocol.EncodeResult(&res)

			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("EncodeResult = %v, want error containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("EncodeResult: %v", err)
			}
			if len(data) > 64<<20 {
				t.Errorf("encoded result is %d bytes, want at most %d", len(data), 64<<20)
			}
			if bytes.HasSuffix(data, []byte("\n")) {
				t.Error("encoded result ends in a newline")
			}
			if len(res.Files) != files || len(res.Coverage.Skipped) != skipped || res.Coverage.Truncated {
				t.Error("EncodeResult changed its argument")
			}
			if tt.wantPlain {
				want, err := json.Marshal(res)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(data, want) {
					t.Error("output differs from the plain encoding")
				}
			}
			if tt.measure {
				var plain bytes.Buffer
				enc := json.NewEncoder(&plain)
				enc.SetEscapeHTML(false)
				if err := enc.Encode(res); err != nil {
					t.Fatal(err)
				}
				t.Logf("encoded size: %d bytes before shrinking, %d after", plain.Len(), len(data))
			}
			var got protocol.Result
			if err := protocol.DecodeStrict(data, &got); err != nil {
				t.Fatalf("DecodeStrict: %v", err)
			}
			if tt.wantValid {
				if err := got.Validate(); err != nil {
					t.Errorf("Validate() = %v", err)
				}
			}
			if got.Coverage.Truncated != tt.wantTruncated {
				t.Errorf("Truncated = %v, want %v", got.Coverage.Truncated, tt.wantTruncated)
			}
			if sk := got.Coverage.Skipped; tt.wantTruncated && (len(sk) == 0 || sk[len(sk)-1].Reason != protocol.SkipBudget || !sk[len(sk)-1].HidesContent()) {
				t.Errorf("last skip = %+v, want a budget skip", sk)
			}
			if len(got.Findings) != len(res.Findings) || len(got.Reasons) != len(res.Reasons) {
				t.Errorf("%d findings and %d reasons, want %d and %d", len(got.Findings), len(got.Reasons), len(res.Findings), len(res.Reasons))
			}
			if len(got.Files) != tt.wantFiles || len(got.Coverage.Skipped) != tt.wantSkipped || len(got.Findings[0].Evidence) != tt.wantEvidence || len(got.IOCs) != tt.wantIOCs {
				t.Errorf("%d files, %d skipped, %d evidence, %d iocs; want %d, %d, %d, %d",
					len(got.Files), len(got.Coverage.Skipped), len(got.Findings[0].Evidence), len(got.IOCs),
					tt.wantFiles, tt.wantSkipped, tt.wantEvidence, tt.wantIOCs)
			}
		})
	}
}
