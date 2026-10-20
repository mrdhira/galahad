package report_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/mrdhira/galahad/internal/protocol"
	"github.com/mrdhira/galahad/internal/report"
)

var refDef = regexp.MustCompile(`^\s*(- |\| )?\[[.@]\]:`)

func result(snippet, path string) *protocol.Result {
	ev := protocol.Evidence{Path: path, Line: 3, Snippet: snippet}
	return &protocol.Result{
		SchemaVersion: protocol.SchemaVersion,
		Tool:          protocol.Tool{Name: "galahad-agent", Version: "test"},
		Target:        protocol.Target{Name: "sample", Kind: protocol.TargetDir, Size: 10, SHA256: strings.Repeat("a", 64), FileCount: 1},
		StartedAt:     time.Unix(0, 0).UTC(),
		FinishedAt:    time.Unix(1, 0).UTC(),
		Files:         []protocol.FileInfo{},
		Findings: []protocol.Finding{
			{RuleID: "GAL-SIG-001", Severity: protocol.SeverityCritical, Title: "Known test signature", Attack: "T1204", Analyzer: "signature", Evidence: []protocol.Evidence{ev}},
			{RuleID: "GAL-AUTOEXEC-001", Severity: protocol.SeverityMedium, Title: "Runs on install", Attack: "T1059", Analyzer: "autoexec", Evidence: []protocol.Evidence{{Path: "package.json", Line: 1, Snippet: "postinstall"}}},
			{RuleID: "GAL-X-001", Severity: protocol.SeverityLow, Title: "No evidence", Analyzer: "x"},
		},
		IOCs: []protocol.IOC{
			{Type: "url", Value: "https://collect.sinkhole.test/k", Path: "a.txt", Line: 1},
			{Type: "email", Value: "who@sinkhole.test", Path: "a.txt", Line: 2},
		},
		Coverage:        protocol.Coverage{FilesSeen: 2, FilesAnalyzed: 1, Skipped: []protocol.Skip{{Path: "big.bin", Reason: "too_large"}}, Analyzers: []string{"signature"}},
		Verdict:         protocol.VerdictMalicious,
		Score:           100,
		Confidence:      90,
		ConfidenceLevel: "high",
		Reasons:         []string{"hard trigger GAL-SIG-001 (critical) at a.txt:3"},
	}
}

func TestWrite(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		snippet string
		path    string
		reasons []string
		// expectations
		wantBoth       []string // in summary.md and report.html
		wantMD         []string
		wantHTML       []string
		wantNeitherHas []string // absent from both
		wantMDAbsent   []string
		wantHTMLAbsent []string
	}{
		{
			name:           "plain result renders every section with defanged URLs",
			snippet:        "curl https://collect.sinkhole.test/k",
			path:           "a.txt",
			wantBoth:       []string{"GAL-SIG-001", "GAL-AUTOEXEC-001", "hxxps://collect[.]sinkhole[.]test/k", "who[@]sinkhole[.]test", "T1204", "a.txt:3", "big.bin"},
			wantMD:         []string{"## Findings (3)", "## Auto-execution inventory (1)", "## IOCs (2)", "## Coverage"},
			wantHTML:       []string{`content="default-src 'none'; style-src 'unsafe-inline'"`, "Auto-execution inventory (1)", "IOCs (2)", "Coverage"},
			wantNeitherHas: []string{"https://collect.sinkhole.test", "who@sinkhole.test", "href=", "<script", "src="},
		},
		{
			name:           "script tag in a snippet is escaped",
			snippet:        "<script>alert(1)</script>",
			path:           "a.txt",
			wantMD:         []string{`&lt;script&gt;alert\(1\)&lt;/script&gt;`},
			wantHTML:       []string{"&lt;script&gt;alert(1)&lt;/script&gt;"},
			wantNeitherHas: []string{"<script", "</script"},
		},
		{
			name:           "img onerror breakout in snippet and path is escaped",
			snippet:        `"><img src=x onerror=alert(1)>`,
			path:           `x"><img src=y onerror=1>.txt`,
			wantMD:         []string{`&lt;img src=x onerror=alert\(1\)&gt;`},
			wantHTML:       []string{"&#34;&gt;&lt;img src=x onerror=alert(1)&gt;"},
			wantNeitherHas: []string{"<img", `"><img`},
		},
		{
			name:           "markdown link, image, pipe and backtick cannot become markup",
			snippet:        "[x](javascript:alert(1)) ![i](http://e.test/p.png) a|b `c`",
			path:           "a|b.txt",
			wantMD:         []string{`\[x\]\(javascript:alert\(1\)\)`, `!\[i\]`, `a\|b`, "\\`c\\`"},
			wantNeitherHas: []string{"http://e.test"},
			wantMDAbsent:   []string{"](javascript", "](http"},
		},
		{
			name:         "link reference definitions cannot turn defang markers into links",
			snippet:      "![.] evil[.]test",
			path:         "a.txt",
			reasons:      []string{"[.]: //evil.test/t", "[@]: javascript:x"},
			wantMD:       []string{`\[.]: //evil.test/t`, `\[@]: javascript:x`, `\![.] evil[.]test`},
			wantMDAbsent: []string{"\n- [.]:", "\n- [@]:", " ![.]"},
		},
		{
			name:           "www host and newline are neutralized",
			snippet:        "www.evil.test\n# heading",
			path:           "a.txt",
			wantMD:         []string{"www[.]evil.test # heading"},
			wantNeitherHas: []string{"\n# heading"},
			wantMDAbsent:   []string{"www.evil.test"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given a result with untrusted text
			res := result(tt.snippet, tt.path)
			if tt.reasons != nil {
				res.Reasons = tt.reasons
			}
			dir := filepath.Join(t.TempDir(), "out", "nested")

			// When the reports are written
			paths, err := report.Write(dir, res)
			if err != nil {
				t.Fatal(err)
			}

			// Then report.json is the result and the other files escape and defang
			want, _ := json.MarshalIndent(res, "", "  ")
			if got := read(t, paths.JSON); got != string(want)+"\n" {
				t.Errorf("report.json differs from the result")
			}
			md, html := read(t, paths.Markdown), read(t, paths.HTML)
			check(t, "summary.md", md, append(tt.wantBoth, tt.wantMD...), append(tt.wantNeitherHas, tt.wantMDAbsent...))
			check(t, "report.html", html, append(tt.wantBoth, tt.wantHTML...), append(tt.wantNeitherHas, tt.wantHTMLAbsent...))
			for _, l := range strings.Split(md, "\n") {
				if refDef.MatchString(l) {
					t.Errorf("summary.md line %q can define a link reference", l)
				}
			}
			if runtime.GOOS != "windows" {
				checkMode(t, dir, 0o750)
				for _, p := range []string{paths.JSON, paths.Markdown, paths.HTML} {
					checkMode(t, p, 0o600)
				}
			}
		})
	}
}

func TestWriteLimits(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		findings int
		iocs     int
		// expectations
		wantMDFindings int
		wantMDIOCs     int
		wantHTMLIOCs   int
	}{
		{name: "few items are all listed", findings: 3, iocs: 3, wantMDFindings: 3, wantMDIOCs: 3, wantHTMLIOCs: 3},
		{name: "summary.md keeps top 10 findings and 20 IOCs, html keeps all", findings: 25, iocs: 40, wantMDFindings: 10, wantMDIOCs: 20, wantHTMLIOCs: 40},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := result("s", "a.txt")
			res.Findings, res.IOCs = nil, nil
			for i := 0; i < tt.findings; i++ {
				res.Findings = append(res.Findings, protocol.Finding{RuleID: "GAL-R-001", Severity: protocol.SeverityLow, Title: "t", Evidence: []protocol.Evidence{{Path: "a", Line: i + 1}}})
			}
			for i := 0; i < tt.iocs; i++ {
				res.IOCs = append(res.IOCs, protocol.IOC{Type: "ip", Value: "192.0.2.1", Path: "a", Line: i + 1})
			}

			paths, err := report.Write(t.TempDir(), res)
			if err != nil {
				t.Fatal(err)
			}

			md := read(t, paths.Markdown)
			if n := strings.Count(md, "| low |"); n != tt.wantMDFindings {
				t.Errorf("finding rows = %d, want %d", n, tt.wantMDFindings)
			}
			if n := strings.Count(md, "| ip |"); n != tt.wantMDIOCs {
				t.Errorf("ioc rows = %d, want %d", n, tt.wantMDIOCs)
			}
			if n := strings.Count(read(t, paths.HTML), "192[.]0[.]2[.]1"); n != tt.wantHTMLIOCs {
				t.Errorf("html IOCs = %d, want %d", n, tt.wantHTMLIOCs)
			}
		})
	}
}

func TestWriteError(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		dir func(t *testing.T) string
	}{
		{name: "directory path is under a file", dir: func(t *testing.T) string {
			f := filepath.Join(t.TempDir(), "f")
			if err := os.WriteFile(f, nil, 0o600); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(f, "sub")
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := report.Write(tt.dir(t), result("s", "a")); err == nil {
				t.Error("Write succeeded, want an error")
			}
		})
	}
}

func TestTerminal(t *testing.T) {
	paths := report.Paths{JSON: "/o/report.json", Markdown: "/o/summary.md", HTML: "/o/report.html"}
	tests := []struct {
		name string
		// inputs
		mutate func(*protocol.Result)
		color  bool
		// expectations
		wantContain []string
		wantAbsent  []string
	}{
		{
			name: "plain output",
			wantContain: []string{
				"Verdict: MALICIOUS", "Score: 100/100  Confidence: 90% (high)",
				"CRITICAL GAL-SIG-001 a.txt:3 Known test signature", "MEDIUM GAL-AUTOEXEC-001 package.json:1 Runs on install",
				"LOW GAL-X-001 No evidence", "/o/report.html", "/o/summary.md", "/o/report.json",
			},
			wantAbsent: []string{"\x1b["},
		},
		{
			name:        "color adds escape codes",
			color:       true,
			wantContain: []string{"\x1b[31m", "Known test signature"},
		},
		{
			name: "untrusted text is defanged and stripped of control characters",
			mutate: func(r *protocol.Result) {
				r.Findings[0].Evidence[0].Path = "\x1b[2J https://e.test/x\nnext"
			},
			wantContain: []string{"hxxps://e[.]test/x next:3"},
			wantAbsent:  []string{"\x1b", "https://e.test"},
		},
		{
			name: "more than ten findings are cut",
			mutate: func(r *protocol.Result) {
				for i := 0; i < 12; i++ {
					r.Findings = append(r.Findings, protocol.Finding{RuleID: "GAL-R-001", Severity: protocol.SeverityInfo, Title: "t"})
				}
			},
			wantContain: []string{"... 5 more in report.json"},
		},
		{
			name:        "suspicious verdict is yellow",
			mutate:      func(r *protocol.Result) { r.Verdict, r.Findings = protocol.VerdictSuspicious, nil },
			color:       true,
			wantContain: []string{"Verdict: \x1b[1m\x1b[33mSUSPICIOUS"},
		},
		{
			name:        "clean verdict is green",
			mutate:      func(r *protocol.Result) { r.Verdict, r.Findings = protocol.VerdictClean, nil },
			color:       true,
			wantContain: []string{"\x1b[32mCLEAN"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := result("s", "a.txt")
			if tt.mutate != nil {
				tt.mutate(res)
			}
			var b bytes.Buffer

			report.Terminal(&b, res, paths, tt.color)

			check(t, "output", b.String(), tt.wantContain, tt.wantAbsent)
		})
	}
}

func check(t *testing.T, name, got string, want, absent []string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(got, w) {
			t.Errorf("%s lacks %q:\n%s", name, w, got)
		}
	}
	for _, a := range absent {
		if strings.Contains(got, a) {
			t.Errorf("%s contains %q:\n%s", name, a, got)
		}
	}
}

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func checkMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != want {
		t.Errorf("%s mode = %v, want %v", path, st.Mode().Perm(), want)
	}
}
