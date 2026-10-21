package report_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
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

var refDef = regexp.MustCompile(`(^|[^\\])\[[.@]\]:`)

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
			wantMD:       []string{`\[.\]: //evil.test/t`, `\[@\]: javascript:x`, `\!\[.\] evil[.]test`},
			wantMDAbsent: []string{"\n- [.]:", "\n- [@]:", " ![.]"},
		},
		{
			name:         "link reference definitions behind list markers are escaped",
			snippet:      "![.] evil[.]test",
			path:         "a.txt",
			reasons:      []string{"- [.]: //evil.test/n1", "+ [@]: //evil.test/n2", "1. [.]: //evil.test/n3", "[.]: //evil.test/t"},
			wantMD:       []string{`- \[.\]: //evil.test/n1`, `+ \[@\]: //evil.test/n2`, `1. \[.\]: //evil.test/n3`, `\!\[.\] evil[.]test`},
			wantMDAbsent: []string{" [.]:", " [@]:", "![.]"},
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

func TestWriteContent(t *testing.T) {
	sha := strings.Repeat("a", 64)
	tests := []struct {
		name string
		// inputs
		mutate func(*protocol.Result)
		// expectations
		wantBoth       []string // in summary.md and report.html
		wantMD         []string
		wantHTML       []string
		wantNeitherHas []string // absent from both
		wantMDAbsent   []string
		wantHTMLAbsent []string
	}{
		{
			name: "full report: target, reasons, IOC hosts, coverage and tables together",
			mutate: func(r *protocol.Result) {
				r.Target = protocol.Target{Name: "pack.zip", Kind: protocol.TargetFile, Size: 208896, SHA256: sha, FileCount: 1}
				r.IOCs = append(r.IOCs, protocol.IOC{Type: "domain", Value: "collect.sinkhole.test", Path: "a.txt", Line: 1})
				r.Reasons = []string{"beacon to collect.sinkhole.test"}
				r.Coverage = protocol.Coverage{FilesSeen: 3, FilesAnalyzed: 3, Skipped: []protocol.Skip{{Path: "pack.zip!/enc", Reason: "parse_error"}}}
			},
			wantMD:         []string{"- beacon to collect[.]sinkhole[.]test", "- Kind: file\n", "- SHA-256: " + sha, "- Size: 204 KiB", "- Files analyzed: 3 of 3 (1 item also skipped)", "- **Warning:** 1 item was not analyzed; the verdict does not cover it"},
			wantHTML:       []string{"beacon to collect[.]sinkhole[.]test", "<td>file</td>", "<td>204 KiB</td>", `<p class="warn">`, `aria-label="Findings"`},
			wantNeitherHas: []string{"collect.sinkhole.test", "(100%)"},
		},
		{
			name: "domains from the IOC list are defanged in free text only",
			mutate: func(r *protocol.Result) {
				r.IOCs = append(r.IOCs, protocol.IOC{Type: "domain", Value: "collect.sinkhole.test", Path: "a.txt", Line: 1})
				r.Findings[0].Title = "Beacon to collect.sinkhole.test"
				r.Findings[0].Evidence[0].Snippet = "hostname: 'collect.sinkhole.test' // setup.js"
				r.Reasons = []string{"calls COLLECT.sinkhole.test"}
			},
			wantBoth:       []string{"Beacon to collect[.]sinkhole[.]test", "setup.js", "calls COLLECT[.]sinkhole[.]test"},
			wantMD:         []string{"hostname: 'collect[.]sinkhole[.]test'"},
			wantHTML:       []string{"hostname: &#39;collect[.]sinkhole[.]test&#39;"},
			wantNeitherHas: []string{"collect.sinkhole.test", "COLLECT.sinkhole.test"},
		},
		{
			name: "paths are not treated as domains",
			mutate: func(r *protocol.Result) {
				r.IOCs = append(r.IOCs, protocol.IOC{Type: "domain", Value: "setup.test", Path: "a.txt", Line: 1})
				r.Findings[0].Evidence[0].Path = "setup.test"
				r.Findings[0].Evidence[0].Snippet = "run setup.test"
			},
			wantBoth:       []string{"run setup[.]test", "setup.test:3"},
			wantNeitherHas: []string{"setup[.]test:3"},
		},
		{
			name: "a defanged domain after a non-alphanumeric stays safe in markdown",
			mutate: func(r *protocol.Result) {
				r.IOCs = append(r.IOCs, protocol.IOC{Type: "domain", Value: "evil.test", Path: "a.txt", Line: 1})
				r.Reasons = []string{"[.]: //evil.test/x", "(evil.test)"}
			},
			wantMD:       []string{`\[.\]: //evil[.]test/x`, `\(evil[.]test\)`},
			wantMDAbsent: []string{"\n- [.]:"},
		},
		{
			name: "directory target shows folder and file count without a hash",
			mutate: func(r *protocol.Result) {
				r.Target = protocol.Target{Name: "repo", Kind: protocol.TargetDir, Size: 208896, SHA256: sha, FileCount: 2}
			},
			wantMD:         []string{"- Kind: folder, 2 files", "- Size: 204 KiB"},
			wantHTML:       []string{"<td>folder, 2 files</td>", "<td>204 KiB</td>"},
			wantNeitherHas: []string{"SHA-256", sha, "208896"},
		},
		{
			name:     "directory with one file is singular",
			mutate:   func(r *protocol.Result) { r.Target.FileCount, r.Target.Size = 1, 1 },
			wantBoth: []string{"folder, 1 file", "1 byte"},
			wantNeitherHas: []string{
				"1 files", "1 bytes",
			},
		},
		{
			name: "file target shows hash and size",
			mutate: func(r *protocol.Result) {
				r.Target = protocol.Target{Name: "a.zip", Kind: protocol.TargetFile, Size: 5 * 1024 * 1024, SHA256: sha, FileCount: 1}
			},
			wantMD:         []string{"- Kind: file\n", "- SHA-256: " + sha, "- Size: 5.0 MiB"},
			wantHTML:       []string{"<td>file</td>", `<th scope="row">SHA-256</th><td><code>` + sha + `</code>`, "<td>5.0 MiB</td>"},
			wantNeitherHas: []string{"1 file"},
		},
		{
			name: "file target without a hash has no hash row",
			mutate: func(r *protocol.Result) {
				r.Target = protocol.Target{Name: "a.zip", Kind: protocol.TargetFile, Size: 12, FileCount: 1}
			},
			wantBoth:       []string{"12 bytes"},
			wantNeitherHas: []string{"SHA-256"},
		},
		{
			name: "ftp and file urls are defanged",
			mutate: func(r *protocol.Result) {
				r.Findings[0].Evidence[0].Snippet = "get ftp://f.test/a.bin, ftps://g.test/b and file:///C:/x.exe"
			},
			wantBoth:       []string{"fxp://f[.]test/a[.]bin", "fxps://g[.]test/b", "fxle:///C:/x[.]exe"},
			wantNeitherHas: []string{"ftp://", "ftps://", "file://"},
		},
		{
			name: "skips next to full analysis never read 100%",
			mutate: func(r *protocol.Result) {
				r.Coverage = protocol.Coverage{FilesSeen: 2, FilesAnalyzed: 2, Skipped: []protocol.Skip{{Path: "a.zip!/enc", Reason: "parse_error"}}}
			},
			wantMD:         []string{"- Files analyzed: 2 of 2 (1 item also skipped)", "- **Warning:** 1 item was not analyzed; the verdict does not cover it"},
			wantHTML:       []string{"Files analyzed: 2 of 2 (1 item also skipped).", `<p class="warn">1 item was not analyzed; the verdict does not cover it.</p>`},
			wantNeitherHas: []string{"(100%)"},
		},
		{
			name: "several skips are counted and pluralized",
			mutate: func(r *protocol.Result) {
				r.Coverage = protocol.Coverage{FilesSeen: 3, FilesAnalyzed: 3, Skipped: []protocol.Skip{{Path: "a", Reason: "encrypted"}, {Path: "b", Reason: "depth"}}}
			},
			wantBoth:       []string{"(2 items also skipped)", "2 items were not analyzed; the verdict does not cover them"},
			wantNeitherHas: []string{"(100%)"},
		},
		{
			name: "almost all files with a skip is capped below 100%",
			mutate: func(r *protocol.Result) {
				r.Coverage = protocol.Coverage{FilesSeen: 1000, FilesAnalyzed: 999, Skipped: []protocol.Skip{{Path: "a", Reason: "timeout"}}}
			},
			wantBoth:       []string{"Files analyzed: 999 of 1000 (99%)", "1 item was not analyzed"},
			wantNeitherHas: []string{"(100%)"},
		},
		{
			name: "percentage is rounded like scoring and no warning without skips",
			mutate: func(r *protocol.Result) {
				r.Coverage = protocol.Coverage{FilesSeen: 3, FilesAnalyzed: 2, Skipped: []protocol.Skip{}}
			},
			wantMD:         []string{"- Files analyzed: 2 of 3 (67%)", "- Skipped: none"},
			wantHTML:       []string{"Files analyzed: 2 of 3 (67%).", "Nothing skipped."},
			wantNeitherHas: []string{"not analyzed", "66%"},
		},
		{
			name: "percentage uses the same rounding as the scoring reasons",
			mutate: func(r *protocol.Result) {
				r.Coverage = protocol.Coverage{FilesSeen: 200, FilesAnalyzed: 29, Skipped: []protocol.Skip{}}
			},
			wantBoth: []string{"Files analyzed: 29 of 200 (14%)"},
		},
		{
			name: "everything analyzed with nothing skipped is 100%",
			mutate: func(r *protocol.Result) {
				r.Coverage = protocol.Coverage{FilesSeen: 4, FilesAnalyzed: 4, Skipped: []protocol.Skip{}}
			},
			wantBoth:       []string{"Files analyzed: 4 of 4 (100%)"},
			wantNeitherHas: []string{"not analyzed"},
		},
		{
			name: "no files seen shows 0%",
			mutate: func(r *protocol.Result) {
				r.Coverage = protocol.Coverage{Skipped: []protocol.Skip{}}
			},
			wantBoth: []string{"Files analyzed: 0 of 0 (0%)"},
		},
		{
			name:   "html tables keep table semantics and scroll in a region",
			mutate: func(r *protocol.Result) {},
			wantHTML: []string{
				`<div class="scroll" tabindex="0" role="region" aria-label="Target">`,
				`<div class="scroll" tabindex="0" role="region" aria-label="Findings">`,
				`<div class="scroll" tabindex="0" role="region" aria-label="Auto-execution inventory">`,
				`<div class="scroll" tabindex="0" role="region" aria-label="IOCs">`,
				`<div class="scroll" tabindex="0" role="region" aria-label="Skipped items">`,
				"<thead>", `<th scope="col">Severity</th>`, `<th scope="col">Value</th>`, `<th scope="col">Reason</th>`,
				`<th scope="row">Name</th>`, "<tbody>", ".scroll{overflow-x:auto}",
			},
			wantHTMLAbsent: []string{"display:block", "<script", "href="},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := result("snippet", "a.txt")
			tt.mutate(res)

			paths, err := report.Write(t.TempDir(), res)
			if err != nil {
				t.Fatal(err)
			}

			md, html := read(t, paths.Markdown), read(t, paths.HTML)
			check(t, "summary.md", md, append(tt.wantBoth, tt.wantMD...), append(tt.wantNeitherHas, tt.wantMDAbsent...))
			check(t, "report.html", html, append(tt.wantBoth, tt.wantHTML...), append(tt.wantNeitherHas, tt.wantHTMLAbsent...))
			for _, l := range strings.Split(md, "\n") {
				if refDef.MatchString(l) {
					t.Errorf("summary.md line %q can define a link reference", l)
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

// TestWriteScalesWithIOCs guards against rendering time that grows with IOCs times text: a hostile
// repository controls the number of IOC domains. It compares run times instead of using a fixed
// limit, so a slow machine or the race detector does not make it flaky.
func TestWriteScalesWithIOCs(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		findings, fewIOCs, manyIOCs int
		// expectations
		wantMaxRatio float64
	}{
		{name: "1000 domain IOCs over 2000 findings cost about the same as 1", findings: 2000, fewIOCs: 1, manyIOCs: 1000, wantMaxRatio: 5},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			run := func(iocs int) time.Duration {
				res := result("s", "a.txt")
				snippet := "hostname: 'h5.sinkhole.test' " + strings.Repeat("x", 170)
				res.Findings, res.IOCs = nil, nil
				for i := 0; i < tt.findings; i++ {
					res.Findings = append(res.Findings, protocol.Finding{RuleID: "GAL-R-001", Severity: protocol.SeverityLow, Title: "t", Evidence: []protocol.Evidence{{Path: "a", Line: i + 1, Snippet: snippet}}})
				}
				for i := 0; i < iocs; i++ {
					res.IOCs = append(res.IOCs, protocol.IOC{Type: "domain", Value: fmt.Sprintf("h%d.sinkhole.test", i+5), Path: "a", Line: 1})
				}
				dir := t.TempDir()
				best := time.Duration(math.MaxInt64)
				for range 3 {
					start := time.Now()
					if _, err := report.Write(dir, res); err != nil {
						t.Fatal(err)
					}
					best = min(best, time.Since(start))
				}
				return best
			}
			few, many := run(tt.fewIOCs), run(tt.manyIOCs)
			if ratio := float64(many) / float64(few); ratio > tt.wantMaxRatio {
				t.Errorf("Write took %v with %d IOCs and %v with %d, ratio %.1f, want at most %.1f", many, tt.manyIOCs, few, tt.fewIOCs, ratio, tt.wantMaxRatio)
			}
			t.Logf("%d IOCs: %v, %d IOCs: %v", tt.manyIOCs, many, tt.fewIOCs, few)
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
			name:        "skipped items get a warning",
			wantContain: []string{"Warning: 1 item was not analyzed; the verdict does not cover it"},
		},
		{
			name:       "no skips no warning",
			mutate:     func(r *protocol.Result) { r.Coverage.Skipped = nil },
			wantAbsent: []string{"Warning"},
		},
		{
			name: "IOC domains are defanged in titles",
			mutate: func(r *protocol.Result) {
				r.IOCs = append(r.IOCs, protocol.IOC{Type: "domain", Value: "collect.sinkhole.test"})
				r.Findings[0].Title = "Beacon to collect.sinkhole.test"
			},
			wantContain: []string{"Beacon to collect[.]sinkhole[.]test"},
			wantAbsent:  []string{"collect.sinkhole.test"},
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
