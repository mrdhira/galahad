// Package report renders a validated protocol.Result into report.json, summary.md and report.html
// and into a short terminal summary. Every string in a Result comes from analyzed (untrusted)
// content, so each renderer escapes it for its format and defangs URLs and email addresses.
// The package only imports internal/protocol and internal/defang, so the host may use it.
package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode"

	"github.com/mrdhira/galahad/internal/defang"
	"github.com/mrdhira/galahad/internal/protocol"
)

// Report file names inside the output directory.
const (
	JSONName     = "report.json"
	MarkdownName = "summary.md"
	HTMLName     = "report.html"
)

// Paths holds the locations of the three report files.
type Paths struct {
	JSON     string
	Markdown string
	HTML     string
}

// Write creates dir (mode 0750) and writes report.json, summary.md and report.html into it
// (mode 0600). report.json is the Result as given, so callers validate it first.
func Write(dir string, res *protocol.Result) (Paths, error) {
	p := Paths{
		JSON:     filepath.Join(dir, JSONName),
		Markdown: filepath.Join(dir, MarkdownName),
		HTML:     filepath.Join(dir, HTMLName),
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return p, err
	}
	j, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		return p, err
	}
	h, err := renderHTML(res)
	if err != nil {
		return p, err
	}
	for _, f := range []struct {
		path string
		data []byte
	}{
		{p.JSON, append(j, '\n')},
		{p.Markdown, []byte(renderMarkdown(res))},
		{p.HTML, h},
	} {
		if err := writeFile(f.path, f.data); err != nil {
			return p, err
		}
	}
	return p, nil
}

func writeFile(path string, data []byte) error {
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return err
	}
	// WriteFile keeps the mode of an existing file.
	return os.Chmod(path, 0o600)
}

// row is one evidence line of a finding (or a finding without evidence).
type row struct {
	Severity protocol.Severity
	Rule     string
	Title    string
	Attack   string
	Location string // path:line, empty without evidence
	Snippet  string
}

var severityRank = map[protocol.Severity]int{
	protocol.SeverityInfo:     0,
	protocol.SeverityLow:      1,
	protocol.SeverityMedium:   2,
	protocol.SeverityHigh:     3,
	protocol.SeverityCritical: 4,
}

// rows flattens findings into one row per evidence entry, most severe first. keep selects findings.
func rows(res *protocol.Result, keep func(protocol.Finding) bool) []row {
	var out []row
	for _, f := range res.Findings {
		if keep != nil && !keep(f) {
			continue
		}
		base := row{Severity: f.Severity, Rule: f.RuleID, Title: f.Title, Attack: f.Attack}
		if len(f.Evidence) == 0 {
			out = append(out, base)
			continue
		}
		for _, e := range f.Evidence {
			r := base
			r.Location = location(e.Path, e.Line)
			r.Snippet = e.Snippet
			out = append(out, r)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		return severityRank[out[i].Severity] > severityRank[out[j].Severity]
	})
	return out
}

func isAutoexec(f protocol.Finding) bool { return strings.HasPrefix(f.RuleID, "GAL-AUTOEXEC-") }

func location(path string, line int) string {
	if line > 0 {
		return fmt.Sprintf("%s:%d", path, line)
	}
	return path
}

// clean defangs URLs and email addresses and replaces control characters (including ESC and
// newlines) with spaces. All renderers start from it.
func clean(s string) string {
	return defang.DefangText(stripControl(s))
}

// cleanValue is clean for a value that is a URL, domain, IP or email as a whole.
func cleanValue(s string) string {
	return defang.Defang(stripControl(s))
}

func stripControl(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == '\u2028' || r == '\u2029' {
			return ' '
		}
		return r
	}, s)
}

func percent(analyzed, seen int) string {
	if seen <= 0 {
		return "0%"
	}
	return fmt.Sprintf("%d%%", analyzed*100/seen)
}
