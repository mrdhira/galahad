// Package report renders a validated protocol.Result into report.json, summary.md and report.html
// and into a short terminal summary. Every string in a Result comes from analyzed (untrusted)
// content, so each renderer escapes it for its format and defangs URLs and email addresses.
// The package only imports internal/protocol and internal/defang, so the host may use it.
package report

import (
	"encoding/json"
	"fmt"
	"math"
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

// text is clean for free text (snippets, titles, reasons): it also defangs the bare domains and
// IP addresses that are in the IOC list. Paths are never passed through it.
func text(hosts map[string]bool, s string) string {
	return defang.DefangHosts(clean(s), hosts)
}

// iocHosts returns the lowercase domains and IP addresses of the IOC list. Renderers build it once.
func iocHosts(res *protocol.Result) map[string]bool {
	hosts := map[string]bool{}
	for _, i := range res.IOCs {
		if i.Type == "domain" || i.Type == "ip" {
			hosts[strings.ToLower(stripControl(i.Value))] = true
		}
	}
	return hosts
}

// percent rounds like scoring does. It never shows 100% when a file was not analyzed.
func percent(analyzed, seen int) string {
	if seen <= 0 {
		return "0%"
	}
	p := int(math.Round(float64(analyzed) / float64(seen) * 100))
	if p >= 100 && analyzed < seen {
		p = 99
	}
	return fmt.Sprintf("%d%%", p)
}

// plural returns "1 file" or "2 files".
func plural(n int, noun string) string {
	if n == 1 {
		return fmt.Sprintf("1 %s", noun)
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

// humanSize formats a byte count as bytes, KiB, MiB or GiB.
func humanSize(n int64) string {
	if n < 1024 {
		return plural(int(n), "byte")
	}
	v := float64(n)
	unit := ""
	for _, u := range []string{"KiB", "MiB", "GiB"} {
		v /= 1024
		unit = u
		if v < 1024 {
			break
		}
	}
	if v < 10 {
		return fmt.Sprintf("%.1f %s", v, unit)
	}
	return fmt.Sprintf("%.0f %s", v, unit)
}

// targetInfo is how renderers describe the target. Kind and Size are built here from validated
// numbers; SHA256 is raw, empty for a folder, and the renderer must escape it.
type targetInfo struct{ Kind, Size, SHA256 string }

func describeTarget(t protocol.Target) targetInfo {
	if t.Kind == protocol.TargetDir {
		return targetInfo{Kind: "folder, " + plural(t.FileCount, "file"), Size: humanSize(t.Size)}
	}
	return targetInfo{Kind: "file", Size: humanSize(t.Size), SHA256: t.SHA256}
}

// coverageLine is the coverage sentence. Skipped items are not in FilesSeen, so with skips it
// says "all files read" instead of 100%.
func coverageLine(c protocol.Coverage) string {
	if len(c.Skipped) > 0 && c.FilesSeen > 0 && c.FilesAnalyzed >= c.FilesSeen {
		return fmt.Sprintf("Files analyzed: %d of %d (all files read, %s skipped)", c.FilesAnalyzed, c.FilesSeen, plural(len(c.Skipped), "item"))
	}
	return fmt.Sprintf("Files analyzed: %d of %d (%s)", c.FilesAnalyzed, c.FilesSeen, percent(c.FilesAnalyzed, c.FilesSeen))
}

// coverageWarning is empty when nothing was skipped.
func coverageWarning(c protocol.Coverage) string {
	switch n := len(c.Skipped); n {
	case 0:
		return ""
	case 1:
		return "1 item was not analyzed; the verdict does not cover it"
	default:
		return fmt.Sprintf("%d items were not analyzed; the verdict does not cover them", n)
	}
}
