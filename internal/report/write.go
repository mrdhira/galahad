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
	"slices"
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
	Path     string // empty without evidence
	Line     int
	Location string // path:line, empty without evidence
	Snippet  string
	Auto     bool // the finding is an auto-execution one
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
		base := row{Severity: f.Severity, Rule: f.RuleID, Title: f.Title, Attack: f.Attack, Auto: isAutoexec(f)}
		if len(f.Evidence) == 0 {
			out = append(out, base)
			continue
		}
		for _, e := range f.Evidence {
			r := base
			r.Path, r.Line = e.Path, e.Line
			r.Location = location(e.Path, e.Line)
			r.Snippet = strings.TrimLeftFunc(e.Snippet, unicode.IsSpace)
			out = append(out, r)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		return severityRank[out[i].Severity] > severityRank[out[j].Severity]
	})
	return out
}

// entry is one finding inside a group.
type entry struct {
	Severity protocol.Severity
	Rule     string
	Title    string
	Attack   string
	Auto     bool
}

// group is the findings that share a location and a snippet, so the reader sees the code once.
// Entries are most severe first. A row without evidence is a group of its own.
type group struct {
	Entries           []entry
	Location, Snippet string
}

// groups merges the rows of the kept findings by path, line and snippet. The key is not the
// "path:line" text: a file named "a:1" would collide with line 1 of file "a". Groups keep the order of
// their most severe row.
func groups(res *protocol.Result, keep func(protocol.Finding) bool) []group {
	var out []group
	type key struct {
		path    string
		line    int
		snippet string
	}
	at := map[key]int{}
	for _, r := range rows(res, keep) {
		e := entry{Severity: r.Severity, Rule: r.Rule, Title: r.Title, Attack: r.Attack, Auto: r.Auto}
		if r.Path == "" && r.Line == 0 && r.Snippet == "" {
			out = append(out, group{Entries: []entry{e}})
			continue
		}
		k := key{r.Path, r.Line, r.Snippet}
		i, ok := at[k]
		if !ok {
			at[k] = len(out)
			out = append(out, group{Entries: []entry{e}, Location: r.Location, Snippet: r.Snippet})
			continue
		}
		if !slices.Contains(out[i].Entries, e) {
			out[i].Entries = append(out[i].Entries, e)
		}
	}
	return out
}

func (g group) severity() protocol.Severity { return g.Entries[0].Severity }

// rules, titles and attacks join the distinct values of the group's entries.
func (g group) rules() string   { return g.join(", ", func(e entry) string { return e.Rule }) }
func (g group) titles() string  { return g.join("; ", func(e entry) string { return e.Title }) }
func (g group) attacks() string { return g.join(", ", func(e entry) string { return e.Attack }) }

func (g group) join(sep string, get func(entry) string) string {
	var vals []string
	for _, e := range g.Entries {
		if v := get(e); v != "" && !slices.Contains(vals, v) {
			vals = append(vals, v)
		}
	}
	return strings.Join(vals, sep)
}

// findingsHeading is the Findings heading: the number of findings, and the number of locations
// when that differs, so it agrees with the meta line.
func findingsHeading(res *protocol.Result, gs []group) string {
	if len(gs) == len(res.Findings) {
		return fmt.Sprintf("Findings (%d)", len(res.Findings))
	}
	return fmt.Sprintf("Findings (%d, at %s)", len(res.Findings), plural(len(gs), "location"))
}

// maxWhy is how many reasons the verdict header lists.
const maxWhy = 3

// why returns the first maxWhy groups whose most severe finding is critical or high. Without
// any, it falls back to the medium ones: a score of 70 or more is malicious even when every
// finding is medium. A title that repeats at another location is listed once, so the reasons
// differ. A clean verdict has no reasons.
func why(v protocol.Verdict, gs []group) []group {
	if v == protocol.VerdictClean {
		return nil
	}
	top := pick(gs, protocol.SeverityCritical, protocol.SeverityHigh)
	if len(top) == 0 {
		top = pick(gs, protocol.SeverityMedium)
	}
	return top
}

func pick(gs []group, sevs ...protocol.Severity) []group {
	var out []group
	seen := map[string]bool{}
	for _, g := range gs {
		title := g.Entries[0].Title
		if seen[title] || !slices.Contains(sevs, g.severity()) {
			continue
		}
		seen[title] = true
		if out = append(out, g); len(out) == maxWhy {
			break
		}
	}
	return out
}

// actionLine tells the reader what to do with the target.
func actionLine(v protocol.Verdict) string {
	switch v {
	case protocol.VerdictMalicious:
		return "Do not open, install or run this."
	case protocol.VerdictClean:
		return "No known-bad patterns found. This is not a guarantee."
	default:
		return "Treat with caution. Review the findings below before you open, install or run it."
	}
}

// metaLine is the one-line summary under the verdict. Next to skipped items it gives counts, not a
// percentage, and it counts the items that were not analyzed only when there are some.
func metaLine(res *protocol.Result) string {
	c := res.Coverage
	cov := "coverage " + percent(c.FilesAnalyzed, c.FilesSeen)
	if alsoSkipped(c) {
		cov = fmt.Sprintf("%d of %s analyzed", c.FilesAnalyzed, plural(c.FilesSeen, "file"))
	}
	line := fmt.Sprintf("Score %d/100 \u00b7 confidence %d%% (%s) \u00b7 %s \u00b7 %s",
		res.Score, res.Confidence, clean(res.ConfidenceLevel), plural(len(res.Findings), "finding"), cov)
	if n := len(c.Skipped); n > 0 {
		line += fmt.Sprintf(" \u00b7 %d not analyzed", n)
	}
	return line
}

// iocHeading names the IOC section. On a clean verdict the indicators are not a sign of compromise.
func iocHeading(res *protocol.Result) string {
	if res.Verdict == protocol.VerdictClean {
		return "Network indicators (not a sign of compromise)"
	}
	return fmt.Sprintf("IOCs (%d)", len(res.IOCs))
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

// iocHosts returns the lowercase domains and IP addresses of the IOC list and the hosts the guest
// asked the proxy for, so a bare host in a finding or a reason is defanged too. Renderers build it once.
func iocHosts(res *protocol.Result) map[string]bool {
	hosts := map[string]bool{}
	for _, i := range res.IOCs {
		if i.Type == "domain" || i.Type == "ip" {
			hosts[strings.ToLower(stripControl(i.Value))] = true
		}
	}
	if res.Network != nil {
		for _, e := range res.Network.Events {
			hosts[strings.ToLower(stripControl(e.Host))] = true
		}
	}
	return hosts
}

// netRow is one line of the Network section. Host and Reason are defanged and cleaned; Label
// says what happened: BLOCKED for a refused non-public address, else denied or allowed.
type netRow struct {
	Label, Host, Reason string
	Port, Count         int
}

// netRows returns the rows of the Network section, blocked ones first, then the other denials,
// then the allowed ones. Each group keeps the order of the proxy.
func netRows(res *protocol.Result) []netRow {
	if res.Network == nil {
		return nil
	}
	var out []netRow
	for _, e := range res.Network.Events {
		r := netRow{Label: clean(e.Decision), Host: cleanValue(e.Host), Reason: clean(e.Reason), Port: e.Port, Count: e.Count}
		if e.Blocked {
			r.Label = "BLOCKED"
		}
		out = append(out, r)
	}
	rank := func(r netRow) int {
		switch r.Label {
		case "BLOCKED":
			return 0
		case protocol.DecisionDenied:
			return 1
		}
		return 2
	}
	sort.SliceStable(out, func(i, j int) bool { return rank(out[i]) < rank(out[j]) })
	return out
}

// text is how a row reads on one line: "BLOCKED 169[.]254[.]169[.]254:443 (2 requests): metadata".
func (r netRow) text() string {
	line := fmt.Sprintf("%s %s:%d (%s)", r.Label, r.Host, r.Port, plural(r.Count, "request"))
	if r.Reason != "" {
		line += ": " + r.Reason
	}
	return line
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

// alsoSkipped is true when every seen file was analyzed but other items were skipped, so a
// percentage would read 100% next to a skip.
func alsoSkipped(c protocol.Coverage) bool {
	return len(c.Skipped) > 0 && c.FilesSeen > 0 && c.FilesAnalyzed >= c.FilesSeen
}

// coverageLine is the coverage sentence. Some skipped items are not in FilesSeen, so with skips
// it names them next to the counts instead of showing 100%.
func coverageLine(c protocol.Coverage) string {
	if alsoSkipped(c) {
		return fmt.Sprintf("Files analyzed: %d of %d (%s also skipped)", c.FilesAnalyzed, c.FilesSeen, plural(len(c.Skipped), "item"))
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
