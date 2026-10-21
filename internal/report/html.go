package report

import (
	"bytes"
	_ "embed"
	"html/template"
	"strings"

	"github.com/mrdhira/galahad/internal/protocol"
)

//go:embed report.html.tmpl
var htmlSource string

var htmlTemplate = template.Must(template.New("report").Parse(htmlSource))

type htmlData struct {
	Verdict, VerdictClass string
	Action, Meta          string
	Why, AutoExec         []htmlLine
	Reasons               []string
	TargetName            string
	Target                targetInfo
	Findings              []htmlGroup
	IOCHeading            string
	IOCs                  []htmlIOC
	IOCValues             []string
	CoverageLine          string
	CoverageWarning       string
	Truncated             bool
	Skips                 []protocol.Skip
}

// htmlLine is one line of the Why and Runs automatically lists.
type htmlLine struct{ Severity, Title, Location string }

type htmlEntry struct {
	Severity, Rule, Title, Attack string
	Auto                          bool
}

type htmlGroup struct {
	Entries           []htmlEntry
	Location, Snippet string
}

type htmlIOC struct{ Type, Value, Location string }

// renderHTML renders the self-contained report page. html/template escapes every value; the
// strings are defanged first and the template has no links, scripts or external resources.
func renderHTML(res *protocol.Result) ([]byte, error) {
	hosts := iocHosts(res)
	all := groups(res, nil)
	d := htmlData{
		Verdict:         strings.ToUpper(clean(string(res.Verdict))),
		VerdictClass:    "clean",
		Action:          actionLine(res.Verdict),
		Meta:            metaLine(res, len(all)),
		TargetName:      clean(res.Target.Name),
		Target:          describeTarget(res.Target),
		Findings:        cleanGroups(hosts, all),
		IOCHeading:      iocHeading(res),
		CoverageLine:    coverageLine(res.Coverage),
		CoverageWarning: coverageWarning(res.Coverage),
		Truncated:       res.Coverage.Truncated,
	}
	d.Target.SHA256 = clean(d.Target.SHA256)
	if res.Verdict == protocol.VerdictSuspicious || res.Verdict == protocol.VerdictMalicious {
		d.VerdictClass = string(res.Verdict)
	}
	for _, g := range why(all) {
		e := g.Entries[0]
		d.Why = append(d.Why, htmlLine{Severity: cleanSeverity(e.Severity), Title: text(hosts, e.Title), Location: clean(g.Location)})
	}
	for _, g := range groups(res, isAutoexec) {
		d.AutoExec = append(d.AutoExec, htmlLine{Severity: cleanSeverity(g.severity()), Title: text(hosts, g.titles()), Location: clean(g.Location)})
	}
	for _, r := range res.Reasons {
		d.Reasons = append(d.Reasons, text(hosts, r))
	}
	seen := map[string]bool{}
	for _, i := range res.IOCs {
		v := cleanValue(i.Value)
		d.IOCs = append(d.IOCs, htmlIOC{Type: clean(i.Type), Value: v, Location: clean(location(i.Path, i.Line))})
		if !seen[v] {
			seen[v] = true
			d.IOCValues = append(d.IOCValues, v)
		}
	}
	for _, s := range res.Coverage.Skipped {
		d.Skips = append(d.Skips, protocol.Skip{Path: clean(s.Path), Reason: clean(s.Reason)})
	}
	var b bytes.Buffer
	if err := htmlTemplate.Execute(&b, d); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func cleanGroups(hosts map[string]bool, gs []group) []htmlGroup {
	out := make([]htmlGroup, len(gs))
	for i, g := range gs {
		out[i] = htmlGroup{Location: clean(g.Location), Snippet: text(hosts, g.Snippet)}
		for _, e := range g.Entries {
			out[i].Entries = append(out[i].Entries, htmlEntry{Severity: cleanSeverity(e.Severity), Rule: clean(e.Rule), Title: text(hosts, e.Title), Attack: clean(e.Attack), Auto: e.Auto})
		}
	}
	return out
}

// cleanSeverity keeps only the known severities, so the value is safe in a CSS class name.
func cleanSeverity(s protocol.Severity) string {
	if _, ok := severityRank[s]; !ok {
		return "unknown"
	}
	return string(s)
}
