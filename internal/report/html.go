package report

import (
	"bytes"
	_ "embed"
	"html/template"

	"github.com/mrdhira/galahad/internal/protocol"
)

//go:embed report.html.tmpl
var htmlSource string

var htmlTemplate = template.Must(template.New("report").Parse(htmlSource))

type htmlData struct {
	Verdict, VerdictClass string
	Score, Confidence     int
	ConfidenceLevel       string
	Reasons               []string
	TargetName            string
	Target                targetInfo
	Findings, AutoExec    []row
	IOCs                  []htmlIOC
	CoverageLine          string
	CoverageWarning       string
	Truncated             bool
	Skips                 []protocol.Skip
}

type htmlIOC struct{ Type, Value, Location string }

// renderHTML renders the self-contained report page. html/template escapes every value; the
// strings are defanged first and the template has no links, scripts or external resources.
func renderHTML(res *protocol.Result) ([]byte, error) {
	hosts := iocHosts(res)
	d := htmlData{
		Verdict:         clean(string(res.Verdict)),
		VerdictClass:    "clean",
		Score:           res.Score,
		Confidence:      res.Confidence,
		ConfidenceLevel: clean(res.ConfidenceLevel),
		TargetName:      clean(res.Target.Name),
		Target:          describeTarget(res.Target),
		Findings:        cleanRows(hosts, rows(res, nil)),
		AutoExec:        cleanRows(hosts, rows(res, isAutoexec)),
		CoverageLine:    coverageLine(res.Coverage),
		CoverageWarning: coverageWarning(res.Coverage),
		Truncated:       res.Coverage.Truncated,
	}
	d.Target.SHA256 = clean(d.Target.SHA256)
	if res.Verdict == protocol.VerdictSuspicious || res.Verdict == protocol.VerdictMalicious {
		d.VerdictClass = string(res.Verdict)
	}
	for _, r := range res.Reasons {
		d.Reasons = append(d.Reasons, text(hosts, r))
	}
	for _, i := range res.IOCs {
		d.IOCs = append(d.IOCs, htmlIOC{Type: clean(i.Type), Value: cleanValue(i.Value), Location: clean(location(i.Path, i.Line))})
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

func cleanRows(hosts map[string]bool, rs []row) []row {
	out := make([]row, len(rs))
	for i, r := range rs {
		sev := r.Severity
		if _, ok := severityRank[sev]; !ok {
			sev = "unknown"
		}
		out[i] = row{Severity: sev, Rule: clean(r.Rule), Title: text(hosts, r.Title), Attack: clean(r.Attack), Location: clean(r.Location), Snippet: text(hosts, r.Snippet)}
	}
	return out
}
