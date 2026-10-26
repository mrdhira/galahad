package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/mrdhira/galahad/internal/protocol"
)

const termMaxFindings = 10

const (
	ansiReset  = "\x1b[0m"
	ansiBold   = "\x1b[1m"
	ansiRed    = "\x1b[31m"
	ansiYellow = "\x1b[33m"
	ansiGreen  = "\x1b[32m"
	ansiDim    = "\x1b[2m"
)

// Terminal prints the verdict, what to do about it, score, confidence, why, what runs
// automatically, one line for an AI opinion, up to 10 findings, up to 10 network destinations and the report paths.
// color adds ANSI colors; the caller decides (stdout is a TTY and NO_COLOR is unset).
// Untrusted text is defanged and stripped of control characters either way.
func Terminal(w io.Writer, res *protocol.Result, p Paths, color bool) {
	paint := func(code, s string) string {
		if !color {
			return s
		}
		return code + s + ansiReset
	}
	verdictColor := ansiGreen
	switch res.Verdict {
	case protocol.VerdictSuspicious:
		verdictColor = ansiYellow
	case protocol.VerdictMalicious:
		verdictColor = ansiRed
	}
	sevPaint := func(sev protocol.Severity, s string) string {
		switch sev {
		case protocol.SeverityCritical, protocol.SeverityHigh:
			return paint(ansiRed, s)
		case protocol.SeverityMedium:
			return paint(ansiYellow, s)
		}
		return paint(ansiDim, s)
	}

	fmt.Fprintf(w, "Verdict: %s\n", paint(ansiBold+verdictColor, strings.ToUpper(clean(string(res.Verdict)))))
	fmt.Fprintln(w, actionLine(res.Verdict))
	fmt.Fprintf(w, "Score: %d/100  Confidence: %d%% (%s)\n", res.Score, res.Confidence, clean(res.ConfidenceLevel))

	if warn := coverageWarning(res.Coverage); warn != "" {
		fmt.Fprintf(w, "Warning: %s\n", warn)
	}

	hosts := iocHosts(res)
	all := groups(res, nil)
	if top := why(res.Verdict, all); len(top) > 0 {
		fmt.Fprintf(w, "\nWhy:\n")
		for _, g := range top {
			e := g.Entries[0]
			line := strings.ToUpper(clean(string(e.Severity))) + " " + text(hosts, e.Title)
			if g.Location != "" {
				line += " in " + clean(g.Location)
			}
			fmt.Fprintf(w, "  %s\n", sevPaint(e.Severity, line))
		}
	}
	if line := aiTerminal(res); line != "" {
		fmt.Fprintf(w, "\n%s\n", line)
	}
	if auto := groups(res, isAutoexec); len(auto) > 0 {
		fmt.Fprintf(w, "\nRuns automatically (%d):\n", len(auto))
		for i, g := range auto {
			if i == termMaxFindings {
				fmt.Fprintln(w, "  "+paint(ansiDim, fmt.Sprintf("... %d more in %s", len(auto)-termMaxFindings, JSONName)))
				break
			}
			line := strings.ToUpper(clean(string(g.severity()))) + " " + text(hosts, g.titles())
			if g.Location != "" {
				line += " in " + clean(g.Location)
			}
			fmt.Fprintf(w, "  %s\n", sevPaint(g.severity(), line))
		}
	}
	if len(all) > 0 {
		fmt.Fprintf(w, "\n%s:\n", findingsHeading(res, all))
	}
	for i, g := range all {
		if i == termMaxFindings {
			fmt.Fprintln(w, "  "+paint(ansiDim, fmt.Sprintf("... %d more in %s", len(all)-termMaxFindings, JSONName)))
			break
		}
		line := strings.ToUpper(clean(string(g.severity()))) + " " + clean(g.rules())
		if g.Location != "" {
			line += " " + clean(g.Location)
		}
		fmt.Fprintf(w, "  %s %s\n", sevPaint(g.severity(), line), text(hosts, g.titles()))
	}

	if res.Network != nil {
		rows := netRows(res)
		fmt.Fprintf(w, "\nNetwork (%s):\n", plural(len(rows), "destination"))
		for i, r := range rows {
			if i == termMaxFindings {
				fmt.Fprintln(w, "  "+paint(ansiDim, fmt.Sprintf("... %d more in %s", len(rows)-termMaxFindings, JSONName)))
				break
			}
			line := r.text()
			if r.Label == "BLOCKED" {
				line = paint(ansiRed, line)
			}
			fmt.Fprintf(w, "  %s\n", line)
		}
	}

	fmt.Fprintf(w, "\nReports:\n  %s\n  %s\n  %s\n", clean(p.HTML), clean(p.Markdown), clean(p.JSON))
}
