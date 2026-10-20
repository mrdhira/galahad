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

// Terminal prints the verdict, score, confidence, up to 10 findings and the report paths.
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

	fmt.Fprintf(w, "Verdict: %s\n", paint(ansiBold+verdictColor, strings.ToUpper(clean(string(res.Verdict)))))
	fmt.Fprintf(w, "Score: %d/100  Confidence: %d%% (%s)\n", res.Score, res.Confidence, clean(res.ConfidenceLevel))

	rs := rows(res, nil)
	if len(rs) > 0 {
		fmt.Fprintln(w)
	}
	for i, r := range rs {
		if i == termMaxFindings {
			fmt.Fprintln(w, paint(ansiDim, fmt.Sprintf("... %d more in %s", len(rs)-termMaxFindings, JSONName)))
			break
		}
		sevColor := ansiDim
		switch r.Severity {
		case protocol.SeverityCritical, protocol.SeverityHigh:
			sevColor = ansiRed
		case protocol.SeverityMedium:
			sevColor = ansiYellow
		}
		line := strings.ToUpper(clean(string(r.Severity))) + " " + clean(r.Rule)
		if r.Location != "" {
			line += " " + clean(r.Location)
		}
		fmt.Fprintf(w, "%s %s\n", paint(sevColor, line), clean(r.Title))
	}

	fmt.Fprintf(w, "\nReports:\n  %s\n  %s\n  %s\n", clean(p.HTML), clean(p.Markdown), clean(p.JSON))
}
