// Package scoring turns findings and coverage into a verdict, a risk score, a
// confidence and plain-language reasons. It is host-safe: it only imports
// internal/protocol and never parses untrusted bytes.
//
// The model is documented in docs/milestones/M1.md, section 4.
package scoring

import (
	"fmt"
	"math"
	"slices"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/mrdhira/galahad/internal/protocol"
)

// Thresholds of the model.
const (
	maliciousScore  = 70
	suspiciousScore = 15
	minCoverage     = 0.5
)

var weights = map[protocol.Severity]int{
	protocol.SeverityInfo:     0,
	protocol.SeverityLow:      5,
	protocol.SeverityMedium:   15,
	protocol.SeverityHigh:     35,
	protocol.SeverityCritical: 100,
}

var rank = map[protocol.Severity]int{
	protocol.SeverityInfo:     0,
	protocol.SeverityLow:      1,
	protocol.SeverityMedium:   2,
	protocol.SeverityHigh:     3,
	protocol.SeverityCritical: 4,
}

// Apply scores res in place: it sets Verdict, Score, Confidence,
// ConfidenceLevel and Reasons from res.Findings and res.Coverage.
func Apply(res *protocol.Result) {
	// Each rule ID counts once, at its highest severity. The first finding at
	// that severity gives the evidence shown in the reasons.
	top := map[string]protocol.Finding{}
	var ids []string
	hasLow := false
	analyzers := map[string]bool{}
	for _, f := range res.Findings {
		if rank[f.Severity] >= rank[protocol.SeverityLow] {
			hasLow = true
		}
		if rank[f.Severity] >= rank[protocol.SeverityMedium] {
			analyzers[f.Analyzer] = true
		}
		cur, seen := top[f.RuleID]
		if !seen {
			ids = append(ids, f.RuleID)
		}
		if !seen || rank[f.Severity] > rank[cur.Severity] {
			top[f.RuleID] = f
		}
	}
	sort.Strings(ids)

	total := 0
	var hard []string
	for _, id := range ids {
		f := top[id]
		total += weights[f.Severity]
		if f.Severity == protocol.SeverityCritical {
			hard = append(hard, hardTrigger(f))
		}
	}
	score := min(100, total)

	var reasons []string
	verdict := protocol.VerdictClean
	switch {
	case len(hard) > 0:
		verdict = protocol.VerdictMalicious
		reasons = append(reasons, hard...)
	case score >= maliciousScore:
		verdict = protocol.VerdictMalicious
		reasons = append(reasons, fmt.Sprintf("score %d >= %d", score, maliciousScore))
	case score >= suspiciousScore:
		verdict = protocol.VerdictSuspicious
		reasons = append(reasons, fmt.Sprintf("score %d >= %d", score, suspiciousScore))
	case len(res.Findings) == 0:
		reasons = append(reasons, "no findings")
	default:
		reasons = append(reasons, fmt.Sprintf("score %d < %d", score, suspiciousScore))
	}

	cov := 0.0
	if res.Coverage.FilesSeen > 0 {
		cov = float64(res.Coverage.FilesAnalyzed) / float64(res.Coverage.FilesSeen)
	}
	clean := verdict == protocol.VerdictClean
	if clean && cov < minCoverage {
		verdict = protocol.VerdictSuspicious
		why := "less than half of the files could be analyzed"
		if res.Coverage.FilesSeen == 0 {
			why = "no files were found to analyze"
		}
		reasons = append(reasons,
			fmt.Sprintf("coverage %d%% < %d%%", int(math.Round(cov*100)), int(minCoverage*100)), why)
	}

	if clean && slices.ContainsFunc(res.Coverage.Skipped, protocol.Skip.HidesContent) {
		verdict = protocol.VerdictSuspicious
		reasons = append(reasons, "part of the input could not be analyzed")
	}

	if verdict == protocol.VerdictClean && res.Coverage.Truncated {
		reasons = append(reasons, "a limit or a guest tool that did not run cut the analysis short")
	}

	agree := len(analyzers) >= 2
	if agree {
		names := make([]string, 0, len(analyzers))
		for n := range analyzers {
			names = append(names, n)
		}
		sort.Strings(names)
		reasons = append(reasons, "agreement: "+strings.Join(names, ", "))
	}

	var conf int
	switch {
	case len(hard) > 0 && agree:
		conf = 100
	case len(hard) > 0:
		conf = 90
	default:
		a := 1.0
		switch {
		case verdict == protocol.VerdictClean:
			if hasLow {
				a = 0.9
			}
			if res.Coverage.Truncated {
				a *= 0.5
			}
		case !agree:
			a = 0.75
		}
		conf = int(math.Round(100 * cov * a))
	}

	res.Verdict = verdict
	res.Score = score
	res.Confidence = conf
	res.ConfidenceLevel = level(conf)
	reasons = reasons[:min(len(reasons), protocol.MaxReasonCount)]
	for i, r := range reasons {
		reasons[i] = limit(r)
	}
	res.Reasons = reasons
}

func hardTrigger(f protocol.Finding) string {
	s := fmt.Sprintf("hard trigger %s (%s)", f.RuleID, f.Severity)
	if len(f.Evidence) > 0 {
		e := f.Evidence[0]
		s += " at " + protocol.CleanPath(e.Path)
		if e.Line > 0 {
			s += fmt.Sprintf(":%d", e.Line)
		}
	}
	return s
}

func level(conf int) string {
	switch {
	case conf >= 80:
		return "high"
	case conf >= 50:
		return "medium"
	default:
		return "low"
	}
}

// limit cuts s at protocol.MaxReason runes without splitting a rune.
func limit(s string) string {
	if utf8.RuneCountInString(s) <= protocol.MaxReason {
		return s
	}
	return string([]rune(s)[:protocol.MaxReason])
}
