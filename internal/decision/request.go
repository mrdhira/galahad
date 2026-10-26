// Package decision builds the request for a decision provider from a validated Result and redacts
// secrets from it. It is host only and parses no untrusted bytes: it reads strings that
// protocol.Result.Validate has already checked.
package decision

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	"github.com/mrdhira/galahad/internal/protocol"
)

// hostAnalyzer is the analyzer of the findings that the host makes (GAL-NET-001). Their snippets hold
// the network log, so they are sent as rule, severity and title only.
const hostAnalyzer = "network"

// filenameAnalyzer is the analyzer whose snippet is the name of the file.
const filenameAnalyzer = "filename"

// targetName stands for the name of a file target in an evidence path.
const targetName = "(target)"

// severityRank orders the severities that are sent, highest first. Other severities rank 0 and are not sent.
func severityRank(s protocol.Severity) int {
	switch s {
	case protocol.SeverityCritical:
		return 4
	case protocol.SeverityHigh:
		return 3
	case protocol.SeverityMedium:
		return 2
	case protocol.SeverityLow:
		return 1
	}
	return 0
}

// entry is a finding that may be sent, with the path as the Result has it, for the order.
type entry struct {
	finding protocol.DecisionFinding
	path    string
}

// Select builds the request for the provider from a validated Result. It takes the findings at low
// or above, one for each rule and path, ordered by severity (highest first), then rule ID, path and
// line, at most protocol.MaxDecisionFindings of them, and the first evidence entry of each. The name
// of a file target in a path, a title or a snippet is replaced by "(target)", a filename finding
// for the target itself goes without snippet (it is the name), and a finding that the host made goes
// without path, line or snippet. Nothing else of the Result is used: not the name, the IOCs, the
// files, the hashes, the network log, the verdict, the score or the reasons.
//
// ok is false when there is nothing to send, that is when no guest finding is at low or above.
// If the redacted request would be over protocol.MaxDecisionRequest, the entries of the lowest rank
// are dropped until it fits, and Input.Omitted counts the entries that were not sent. The request is
// not redacted: the caller runs Redact on it before encoding. err is set when the request is not
// valid even without findings, for example when model is not a model name.
func Select(res protocol.Result, model string) (protocol.DecisionRequest, bool, error) {
	var entries []entry
	guest := false
	for _, f := range res.Findings {
		if severityRank(f.Severity) == 0 {
			continue
		}
		e := entry{finding: protocol.DecisionFinding{RuleID: f.RuleID, Severity: f.Severity, Title: f.Title, Analyzer: f.Analyzer}}
		if f.Analyzer == hostAnalyzer {
			entries = append(entries, e)
			continue
		}
		guest = true
		if len(f.Evidence) > 0 {
			ev := f.Evidence[0]
			e.path = ev.Path
			e.finding.Path, e.finding.Line = targetPath(res.Target, ev.Path), ev.Line
			e.finding.Title, e.finding.Snippet = hideName(res.Target, f.Title), hideName(res.Target, ev.Snippet)
			if f.Analyzer == filenameAnalyzer && isFileTarget(res.Target) && ev.Path == res.Target.Name {
				e.finding.Snippet = "" // the snippet is the name of the file, as it was or as it is shown
			}
		}
		entries = append(entries, e)
	}
	if !guest {
		return protocol.DecisionRequest{}, false, nil
	}

	slices.SortStableFunc(entries, func(a, b entry) int {
		return cmp.Or(
			cmp.Compare(severityRank(b.finding.Severity), severityRank(a.finding.Severity)),
			cmp.Compare(a.finding.RuleID, b.finding.RuleID),
			cmp.Compare(a.path, b.path),
			cmp.Compare(a.finding.Line, b.finding.Line),
		)
	})
	type key struct{ rule, path string }
	seen := make(map[key]bool, len(entries))
	findings := make([]protocol.DecisionFinding, 0, protocol.MaxDecisionFindings)
	for _, e := range entries {
		if k := (key{e.finding.RuleID, e.path}); !seen[k] {
			seen[k] = true
			findings = append(findings, e.finding)
		}
	}

	req := protocol.DecisionRequest{
		Model:               model,
		PromptFormatVersion: protocol.PromptFormatVersion,
		Input: protocol.DecisionInput{
			Schema:   protocol.DecisionSchema,
			Notice:   protocol.DecisionNotice,
			Target:   protocol.DecisionTarget{Kind: res.Target.Kind, FileCount: res.Target.FileCount},
			Coverage: protocol.DecisionCoverage{FilesSeen: res.Coverage.FilesSeen, FilesAnalyzed: res.Coverage.FilesAnalyzed, Truncated: res.Coverage.Truncated},
			Findings: findings,
		},
		Questions: protocol.DecisionQuestions(),
	}
	if n := len(findings) - protocol.MaxDecisionFindings; n > 0 {
		req.Input.Findings, req.Input.Omitted = findings[:protocol.MaxDecisionFindings], n
	}
	for {
		redacted := req
		redacted.Input.Findings = slices.Clone(req.Input.Findings)
		Redact(&redacted)
		err := redacted.Validate()
		if err == nil {
			return req, true, nil
		}
		if len(req.Input.Findings) == 0 {
			return protocol.DecisionRequest{}, false, fmt.Errorf("decision request: %w", err)
		}
		req.Input.Findings = req.Input.Findings[:len(req.Input.Findings)-1]
		req.Input.Omitted++
	}
}

// isFileTarget reports whether t is a file target that has a name to hide.
func isFileTarget(t protocol.Target) bool { return t.Kind == protocol.TargetFile && t.Name != "" }

// minHiddenName is the shortest name that hideName replaces in a text. "(target)" is longer than a
// shorter name, and a text full of it (a file named "a") would outgrow the limits of Validate.
const minHiddenName = 3

// hideName replaces every occurrence of the name of a file target in text by "(target)".
func hideName(t protocol.Target, text string) string {
	if !isFileTarget(t) || len(t.Name) < minHiddenName {
		return text
	}
	return strings.ReplaceAll(text, t.Name, targetName)
}

// targetPath replaces the name of a file target at the start of an evidence path by "(target)": the
// path of the file itself, or of a member after "!/".
func targetPath(t protocol.Target, path string) string {
	if !isFileTarget(t) {
		return path
	}
	if path == t.Name {
		return targetName
	}
	if rest, ok := strings.CutPrefix(path, t.Name+"!/"); ok {
		return targetName + "!/" + rest
	}
	return path
}
