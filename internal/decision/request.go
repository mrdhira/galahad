// Package decision builds the request for a decision provider from a validated Result and redacts
// secrets from it. It is host only and parses no untrusted bytes: it reads strings that
// protocol.Result.Validate has already checked.
package decision

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"

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
// ok is false when there is nothing to send, that is when no guest finding is at low or above, or
// none of them is valid once redacted. An entry that is not valid on its own is left out. If the
// redacted request would be over protocol.MaxDecisionRequest, the entries of the lowest rank are
// dropped until it fits. Input.Omitted counts the entries that were not sent. The request is
// not redacted: the caller runs Redact on it before encoding. err is set when the request is not
// valid even without findings, for example when model is not a model name.
func Select(res protocol.Result, model string) (protocol.DecisionRequest, bool, error) {
	var entries []entry
	guest := false
	for _, f := range res.Findings {
		if severityRank(f.Severity) == 0 {
			continue
		}
		e := entry{finding: protocol.DecisionFinding{RuleID: f.RuleID, Severity: f.Severity, Title: hideName(res.Target, f.Title), Analyzer: f.Analyzer}}
		if f.Analyzer == hostAnalyzer {
			entries = append(entries, e)
			continue
		}
		guest = true
		if len(f.Evidence) > 0 {
			ev := f.Evidence[0]
			e.path = ev.Path
			e.finding.Path, e.finding.Line = targetPath(res.Target, ev.Path), ev.Line
			e.finding.Snippet = hideName(res.Target, ev.Snippet)
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
	req := protocol.DecisionRequest{
		Model:               model,
		PromptFormatVersion: protocol.PromptFormatVersion,
		Input: protocol.DecisionInput{
			Schema:   protocol.DecisionSchema,
			Notice:   protocol.DecisionNotice,
			Target:   protocol.DecisionTarget{Kind: res.Target.Kind, FileCount: res.Target.FileCount},
			Coverage: protocol.DecisionCoverage{FilesSeen: res.Coverage.FilesSeen, FilesAnalyzed: res.Coverage.FilesAnalyzed, Truncated: res.Coverage.Truncated},
			Findings: []protocol.DecisionFinding{},
		},
		Questions: protocol.DecisionQuestions(),
	}
	if err := req.Validate(); err != nil {
		return protocol.DecisionRequest{}, false, fmt.Errorf("decision request: %w", err)
	}

	// A finding that is not valid on its own, once redacted, is left out. Omitted counts every
	// unique entry that is not sent, whatever the reason.
	type key struct{ rule, path string }
	seen := make(map[key]bool, len(entries))
	guest = false
	for _, e := range entries {
		k := key{e.finding.RuleID, e.path}
		if seen[k] {
			continue
		}
		seen[k] = true
		req.Input.Omitted++
		if len(req.Input.Findings) < protocol.MaxDecisionFindings && validAlone(req, e.finding) {
			guest = guest || e.finding.Analyzer != hostAnalyzer
			req.Input.Findings = append(req.Input.Findings, e.finding)
		}
	}
	if !guest {
		return protocol.DecisionRequest{}, false, nil
	}
	for len(req.Input.Findings) > 0 {
		redacted := req
		redacted.Input.Findings = slices.Clone(req.Input.Findings)
		Redact(&redacted)
		if redacted.Validate() == nil {
			req.Input.Omitted -= len(req.Input.Findings)
			return req, true, nil
		}
		req.Input.Findings = req.Input.Findings[:len(req.Input.Findings)-1]
	}
	return protocol.DecisionRequest{}, false, nil
}

// validAlone reports whether req is valid, once redacted, with f as its only finding.
func validAlone(req protocol.DecisionRequest, f protocol.DecisionFinding) bool {
	req.Input.Findings = []protocol.DecisionFinding{f}
	Redact(&req)
	return req.Validate() == nil
}

// isFileTarget reports whether t is a file target that has a name to hide.
func isFileTarget(t protocol.Target) bool { return t.Kind == protocol.TargetFile && t.Name != "" }

// minHiddenName is the shortest name, in runes, that hideName replaces in a text. "(target)" is longer
// than a shorter name, and a text full of it (a file named "a") would outgrow the limits of Validate.
const minHiddenName = 3

// hideName replaces every occurrence of the name of a file target in text by "(target)".
func hideName(t protocol.Target, text string) string {
	if !isFileTarget(t) || utf8.RuneCountInString(t.Name) < minHiddenName {
		return text
	}
	return strings.ReplaceAll(text, t.Name, targetName)
}

// targetPath replaces the name of a file target in an evidence path by "(target)": the path of the
// file itself, the start of the path of a member after "!/", and any later occurrence of the name.
func targetPath(t protocol.Target, path string) string {
	if !isFileTarget(t) {
		return path
	}
	if path == t.Name {
		return targetName
	}
	if rest, ok := strings.CutPrefix(path, t.Name+"!/"); ok {
		return targetName + "!/" + hideName(t, rest)
	}
	return hideName(t, path)
}
