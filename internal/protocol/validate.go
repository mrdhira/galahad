package protocol

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

var (
	ruleIDRe = regexp.MustCompile(`^GAL-[A-Z]+-\d{3}$`)
	attackRe = regexp.MustCompile(`^T\d{4}(\.\d{3})?$`)
)

// Validate checks a decoded Result and returns the first problem found.
// An empty Verdict and ConfidenceLevel are accepted: a result written before
// scoring has run is valid, just not scored yet.
func (r *Result) Validate() error {
	if r.SchemaVersion != SchemaVersion {
		return fmt.Errorf("schema_version %d, want %d", r.SchemaVersion, SchemaVersion)
	}
	if err := checkText("tool.name", r.Tool.Name); err != nil {
		return err
	}
	if err := checkText("tool.version", r.Tool.Version); err != nil {
		return err
	}
	if len(r.Target.Name) > MaxPath {
		return fmt.Errorf("target.name is %d bytes, max %d", len(r.Target.Name), MaxPath)
	}
	if err := checkText("target.name", r.Target.Name); err != nil {
		return err
	}
	if r.Target.Kind != TargetFile && r.Target.Kind != TargetDir {
		return fmt.Errorf("target.kind %q not allowed", r.Target.Kind)
	}
	switch r.Verdict {
	case "", VerdictClean, VerdictSuspicious, VerdictMalicious:
	default:
		return fmt.Errorf("verdict %q not allowed", r.Verdict)
	}
	switch r.ConfidenceLevel {
	case "", "low", "medium", "high":
	default:
		return fmt.Errorf("confidence_level %q not allowed", r.ConfidenceLevel)
	}
	if r.Score < 0 || r.Score > 100 {
		return fmt.Errorf("score %d out of range 0-100", r.Score)
	}
	if r.Confidence < 0 || r.Confidence > 100 {
		return fmt.Errorf("confidence %d out of range 0-100", r.Confidence)
	}
	if len(r.Findings) > MaxFindings {
		return fmt.Errorf("%d findings, max %d", len(r.Findings), MaxFindings)
	}
	if len(r.IOCs) > MaxIOCs {
		return fmt.Errorf("%d iocs, max %d", len(r.IOCs), MaxIOCs)
	}
	if len(r.Files) > MaxFiles {
		return fmt.Errorf("%d files, max %d", len(r.Files), MaxFiles)
	}
	if len(r.Coverage.Skipped) > MaxSkipped {
		return fmt.Errorf("%d skipped, max %d", len(r.Coverage.Skipped), MaxSkipped)
	}
	if len(r.Coverage.Analyzers) > MaxAnalyzers {
		return fmt.Errorf("%d analyzers, max %d", len(r.Coverage.Analyzers), MaxAnalyzers)
	}
	if len(r.Reasons) > MaxReasonCount {
		return fmt.Errorf("%d reasons, max %d", len(r.Reasons), MaxReasonCount)
	}
	for i, f := range r.Files {
		if err := checkPath(f.Path); err != nil {
			return fmt.Errorf("files[%d]: %w", i, err)
		}
		if err := checkText("kind", f.Kind); err != nil {
			return fmt.Errorf("files[%d]: %w", i, err)
		}
	}
	perRuleFile := map[string]int{}
	for i, f := range r.Findings {
		if err := f.validate(); err != nil {
			return fmt.Errorf("findings[%d]: %w", i, err)
		}
		key := f.RuleID + "\x00" + f.Evidence[0].Path
		if perRuleFile[key]++; perRuleFile[key] > MaxFindingsPerRulePerFile {
			return fmt.Errorf("findings[%d]: more than %d findings of %s in %q", i, MaxFindingsPerRulePerFile, f.RuleID, f.Evidence[0].Path)
		}
	}
	for i, ioc := range r.IOCs {
		if err := ioc.validate(); err != nil {
			return fmt.Errorf("iocs[%d]: %w", i, err)
		}
	}
	for i, s := range r.Coverage.Skipped {
		if err := checkPath(s.Path); err != nil {
			return fmt.Errorf("coverage.skipped[%d]: %w", i, err)
		}
		switch s.Reason {
		case SkipTooLarge, SkipBudget, SkipDepth, SkipUnsupported, SkipEncrypted, SkipParseError, SkipUnreadable, SkipTimeout, SkipPanic:
		default:
			return fmt.Errorf("coverage.skipped[%d]: reason %q not allowed", i, s.Reason)
		}
	}
	for i, a := range r.Coverage.Analyzers {
		if err := checkText("name", a); err != nil {
			return fmt.Errorf("coverage.analyzers[%d]: %w", i, err)
		}
	}
	for i, s := range r.Reasons {
		if n := utf8.RuneCountInString(s); n > MaxReason {
			return fmt.Errorf("reasons[%d]: %d runes, max %d", i, n, MaxReason)
		}
		if err := checkText("text", s); err != nil {
			return fmt.Errorf("reasons[%d]: %w", i, err)
		}
	}
	return nil
}

func (f Finding) validate() error {
	if !ruleIDRe.MatchString(f.RuleID) {
		return fmt.Errorf("rule_id %q does not match %s", f.RuleID, ruleIDRe)
	}
	switch f.Severity {
	case SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
	default:
		return fmt.Errorf("severity %q not allowed", f.Severity)
	}
	if f.Attack != "" && !attackRe.MatchString(f.Attack) {
		return fmt.Errorf("attack %q does not match %s", f.Attack, attackRe)
	}
	if err := checkText("analyzer", f.Analyzer); err != nil {
		return err
	}
	if hasUnsafe(f.Title) {
		return errors.New("title has control or bidi characters")
	}
	if len(f.Evidence) == 0 {
		return errors.New("no evidence")
	}
	if len(f.Evidence) > MaxEvidence {
		return fmt.Errorf("%d evidence entries, max %d", len(f.Evidence), MaxEvidence)
	}
	for i, e := range f.Evidence {
		if err := checkPath(e.Path); err != nil {
			return fmt.Errorf("evidence[%d]: %w", i, err)
		}
		if n := utf8.RuneCountInString(e.Snippet); n > MaxSnippet {
			return fmt.Errorf("evidence[%d]: snippet has %d runes, max %d", i, n, MaxSnippet)
		}
		if hasUnsafe(e.Snippet) {
			return fmt.Errorf("evidence[%d]: snippet has control or bidi characters", i)
		}
	}
	return nil
}

func (i IOC) validate() error {
	switch i.Type {
	case "url", "domain", "ip", "email":
	default:
		return fmt.Errorf("type %q not allowed", i.Type)
	}
	if hasUnsafe(i.Value) {
		return errors.New("value has control or bidi characters")
	}
	return checkPath(i.Path)
}

func checkPath(p string) error {
	switch {
	case p == "":
		return errors.New("path is empty")
	case len(p) > MaxPath:
		return fmt.Errorf("path is %d bytes, max %d", len(p), MaxPath)
	case strings.ContainsRune(p, 0):
		return errors.New("path contains NUL")
	case p[0] == '/':
		return fmt.Errorf("path %q starts with /", p)
	case hasUnsafe(p):
		return errors.New("path has control or bidi characters")
	}
	return nil
}

func checkText(field, s string) error {
	if hasUnsafe(s) {
		return fmt.Errorf("%s has control or bidi characters or invalid UTF-8", field)
	}
	return nil
}

// hasUnsafe reports invalid UTF-8 (which would hide 8-bit control bytes), control and bidi characters.
func hasUnsafe(s string) bool {
	return !utf8.ValidString(s) || strings.IndexFunc(s, unsafeRune) >= 0
}
