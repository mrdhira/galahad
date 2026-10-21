// Package protocol defines the versioned result schema shared by the guest agent
// and the host. It is host-safe: it never parses untrusted bytes.
//
// Result.Validate checks a decoded result: enums, ID formats, ranges and counts,
// and that every string a renderer may print is valid UTF-8 without control or
// bidi characters. Paths and the target name are also length bounded, snippets
// and reasons are bounded in runes.
package protocol

import "time"

// Target kinds.
const (
	TargetFile = "file"
	TargetDir  = "dir"
)

// Skip reasons.
const (
	SkipTooLarge    = "too_large"
	SkipBudget      = "budget"
	SkipDepth       = "depth"
	SkipUnsupported = "unsupported"
	SkipEncrypted   = "encrypted"
	SkipParseError  = "parse_error"
	SkipTimeout     = "timeout"
	SkipPanic       = "panic"
)

// MaxReason is the longest allowed entry of Result.Reasons, in runes.
const MaxReason = MaxSnippet * 2

// SchemaVersion is the value of Result.SchemaVersion.
const SchemaVersion = 1

// Limits on output and validation.
const (
	MaxFindings               = 2000
	MaxFindingsPerRulePerFile = 20
	MaxIOCs                   = 1000
	MaxSnippet                = 200  // runes
	MaxPath                   = 1024 // bytes
)

// Severity is the impact level of a rule.
type Severity string

// Allowed severities.
const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// Verdict is the overall judgement of a scan. The empty verdict means the
// result has not been scored yet.
type Verdict string

// Allowed verdicts.
const (
	VerdictClean      Verdict = "clean"
	VerdictSuspicious Verdict = "suspicious"
	VerdictMalicious  Verdict = "malicious"
)

// ExitCode maps the verdict to the process exit code: 0 clean (or not scored), 10 suspicious, 20 malicious.
func (v Verdict) ExitCode() int {
	switch v {
	case VerdictSuspicious:
		return 10
	case VerdictMalicious:
		return 20
	default:
		return 0
	}
}

// Rule describes a detection rule. Analyzers declare rules and build findings from them.
type Rule struct {
	ID       string   `json:"id"`
	Severity Severity `json:"severity"`
	Title    string   `json:"title"`
	Attack   string   `json:"attack"`
}

// Finding builds a finding for the rule. The first evidence is the primary one.
func (r Rule) Finding(ev ...Evidence) Finding {
	return Finding{RuleID: r.ID, Severity: r.Severity, Title: r.Title, Attack: r.Attack, Evidence: ev}
}

// Evidence points at the place a finding was seen. Path is slash-separated and
// relative to the target; container members use "!/". Line 0 means no line.
type Evidence struct {
	Path    string `json:"path"`
	Line    int    `json:"line"`
	Snippet string `json:"snippet"`
}

// Finding is one rule hit.
type Finding struct {
	RuleID   string     `json:"rule_id"`
	Severity Severity   `json:"severity"`
	Title    string     `json:"title"`
	Attack   string     `json:"attack"`
	Analyzer string     `json:"analyzer"`
	Evidence []Evidence `json:"evidence"`
}

// IOC is an indicator of compromise. Type is url, domain, ip or email; Value is raw (not defanged).
type IOC struct {
	Type  string `json:"type"`
	Value string `json:"value"`
	Path  string `json:"path"`
	Line  int    `json:"line"`
}

// FileInfo describes one inspected file.
type FileInfo struct {
	Path    string  `json:"path"`
	Size    int64   `json:"size"`
	Kind    string  `json:"kind"`
	SHA256  string  `json:"sha256"`
	Entropy float64 `json:"entropy"`
}

// Skip records a file that was not analyzed and why.
type Skip struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

// Coverage says how much of the target was analyzed.
type Coverage struct {
	FilesSeen     int      `json:"files_seen"`
	FilesAnalyzed int      `json:"files_analyzed"`
	Skipped       []Skip   `json:"skipped"`
	Analyzers     []string `json:"analyzers"`
	Truncated     bool     `json:"truncated"`
}

// Target describes what was scanned. SHA256 is set for file targets only. Size is the file size,
// or for a directory the total bytes of the top-level files read.
type Target struct {
	Name      string `json:"name"`
	Kind      string `json:"kind"`
	Size      int64  `json:"size"`
	SHA256    string `json:"sha256"`
	FileCount int    `json:"file_count"`
}

// Tool identifies the program that produced the result.
type Tool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Result is the full scan result.
type Result struct {
	SchemaVersion   int        `json:"schema_version"`
	Tool            Tool       `json:"tool"`
	Target          Target     `json:"target"`
	StartedAt       time.Time  `json:"started_at"`
	FinishedAt      time.Time  `json:"finished_at"`
	Files           []FileInfo `json:"files"`
	Findings        []Finding  `json:"findings"`
	IOCs            []IOC      `json:"iocs"`
	Coverage        Coverage   `json:"coverage"`
	Verdict         Verdict    `json:"verdict"`
	Score           int        `json:"score"`
	Confidence      int        `json:"confidence"`
	ConfidenceLevel string     `json:"confidence_level"`
	Reasons         []string   `json:"reasons"`
}
