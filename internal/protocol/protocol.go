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
	SkipTooLarge    = "too_large" // a file over a size limit of its own
	SkipBudget      = "budget"    // a container with more members or bytes than its budget allows, or a file whose work budget ran out before its end
	SkipDepth       = "depth"
	SkipUnsupported = "unsupported"
	SkipEncrypted   = "encrypted"
	SkipParseError  = "parse_error"
	SkipUnreadable  = "unreadable" // a container member that could not be extracted
	SkipTimeout     = "timeout"
	SkipPanic       = "panic"
)

// Causes a guest tool is left out, as in LeftOut.Cause.
const (
	LeftOutNoNetwork = "no_network" // the tool needs the network and the host could not reach it
	LeftOutTimeout   = "timeout"    // the tool ran out of time
	LeftOutFailed    = "failed"     // any other reason; tools.log has the detail
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
	MaxIOCValue               = 2048 // bytes; the PDF analyzer keeps link targets up to this length
	MaxName                   = 64   // bytes: tool, analyzer, file kind, sha256
	MaxTitle                  = 200  // runes
	MaxEvidence               = 8    // entries per finding; the producers emit at most 3

	// The caps below bound the size of a Result. EncodeResult guarantees the 64 MiB
	// Result frame by cutting the files and skips of a Result that is still too big
	// (TestEncodeResult); the findings, which decide the verdict, always fit.
	// MaxFiles is analyze.MaxFiles + analyze.MaxExtraFiles (20 000 + 2 000); protocol
	// must not import analyze, so the sum is repeated here. MaxSkipped is lower
	// because the engine ends a longer list with one budget skip.
	MaxFiles       = 22000
	MaxSkipped     = 13000
	MaxAnalyzers   = 32  // the engine has about a dozen, plus the guest tools
	MaxReasonCount = 128 // one per critical rule, plus a few fixed lines
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

// Unread reports a skip that leaves a file or member unread: too large, over a
// budget, too deep, encrypted, cut short by a timeout or a panic, or a container
// member that could not be extracted. Such a member counts as seen but not
// analyzed.
func (s Skip) Unread() bool {
	return s.Reason == SkipTooLarge || s.HidesContent()
}

// HidesContent reports a skip behind which a payload could be hidden on purpose:
// a container that is too deep, encrypted or over its member budget, a file
// whose work budget ran out before its end, input that makes an analyzer run
// out of time or panic, or a member the container could not extract, such as a
// zip member with an unsupported compression method. A file that is only too
// large, such as a data file or a media file, is not one, and neither is a file
// that is unsupported or fails to parse, even inside a container: benign inputs
// have those, so they lower confidence but never decide the verdict.
func (s Skip) HidesContent() bool {
	switch s.Reason {
	case SkipBudget, SkipDepth, SkipEncrypted, SkipTimeout, SkipPanic, SkipUnreadable:
		return true
	}
	return false
}

// LeftOut records a guest tool that did not scan the input and why.
type LeftOut struct {
	Tool  string `json:"tool"`
	Cause string `json:"cause"`
}

// Coverage says how much of the target was analyzed. LeftOut names the guest tools that did not run.
type Coverage struct {
	FilesSeen     int       `json:"files_seen"`
	FilesAnalyzed int       `json:"files_analyzed"`
	Skipped       []Skip    `json:"skipped"`
	Analyzers     []string  `json:"analyzers"`
	Truncated     bool      `json:"truncated"`
	LeftOut       []LeftOut `json:"left_out,omitempty"`
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
	// Network is set by the host from its proxy. A guest never sends it.
	Network *Network `json:"network,omitempty"`
}
