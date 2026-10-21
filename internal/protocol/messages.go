package protocol

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"
)

// ProtocolVersion is the value of Hello.Protocol.
const ProtocolVersion = 1

// Job kinds.
const (
	KindScan     = "scan"
	KindUpdate   = "update"
	KindProbe    = "probe"
	KindNetProbe = "net-probe"
)

// Job sources.
const (
	SourceLocal = "local"
	SourceURL   = "url"
	SourceDrive = "drive"
	SourceGit   = "git"
)

// Progress stages.
const (
	StageIngest  = "ingest"
	StageAnalyze = "analyze"
	StageClamAV  = "clamav"
	StageYARA    = "yara"
	StageCapa    = "capa"
	StageOSV     = "osv"
)

// ArtifactID names an artifact. It is the first byte of an Artifact frame.
type ArtifactID byte

// Artifact ids.
const (
	ArtifactIngestLog ArtifactID = iota + 1
	ArtifactToolsLog
	ArtifactProbeJSON
)

// Error codes.
const (
	CodeProtocol     = "protocol"
	CodeIngest       = "ingest"
	CodeNotAllowed   = "not_allowed"
	CodeDrivePrivate = "drive_private"
	CodeDriveQuota   = "drive_quota"
	CodeTooLarge     = "too_large"
	CodeTimeout      = "timeout"
	CodeInternal     = "internal"
)

// Limits on message fields.
const (
	MaxInputBytes   = 1 << 30 // local input: bytes sent in Data frames
	MaxInputEntries = 200000  // local input: entries of the tar stream
	MaxTimeoutSec   = 24 * 60 * 60
	MaxErrorMessage = 512 // runes
	MaxVersion      = 64  // bytes
	MaxURL          = 2048
	MaxReply        = 128 // runes
)

var (
	jobIDRe  = regexp.MustCompile(`^\d{8}-\d{6}-[0-9a-f]{6}$`)
	sha256Re = regexp.MustCompile(`^[0-9a-f]{64}$`)
	hostRe   = regexp.MustCompile(`^[a-z0-9.-]{1,253}$`)
)

func oneOf(field, v string, allowed ...string) error {
	if !slices.Contains(allowed, v) {
		return fmt.Errorf("%s %q not allowed", field, v)
	}
	return nil
}

// Hello is the first frame of the guest.
type Hello struct {
	Protocol     int    `json:"protocol"`
	AgentVersion string `json:"agent_version"`
}

// Validate checks the protocol number and the version text.
func (h Hello) Validate() error {
	if h.Protocol != ProtocolVersion {
		return fmt.Errorf("protocol %d, want %d", h.Protocol, ProtocolVersion)
	}
	if h.AgentVersion == "" || len(h.AgentVersion) > MaxVersion {
		return fmt.Errorf("agent_version is %d bytes, want 1-%d", len(h.AgentVersion), MaxVersion)
	}
	return checkText("agent_version", h.AgentVersion)
}

// Timeouts are in seconds. Job is the whole job; Ingest is the share for the
// ingest step, and 0 means the agent's default.
type Timeouts struct {
	Job    int `json:"job"`
	Ingest int `json:"ingest"`
}

// Job tells the guest what to do. Source is set for scan jobs only. Name is the
// target name, URL the address to fetch for the url, drive and git sources.
type Job struct {
	ID         string    `json:"id"`
	Kind       string    `json:"kind"`
	Source     string    `json:"source"`
	Name       string    `json:"name"`
	URL        string    `json:"url"`
	Submodules bool      `json:"submodules"`
	Timeouts   Timeouts  `json:"timeouts"`
	Now        time.Time `json:"now"`
}

// Validate checks the ID format, the enums, the text fields and the timeouts.
func (j Job) Validate() error {
	if !jobIDRe.MatchString(j.ID) {
		return fmt.Errorf("id %q does not match %s", j.ID, jobIDRe)
	}
	if err := oneOf("kind", j.Kind, KindScan, KindUpdate, KindProbe, KindNetProbe); err != nil {
		return err
	}
	if j.Kind == KindScan {
		if err := oneOf("source", j.Source, SourceLocal, SourceURL, SourceDrive, SourceGit); err != nil {
			return err
		}
	} else if j.Source != "" {
		return fmt.Errorf("source %q on a %s job", j.Source, j.Kind)
	}
	if len(j.Name) > MaxPath {
		return fmt.Errorf("name is %d bytes, max %d", len(j.Name), MaxPath)
	}
	// The name of a local target is a file name. It may hold control or bidi characters, which
	// the analyzers report as findings, so only what JSON and a path cannot carry is refused.
	if !utf8.ValidString(j.Name) || strings.ContainsRune(j.Name, 0) {
		return errors.New("name is not valid UTF-8 text without NUL")
	}
	if len(j.URL) > MaxURL {
		return fmt.Errorf("url is %d bytes, max %d", len(j.URL), MaxURL)
	}
	if err := checkText("url", j.URL); err != nil {
		return err
	}
	if j.Timeouts.Job < 1 || j.Timeouts.Job > MaxTimeoutSec {
		return fmt.Errorf("timeouts.job %d out of range 1-%d", j.Timeouts.Job, MaxTimeoutSec)
	}
	if j.Timeouts.Ingest < 0 || j.Timeouts.Ingest > MaxTimeoutSec {
		return fmt.Errorf("timeouts.ingest %d out of range 0-%d", j.Timeouts.Ingest, MaxTimeoutSec)
	}
	if j.Now.IsZero() {
		return errors.New("now is not set")
	}
	return nil
}

// End closes the tar stream: the byte count and sha256 the host sent.
type End struct {
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

// Validate checks the byte count against MaxInputBytes and the hash format.
func (e End) Validate() error {
	if e.Bytes < 0 || e.Bytes > MaxInputBytes {
		return fmt.Errorf("bytes %d out of range 0-%d", e.Bytes, MaxInputBytes)
	}
	if !sha256Re.MatchString(e.SHA256) {
		return fmt.Errorf("sha256 %q is not 64 lowercase hex digits", e.SHA256)
	}
	return nil
}

// Progress reports the stage the guest has reached.
type Progress struct {
	Stage string `json:"stage"`
}

// Validate checks the stage enum.
func (p Progress) Validate() error {
	return oneOf("stage", p.Stage, StageIngest, StageAnalyze, StageClamAV, StageYARA, StageCapa, StageOSV)
}

// Artifact is a raw log from the guest. The host stores the bytes and never parses them.
type Artifact struct {
	ID   ArtifactID
	Data []byte
}

// Validate checks the id enum.
func (a Artifact) Validate() error {
	switch a.ID {
	case ArtifactIngestLog, ArtifactToolsLog, ArtifactProbeJSON:
		return nil
	}
	return fmt.Errorf("artifact id %d not allowed", byte(a.ID))
}

// Marshal returns the frame payload: the id byte, then the data.
func (a Artifact) Marshal() []byte {
	return append([]byte{byte(a.ID)}, a.Data...)
}

// ParseArtifact splits a frame payload into the id and the data, and validates the id.
func ParseArtifact(payload []byte) (Artifact, error) {
	if len(payload) == 0 {
		return Artifact{}, errors.New("artifact payload is empty")
	}
	a := Artifact{ID: ArtifactID(payload[0]), Data: payload[1:]}
	return a, a.Validate()
}

// Error is how the guest reports a failed job.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Validate checks the code enum and that the message is short, safe text.
func (e Error) Validate() error {
	if err := oneOf("code", e.Code, CodeProtocol, CodeIngest, CodeNotAllowed, CodeDrivePrivate, CodeDriveQuota, CodeTooLarge, CodeTimeout, CodeInternal); err != nil {
		return err
	}
	if n := utf8.RuneCountInString(e.Message); n > MaxErrorMessage {
		return fmt.Errorf("message has %d runes, max %d", n, MaxErrorMessage)
	}
	return checkText("message", e.Message)
}

// Connect asks the host proxy for a tunnel to a host and port.
type Connect struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

// Validate checks the host name format and the port range.
func (c Connect) Validate() error {
	if !hostRe.MatchString(c.Host) {
		return fmt.Errorf("host %q does not match %s", c.Host, hostRe)
	}
	if c.Port < 1 || c.Port > 65535 {
		return fmt.Errorf("port %d out of range 1-65535", c.Port)
	}
	return nil
}

// ConnectReply is the host's answer to Connect. Reason says why a tunnel was refused.
type ConnectReply struct {
	OK     bool   `json:"ok"`
	Reason string `json:"reason"`
}

// Validate checks that the reason is short, safe text.
func (c ConnectReply) Validate() error {
	if n := utf8.RuneCountInString(c.Reason); n > MaxReply {
		return fmt.Errorf("reason has %d runes, max %d", n, MaxReply)
	}
	return checkText("reason", c.Reason)
}
