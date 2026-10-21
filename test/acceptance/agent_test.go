package acceptance_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// report mirrors the parts of report.json the tests read. It does not import internal packages.
type report struct {
	Target struct {
		Name      string `json:"name"`
		Kind      string `json:"kind"`
		SHA256    string `json:"sha256"`
		FileCount int    `json:"file_count"`
	} `json:"target"`
	Files []struct {
		Path string `json:"path"`
	} `json:"files"`
	Findings []struct {
		RuleID   string `json:"rule_id"`
		Severity string `json:"severity"`
		Analyzer string `json:"analyzer"`
		Evidence []struct {
			Path    string `json:"path"`
			Line    int    `json:"line"`
			Snippet string `json:"snippet"`
		} `json:"evidence"`
	} `json:"findings"`
	IOCs []struct {
		Type  string `json:"type"`
		Value string `json:"value"`
	} `json:"iocs"`
	Coverage struct {
		FilesSeen     int `json:"files_seen"`
		FilesAnalyzed int `json:"files_analyzed"`
		Skipped       []struct {
			Path   string `json:"path"`
			Reason string `json:"reason"`
		} `json:"skipped"`
	} `json:"coverage"`
	Verdict         string   `json:"verdict"`
	Score           int      `json:"score"`
	ConfidenceLevel string   `json:"confidence_level"`
	Reasons         []string `json:"reasons"`
}

// analyze runs "galahad-agent analyze" on target, expects exit code wantCode and returns the parsed report.
// Extra flags go before the path.
func analyze(t *testing.T, target string, wantCode int, flags ...string) report {
	t.Helper()
	rep, _ := analyzeOut(t, target, wantCode, flags...)
	return rep
}

// analyzeOut is analyze that also returns the output directory, for tests that read summary.md or report.html.
func analyzeOut(t *testing.T, target string, wantCode int, flags ...string) (report, string) {
	t.Helper()
	out := filepath.Join(t.TempDir(), "out")
	args := append([]string{"analyze", "--unsafe-host", "-o", out}, flags...)
	stdout, stderr, code := runAgent(t, append(args, target)...)
	if code != wantCode {
		t.Fatalf("analyze exit = %d, want %d\nstdout: %s\nstderr: %s", code, wantCode, stdout, stderr)
	}
	rep, err := readReport(filepath.Join(out, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	return rep, out
}

// readReport parses the report.json at path.
func readReport(path string) (report, error) {
	var rep report
	b, err := os.ReadFile(path)
	if err != nil {
		return rep, err
	}
	if err := json.Unmarshal(b, &rep); err != nil {
		return rep, fmt.Errorf("%s: %w", path, err)
	}
	return rep, nil
}

// otherFindings returns the rule IDs of the findings that are not auto-execution
// inventory (GAL-AUTOEXEC-006 to 008), which only list where automation exists.
func otherFindings(rep report) []string {
	var ids []string
	for _, f := range rep.Findings {
		if !slices.Contains([]string{"GAL-AUTOEXEC-006", "GAL-AUTOEXEC-007", "GAL-AUTOEXEC-008"}, f.RuleID) {
			ids = append(ids, f.RuleID)
		}
	}
	return ids
}

// hasFinding reports whether the report has a finding of rule with evidence at "path:line".
func hasFinding(rep report, rule, at string) bool {
	for _, f := range rep.Findings {
		for _, e := range f.Evidence {
			if f.RuleID == rule && fmt.Sprintf("%s:%d", e.Path, e.Line) == at {
				return true
			}
		}
	}
	return false
}

// writeEICAR writes the EICAR test file to dir/eicar.txt. The signature is built from
// parts so that no file in the repository contains it.
func writeEICAR(t *testing.T, dir string) string {
	t.Helper()
	sig := `X5O!P%@AP[4\PZX54(P^)7CC)7}$` + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!" + "$H+H*"
	p := filepath.Join(dir, "eicar.txt")
	if err := os.WriteFile(p, []byte(sig), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestAgentSmoke(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantStdout string // substring; empty means stdout must be empty
		wantStderr string // substring; empty means stderr must be empty
	}{
		{name: "version prints stamped build info", args: []string{"version"}, wantCode: 0, wantStdout: "galahad-agent " + stampedVersion + " (" + stampedCommit + ", "},
		{name: "no args prints usage", args: nil, wantCode: 0, wantStdout: "Usage: galahad-agent"},
		{name: "help prints usage", args: []string{"help"}, wantCode: 0, wantStdout: "Usage: galahad-agent"},
		{name: "unknown command", args: []string{"frobnicate"}, wantCode: 2, wantStderr: "frobnicate"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given the agent built with a stamped version
			// When running it with the case's arguments
			stdout, stderr, code := runAgent(t, tt.args...)
			// Then exit code, stdout and stderr match
			if code != tt.wantCode {
				t.Errorf("exit = %d, want %d", code, tt.wantCode)
			}
			checkOutput(t, "stdout", stdout, tt.wantStdout)
			checkOutput(t, "stderr", stderr, tt.wantStderr)
			if tt.wantCode == 2 && !strings.Contains(stderr, "Usage") {
				t.Errorf("stderr lacks usage: %q", stderr)
			}
		})
	}
}

func TestAgentHostGuard(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		flags []string
		// expectations
		wantRefusal bool // when the runner is not a VM
	}{
		{name: "without the flag refuses outside a VM", wantRefusal: true},
		{name: "with the flag proceeds", flags: []string{"--unsafe-host"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given a harmless file and the built agent
			target := filepath.Join(t.TempDir(), "a.txt")
			if err := os.WriteFile(target, []byte("hello\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			out := filepath.Join(t.TempDir(), "out")
			args := append([]string{"analyze"}, tt.flags...)
			// When it analyzes the file
			stdout, stderr, code := runAgent(t, append(args, "-o", out, target)...)
			// Then it refuses (exit 2, naming the flag) on a non-VM host, or writes a report on a VM or with the flag
			refused := strings.Contains(stderr, "refusing to analyze untrusted input outside a VM")
			if refused && !tt.wantRefusal {
				t.Fatalf("refused despite the flag: %s", stderr)
			}
			if refused {
				if code != 2 || !strings.Contains(stderr, "--unsafe-host") || stdout != "" {
					t.Errorf("refusal exit = %d, stdout %q, stderr %q, want exit 2, empty stdout, --unsafe-host hint", code, stdout, stderr)
				}
				if _, err := os.Stat(filepath.Join(out, "report.json")); err == nil {
					t.Error("report written despite refusal")
				}
				return
			}
			if code != 0 || !strings.Contains(stdout, "report.html") {
				t.Errorf("exit = %d, stdout %q, stderr %q, want a report", code, stdout, stderr)
			}
			if _, err := os.Stat(filepath.Join(out, "report.json")); err != nil {
				t.Error(err)
			}
		})
	}
}

func TestAgentAnalyze(t *testing.T) {
	tests := []struct {
		name string
		// setup returns the target to analyze
		setup func(t *testing.T) string
		// expectations
		wantCode       int
		wantVerdict    string
		wantLevel      string
		wantRule       string // rule that must be present at wantAt and in the reasons; empty means no findings at all
		wantAt         string
		wantTargetKind string
	}{
		{
			name: "EICAR file built at test time is flagged",
			setup: func(t *testing.T) string {
				return writeEICAR(t, t.TempDir())
			},
			wantCode:       20,
			wantVerdict:    "malicious",
			wantLevel:      "high",
			wantRule:       "GAL-SIG-001",
			wantAt:         "eicar.txt:1",
			wantTargetKind: "file",
		},
		{
			name: "EICAR in a directory is flagged",
			setup: func(t *testing.T) string {
				dir := t.TempDir()
				writeEICAR(t, dir)
				return dir
			},
			wantCode:       20,
			wantVerdict:    "malicious",
			wantLevel:      "high",
			wantRule:       "GAL-SIG-001",
			wantAt:         "eicar.txt:1",
			wantTargetKind: "dir",
		},
		{
			name: "benign Go CLI sources have no findings and are fully analyzed",
			setup: func(t *testing.T) string {
				// The Makefile and pre-commit config of the fixture get an info inventory finding
				// from the autoexec analyzer (see TestAutoexec), so only the Go sources are copied.
				root, err := moduleRoot()
				if err != nil {
					t.Fatal(err)
				}
				dir := t.TempDir()
				for _, name := range []string{"go.mod", "main.go"} {
					b, err := os.ReadFile(filepath.Join(root, "testdata", "corpus", "benign-go-cli", name))
					if err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
						t.Fatal(err)
					}
				}
				return dir
			},
			wantCode:       0,
			wantVerdict:    "clean",
			wantLevel:      "high",
			wantTargetKind: "dir",
		},
		{
			name:           "the agent binary does not carry the EICAR signature",
			setup:          func(*testing.T) string { return agentPath },
			wantCode:       0,
			wantVerdict:    "clean",
			wantLevel:      "high",
			wantTargetKind: "file",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given a target
			target := tt.setup(t)
			// When the agent analyzes it
			rep := analyze(t, target, tt.wantCode)
			// Then the report has the expected finding (or none) and the coverage is complete
			if tt.wantRule == "" {
				if len(rep.Findings) != 0 {
					t.Errorf("findings = %+v, want none", rep.Findings)
				}
			} else if !hasFinding(rep, tt.wantRule, tt.wantAt) {
				t.Errorf("no %s at %s in %+v", tt.wantRule, tt.wantAt, rep.Findings)
			}
			if rep.Target.Kind != tt.wantTargetKind {
				t.Errorf("target kind = %q, want %q", rep.Target.Kind, tt.wantTargetKind)
			}
			if rep.Coverage.FilesSeen == 0 || rep.Coverage.FilesAnalyzed != rep.Coverage.FilesSeen || len(rep.Coverage.Skipped) != 0 {
				t.Errorf("coverage seen/analyzed/skipped = %d/%d/%v, want all files analyzed", rep.Coverage.FilesSeen, rep.Coverage.FilesAnalyzed, rep.Coverage.Skipped)
			}
			if rep.Verdict != tt.wantVerdict || rep.ConfidenceLevel != tt.wantLevel {
				t.Errorf("verdict/confidence_level = %q/%q, want %q/%q", rep.Verdict, rep.ConfidenceLevel, tt.wantVerdict, tt.wantLevel)
			}
			if tt.wantRule != "" && !strings.Contains(strings.Join(rep.Reasons, "\n"), tt.wantRule) {
				t.Errorf("reasons %q do not mention %s", rep.Reasons, tt.wantRule)
			}
			if tt.wantTargetKind == "file" && len(rep.Target.SHA256) != 64 {
				t.Errorf("file target sha256 = %q, want 64 hex chars", rep.Target.SHA256)
			}
		})
	}
}

func TestAgentAnalyzeUsage(t *testing.T) {
	tests := []struct {
		name string
		// setup returns the arguments after "analyze"
		setup func(t *testing.T) []string
		// expectations
		wantCode   int
		wantStderr string // substring
	}{
		{
			name:       "missing path",
			setup:      func(*testing.T) []string { return nil },
			wantCode:   2,
			wantStderr: "exactly one path",
		},
		{
			name: "nonexistent target",
			setup: func(t *testing.T) []string {
				return []string{"-o", t.TempDir(), filepath.Join(t.TempDir(), "missing")}
			},
			wantCode:   1,
			wantStderr: "galahad-agent analyze:",
		},
		{
			name: "output inside the target is refused and nothing is written",
			setup: func(t *testing.T) []string {
				dir := t.TempDir()
				writeEICAR(t, dir)
				return []string{"-o", filepath.Join(dir, "out"), dir}
			},
			wantCode:   2,
			wantStderr: "inside the target",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given arguments that are wrong
			args := append([]string{"analyze"}, tt.setup(t)...)
			// When the agent runs
			stdout, stderr, code := runAgent(t, args...)
			// Then it fails with the expected code and message, and writes no report into the target
			if code != tt.wantCode {
				t.Errorf("exit = %d, want %d", code, tt.wantCode)
			}
			checkOutput(t, "stderr", stderr, tt.wantStderr)
			if stdout != "" {
				t.Errorf("stdout = %q, want empty", stdout)
			}
			if len(args) > 1 && args[1] == "-o" {
				if _, err := os.Stat(filepath.Join(args[2], "report.json")); err == nil {
					t.Errorf("report written to %s", args[2])
				}
			}
		})
	}
}
