package agent_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/mrdhira/galahad/internal/agent"
	"github.com/mrdhira/galahad/internal/protocol"
)

func TestRun(t *testing.T) {
	tests := []struct {
		name         string
		args         []string
		wantCode     int
		wantStdout   string // substring; empty means stdout must be empty
		wantStderr   string // substring; empty means stderr must be empty
		wantPlatform bool   // stdout also names the Go version and GOOS/GOARCH
	}{
		{name: "version prints build info", args: []string{"version"}, wantCode: agent.ExitClean, wantStdout: "galahad-agent dev (", wantPlatform: true},
		{name: "no args prints usage", args: nil, wantCode: agent.ExitClean, wantStdout: "Usage: galahad-agent"},
		{name: "help prints usage", args: []string{"help"}, wantCode: agent.ExitClean, wantStdout: "Commands:"},
		{name: "-h prints usage", args: []string{"-h"}, wantCode: agent.ExitClean, wantStdout: "Commands:"},
		{name: "--help prints usage", args: []string{"--help"}, wantCode: agent.ExitClean, wantStdout: "Commands:"},
		{name: "unknown command", args: []string{"bogus"}, wantCode: agent.ExitUsage, wantStderr: `unknown command "bogus"`},
		{name: "version -h prints usage", args: []string{"version", "-h"}, wantCode: agent.ExitClean, wantStdout: "Commands:"},
		{name: "version bad flag", args: []string{"version", "--nope"}, wantCode: agent.ExitUsage, wantStderr: "flag provided but not defined"},
		{name: "version extra argument", args: []string{"version", "x"}, wantCode: agent.ExitUsage, wantStderr: "unexpected argument"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out, errb bytes.Buffer
			if got := agent.Run(tt.args, &out, &errb); got != tt.wantCode {
				t.Fatalf("exit = %d, want %d", got, tt.wantCode)
			}
			checkOutput(t, "stdout", out.String(), tt.wantStdout)
			checkOutput(t, "stderr", errb.String(), tt.wantStderr)
			if tt.wantPlatform {
				for _, want := range []string{runtime.Version(), runtime.GOOS + "/" + runtime.GOARCH} {
					if !strings.Contains(out.String(), want) {
						t.Errorf("stdout %q missing %q", out.String(), want)
					}
				}
			}
			if tt.wantCode == agent.ExitUsage && !strings.Contains(errb.String(), "Usage: galahad-agent") {
				t.Errorf("stderr lacks usage: %q", errb.String())
			}
		})
	}
}

func TestRunVersionJSON(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		wantCode    int
		wantKeys    []string
		wantVersion string
	}{
		{
			name:        "version --json prints build info",
			args:        []string{"version", "--json"},
			wantCode:    agent.ExitClean,
			wantKeys:    []string{"version", "commit", "go", "os", "arch"},
			wantVersion: "dev",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out, errb bytes.Buffer
			if got := agent.Run(tt.args, &out, &errb); got != tt.wantCode {
				t.Fatalf("exit = %d, want %d", got, tt.wantCode)
			}
			var m map[string]string
			if err := json.Unmarshal(out.Bytes(), &m); err != nil {
				t.Fatalf("invalid JSON %q: %v", out.String(), err)
			}
			if len(m) != len(tt.wantKeys) {
				t.Errorf("got %v, want keys %v", m, tt.wantKeys)
			}
			for _, k := range tt.wantKeys {
				if _, ok := m[k]; !ok {
					t.Errorf("missing key %q in %v", k, m)
				}
			}
			if m["version"] != tt.wantVersion {
				t.Errorf("version = %q, want %q", m["version"], tt.wantVersion)
			}
			if c := m["commit"]; c == "" || (c != "unknown" && len(c) > 12) {
				t.Errorf("commit = %q, want 1-12 chars or \"unknown\"", c)
			}
			if errb.Len() != 0 {
				t.Errorf("stderr = %q, want empty", errb.String())
			}
		})
	}
}

func TestRunAnalyze(t *testing.T) {
	// The test signature is built from parts so no file in the repo contains it.
	eicar := `X5O!P%@AP[4\PZX54(P^)7CC)7}$` + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!" + "$H+H*"
	tests := []struct {
		name string
		// inputs: setup returns the command arguments and the report path to check ("" for none)
		setup func(t *testing.T, tmp string) (args []string, report string)
		// expectations
		wantCode     int
		wantStdout   string           // substring; empty means stdout must be empty
		wantStderr   string           // substring; empty means stderr must be empty
		wantVerdict  protocol.Verdict // empty only for cases that write no report
		wantRule     string           // rule that must be in the report
		wantFiles    int
		wantNoReport bool
	}{
		{
			name: "directory target writes a valid report",
			setup: func(t *testing.T, tmp string) ([]string, string) {
				target := filepath.Join(tmp, "target")
				mustWrite(t, filepath.Join(target, "a.txt"), "hello\n")
				mustWrite(t, filepath.Join(target, "sub", "e.txt"), eicar)
				out := filepath.Join(tmp, "out")
				return []string{"analyze", "-o", out, target}, filepath.Join(out, "report.json")
			},
			wantCode:    agent.ExitMalicious,
			wantStdout:  "report: ",
			wantVerdict: protocol.VerdictMalicious,
			wantRule:    "GAL-SIG-001",
			wantFiles:   2,
		},
		{
			name: "one high finding exits suspicious",
			setup: func(t *testing.T, tmp string) ([]string, string) {
				target := filepath.Join(tmp, "notes.txt")
				mustWrite(t, target, "\x7fELF\x02\x01\x01"+strings.Repeat("\x00", 64))
				out := filepath.Join(tmp, "out")
				return []string{"analyze", "-o", out, target}, filepath.Join(out, "report.json")
			},
			wantCode:    agent.ExitSuspicious,
			wantStdout:  "report: ",
			wantVerdict: protocol.VerdictSuspicious,
			wantRule:    "GAL-IDENT-001",
			wantFiles:   1,
		},
		{
			name: "file target writes a valid report",
			setup: func(t *testing.T, tmp string) ([]string, string) {
				target := filepath.Join(tmp, "a.txt")
				mustWrite(t, target, "hello\n")
				out := filepath.Join(tmp, "out")
				return []string{"analyze", "-timeout", "1m", "-o", out, target}, filepath.Join(out, "report.json")
			},
			wantCode:    agent.ExitClean,
			wantStdout:  "report: ",
			wantVerdict: protocol.VerdictClean,
			wantFiles:   1,
		},
		{
			name: "default output is a temporary directory",
			setup: func(t *testing.T, tmp string) ([]string, string) {
				t.Setenv("TMPDIR", tmp)
				t.Setenv("TMP", tmp)
				t.Setenv("TEMP", tmp)
				target := filepath.Join(tmp, "a.txt")
				mustWrite(t, target, "hello\n")
				return []string{"analyze", target}, ""
			},
			wantCode:    agent.ExitClean,
			wantStdout:  "report: ",
			wantVerdict: protocol.VerdictClean,
			wantFiles:   1,
		},
		{
			name:       "-h prints usage",
			setup:      func(*testing.T, string) ([]string, string) { return []string{"analyze", "-h"}, "" },
			wantCode:   agent.ExitClean,
			wantStdout: "Commands:",
		},
		{
			name:       "unknown flag",
			setup:      func(*testing.T, string) ([]string, string) { return []string{"analyze", "--nope", "x"}, "" },
			wantCode:   agent.ExitUsage,
			wantStderr: "flag provided but not defined",
		},
		{
			name:       "missing path",
			setup:      func(*testing.T, string) ([]string, string) { return []string{"analyze"}, "" },
			wantCode:   agent.ExitUsage,
			wantStderr: "exactly one path",
		},
		{
			name: "nonexistent target",
			setup: func(t *testing.T, tmp string) ([]string, string) {
				out := filepath.Join(tmp, "out")
				return []string{"analyze", "-o", out, filepath.Join(tmp, "missing")}, filepath.Join(out, "report.json")
			},
			wantCode:     agent.ExitError,
			wantStderr:   "galahad-agent analyze:",
			wantNoReport: true,
		},
		{
			name: "output directory inside the target",
			setup: func(t *testing.T, tmp string) ([]string, string) {
				target := filepath.Join(tmp, "target")
				mustWrite(t, filepath.Join(target, "a.txt"), "hello\n")
				out := filepath.Join(target, "new", "out")
				return []string{"analyze", "-o", out, target}, filepath.Join(out, "report.json")
			},
			wantCode:     agent.ExitUsage,
			wantStderr:   "inside the target",
			wantNoReport: true,
		},
		{
			name: "output directory cannot be created",
			setup: func(t *testing.T, tmp string) ([]string, string) {
				target := filepath.Join(tmp, "a.txt")
				mustWrite(t, target, "hello\n")
				blocker := filepath.Join(tmp, "blocker")
				mustWrite(t, blocker, "x")
				return []string{"analyze", "-o", filepath.Join(blocker, "out"), target}, ""
			},
			wantCode:   agent.ExitError,
			wantStderr: "galahad-agent analyze:",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmp := t.TempDir()
			args, report := tt.setup(t, tmp)
			var out, errb bytes.Buffer

			code := agent.RunWithEnv(args, &out, &errb, agent.Env{DetectVM: func() (bool, string) { return true, "test" }})

			if code != tt.wantCode {
				t.Fatalf("exit = %d, want %d (stderr %q)", code, tt.wantCode, errb.String())
			}
			checkOutput(t, "stdout", out.String(), tt.wantStdout)
			checkOutput(t, "stderr", errb.String(), tt.wantStderr)
			if tt.wantNoReport {
				if _, err := os.Stat(report); err == nil {
					t.Errorf("report %s exists, want none", report)
				}
				return
			}
			if tt.wantFiles == 0 {
				return
			}
			if report == "" {
				report = strings.TrimSpace(strings.TrimPrefix(out.String(), "report: "))
			}
			b, err := os.ReadFile(report)
			if err != nil {
				t.Fatal(err)
			}
			var res protocol.Result
			dec := json.NewDecoder(bytes.NewReader(b))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&res); err != nil {
				t.Fatal(err)
			}
			if err := res.Validate(); err != nil {
				t.Errorf("report does not validate: %v", err)
			}
			if res.Tool.Name != "galahad-agent" || res.Verdict != tt.wantVerdict || len(res.Files) != tt.wantFiles {
				t.Errorf("tool %q verdict %q files %d, want galahad-agent, %q, %d", res.Tool.Name, res.Verdict, len(res.Files), tt.wantVerdict, tt.wantFiles)
			}
			if res.Verdict == protocol.VerdictMalicious && tt.wantRule != "" && !strings.Contains(strings.Join(res.Reasons, "\n"), tt.wantRule) {
				t.Errorf("reasons %q do not mention %s", res.Reasons, tt.wantRule)
			}
			if tt.wantRule != "" && (len(res.Findings) != 1 || res.Findings[0].RuleID != tt.wantRule) {
				t.Errorf("findings = %+v, want one %s", res.Findings, tt.wantRule)
			}
			if runtime.GOOS != "windows" {
				if st, err := os.Stat(report); err != nil || st.Mode().Perm() != 0o600 {
					t.Errorf("report stat = %v, %v, want mode 0600", st, err)
				}
			}
		})
	}
}

func TestRunAnalyzeHostGuard(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		flags  []string
		inVM   bool
		reason string
		// expectations
		wantCode     int
		wantStderr   []string // substrings; none means stderr must be empty
		wantReport   bool
		wantNoStdout bool
	}{
		{name: "in a VM proceeds silently", inVM: true, reason: "test vm", wantCode: agent.ExitClean, wantReport: true},
		{
			name: "not in a VM without the flag refuses", reason: "no virtualization detected",
			wantCode:     agent.ExitUsage,
			wantStderr:   []string{"refusing to analyze untrusted input outside a VM", "no virtualization detected", "--unsafe-host"},
			wantNoStdout: true,
		},
		{
			name: "not in a VM with the flag warns and proceeds", flags: []string{"--unsafe-host"}, reason: "no virtualization detected",
			wantCode:   agent.ExitClean,
			wantStderr: []string{"WARNING", "--unsafe-host"},
			wantReport: true,
		},
		{name: "in a VM with the flag proceeds silently", flags: []string{"--unsafe-host"}, inVM: true, reason: "test vm", wantCode: agent.ExitClean, wantReport: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmp := t.TempDir()
			target := filepath.Join(tmp, "a.txt")
			mustWrite(t, target, "hello\n")
			out := filepath.Join(tmp, "out")
			args := append([]string{"analyze"}, tt.flags...)
			args = append(args, "-o", out, target)
			var stdout, stderr bytes.Buffer

			code := agent.RunWithEnv(args, &stdout, &stderr, agent.Env{DetectVM: func() (bool, string) { return tt.inVM, tt.reason }})

			if code != tt.wantCode {
				t.Fatalf("exit = %d, want %d (stderr %q)", code, tt.wantCode, stderr.String())
			}
			if len(tt.wantStderr) == 0 && stderr.Len() != 0 {
				t.Errorf("stderr = %q, want empty", stderr.String())
			}
			for _, want := range tt.wantStderr {
				if !strings.Contains(stderr.String(), want) {
					t.Errorf("stderr %q missing %q", stderr.String(), want)
				}
			}
			if tt.wantNoStdout && stdout.Len() != 0 {
				t.Errorf("stdout = %q, want empty", stdout.String())
			}
			_, err := os.Stat(filepath.Join(out, "report.json"))
			if (err == nil) != tt.wantReport {
				t.Errorf("report exists = %v, want %v", err == nil, tt.wantReport)
			}
		})
	}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func checkOutput(t *testing.T, name, got, want string) {
	t.Helper()
	if want == "" {
		if got != "" {
			t.Errorf("%s = %q, want empty", name, got)
		}
		return
	}
	if !strings.Contains(got, want) {
		t.Errorf("%s %q missing %q", name, got, want)
	}
}
