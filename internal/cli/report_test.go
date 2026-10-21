package cli_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mrdhira/galahad/internal/cli"
	"github.com/mrdhira/galahad/internal/job"
	"github.com/mrdhira/galahad/internal/protocol"
)

func TestRunReport(t *testing.T) {
	// withReport adds a finished job, then lets edit change its report.json.
	withReport := func(res *protocol.Result, edit func(t *testing.T, path string)) func(t *testing.T, home string) {
		return func(t *testing.T, home string) {
			dir := addJob(t, home, idOld, job.StateDone, "a.pdf", res)
			if edit != nil {
				edit(t, filepath.Join(dir, "report.json"))
			}
		}
	}
	write := func(content string) func(t *testing.T, path string) {
		return func(t *testing.T, path string) {
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	replace := func(old, new string) func(t *testing.T, path string) {
		return func(t *testing.T, path string) {
			data, err := os.ReadFile(path) // #nosec G304 -- test fixture path under t.TempDir()
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(data), old) {
				t.Fatalf("report.json lacks %q", old)
			}
			write(strings.Replace(string(data), old, new, 1))(t, path)
		}
	}
	malicious := testResult(protocol.VerdictMalicious, 95)
	tests := []struct {
		name string
		// inputs
		args  []string
		setup func(t *testing.T, home string)
		// expectations
		wantCode     int
		wantStdout   []string
		wantStderr   []string
		wantAbsent   []string
		wantFileJSON bool // stdout is report.json, byte for byte
	}{
		{
			name: "malicious prints the summary and the paths and exits 20",
			args: []string{idOld}, setup: withReport(malicious, nil),
			wantCode:   cli.ExitMalicious,
			wantStdout: []string{"Verdict: MALICIOUS", "Score: 95/100", "GAL-SIG-001", "Reports:", filepath.Join("jobs", idOld, "report.json"), filepath.Join("jobs", idOld, "summary.md"), filepath.Join("jobs", idOld, "report.html")},
		},
		{
			name: "suspicious exits 10",
			args: []string{idOld}, setup: withReport(testResult(protocol.VerdictSuspicious, 40), nil),
			wantCode: cli.ExitSuspicious, wantStdout: []string{"Verdict: SUSPICIOUS"},
		},
		{
			name: "clean exits 0",
			args: []string{idOld}, setup: withReport(testResult(protocol.VerdictClean, 0), nil),
			wantCode: cli.ExitClean, wantStdout: []string{"Verdict: CLEAN"},
		},
		{
			name: "--json before the id prints the file and exits with the verdict",
			args: []string{"--json", idOld}, setup: withReport(malicious, nil),
			wantCode: cli.ExitMalicious, wantFileJSON: true, wantAbsent: []string{"Verdict:"},
		},
		{
			name: "--json after the id",
			args: []string{idOld, "--json"}, setup: withReport(malicious, nil),
			wantCode: cli.ExitMalicious, wantFileJSON: true,
		},
		{name: "-h prints usage", args: []string{"-h"}, wantCode: cli.ExitClean, wantStdout: []string{"Usage: galahad"}},
		{name: "unknown flag", args: []string{"--nope", idOld}, wantCode: cli.ExitUsage, wantStderr: []string{"flag provided but not defined"}},
		{name: "no id", wantCode: cli.ExitUsage, wantStderr: []string{"want exactly one job id, got 0"}},
		{name: "two ids", args: []string{idOld, idNew}, wantCode: cli.ExitUsage, wantStderr: []string{"want exactly one job id, got 2"}},
		{name: "malformed id", args: []string{"../" + idOld}, wantCode: cli.ExitUsage, wantStderr: []string{`invalid job id "../` + idOld + `"`}},
		{name: "malformed id with escape codes is cleaned", args: []string{"\x1b]0;x\a"}, wantCode: cli.ExitUsage, wantStderr: []string{`invalid job id "\\u001b]0;x\\u0007"`}},
		{name: "unknown id", args: []string{idMissing}, wantCode: cli.ExitError, wantStderr: []string{"no report.json for job " + idMissing}},
		{
			name: "a job without a report",
			args: []string{idOld}, setup: withReport(nil, nil),
			wantCode: cli.ExitError, wantStderr: []string{"no report.json for job " + idOld},
		},
		{
			name: "report.json that is not a regular file",
			args: []string{idOld}, setup: func(t *testing.T, home string) {
				dir := addJob(t, home, idOld, job.StateDone, "a.pdf", nil)
				if err := os.Mkdir(filepath.Join(dir, "report.json"), 0o700); err != nil {
					t.Fatal(err)
				}
			},
			wantCode: cli.ExitError, wantStderr: []string{"job " + idOld + ": report.json is not a regular file"},
		},
		{
			name: "report.json over the size cap",
			args: []string{idOld}, setup: withReport(malicious, func(t *testing.T, path string) {
				f, err := os.OpenFile(path, os.O_WRONLY, 0o600) // #nosec G304 -- test fixture path under t.TempDir()
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = f.Close() }() // the file is only truncated
				if err := f.Truncate(64<<20 + 1); err != nil {
					t.Skipf("filesystem cannot hold a sparse 64 MiB file: %v", err)
				}
			}),
			wantCode: cli.ExitError, wantStderr: []string{"report.json is larger than 67108864 bytes"},
		},
		{
			name: "report.json with a field the schema does not have",
			args: []string{idOld}, setup: withReport(malicious, replace(`"verdict"`, `"extra": 1, "verdict"`)),
			wantCode: cli.ExitError, wantStderr: []string{"report.json: json: unknown field"},
		},
		{
			name: "report.json that is not JSON",
			args: []string{idOld}, setup: withReport(malicious, write("not json")),
			wantCode: cli.ExitError, wantStderr: []string{"report.json:"},
		},
		{
			name: "report.json with data after the JSON value",
			args: []string{idOld}, setup: withReport(malicious, replace(`"reasons": []`, `"reasons": []`+"\n}\n{")),
			wantCode: cli.ExitError, wantStderr: []string{"report.json:"},
		},
		{
			name: "report.json that fails Validate",
			args: []string{idOld}, setup: withReport(malicious, replace(`"score": 95`, `"score": 101`)),
			wantCode: cli.ExitError, wantStderr: []string{"report.json: score 101 out of range"},
		},
		{
			name: "control characters in report.json do not reach the terminal",
			args: []string{idOld}, setup: withReport(malicious, replace(`"Known test signature"`, `"x\u001b[2Jy"`)),
			wantCode: cli.ExitError, wantStderr: []string{"report.json: findings[0]: title has control or bidi characters"},
		},
		{
			name: "a job directory that is a symlink is refused",
			args: []string{idNew}, setup: func(t *testing.T, home string) {
				withReport(malicious, nil)(t, home)
				symlinkOrSkip(t, filepath.Join(home, "jobs", idOld), filepath.Join(home, "jobs", idNew))
			},
			wantCode: cli.ExitError, wantStderr: []string{"job " + idNew + ": " + idNew + " is not a job directory"},
		},
		{
			name: "report.json that is a symlink out of the job directory is refused",
			args: []string{idOld}, setup: withReport(malicious, func(t *testing.T, path string) {
				outside := filepath.Join(t.TempDir(), "report.json")
				if err := os.Rename(path, outside); err != nil {
					t.Fatal(err)
				}
				symlinkOrSkip(t, outside, path)
			}),
			wantCode: cli.ExitError, wantStderr: []string{"report.json is not a regular file"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home := t.TempDir()
			if tt.setup != nil {
				tt.setup(t, home)
			}
			var out, errb bytes.Buffer
			if got := cli.RunWithEnv(append([]string{"report"}, tt.args...), &out, &errb, cli.Env{Home: home}); got != tt.wantCode {
				t.Fatalf("exit = %d, want %d\nstdout: %s\nstderr: %s", got, tt.wantCode, out.String(), errb.String())
			}
			checkStreams(t, out.String(), errb.String(), tt.wantStdout, tt.wantStderr, tt.wantAbsent)
			if tt.wantFileJSON {
				want, err := os.ReadFile(filepath.Join(home, "jobs", idOld, "report.json")) // #nosec G304 -- test fixture path under t.TempDir()
				if err != nil {
					t.Fatal(err)
				}
				if out.String() != string(want) {
					t.Errorf("stdout is not report.json:\n%s", out.String())
				}
			}
		})
	}
}
