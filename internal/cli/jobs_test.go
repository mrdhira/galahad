package cli_test

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/mrdhira/galahad/internal/cli"
	"github.com/mrdhira/galahad/internal/job"
	"github.com/mrdhira/galahad/internal/protocol"
	"github.com/mrdhira/galahad/internal/report"
)

const (
	idOld     = "20261021-153012-aaaaaa"
	idNew     = "20261021-153013-bbbbbb"
	idBad     = "20261021-153011-cccccc"
	idMissing = "20261021-153010-dddddd"
)

// addJob writes the job directory of a finished job. A non-nil res is written as its reports.
func addJob(t *testing.T, home, id string, state job.State, target string, res *protocol.Result) string {
	t.Helper()
	jobs := filepath.Join(home, "jobs")
	dir := job.Dir(jobs, id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	created := time.Date(2026, 10, 21, 15, 30, 12, 0, time.UTC)
	j := job.Job{ID: id, CreatedAt: created, Target: job.Target{Input: target, Kind: "path"}, Image: "core", Backend: "fake", State: state}
	if res != nil {
		j.Verdict, j.Score, j.ExitCode = string(res.Verdict), res.Score, res.Verdict.ExitCode()
		if _, err := report.Write(dir, res); err != nil {
			t.Fatal(err)
		}
	}
	if err := job.Save(jobs, j); err != nil {
		t.Fatal(err)
	}
	return dir
}

// testResult is a validated Result with one finding.
func testResult(verdict protocol.Verdict, score int) *protocol.Result {
	return &protocol.Result{
		SchemaVersion: protocol.SchemaVersion,
		Tool:          protocol.Tool{Name: "galahad-agent", Version: "dev"},
		Target:        protocol.Target{Name: "sample", Kind: protocol.TargetFile, Size: 10, SHA256: strings.Repeat("a", 64)},
		StartedAt:     time.Unix(0, 0).UTC(),
		FinishedAt:    time.Unix(1, 0).UTC(),
		Files:         []protocol.FileInfo{},
		Findings: []protocol.Finding{
			{RuleID: "GAL-SIG-001", Severity: protocol.SeverityHigh, Title: "Known test signature", Analyzer: "signature", Evidence: []protocol.Evidence{{Path: "a.txt", Line: 3, Snippet: "x"}}},
		},
		IOCs:            []protocol.IOC{},
		Coverage:        protocol.Coverage{FilesSeen: 1, FilesAnalyzed: 1, Skipped: []protocol.Skip{}, Analyzers: []string{"static"}},
		Verdict:         verdict,
		Score:           score,
		Confidence:      90,
		ConfidenceLevel: "high",
		Reasons:         []string{},
	}
}

func symlinkOrSkip(t *testing.T, target, link string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("creating symlinks needs a privilege on Windows")
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}

func TestRunJobs(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		args  []string
		setup func(t *testing.T, home string)
		// expectations
		wantCode   int
		wantStdout []string // substrings
		wantStderr []string // substrings
		wantAbsent []string // not in stdout or stderr
	}{
		{
			name: "lists the jobs newest first with state, verdict, score, date and target",
			setup: func(t *testing.T, home string) {
				addJob(t, home, idOld, job.StateDone, "old.pdf", testResult(protocol.VerdictMalicious, 95))
				addJob(t, home, idNew, job.StateFailed, "new.pdf", nil)
			},
			wantCode: cli.ExitClean,
			wantStdout: []string{
				"ID                      STATE   VERDICT    SCORE  DATE                 TARGET\n" +
					idNew + "  failed  -          -      2026-10-21 15:30:12  new.pdf\n" +
					idOld + "  done    malicious  95     2026-10-21 15:30:12  old.pdf\n",
			},
		},
		{
			name: "skips an unreadable job with a note and cleans the target",
			setup: func(t *testing.T, home string) {
				addJob(t, home, idOld, job.StateDone, "\x1b]0;PWNED\a\u202e.pdf", testResult(protocol.VerdictClean, 0))
				dir := addJob(t, home, idBad, job.StateDone, "bad.pdf", nil)
				if err := os.WriteFile(filepath.Join(dir, "job.json"), []byte(`{"id":"`+idBad+`","evil":true}`), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(home, "jobs", "stray.txt"), nil, 0o600); err != nil {
					t.Fatal(err)
				}
			},
			wantCode:   cli.ExitClean,
			wantStdout: []string{idOld, `\u001b]0;PWNED\u0007\u202e.pdf`},
			wantStderr: []string{"skipped " + idBad + ": job.json is missing, unreadable or invalid"},
			wantAbsent: []string{"stray"},
		},
		{
			name: "skips a job directory that is a symlink",
			setup: func(t *testing.T, home string) {
				addJob(t, home, idOld, job.StateDone, "old.pdf", testResult(protocol.VerdictClean, 0))
				symlinkOrSkip(t, filepath.Join(home, "jobs", idOld), filepath.Join(home, "jobs", idNew))
			},
			wantCode:   cli.ExitClean,
			wantStdout: []string{idOld},
			wantStderr: []string{"skipped " + idNew},
		},
		{name: "no jobs", setup: func(t *testing.T, home string) {}, wantCode: cli.ExitClean, wantStdout: []string{"No jobs."}},
		{name: "-h prints usage", args: []string{"-h"}, wantCode: cli.ExitClean, wantStdout: []string{"Usage: galahad"}},
		{name: "unknown flag", args: []string{"--nope"}, wantCode: cli.ExitUsage, wantStderr: []string{"flag provided but not defined"}},
		{name: "unexpected argument", args: []string{"x\x1b"}, wantCode: cli.ExitUsage, wantStderr: []string{`unexpected argument "x\\u001b"`}},
		{
			name: "jobs path is a file",
			setup: func(t *testing.T, home string) {
				if err := os.WriteFile(filepath.Join(home, "jobs"), nil, 0o600); err != nil {
					t.Fatal(err)
				}
			},
			wantCode: cli.ExitError, wantStderr: []string{"galahad jobs: list jobs"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home := t.TempDir()
			if tt.setup != nil {
				tt.setup(t, home)
			}
			var out, errb bytes.Buffer
			if got := cli.RunWithEnv(append([]string{"jobs"}, tt.args...), &out, &errb, cli.Env{Home: home}); got != tt.wantCode {
				t.Fatalf("exit = %d, want %d\nstderr: %s", got, tt.wantCode, errb.String())
			}
			checkStreams(t, out.String(), errb.String(), tt.wantStdout, tt.wantStderr, tt.wantAbsent)
		})
	}
}

func TestRunJobsRm(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		args  []string
		setup func(t *testing.T, home string)
		// expectations
		wantCode   int
		wantStdout []string
		wantStderr []string
		wantGone   []string // job directories that are removed
		wantKept   []string // job directories that are still there
	}{
		{
			name: "removes one job",
			args: []string{"rm", idOld},
			setup: func(t *testing.T, home string) {
				addJob(t, home, idOld, job.StateDone, "old.pdf", testResult(protocol.VerdictClean, 0))
				addJob(t, home, idNew, job.StateDone, "new.pdf", testResult(protocol.VerdictClean, 0))
			},
			wantCode: cli.ExitClean, wantStdout: []string{"removed " + idOld}, wantGone: []string{idOld}, wantKept: []string{idNew},
		},
		{
			name: "removes several jobs, one with a job.json that is not valid",
			args: []string{"rm", idOld, idBad},
			setup: func(t *testing.T, home string) {
				addJob(t, home, idOld, job.StateDone, "old.pdf", nil)
				dir := addJob(t, home, idBad, job.StateDone, "bad.pdf", nil)
				if err := os.WriteFile(filepath.Join(dir, "job.json"), []byte("nope"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
			wantCode: cli.ExitClean, wantStdout: []string{"removed " + idOld, "removed " + idBad}, wantGone: []string{idOld, idBad},
		},
		{name: "-h prints usage", args: []string{"rm", "-h"}, wantCode: cli.ExitClean, wantStdout: []string{"Usage: galahad"}},
		{name: "unknown flag", args: []string{"rm", "--nope"}, wantCode: cli.ExitUsage, wantStderr: []string{"flag provided but not defined"}},
		{name: "no id", args: []string{"rm"}, wantCode: cli.ExitUsage, wantStderr: []string{"want at least one job id"}},
		{
			name: "a malformed id removes nothing",
			args: []string{"rm", idOld, "../" + idNew},
			setup: func(t *testing.T, home string) {
				addJob(t, home, idOld, job.StateDone, "old.pdf", nil)
			},
			wantCode: cli.ExitUsage, wantStderr: []string{`invalid job id "../` + idNew + `"`}, wantKept: []string{idOld},
		},
		{name: "a malformed id with escape codes is cleaned", args: []string{"rm", "\x1b[2J"}, wantCode: cli.ExitUsage, wantStderr: []string{`invalid job id "\\u001b[2J"`}},
		{
			name: "an unknown id exits 1 and the others are still removed",
			args: []string{"rm", idMissing, idOld},
			setup: func(t *testing.T, home string) {
				addJob(t, home, idOld, job.StateDone, "old.pdf", nil)
			},
			wantCode: cli.ExitError, wantStdout: []string{"removed " + idOld}, wantStderr: []string{"no job " + idMissing}, wantGone: []string{idOld},
		},
		{
			name: "a job directory that is a symlink is refused and its target is kept",
			args: []string{"rm", idNew},
			setup: func(t *testing.T, home string) {
				addJob(t, home, idOld, job.StateDone, "old.pdf", nil)
				symlinkOrSkip(t, filepath.Join(home, "jobs", idOld), filepath.Join(home, "jobs", idNew))
			},
			wantCode: cli.ExitError, wantStderr: []string{"not a job directory"}, wantKept: []string{idOld, idNew},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home := t.TempDir()
			if tt.setup != nil {
				tt.setup(t, home)
			}
			var out, errb bytes.Buffer
			if got := cli.RunWithEnv(append([]string{"jobs"}, tt.args...), &out, &errb, cli.Env{Home: home}); got != tt.wantCode {
				t.Fatalf("exit = %d, want %d\nstderr: %s", got, tt.wantCode, errb.String())
			}
			checkStreams(t, out.String(), errb.String(), tt.wantStdout, tt.wantStderr, nil)
			for _, id := range tt.wantGone {
				if _, err := os.Lstat(filepath.Join(home, "jobs", id)); !os.IsNotExist(err) {
					t.Errorf("job %s still exists: %v", id, err)
				}
			}
			for _, id := range tt.wantKept {
				if _, err := os.Lstat(filepath.Join(home, "jobs", id)); err != nil {
					t.Errorf("job %s is gone: %v", id, err)
				}
			}
		})
	}
}

// checkStreams checks that each want is in its stream, that nothing in wantAbsent is in either, and
// that neither stream has a control character other than a newline.
func checkStreams(t *testing.T, stdout, stderr string, wantStdout, wantStderr, wantAbsent []string) {
	t.Helper()
	for _, w := range wantStdout {
		if !strings.Contains(stdout, w) {
			t.Errorf("stdout lacks %q:\n%s", w, stdout)
		}
	}
	for _, w := range wantStderr {
		if !strings.Contains(stderr, w) {
			t.Errorf("stderr lacks %q:\n%s", w, stderr)
		}
	}
	for _, w := range wantAbsent {
		if strings.Contains(stdout, w) || strings.Contains(stderr, w) {
			t.Errorf("output has %q:\n%s\n%s", w, stdout, stderr)
		}
	}
	for _, s := range []string{stdout, stderr} {
		if strings.ContainsAny(strings.ReplaceAll(s, "\n", ""), "\x00\x07\x08\x1b\r\u202e") {
			t.Errorf("output has control characters: %q", s)
		}
	}
}
