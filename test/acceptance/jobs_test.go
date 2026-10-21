package acceptance_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestJobsAndReport scans a fixture, then lists, reports and removes the job through the built binary.
// The "{id}" in the args is the ID of the job the scan made. P1-P6 reports must come back unchanged
// from disk, and a job directory is never trusted: tampered files and symlinks end in an error.
func TestJobsAndReport(t *testing.T) {
	const unknown = "20261021-000000-abcdef"
	tests := []struct {
		name string
		// inputs
		args  []string
		setup func(t *testing.T, jobsDir, id string) // changes the job directory after the scan
		// expectations
		wantCode     int
		wantStdout   string // substring
		wantStderr   string // substring
		wantAbsent   string // not in stdout
		wantFileJSON bool   // stdout is report.json of the job, byte for byte
		wantGone     bool   // the job directory is removed
		wantKept     string // a path, relative to the jobs directory's parent, that must still exist
	}{
		{
			name: "jobs lists the scanned job",
			args: []string{"jobs"}, wantCode: 0, wantStdout: "{id}  done  ",
		},
		{
			name: "report exits with the verdict of the scan",
			args: []string{"report", "{id}"}, wantCode: 20, wantStdout: "MALICIOUS",
		},
		{
			name: "report --json prints report.json",
			args: []string{"report", "{id}", "--json"}, wantCode: 20, wantFileJSON: true,
		},
		{
			name: "jobs rm removes the job",
			args: []string{"jobs", "rm", "{id}"}, wantCode: 0, wantStdout: "removed {id}", wantGone: true,
		},
		{
			name: "jobs lists nothing after jobs rm",
			args: []string{"jobs"}, wantCode: 0, wantStdout: "No jobs.", wantAbsent: "{id}", wantGone: true,
			setup: func(t *testing.T, jobsDir, id string) {
				if stdout, stderr, code := run(t, "jobs", "rm", id); code != 0 {
					t.Fatalf("jobs rm = %d\n%s%s", code, stdout, stderr)
				}
			},
		},
		{
			name: "a malformed id in report is a usage error",
			args: []string{"report", "../{id}"}, wantCode: 2, wantStderr: "invalid job id",
		},
		{
			name: "a malformed id in jobs rm is a usage error and nothing is removed",
			args: []string{"jobs", "rm", "{id}", "../{id}"}, wantCode: 2, wantStderr: "invalid job id", wantKept: "jobs/{id}/report.json",
		},
		{
			name: "an unknown id in report is an error",
			args: []string{"report", unknown}, wantCode: 1, wantStderr: "no report.json for job " + unknown,
		},
		{
			name: "an unknown id in jobs rm is an error",
			args: []string{"jobs", "rm", unknown}, wantCode: 1, wantStderr: "no job " + unknown,
		},
		{
			name: "a report.json with a field the schema does not have is an error",
			args: []string{"report", "{id}"}, wantCode: 1, wantStderr: "unknown field",
			setup: func(t *testing.T, jobsDir, id string) {
				p := filepath.Join(jobsDir, id, "report.json")
				data := readFile(t, p)
				writeBytes(t, p, []byte(strings.Replace(data, `"verdict"`, `"extra": 1, "verdict"`, 1)))
			},
		},
		{
			name: "a report.json over the size cap is an error",
			args: []string{"report", "{id}"}, wantCode: 1, wantStderr: "larger than 67108864 bytes",
			setup: func(t *testing.T, jobsDir, id string) {
				f, err := os.OpenFile(filepath.Join(jobsDir, id, "report.json"), os.O_WRONLY, 0o600) // #nosec G304 -- test fixture path under t.TempDir()
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = f.Close() }() // the file is only truncated
				if err := f.Truncate(64<<20 + 1); err != nil {
					t.Skipf("filesystem cannot hold a sparse 64 MiB file: %v", err)
				}
			},
		},
		{
			name: "report refuses a job directory that is a symlink out of the jobs directory",
			args: []string{"report", "{id}"}, wantCode: 1, wantStderr: "not a job directory",
			setup: symlinkJobOut,
		},
		{
			name: "jobs rm refuses a job directory that is a symlink and keeps the target",
			args: []string{"jobs", "rm", "{id}"}, wantCode: 1, wantStderr: "not a job directory",
			setup: symlinkJobOut, wantKept: "outside/report.json",
		},
		{
			name: "jobs skips a job directory that is a symlink",
			args: []string{"jobs"}, wantCode: 0, wantStdout: "No jobs.", wantStderr: "skipped {id}",
			setup: symlinkJobOut,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given a scanned job
			home := t.TempDir()
			if _, stderr, code := scan(t, home, writeEICAR(t, t.TempDir())); code != 20 {
				t.Fatalf("scan exit = %d, want 20\n%s", code, stderr)
			}
			jobsDir := filepath.Join(home, "jobs")
			dir := onlyJob(t, home)
			id := filepath.Base(dir)
			if tt.setup != nil {
				tt.setup(t, jobsDir, id)
			}
			// When the command runs
			expand := func(s string) string { return strings.ReplaceAll(s, "{id}", id) }
			args := make([]string, len(tt.args))
			for i, a := range tt.args {
				args[i] = expand(a)
			}
			stdout, stderr, code := run(t, args...)
			// Then the exit code and the output match
			if code != tt.wantCode {
				t.Fatalf("exit = %d, want %d\nstdout: %s\nstderr: %s", code, tt.wantCode, stdout, stderr)
			}
			if want := expand(tt.wantStdout); !strings.Contains(stdout, want) {
				t.Errorf("stdout lacks %q:\n%s", want, stdout)
			}
			if tt.wantAbsent != "" && strings.Contains(stdout, expand(tt.wantAbsent)) {
				t.Errorf("stdout has %q:\n%s", expand(tt.wantAbsent), stdout)
			}
			if want := expand(tt.wantStderr); !strings.Contains(stderr, want) {
				t.Errorf("stderr lacks %q:\n%s", want, stderr)
			}
			if tt.wantFileJSON && stdout != readFile(t, filepath.Join(dir, "report.json")) {
				t.Errorf("stdout is not report.json:\n%s", stdout)
			}
			if _, err := os.Lstat(dir); os.IsNotExist(err) != tt.wantGone {
				t.Errorf("job directory removed = %v, want %v", os.IsNotExist(err), tt.wantGone)
			}
			if tt.wantKept != "" {
				if _, err := os.Stat(filepath.Join(home, filepath.FromSlash(expand(tt.wantKept)))); err != nil {
					t.Errorf("%s is gone: %v", tt.wantKept, err)
				}
			}
		})
	}
}

// symlinkJobOut moves the job directory out of the jobs directory, to "outside" next to it, and
// leaves a symlink with the job's name in its place.
func symlinkJobOut(t *testing.T, jobsDir, id string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("creating symlinks needs a privilege on Windows")
	}
	outside := filepath.Join(filepath.Dir(jobsDir), "outside")
	if err := os.Rename(filepath.Join(jobsDir, id), outside); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(jobsDir, id)); err != nil {
		t.Fatal(err)
	}
}
