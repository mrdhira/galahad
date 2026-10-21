package acceptance_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// scanJob mirrors the parts of job.json the tests read.
type scanJob struct {
	State    string `json:"state"`
	ExitCode int    `json:"exit_code"`
	Verdict  string `json:"verdict"`
	Error    string `json:"error"`
	Backend  string `json:"backend"`
	Target   struct {
		Kind string `json:"kind"`
	} `json:"target"`
}

// scan runs "galahad scan" through the fake sandbox with its state in home.
func scan(t *testing.T, home string, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	t.Setenv("GALAHAD_HOME", home)
	t.Setenv("GALAHAD_SANDBOX", "fake")
	return run(t, append([]string{"scan"}, args...)...)
}

// onlyJob returns the directory of the one job in home, or "" when there is none.
func onlyJob(t *testing.T, home string) string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(home, "jobs"))
	if os.IsNotExist(err) {
		return ""
	}
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("jobs = %d entries, want 1", len(entries))
	}
	return filepath.Join(home, "jobs", entries[0].Name())
}

func readJob(t *testing.T, dir string) scanJob {
	t.Helper()
	var j scanJob
	if err := json.Unmarshal([]byte(readFile(t, filepath.Join(dir, "job.json"))), &j); err != nil {
		t.Fatal(err)
	}
	return j
}

// TestScanCorpus runs the corpus table through "galahad scan" and the fake sandbox, which must give the
// exit codes and the evidence of "galahad-agent analyze" (TestCorpus). P6: p6-eml-lure is one of the cases.
func TestScanCorpus(t *testing.T) {
	for _, tt := range corpusCases() {
		t.Run(tt.name, func(t *testing.T) {
			// Given a fixture, committed or built at test time
			target := tt.target(t)
			// When it is scanned
			home := t.TempDir()
			stdout, stderr, code := scan(t, home, target)
			// Then the exit code, the report and the evidence match what the agent finds alone
			if code != tt.wantCode {
				t.Fatalf("exit = %d, want %d\nstdout: %s\nstderr: %s", code, tt.wantCode, stdout, stderr)
			}
			dir := onlyJob(t, home)
			rep, err := readReport(filepath.Join(dir, "report.json"))
			if err != nil {
				t.Fatal(err)
			}
			checkCorpus(t, tt, rep, dir)
			if j := readJob(t, dir); j.State != "done" || j.ExitCode != tt.wantCode || j.Verdict != rep.Verdict {
				t.Errorf("job.json = %+v, want state done, exit code %d, verdict %q", j, tt.wantCode, rep.Verdict)
			}
		})
	}
}

func TestScan(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		target     func(t *testing.T) string // the path to scan; no path is given when nil
		args       []string                  // given before the path
		sandbox    *string                   // GALAHAD_SANDBOX instead of "fake"
		fakeResult string                    // GALAHAD_FAKE_RESULT: how the fake agent spoils its Result
		// expectations
		wantCode     int
		wantStdout   string // substring
		wantStderr   string // substring
		wantState    string // job.json state; empty means no job was made
		wantKind     string // target kind of the report
		wantNoReport bool   // report.json must not exist
	}{
		{
			name:     "file target",
			target:   func(t *testing.T) string { return writeEICAR(t, t.TempDir()) },
			wantCode: 20, wantStdout: "MALICIOUS", wantStderr: "galahad: analyze", wantState: "done", wantKind: "file",
		},
		{
			name:     "folder target",
			target:   corpusDir("p1-folderopen-curl"),
			wantCode: 20, wantStdout: "GAL-AUTOEXEC-001", wantStderr: "galahad: ingest", wantState: "done", wantKind: "dir",
		},
		{
			name: "a symlink in a folder is sent as a link and never followed",
			target: func(t *testing.T) string {
				if runtime.GOOS == "windows" {
					t.Skip("creating symlinks needs a privilege on Windows")
				}
				outside := t.TempDir()
				writeEICAR(t, outside)
				dir := filepath.Join(t.TempDir(), "repo")
				if err := os.Mkdir(dir, 0o750); err != nil {
					t.Fatal(err)
				}
				writeBytes(t, filepath.Join(dir, "a.txt"), []byte("hello\n"))
				if err := os.Symlink(outside, filepath.Join(dir, "link")); err != nil {
					t.Fatal(err)
				}
				return dir
			},
			wantCode: 0, wantStdout: "CLEAN", wantState: "done", wantKind: "dir",
		},
		{
			name:     "no path",
			wantCode: 2, wantStderr: "want exactly one path",
		},
		{
			name:     "unknown flag",
			args:     []string{"--nope"},
			target:   func(t *testing.T) string { return t.TempDir() },
			wantCode: 2, wantStderr: "flag provided but not defined",
		},
		{
			name:     "no sandbox backend",
			target:   func(t *testing.T) string { return t.TempDir() },
			sandbox:  new(string),
			wantCode: 1, wantStderr: "sandbox not supported",
		},
		{
			name:     "missing target",
			target:   func(t *testing.T) string { return filepath.Join(t.TempDir(), "missing") },
			wantCode: 1, wantStderr: "galahad scan:",
		},
		{
			name: "input over the byte cap fails before boot",
			target: func(t *testing.T) string {
				p := filepath.Join(t.TempDir(), "big.bin")
				f, err := os.Create(p) // #nosec G304 -- test fixture path under t.TempDir()
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = f.Close() }() // the file is only truncated
				if err := f.Truncate(1<<30 + 1); err != nil {
					t.Skipf("filesystem cannot hold a sparse 1 GiB file: %v", err)
				}
				return p
			},
			wantCode: 1, wantStderr: "the input is too large",
		},
		{
			name:       "result with a field the schema does not have",
			target:     func(t *testing.T) string { return writeEICAR(t, t.TempDir()) },
			fakeResult: "unknown-field",
			wantCode:   1, wantStderr: "unknown field", wantState: "failed", wantNoReport: true,
		},
		{
			name:       "result frame over the limit",
			target:     func(t *testing.T) string { return writeEICAR(t, t.TempDir()) },
			fakeResult: "oversize",
			wantCode:   1, wantStderr: "max 67108864", wantState: "failed", wantNoReport: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given the fake sandbox and a target
			home := t.TempDir()
			t.Setenv("GALAHAD_FAKE_RESULT", tt.fakeResult)
			args := tt.args
			var target string
			if tt.target != nil {
				target = tt.target(t)
				args = append(args, target)
			}
			// When it is scanned
			var stdout, stderr string
			var code int
			if tt.sandbox != nil {
				t.Setenv("GALAHAD_HOME", home)
				t.Setenv("GALAHAD_SANDBOX", *tt.sandbox)
				stdout, stderr, code = run(t, append([]string{"scan"}, args...)...)
			} else {
				stdout, stderr, code = scan(t, home, args...)
			}
			// Then the exit code and the output match
			if code != tt.wantCode {
				t.Errorf("exit = %d, want %d\nstdout: %s\nstderr: %s", code, tt.wantCode, stdout, stderr)
			}
			if !strings.Contains(stdout, tt.wantStdout) {
				t.Errorf("stdout lacks %q:\n%s", tt.wantStdout, stdout)
			}
			if !strings.Contains(stderr, tt.wantStderr) {
				t.Errorf("stderr lacks %q:\n%s", tt.wantStderr, stderr)
			}
			// And job.json has the state, and the report is there or not
			dir := onlyJob(t, home)
			if (dir != "") != (tt.wantState != "") {
				t.Fatalf("job directory %q, want a job: %v", dir, tt.wantState != "")
			}
			if dir == "" {
				return
			}
			j := readJob(t, dir)
			if j.State != tt.wantState || j.Backend != "fake" || j.ExitCode != tt.wantCode {
				t.Errorf("job.json = %+v, want state %q, exit code %d", j, tt.wantState, tt.wantCode)
			}
			_, err := os.Stat(filepath.Join(dir, "report.json"))
			if tt.wantNoReport {
				if err == nil {
					t.Error("report.json exists after a failed job")
				}
				if j.Error == "" {
					t.Error("job.json has no error text")
				}
				return
			}
			rep, err := readReport(filepath.Join(dir, "report.json"))
			if err != nil {
				t.Fatal(err)
			}
			if rep.Target.Kind != tt.wantKind {
				t.Errorf("target kind = %q, want %q", rep.Target.Kind, tt.wantKind)
			}
			if tt.wantKind == "file" {
				sum := sha256.Sum256([]byte(readFile(t, target)))
				if want := hex.EncodeToString(sum[:]); rep.Target.SHA256 != want {
					t.Errorf("target sha256 = %s, want %s: the host and the guest hashed different bytes", rep.Target.SHA256, want)
				}
			}
		})
	}
}
