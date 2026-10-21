package acceptance_test

import (
	"encoding/json"
	"io"
	"net"
	"net/http/cgi"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// needGit skips the test where there is no git or no git-http-backend, and returns the path of the backend.
func needGit(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	out, err := exec.Command("git", "--exec-path").Output()
	if err != nil {
		t.Skipf("git --exec-path: %v", err)
	}
	backend := filepath.Join(strings.TrimSpace(string(out)), "git-http-backend")
	if runtime.GOOS == "windows" {
		backend += ".exe"
	}
	if _, err := os.Stat(backend); err != nil {
		t.Skip("git-http-backend is not installed")
	}
	return backend
}

// runGit runs git in dir with a clean configuration. It is test setup, so it may use any protocol.
func runGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-c", "protocol.file.allow=always", "-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "init.defaultBranch=main"}, args...)...)
	cmd.Dir = dir
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + dir, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=" + os.DevNull}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

// publish commits the files below work as one commit and publishes them as the bare repository root/name.
// Entries that setup added with update-index (a submodule) stay in the commit.
func publish(t *testing.T, work, root, name string, setup func()) {
	t.Helper()
	runGit(t, work, "init", "-q")
	if setup != nil {
		setup()
	}
	runGit(t, work, "add", "--ignore-removal", ".")
	runGit(t, work, "commit", "-q", "-m", "x")
	runGit(t, root, "clone", "-q", "--bare", work, filepath.Join(root, name))
}

func writeText(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// copyTree copies the files below src into dst.
func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(p) // #nosec G304 -- the checked-in corpus
		if err != nil {
			return err
		}
		writeText(t, filepath.Join(dst, rel), string(data))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// gitServer serves the bare repositories below root over the smart http protocol. Every tunnel of the guest ends
// here, because GALAHAD_TEST_SINKHOLE points at it, and git.test is the host name in the repository links.
func gitServer(t *testing.T, backend, root string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(&cgi.Handler{Path: backend, Stderr: io.Discard, Env: []string{"GIT_PROJECT_ROOT=" + root, "GIT_HTTP_EXPORT_ALL=1"}})
	t.Cleanup(srv.Close)
	return srv
}

// P1, P2, P8: a repository is cloned in the guest through the relay and the host proxy, and the report is the one
// of the same files scanned as a folder. A submodule goes through the proxy too, and only https submodules can.
func TestScanGit(t *testing.T) {
	backend := needGit(t)
	const metadata = "https://169.254.169.254/x.git"
	tests := []struct {
		name string
		// inputs
		args   []string
		target string
		// expectations
		wantCode     int
		wantCorpus   string // the corpus case whose evidence the report must show
		wantEvidence string // snippet of GAL-NET-001; empty means no such finding
		wantBlocked  bool
		wantLog      []string // substrings of ingest.log
		wantAbsent   []string // not in ingest.log
		wantHosts    []string // hosts in proxy.log, nothing else
	}{
		{
			name:     "fake-interview-repo exits 20 with the evidence of the folder",
			target:   "http://git.test/interview.git",
			wantCode: 20, wantCorpus: "fake-interview-repo",
			wantLog: []string{"git clone: ok"}, wantHosts: []string{"git.test"},
		},
		{
			name:     "--git clones a link that does not end in .git",
			args:     []string{"--git"},
			target:   "http://git.test/interview",
			wantCode: 20, wantCorpus: "fake-interview-repo",
			wantLog: []string{"git clone: ok"}, wantHosts: []string{"git.test"},
		},
		{
			name:     "a submodule at the metadata address is blocked and reported",
			args:     []string{"--submodules"},
			target:   "http://git.test/metadata.git",
			wantCode: 10, wantEvidence: "CONNECT 169.254.169.254:443 denied: metadata", wantBlocked: true,
			wantLog:   []string{"git clone: ok", "git submodule update", "CONNECT tunnel failed, response 403", "the scan goes on"},
			wantHosts: []string{"git.test", "169.254.169.254"},
		},
		{
			name:     "submodules are not fetched without the option",
			target:   "http://git.test/metadata.git",
			wantCode: 0,
			wantLog:  []string{"git clone: ok"}, wantAbsent: []string{"git submodule update"},
			wantHosts: []string{"git.test"},
		},
		{
			name:      "ext and file submodules are refused and ignored",
			args:      []string{"--submodules"},
			target:    "http://git.test/transports.git",
			wantCode:  0,
			wantLog:   []string{"git clone: ok", "'ext' not allowed", "'file' not allowed"},
			wantHosts: []string{"git.test"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given repositories behind a server that the proxy hooks send every tunnel to
			root, outside := t.TempDir(), t.TempDir()
			interview := t.TempDir()
			copyTree(t, corpus(t, "fake-interview-repo"), interview)
			publish(t, interview, root, "interview.git", nil)
			local := t.TempDir()
			publish(t, local, outside, "local", func() { writeText(t, filepath.Join(local, "MARKER"), "local repository\n") })
			meta := t.TempDir()
			publish(t, meta, root, "metadata.git", func() {
				writeText(t, filepath.Join(meta, "README.md"), "a project with a submodule\n")
				writeText(t, filepath.Join(meta, ".gitmodules"), "[submodule \"vendor\"]\n\tpath = vendor\n\turl = "+metadata+"\n")
				runGit(t, meta, "add", "--ignore-removal", ".")
				runGit(t, meta, "update-index", "--add", "--cacheinfo", "160000,"+strings.Repeat("ab", 20)+",vendor")
			})
			trans := t.TempDir()
			publish(t, trans, root, "transports.git", func() {
				writeText(t, filepath.Join(trans, "README.md"), "a project with odd submodules\n")
				writeText(t, filepath.Join(trans, ".gitmodules"), "[submodule \"a\"]\n\tpath = a\n\turl = ext::touch "+filepath.ToSlash(filepath.Join(outside, "pwned"))+
					"\n[submodule \"b\"]\n\tpath = b\n\turl = file://"+filepath.ToSlash(filepath.Join(outside, "local"))+"\n")
				runGit(t, trans, "add", "--ignore-removal", ".")
				for _, p := range []string{"a", "b"} {
					runGit(t, trans, "update-index", "--add", "--cacheinfo", "160000,"+strings.Repeat("cd", 20)+","+p)
				}
			})
			srv := gitServer(t, backend, root)
			_, port, err := net.SplitHostPort(srv.Listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			t.Setenv("GALAHAD_TEST_RESOLVE", "git.test=127.0.0.1")
			t.Setenv("GALAHAD_TEST_SINKHOLE", "127.0.0.1:"+port)
			home := t.TempDir()

			// When the repository is scanned
			stdout, stderr, code := scan(t, home, append(tt.args, tt.target)...)

			// Then the exit code, the job, the report, the logs and the files outside are as expected
			if code != tt.wantCode {
				t.Fatalf("exit = %d, want %d\nstdout: %s\nstderr: %s", code, tt.wantCode, stdout, stderr)
			}
			dir := onlyJob(t, home)
			j := readJob(t, dir)
			if j.State != "done" || j.ExitCode != tt.wantCode || j.Target.Kind != "git" || j.Blocked != tt.wantBlocked {
				t.Errorf("job.json = %+v, want state done, exit code %d, target kind git, blocked %v", j, tt.wantCode, tt.wantBlocked)
			}
			ingestLog := readFile(t, filepath.Join(dir, "artifacts", "ingest.log"))
			for _, w := range tt.wantLog {
				if !strings.Contains(ingestLog, w) {
					t.Errorf("ingest.log lacks %q:\n%s", w, ingestLog)
				}
			}
			for _, a := range tt.wantAbsent {
				if strings.Contains(ingestLog, a) {
					t.Errorf("ingest.log has %q:\n%s", a, ingestLog)
				}
			}
			if strings.ContainsAny(ingestLog, "\x1b\a\r") {
				t.Errorf("ingest.log has control characters: %q", ingestLog)
			}
			var hosts []string
			for _, line := range strings.Split(strings.TrimSpace(readFile(t, filepath.Join(dir, "proxy.log"))), "\n") {
				var ev struct {
					Host string `json:"host"`
				}
				if err := json.Unmarshal([]byte(line), &ev); err != nil {
					t.Fatalf("proxy.log line %q: %v", line, err)
				}
				if !slices.Contains(hosts, ev.Host) {
					hosts = append(hosts, ev.Host)
				}
			}
			slices.Sort(hosts)
			if want := slices.Sorted(slices.Values(tt.wantHosts)); !slices.Equal(hosts, want) {
				t.Errorf("hosts in proxy.log = %q, want %q", hosts, want)
			}
			for _, name := range []string{"pwned", "MARKER"} {
				if _, err := os.Lstat(filepath.Join(outside, name)); err == nil {
					t.Errorf("%s was created", name)
				}
			}
			rep, err := readReport(filepath.Join(dir, "report.json"))
			if err != nil {
				t.Fatal(err)
			}
			if rep.Target.Kind != "dir" {
				t.Errorf("report target = %+v, want a folder", rep.Target)
			}
			var nr netReport
			if err := json.Unmarshal([]byte(readFile(t, filepath.Join(dir, "report.json"))), &nr); err != nil {
				t.Fatal(err)
			}
			evidence := ""
			for _, f := range nr.Findings {
				if f.RuleID == "GAL-NET-001" {
					for _, e := range f.Evidence {
						evidence += e.Snippet + "\n"
					}
				}
			}
			if (tt.wantEvidence == "") != (evidence == "") || !strings.Contains(evidence, tt.wantEvidence) {
				t.Errorf("GAL-NET-001 evidence = %q, want it to contain %q", evidence, tt.wantEvidence)
			}
			if tt.wantCorpus != "" {
				checkCorpus(t, corpusCaseNamed(t, tt.wantCorpus), rep, dir)
			}
		})
	}
}
