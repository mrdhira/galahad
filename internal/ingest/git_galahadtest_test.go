//go:build galahadtest

package ingest_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/cgi"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/mrdhira/galahad/internal/ingest"
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

// runGit runs git in dir with a clean configuration. Test setup only: it may use any protocol.
func runGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-c", "protocol.file.allow=always", "-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "init.defaultBranch=main"}, args...)...)
	cmd.Dir = dir
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + dir, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=" + os.DevNull}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

// makeRepo commits what setup writes into a working directory, and publishes it as the bare
// repository root/name.
func makeRepo(t *testing.T, root, name string, setup func(work string)) {
	t.Helper()
	work := t.TempDir()
	runGit(t, work, "init", "-q")
	setup(work)
	runGit(t, work, "add", "--ignore-removal", ".") // keeps the entries setup added with update-index
	runGit(t, work, "commit", "-q", "-m", "x")
	runGit(t, root, "clone", "-q", "--bare", work, filepath.Join(root, name))
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// relayServer plays the relay in front of a Git server: it serves the repositories below root over
// the smart http protocol, and refuses every CONNECT as the host proxy refuses a private address.
// Git sends its requests for an http URL to the proxy in absolute form, so the server needs no DNS.
func relayServer(t *testing.T, backend, root string) (srv *httptest.Server, connects func() []string) {
	t.Helper()
	var mu sync.Mutex
	var seen []string
	h := &cgi.Handler{Path: backend, Stderr: io.Discard, Env: []string{"GIT_PROJECT_ROOT=" + root, "GIT_HTTP_EXPORT_ALL=1"}}
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			mu.Lock()
			seen = append(seen, r.Host)
			mu.Unlock()
			http.Error(w, "denied: metadata", http.StatusForbidden)
			return
		}
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), seen...)
	}
}

func TestGitArgsWithHTTP(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		build func(g ingest.Git) []string
		// expectations
		want string
	}{
		{
			name:  "a .test host may use http: the clone allows the protocol",
			build: func(g ingest.Git) []string { return g.CloneArgs("http://git.test/x.git", "/work/input")[:4] },
			want:  "-c protocol.allow=never -c protocol.https.allow=always",
		},
		{
			name: "a .test host may use http: the second option is protocol.http.allow",
			build: func(g ingest.Git) []string {
				return g.CloneArgs("http://git.test/x.git", "/work/input")[4:6]
			},
			want: "-c protocol.http.allow=always",
		},
		{
			name:  "a .test host may use http: the environment allows it",
			build: func(g ingest.Git) []string { return g.Env("http://git.test/x.git")[4:5] },
			want:  "GIT_ALLOW_PROTOCOL=https:http",
		},
		{
			name:  "another host may not",
			build: func(g ingest.Git) []string { return g.Env("http://example.com/x.git")[4:5] },
			want:  "GIT_ALLOW_PROTOCOL=https",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := strings.Join(tt.build(ingest.Git{Relay: gitRelay}), " "); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestGitCloneRepo(t *testing.T) {
	backend := needGit(t)
	const hostile = "https://169.254.169.254/x.git"
	tests := []struct {
		name string
		// inputs
		repo       string
		submodules bool
		// expectations
		wantErr      string // substring; empty means success
		wantFiles    map[string]string
		wantAbsent   []string // paths below the clone that must not exist
		wantLog      []string
		wantConnects []string // CONNECT requests the relay saw
	}{
		{
			name: "a repository is cloned: one commit, a symlink as a plain file, no hooks", repo: "plain.git",
			wantFiles:  map[string]string{"README.md": "hello\n", "link": "/etc/passwd"},
			wantAbsent: []string{".git/hooks"},
			wantLog:    []string{"git clone: ok"},
		},
		{
			name: "a repository that does not exist", repo: "missing.git",
			wantErr: "exit status 128", wantLog: []string{"git clone: exit status 128"},
		},
		{
			name: "submodules are left alone without the option", repo: "modules.git",
			wantFiles: map[string]string{".gitmodules": ""}, wantLog: []string{"git clone: ok"},
		},
		{
			name: "submodules that use ext, file or an address the proxy refuses are logged and ignored", repo: "modules.git", submodules: true,
			wantFiles:    map[string]string{".gitmodules": ""},
			wantAbsent:   []string{"pwned", "file-sub/MARKER", "ext-sub/MARKER"},
			wantLog:      []string{"git clone: ok", "git submodule update", "'file' not allowed", "'ext' not allowed", "CONNECT tunnel failed, response 403", "the scan goes on"},
			wantConnects: []string{"169.254.169.254:443"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given repositories behind a relay
			root := t.TempDir()
			outside := t.TempDir() // where an ext address would create a file, and a local repository holds a marker
			makeRepo(t, root, "plain.git", func(work string) {
				write(t, filepath.Join(work, "README.md"), "hello\n")
				if runtime.GOOS != "windows" {
					if err := os.Symlink("/etc/passwd", filepath.Join(work, "link")); err != nil {
						t.Fatal(err)
					}
				}
			})
			makeRepo(t, outside, "local", func(work string) { write(t, filepath.Join(work, "MARKER"), "local repository\n") })
			makeRepo(t, root, "modules.git", func(work string) {
				write(t, filepath.Join(work, ".gitmodules"), `[submodule "file-sub"]
	path = file-sub
	url = file://`+filepath.ToSlash(filepath.Join(outside, "local"))+`
[submodule "ext-sub"]
	path = ext-sub
	url = ext::touch `+filepath.ToSlash(filepath.Join(outside, "pwned"))+`
[submodule "net-sub"]
	path = net-sub
	url = `+hostile+"\n")
				for _, p := range []string{"file-sub", "ext-sub", "net-sub"} {
					runGit(t, work, "update-index", "--add", "--cacheinfo", "160000,"+strings.Repeat("ab", 20)+","+p)
				}
			})
			srv, connects := relayServer(t, backend, root)
			dest := t.TempDir()

			// When it is cloned through the relay
			g := ingest.Git{Relay: srv.Listener.Addr().String()}
			log, err := g.Clone(context.Background(), "http://git.test/"+tt.repo, dest, tt.submodules)

			// Then the checkout, the log and the requests are as expected
			if (tt.wantErr == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), tt.wantErr)) {
				t.Fatalf("error = %v, want one with %q\n%s", err, tt.wantErr, log)
			}
			for name, want := range tt.wantFiles {
				if name == "link" && runtime.GOOS == "windows" {
					continue
				}
				got, err := os.ReadFile(filepath.Join(dest, name)) // #nosec G304 -- path below t.TempDir()
				if err != nil || (want != "" && string(got) != want) {
					t.Errorf("file %s = %q, %v, want %q", name, got, err, want)
				}
			}
			for _, name := range tt.wantAbsent {
				for _, base := range []string{dest, outside} {
					if _, err := os.Lstat(filepath.Join(base, name)); err == nil {
						t.Errorf("%s exists below %s", name, base)
					}
				}
			}
			for _, w := range tt.wantLog {
				if !strings.Contains(log, w) {
					t.Errorf("log lacks %q:\n%s", w, log)
				}
			}
			if got := connects(); !equal(got, tt.wantConnects) {
				t.Errorf("CONNECT requests = %q, want %q", got, tt.wantConnects)
			}
			if tt.wantErr != "" && errors.Is(err, ingest.ErrNotAllowed) {
				t.Errorf("a missing repository is not a refusal of the relay: %v", err)
			}
		})
	}
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
