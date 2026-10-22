package acceptance_test

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/cgi"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// metadataSubmodule is the address of the one submodule of metadata.git: the cloud metadata service, which the
// proxy must refuse.
const metadataSubmodule = "https://169.254.169.254/x.git"

// publishInterview publishes the fake-interview-repo fixture as the bare repository root/interview.git.
func publishInterview(t *testing.T, root string) {
	t.Helper()
	work := t.TempDir()
	copyTree(t, corpus(t, "fake-interview-repo"), work)
	publish(t, work, root, "interview.git", nil)
}

// publishMetadata publishes root/metadata.git: a project whose only submodule is at the metadata address.
func publishMetadata(t *testing.T, root string) {
	t.Helper()
	work := t.TempDir()
	publish(t, work, root, "metadata.git", func() {
		writeText(t, filepath.Join(work, "README.md"), "a project with a submodule\n")
		writeText(t, filepath.Join(work, ".gitmodules"), "[submodule \"vendor\"]\n\tpath = vendor\n\turl = "+metadataSubmodule+"\n")
		runGit(t, work, "add", "--ignore-removal", ".")
		runGit(t, work, "update-index", "--add", "--cacheinfo", "160000,"+strings.Repeat("ab", 20)+",vendor")
	})
}

// startSinkhole starts one local server that plays the two hosts of the M2 demo, and points the proxy test
// hooks at it. The host proxy resolves git.test and files.test to 127.0.0.1 (GALAHAD_TEST_RESOLVE) and sends
// every tunnel to this server (GALAHAD_TEST_SINKHOLE), so the guest reaches it the way it would reach a real
// host, only through the proxy, whichever sandbox runs it:
//   - git.test serves interview.git (fake-interview-repo) and metadata.git (a submodule at the metadata
//     address) over smart http, with git-http-backend;
//   - files.test serves /statement.pdf, the P4 PDF with a URI action (p4-pdf-openaction-uri).
//
// The Host header tells the two apart. The test is skipped where git-http-backend is missing.
func startSinkhole(t *testing.T) {
	t.Helper()
	backend := needGit(t)
	root := t.TempDir()
	publishInterview(t, root)
	publishMetadata(t, root)
	pdf, err := os.ReadFile(filepath.Join(corpus(t, "p4-pdf-openaction-uri"), "statement.pdf")) // #nosec G304 -- the checked-in corpus
	if err != nil {
		t.Fatal(err)
	}
	git := &cgi.Handler{Path: backend, Stderr: io.Discard, Env: []string{"GIT_PROJECT_ROOT=" + root, "GIT_HTTP_EXPORT_ALL=1"}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Host == "git.test":
			git.ServeHTTP(w, r)
		case r.Host == "files.test" && r.URL.Path == "/statement.pdf":
			_, _ = w.Write(pdf)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	_, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("GALAHAD_TEST_RESOLVE", "git.test=127.0.0.1,files.test=127.0.0.1")
	t.Setenv("GALAHAD_TEST_SINKHOLE", "127.0.0.1:"+port)
}

// proxyHosts returns the sorted, distinct hosts that proxy.log of the job in dir names.
func proxyHosts(t *testing.T, dir string) []string {
	t.Helper()
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
	return hosts
}
