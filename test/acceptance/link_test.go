package acceptance_test

import (
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// corpusCaseNamed returns the case of the corpus table whose name starts with prefix.
func corpusCaseNamed(t *testing.T, prefix string) corpusCase {
	t.Helper()
	for _, c := range corpusCases() {
		if strings.HasPrefix(c.name, prefix) {
			return c
		}
	}
	t.Fatalf("no corpus case starts with %q", prefix)
	return corpusCase{}
}

// linkServer plays both the file host files.test and Drive (drive.test). Every tunnel of the guest ends here,
// because GALAHAD_TEST_SINKHOLE points at it, and the Host header tells the two apart.
func linkServer(t *testing.T, pdf, drivePDF []byte) *httptest.Server {
	t.Helper()
	warning, err := os.ReadFile(filepath.Join("..", "..", "testdata", "drive", "warning.html"))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Host == "files.test" && r.URL.Path == "/invoice.pdf":
			_, _ = w.Write(pdf)
		case r.Host == "files.test" && r.URL.Path == "/to-metadata":
			http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
		case r.Host == "files.test" && r.URL.Path == "/to-evil":
			http.Redirect(w, r, "http://evil.test/payload.pdf", http.StatusFound)
		case r.Host == "drive.test" && r.URL.Path == "/download" && r.URL.Query().Get("id") == "1AbCdEfGhIjKlMnOp" && r.URL.Query().Get("confirm") == "":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(strings.ReplaceAll(string(warning), "@ORIGIN@", "http://drive.test")))
		case r.Host == "drive.test" && r.URL.Path == "/download" && r.URL.Query().Get("confirm") == "t" && r.URL.Query().Get("uuid") != "":
			w.Header().Set("Content-Disposition", `attachment; filename="report.pdf"`)
			_, _ = w.Write(drivePDF)
		case r.Host == "drive.test" && r.URL.Path == "/private":
			http.Redirect(w, r, "https://accounts.google.com/ServiceLogin", http.StatusFound)
		case r.Host == "drive.test" && r.URL.Path == "/quota":
			w.WriteHeader(http.StatusTooManyRequests)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// P4, P6, P8: a link is fetched in the guest through the host proxy, and the report is the one of the file.
func TestScanLink(t *testing.T) {
	pdf, err := os.ReadFile(filepath.Join(corpus(t, "p4-pdf-launch"), "invoice.pdf"))
	if err != nil {
		t.Fatal(err)
	}
	benign, err := os.ReadFile(filepath.Join(corpus(t, "benign-pdf"), "report.pdf"))
	if err != nil {
		t.Fatal(err)
	}
	const driveLink = "https://drive.google.com/file/d/1AbCdEfGhIjKlMnOp/view"
	tests := []struct {
		name string
		// inputs
		args      []string
		target    string
		driveBase string // the path of GALAHAD_TEST_DRIVE_BASE on drive.test
		// expectations
		wantCode    int
		wantCorpus  string // the corpus case whose evidence the report must show
		wantKind    string // target kind in job.json
		wantName    string // target name in report.json
		wantState   string
		wantStderr  []string
		wantAbsent  []string // not in stderr
		wantBlocked bool
		wantLog     []string // substrings of proxy.log
	}{
		{
			name:     "a URL to p4-pdf-launch exits 20 with the evidence of the local file",
			target:   "http://files.test/invoice.pdf",
			wantCode: 20, wantCorpus: "p4-pdf-launch", wantKind: "url", wantName: "invoice.pdf", wantState: "done",
			wantLog: []string{`"host":"files.test"`, `"decision":"allowed"`},
		},
		{
			name:   "a Drive warning page leads to benign-pdf and exits 0",
			args:   []string{"--allow-host", "drive.test"},
			target: driveLink, driveBase: "/download",
			wantCode: 0, wantCorpus: "benign-pdf: destination", wantKind: "drive", wantName: "report.pdf", wantState: "done",
			wantLog: []string{`"host":"drive.test"`, `"decision":"allowed"`},
		},
		{
			name:     "a redirect to a host that is not allowed is refused and the flag comes from the proxy",
			target:   "http://files.test/to-evil",
			wantCode: 1, wantKind: "url", wantState: "failed",
			wantStderr: []string{"the guest failed (not_allowed)", "CONNECT evil.test:80 denied: host not allowed", "rerun with --allow-host evil.test"},
			wantAbsent: []string{"the proxy refused the connection"},
			wantLog:    []string{`"host":"evil.test"`, `"decision":"denied"`, `"reason":"host not allowed"`},
		},
		{
			name:     "a redirect to the metadata address is blocked and reported",
			target:   "http://files.test/to-metadata",
			wantCode: 1, wantKind: "url", wantState: "failed", wantBlocked: true,
			wantStderr: []string{"the guest failed (not_allowed)", "GAL-NET-001: CONNECT 169.254.169.254:80 denied: metadata"},
			wantAbsent: []string{"--allow-host", "the proxy refused the connection"},
			wantLog:    []string{`"host":"169.254.169.254"`, `"decision":"denied"`, `"reason":"metadata"`},
		},
		{
			name:   "a private Drive file is reported with the text of the host",
			args:   []string{"--allow-host", "drive.test"},
			target: driveLink, driveBase: "/private",
			wantCode: 1, wantKind: "drive", wantState: "failed",
			wantStderr: []string{"the guest failed (drive_private): the Drive file is not public"},
			wantAbsent: []string{"accounts.google.com"},
		},
		{
			name:   "a Drive quota is reported with the text of the host",
			args:   []string{"--allow-host", "drive.test"},
			target: driveLink, driveBase: "/quota",
			wantCode: 1, wantKind: "drive", wantState: "failed",
			wantStderr: []string{"the guest failed (drive_quota): Drive refuses the download because of its quota"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given a server for the link, behind the test hooks of the proxy
			srv := linkServer(t, pdf, benign)
			_, port, err := net.SplitHostPort(srv.Listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			t.Setenv("GALAHAD_TEST_RESOLVE", "files.test=127.0.0.1,drive.test=127.0.0.1")
			t.Setenv("GALAHAD_TEST_SINKHOLE", "127.0.0.1:"+port)
			if tt.driveBase != "" {
				t.Setenv("GALAHAD_TEST_DRIVE_BASE", "http://drive.test"+tt.driveBase)
			}
			home := t.TempDir()

			// When the link is scanned
			stdout, stderr, code := scan(t, home, append(tt.args, tt.target)...)

			// Then the exit code, the job, the report and the proxy log are as expected
			if code != tt.wantCode {
				t.Fatalf("exit = %d, want %d\nstdout: %s\nstderr: %s", code, tt.wantCode, stdout, stderr)
			}
			for _, w := range tt.wantStderr {
				if !strings.Contains(stderr, w) {
					t.Errorf("stderr lacks %q:\n%s", w, stderr)
				}
			}
			for _, a := range tt.wantAbsent {
				if strings.Contains(stderr, a) {
					t.Errorf("stderr has %q:\n%s", a, stderr)
				}
			}
			dir := onlyJob(t, home)
			j := readJob(t, dir)
			if j.State != tt.wantState || j.ExitCode != tt.wantCode || j.Target.Kind != tt.wantKind || j.Blocked != tt.wantBlocked {
				t.Errorf("job.json = %+v, want state %s, exit code %d, target kind %s, blocked %v", j, tt.wantState, tt.wantCode, tt.wantKind, tt.wantBlocked)
			}
			logData, _ := os.ReadFile(filepath.Join(dir, "proxy.log"))
			for _, w := range tt.wantLog {
				if !strings.Contains(string(logData), w) {
					t.Errorf("proxy.log lacks %q:\n%s", w, logData)
				}
			}
			if tt.wantState != "done" {
				if _, err := os.Stat(filepath.Join(dir, "report.json")); err == nil {
					t.Error("report.json exists, want none")
				}
				return
			}
			rep, err := readReport(filepath.Join(dir, "report.json"))
			if err != nil {
				t.Fatal(err)
			}
			if rep.Target.Name != tt.wantName || rep.Target.Kind != "file" || len(rep.Target.SHA256) != 64 {
				t.Errorf("report target = %+v, want file %s with a sha256", rep.Target, tt.wantName)
			}
			checkCorpus(t, corpusCaseNamed(t, tt.wantCorpus), rep, dir)
		})
	}
}
