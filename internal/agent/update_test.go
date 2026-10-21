//go:build galahadtest

package agent_test

import (
	"archive/zip"
	"bytes"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/mrdhira/galahad/internal/agent"
	"github.com/mrdhira/galahad/internal/protocol"
)

// updateStubs builds a freshclam and a yarac that stand in for the real ones. freshclam copies its
// configuration to $STUB_CONF and writes the databases named by STUB_FRESHCLAM: "" for main, daily and
// bytecode, "no-daily" for main only, "fail" for exit 52. yarac copies the rules to its output, or does what
// STUB_YARAC says: "fail" for exit 1, "empty" for exit 0 without a file.
func updateStubs(t *testing.T) string {
	t.Helper()
	const code = `package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	switch strings.TrimSuffix(filepath.Base(os.Args[0]), ".exe") {
	case "freshclam":
		conf := strings.TrimPrefix(os.Args[1], "--config-file=")
		data, err := os.ReadFile(conf)
		if err != nil {
			os.Exit(90)
		}
		_ = os.WriteFile(os.Getenv("STUB_CONF"), data, 0o600)
		if os.Getenv("STUB_FRESHCLAM") == "fail" {
			fmt.Fprintln(os.Stderr, "ERROR: Can't download main.cvd")
			os.Exit(52)
		}
		db := strings.Fields(strings.SplitN(string(data), "\n", 2)[0])[1]
		names := []string{"main.cvd", "daily.cvd", "bytecode.cvd"}
		if os.Getenv("STUB_FRESHCLAM") == "no-daily" {
			names = names[:1]
		}
		for _, n := range names {
			_ = os.WriteFile(filepath.Join(db, n), []byte("db"), 0o600)
		}
		fmt.Println("main.cvd updated")
	case "yarac":
		switch os.Getenv("STUB_YARAC") {
		case "fail":
			fmt.Fprintln(os.Stderr, "error: syntax error, unexpected identifier")
			os.Exit(1)
		case "empty":
			return
		}
		rules, err := os.ReadFile(os.Args[1])
		if err != nil {
			os.Exit(91)
		}
		if err := os.WriteFile(os.Args[2], rules, 0o600); err != nil {
			os.Exit(92)
		}
	}
}
`
	exe := ""
	if runtime.GOOS == "windows" {
		exe = ".exe"
	}
	dir := t.TempDir()
	src := filepath.Join(t.TempDir(), "main.go")
	if err := os.WriteFile(src, []byte(code), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"freshclam", "yarac"} {
		build := exec.Command("go", "build", "-o", filepath.Join(dir, name+exe), src)
		if out, err := build.CombinedOutput(); err != nil {
			t.Fatalf("build %s stub: %v\n%s", name, err, out)
		}
	}
	return dir
}

// zipOf returns a zip with the named members.
func zipOf(t *testing.T, members map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, name := range slices.Sorted(func(yield func(string) bool) {
		for n := range members {
			if !yield(n) {
				return
			}
		}
	}) {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(members[name])); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestGuestUpdate(t *testing.T) {
	const rules = "rule Test_Rule { condition: false }\n"
	good := map[string]string{"packages/core/yara-rules-core.yar": rules, "README.md": "# rules\n"}
	stubDir := updateStubs(t)
	refuse := func(reason string) func(net.Conn) {
		return func(c net.Conn) {
			readConnectFrame(c)
			writeReply(c, protocol.FrameConnectReply, `{"ok":false,"reason":"`+reason+`"}`)
		}
	}
	tests := []struct {
		name string
		// inputs
		zip      map[string]string // the release asset; the good one when nil
		notZip   bool              // the asset is not a zip at all
		freshclm string            // STUB_FRESHCLAM
		yarac    string            // STUB_YARAC
		proxy    string            // "backend", a refusal reason, or "none"
		noSigDir bool              // outside a VM, with no drive
		// expectations
		wantErrCode string // an Error frame instead of a Result
		wantMessage string // substring of the Error message
		wantLog     []string
		wantFiles   map[string]string // file on the signatures drive to its content
	}{
		{
			name: "the databases and the compiled rules land on the drive", proxy: "backend",
			wantLog:   []string{"freshclam: ok", "freshclam: main.cvd updated", "yara-forge: yara-forge-rules-core.zip,", "sha256 ", "yarac: ok"},
			wantFiles: map[string]string{"clamav/main.cvd": "db", "clamav/daily.cvd": "db", "yara/core.yarc": rules},
		},
		{
			name: "freshclam fails", proxy: "backend", freshclm: "fail",
			wantErrCode: protocol.CodeInternal, wantMessage: "freshclam exited with code 52: ERROR: Can't download main.cvd",
			wantLog: []string{"freshclam: ERROR: Can't download main.cvd"},
		},
		{
			name: "freshclam leaves no daily database", proxy: "backend", freshclm: "no-daily",
			wantErrCode: protocol.CodeInternal, wantMessage: "freshclam left no daily database",
		},
		{
			name: "the proxy refuses the release host", proxy: "host not allowed",
			wantErrCode: protocol.CodeNotAllowed, wantMessage: "allowed.example.com:80 denied: host not allowed",
			wantLog: []string{"freshclam: ok"},
		},
		{
			name: "the download is not a zip", proxy: "backend", notZip: true,
			wantErrCode: protocol.CodeInternal, wantMessage: "the YARA-Forge zip:",
		},
		{
			name: "a zip without a rules file", proxy: "backend", zip: map[string]string{"README.md": "# rules\n"},
			wantErrCode: protocol.CodeInternal, wantMessage: "has no .yar file",
		},
		{
			name: "a zip with two rules files", proxy: "backend", zip: map[string]string{"a.yar": rules, "b/c.YAR": rules},
			wantErrCode: protocol.CodeInternal, wantMessage: "more than one .yar file",
		},
		{
			name: "yarac fails", proxy: "backend", yarac: "fail",
			wantErrCode: protocol.CodeInternal, wantMessage: "yarac exited with code 1: error: syntax error",
			wantLog: []string{"yarac: error: syntax error, unexpected identifier"},
		},
		{
			name: "yarac writes no file", proxy: "backend", yarac: "empty",
			wantErrCode: protocol.CodeInternal, wantMessage: "yarac wrote no rules file",
		},
		{
			name: "an update without a proxy channel fails", proxy: "none",
			wantErrCode: protocol.CodeIngest, wantMessage: "needs the network",
		},
		{
			name: "an update outside a VM without a drive fails", proxy: "backend", noSigDir: true,
			wantErrCode: protocol.CodeInternal, wantMessage: "needs the signatures drive of the VM",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given the stubs, a signatures directory and a release server behind a proxy
			sigs := t.TempDir()
			conf := filepath.Join(t.TempDir(), "freshclam.conf")
			t.Setenv("PATH", stubDir+string(os.PathListSeparator)+os.Getenv("PATH"))
			t.Setenv("STUB_CONF", conf)
			t.Setenv("STUB_FRESHCLAM", tt.freshclm)
			t.Setenv("STUB_YARAC", tt.yarac)
			t.Setenv("GALAHAD_TEST_SIG_DIR", map[bool]string{false: sigs, true: ""}[tt.noSigDir])
			t.Setenv("GALAHAD_TEST_YARA_URL", "http://allowed.example.com/yara-forge-rules-core.zip")
			asset := zipOf(t, orMembers(tt.zip, good))
			if tt.notZip {
				asset = []byte("not a zip")
			}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write(asset)
			}))
			t.Cleanup(srv.Close)
			var args []string
			switch tt.proxy {
			case "none":
			case "backend":
				args = []string{"--proxy", "tcp:" + hostProxyAt(t, srv.Listener.Addr().String())}
			default:
				args = []string{"--proxy", "tcp:" + fakeProxyAt(t, refuse(tt.proxy))}
			}
			job := protocol.Job{
				ID: "20261021-153012-a1b2c3", Kind: protocol.KindUpdate,
				Timeouts: protocol.Timeouts{Job: 300}, Now: testJob("", 1).Now,
			}

			// When the host sends the job and an empty stream
			c, exit := startGuestWith(t, agent.Env{Setenv: func(string, string) {}}, args...)
			go func() {
				if writeJSON(c, protocol.FrameJob, job) == nil {
					_ = writeJSON(c, protocol.FrameEnd, endOf(nil))
				}
			}()
			got := readGuest(t, c)
			ex := <-exit

			// Then the guest reports success with an empty Result, or the Error, and the drive holds the files
			for _, w := range tt.wantLog {
				if !strings.Contains(got.toolsLog, w) {
					t.Errorf("tools.log lacks %q:\n%s", w, got.toolsLog)
				}
			}
			if tt.wantErrCode != "" {
				if got.errMsg == nil || got.errMsg.Code != tt.wantErrCode || !strings.Contains(got.errMsg.Message, tt.wantMessage) || ex.code != agent.ExitError {
					t.Fatalf("error frame = %+v, exit = %d, want code %q, a message with %q and exit %d; stderr %q",
						got.errMsg, ex.code, tt.wantErrCode, tt.wantMessage, agent.ExitError, ex.stderr)
				}
				return
			}
			if got.result == nil || ex.code != agent.ExitClean {
				t.Fatalf("result = %v, error = %+v, exit = %d; stderr %q", got.result, got.errMsg, ex.code, ex.stderr)
			}
			if r := got.result; r.Target.Name != "signatures" || len(r.Findings) != 0 || !slices.Equal(got.stages, []string{"ingest", "clamav", "yara"}) {
				t.Errorf("result target = %q, findings = %d, stages = %v, want the empty result of an update", r.Target.Name, len(r.Findings), got.stages)
			}
			for name, want := range tt.wantFiles {
				if data, err := os.ReadFile(filepath.Join(sigs, filepath.FromSlash(name))); err != nil || string(data) != want {
					t.Errorf("%s = %q, %v, want %q", name, data, err, want)
				}
			}
			data, err := os.ReadFile(conf)
			if err != nil {
				t.Fatal(err)
			}
			for _, w := range []string{"DatabaseDirectory " + filepath.Join(sigs, "clamav") + "\n", "DNSDatabaseInfo no\n", "DatabaseMirror database.clamav.net\n", "HTTPProxyServer 127.0.0.1\n", "HTTPProxyPort "} {
				if !strings.Contains(string(data), w) {
					t.Errorf("freshclam configuration lacks %q:\n%s", w, data)
				}
			}
		})
	}
}

// orMembers returns m, or def when m is nil.
func orMembers(m, def map[string]string) map[string]string {
	if m == nil {
		return def
	}
	return m
}
