package acceptance_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
)

func sha(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func gzipBytes(t *testing.T, b []byte, tarMember string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if tarMember != "" {
		tw := tar.NewWriter(zw)
		if err := tw.WriteHeader(&tar.Header{Name: "release/" + tarMember, Typeflag: tar.TypeReg, Mode: 0o755, Size: int64(len(b))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(b); err != nil {
			t.Fatal(err)
		}
		if err := tw.Close(); err != nil {
			t.Fatal(err)
		}
	} else if _, err := zw.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// TestSetupAndDoctor runs setup against a local TLS server that holds a small imitation of the image
// release, and then doctor. The binary trusts the server through SSL_CERT_FILE, and reads the pins
// of the imitation and its URL through the galahadtest hooks. It needs a Linux amd64 host, as setup does.
func TestSetupAndDoctor(t *testing.T) {
	linuxAMD64 := runtime.GOOS == "linux" && runtime.GOARCH == "amd64"
	tests := []struct {
		name string
		// inputs
		args      [][]string // commands run in order; the last one is checked
		drop      string     // a URL path the server does not have
		tamper    string     // a URL path whose content is replaced by other bytes of the same size
		onlyOther bool       // runs on hosts that are not Linux amd64
		// expectations
		wantCode     int
		wantStdout   []string
		wantStderr   []string
		wantFiles    []string // under GALAHAD_HOME
		wantNoFiles  []string // under GALAHAD_HOME
		wantRequests int32    // of the last command
		wantNoFail   bool     // doctor: exit 0 exactly when there is no FAIL line
	}{
		{
			name:       "doctor before setup fails and names what is missing",
			args:       [][]string{{"doctor"}},
			wantCode:   1,
			wantStdout: []string{"FAIL  state directory:", "does not exist", "fix: run galahad setup"},
		},
		{
			name:         "setup installs Firecracker and the core image",
			args:         [][]string{{"setup"}},
			wantCode:     0,
			wantStdout:   []string{"firecracker v1.17.0: installed", "vmlinux: installed", "core.ext4: installed"},
			wantFiles:    []string{"bin/firecracker", "images/0.0.1/vmlinux", "images/0.0.1/core.ext4"},
			wantNoFiles:  []string{"images/0.0.1/re.ext4"},
			wantRequests: 3,
		},
		{
			name:         "setup --image re installs the re image",
			args:         [][]string{{"setup", "--image", "re"}},
			wantCode:     0,
			wantStdout:   []string{"re.ext4: installed"},
			wantFiles:    []string{"images/0.0.1/vmlinux", "images/0.0.1/re.ext4"},
			wantNoFiles:  []string{"images/0.0.1/core.ext4"},
			wantRequests: 3,
		},
		{
			name:         "a second setup downloads nothing",
			args:         [][]string{{"setup"}, {"setup"}},
			wantCode:     0,
			wantStdout:   []string{"firecracker v1.17.0: already installed", "vmlinux: already installed", "core.ext4: already installed"},
			wantRequests: 0,
		},
		{
			name:       "doctor after setup passes Firecracker and the image checks",
			args:       [][]string{{"setup"}, {"doctor"}},
			wantStdout: []string{"PASS  platform: linux/amd64", "PASS  firecracker: v1.17.0", "PASS  vmlinux:", "PASS  core.ext4:", "PASS  galahad-agent:", "WARN  re.ext4:"},
			wantNoFail: true,
		},
		{
			name:         "a release that is not published is named",
			args:         [][]string{{"setup"}},
			drop:         "/vmlinux.gz",
			wantCode:     1,
			wantStderr:   []string{"vmlinux.gz: not published yet", "images/linux/build.sh"},
			wantNoFiles:  []string{"images/0.0.1/vmlinux"},
			wantRequests: 2,
		},
		{
			name:         "an image that does not match the pins installs nothing",
			args:         [][]string{{"setup"}},
			tamper:       "/core.ext4.gz",
			wantCode:     1,
			wantStderr:   []string{"core.ext4.gz: does not match the sha256"},
			wantNoFiles:  []string{"images/0.0.1/core.ext4"},
			wantRequests: 3,
		},
		{
			name:       "setup is Linux only for now",
			args:       [][]string{{"setup"}},
			onlyOther:  true,
			wantCode:   1,
			wantStderr: []string{"Linux only until M5"},
		},
		{
			name:       "doctor is Linux only for now",
			args:       [][]string{{"doctor"}},
			onlyOther:  true,
			wantCode:   1,
			wantStdout: []string{"FAIL  platform: " + runtime.GOOS + "/" + runtime.GOARCH},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.onlyOther == linuxAMD64 {
				t.Skip("this case is for another kind of host")
			}
			files := map[string][]byte{}
			var assets []map[string]any
			for _, name := range []string{"vmlinux", "core.ext4", "re.ext4"} {
				raw := bytes.Repeat([]byte(name+" "), 500)
				z := gzipBytes(t, raw, "")
				files["/"+name+".gz"] = z
				assets = append(assets, map[string]any{
					"name": name + ".gz", "file": name, "sha256": sha(z), "size": len(z), "raw_sha256": sha(raw), "raw_size": len(raw),
				})
			}
			archive := gzipBytes(t, []byte("#!/bin/sh\necho 'Firecracker v1.17.0'\n"), "firecracker-v1.17.0-x86_64")
			files["/fc.tgz"] = archive
			delete(files, tt.drop)
			if z, ok := files[tt.tamper]; ok {
				files[tt.tamper] = bytes.Repeat([]byte("x"), len(z))
			}
			var requests atomic.Int32
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				body, ok := files[r.URL.Path]
				if !ok {
					http.NotFound(w, r)
					return
				}
				_, _ = w.Write(body)
			}))
			defer srv.Close()

			dir := t.TempDir()
			pins, err := json.Marshal(map[string]any{
				"version": "0.0.1", "tag": "images-0.0.1", "assets": assets,
				"firecracker": map[string]any{"version": "v1.17.0", "url": srv.URL + "/fc.tgz", "sha256": sha(archive)},
			})
			if err != nil {
				t.Fatal(err)
			}
			pinsFile := filepath.Join(dir, "pins.json")
			certFile := filepath.Join(dir, "server.pem")
			if err := os.WriteFile(pinsFile, pins, 0o600); err != nil {
				t.Fatal(err)
			}
			cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
			if err := os.WriteFile(certFile, cert, 0o600); err != nil {
				t.Fatal(err)
			}
			home := filepath.Join(dir, "state")
			t.Setenv("GALAHAD_HOME", home)
			t.Setenv("GALAHAD_TEST_PINS", pinsFile)
			t.Setenv("GALAHAD_TEST_IMAGES_URL", srv.URL)
			t.Setenv("SSL_CERT_FILE", certFile)

			var stdout, stderr string
			var code int
			for _, args := range tt.args {
				requests.Store(0)
				stdout, stderr, code = run(t, args...)
			}

			wantCode := tt.wantCode
			if tt.wantNoFail {
				wantCode = 0
				if strings.Contains(stdout, "FAIL") {
					wantCode = 1
				}
			}
			if code != wantCode {
				t.Errorf("exit = %d, want %d\nstdout: %s\nstderr: %s", code, wantCode, stdout, stderr)
			}
			for _, w := range tt.wantStdout {
				if !strings.Contains(stdout, w) {
					t.Errorf("stdout lacks %q:\n%s", w, stdout)
				}
			}
			for _, w := range tt.wantStderr {
				if !strings.Contains(stderr, w) {
					t.Errorf("stderr lacks %q:\n%s", w, stderr)
				}
			}
			for _, f := range tt.wantFiles {
				if _, err := os.Stat(filepath.Join(home, f)); err != nil {
					t.Errorf("missing %s: %v", f, err)
				}
			}
			for _, f := range tt.wantNoFiles {
				if _, err := os.Stat(filepath.Join(home, f)); err == nil {
					t.Errorf("%s exists, want it absent", f)
				}
			}
			if n := requests.Load(); n != tt.wantRequests {
				t.Errorf("requests = %d, want %d", n, tt.wantRequests)
			}
		})
	}
}
