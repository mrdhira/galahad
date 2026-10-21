package cli_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mrdhira/galahad/internal/cli"
	"github.com/mrdhira/galahad/internal/images"
	"github.com/mrdhira/galahad/internal/protocol"
	"github.com/mrdhira/galahad/internal/sandbox"
)

const fakeFirecrackerScript = "#!/bin/sh\necho 'Firecracker v1.17.0'\n"

func hexSum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func gzipped(t *testing.T, b []byte, name string, tarred bool) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if tarred {
		tw := tar.NewWriter(zw)
		if err := tw.WriteHeader(&tar.Header{Name: "release/" + name, Typeflag: tar.TypeReg, Mode: 0o755, Size: int64(len(b))}); err != nil {
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

// release is a small imitation of the image release: the pins, the unpacked files the pins describe,
// and what a server holds for each download path.
type release struct {
	pins  images.Pins
	raw   map[string][]byte // unpacked file name -> content
	files map[string][]byte // URL path -> content
}

func newRelease(t *testing.T) *release {
	t.Helper()
	r := &release{
		raw:   map[string][]byte{},
		files: map[string][]byte{},
		pins:  images.Pins{Version: "0.0.1", Tag: "images-0.0.1"},
	}
	for _, name := range []string{"vmlinux", "core.ext4", "re.ext4"} {
		raw := bytes.Repeat([]byte(name+" "), 500)
		z := gzipped(t, raw, "", false)
		r.raw[name] = raw
		r.files["/"+name+".gz"] = z
		r.pins.Assets = append(r.pins.Assets, images.Asset{
			Name: name + ".gz", File: name, SHA256: hexSum(z), Size: int64(len(z)), RawSHA256: hexSum(raw), RawSize: int64(len(raw)),
		})
	}
	archive := gzipped(t, []byte(fakeFirecrackerScript), "firecracker-v1.17.0-x86_64", true)
	r.files["/fc.tgz"] = archive
	r.pins.Firecracker = images.Firecracker{Version: "v1.17.0", SHA256: hexSum(archive)}
	return r
}

// serve starts a TLS server for the files of r. It returns the downloader for it and the request counter.
func (r *release) serve(t *testing.T) (*images.Downloader, *atomic.Int32) {
	t.Helper()
	var requests atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		requests.Add(1)
		body, ok := r.files[req.URL.Path]
		if !ok {
			http.NotFound(w, req)
			return
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	r.pins.Firecracker.URL = srv.URL + "/fc.tgz"
	return &images.Downloader{Client: images.NewClient(srv.Client().Transport, 10*time.Second), BaseURL: srv.URL}, &requests
}

// updateBackend runs a guest for the update job: it takes the Job and End frames, reports the two stages,
// writes "new" to the signatures drive it got, and ends with the empty Result, or with the Error failure.
type updateBackend struct {
	failure string
	spec    *sandbox.Spec // gets the spec of the machine
}

func (updateBackend) Name() string { return "update" }

func (b updateBackend) Start(_ context.Context, s sandbox.Spec) (sandbox.Machine, error) {
	*b.spec = s
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	pl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		_ = l.Close() // the listen error is the one to report
		return nil, err
	}
	m := &cleanMachine{l: l, pl: pl, done: make(chan struct{})}
	go func() {
		defer close(m.done)
		conn, err := net.Dial("tcp", l.Addr().String())
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }() // the guest is gone
		send := func(t protocol.FrameType, v any) {
			data, _ := json.Marshal(v)
			_ = protocol.WriteFrame(conn, t, data)
		}
		send(protocol.FrameHello, protocol.Hello{Protocol: protocol.ProtocolVersion, AgentVersion: "dev"})
		for {
			t, _, err := protocol.ReadFrame(conn)
			if err != nil {
				return
			}
			if t == protocol.FrameEnd {
				break
			}
		}
		send(protocol.FrameProgress, protocol.Progress{Stage: protocol.StageClamAV})
		send(protocol.FrameProgress, protocol.Progress{Stage: protocol.StageYARA})
		if b.failure != "" {
			send(protocol.FrameError, protocol.Error{Code: protocol.CodeInternal, Message: b.failure})
			return
		}
		_ = os.WriteFile(s.Signatures, []byte("new"), 0o600)
		now := time.Now().UTC()
		send(protocol.FrameResult, protocol.Result{
			SchemaVersion: protocol.SchemaVersion,
			Tool:          protocol.Tool{Name: "galahad-agent", Version: "dev"},
			Target:        protocol.Target{Name: "signatures", Kind: protocol.TargetDir},
			StartedAt:     now, FinishedAt: now,
			Files: []protocol.FileInfo{}, Findings: []protocol.Finding{}, IOCs: []protocol.IOC{},
			Coverage: protocol.Coverage{Skipped: []protocol.Skip{}, Analyzers: []string{}},
			Reasons:  []string{},
		})
	}()
	return m, nil
}

func TestSetup(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		args        []string
		first       []string // arguments of an earlier run, which must succeed
		goos        string   // "" = linux
		goarch      string   // "" = amd64
		pinsErr     bool
		homeIsFile  bool
		drop        string // a URL path the server does not have
		tamper      string // a URL path whose content is replaced by other bytes of the same size
		skipWindows bool   // the fake Firecracker is a shell script
		failure     string // the update guest fails with this message
		noBackend   bool   // no sandbox backend on this system
		oldImage    bool   // signatures.img and its stamp exist before the run
		// expectations
		wantCode     int
		wantStdout   []string
		wantStderr   []string
		wantFiles    []string // under the state directory
		wantNoFiles  []string // under the state directory
		wantRequests int      // of the last run
		wantImage    string   // content of signatures.img; empty means no such file
		wantStamp    bool     // signatures.stamp exists
		wantSpec     bool     // the machine got the writable new image
	}{
		{
			name: "the core image: Firecracker, the kernel and core.ext4", args: []string{"--skip-signatures"}, skipWindows: true,
			wantCode:     cli.ExitClean,
			wantStdout:   []string{"firecracker v1.17.0: installed", "vmlinux: installed", "core.ext4: installed"},
			wantFiles:    []string{"bin/firecracker", "images/0.0.1/vmlinux", "images/0.0.1/core.ext4"},
			wantNoFiles:  []string{"images/0.0.1/re.ext4"},
			wantRequests: 3,
		},
		{
			name: "the re image: the kernel and re.ext4", args: []string{"--image", "re", "--skip-signatures"}, skipWindows: true,
			wantCode:     cli.ExitClean,
			wantStdout:   []string{"firecracker v1.17.0: installed", "vmlinux: installed", "re.ext4: installed"},
			wantFiles:    []string{"bin/firecracker", "images/0.0.1/vmlinux", "images/0.0.1/re.ext4"},
			wantNoFiles:  []string{"images/0.0.1/core.ext4"},
			wantRequests: 3,
		},
		{
			name: "a second run downloads nothing", args: []string{"--skip-signatures"}, first: []string{"--skip-signatures"}, skipWindows: true,
			wantCode:     cli.ExitClean,
			wantStdout:   []string{"firecracker v1.17.0: already installed", "vmlinux: already installed", "core.ext4: already installed"},
			wantRequests: 0,
		},
		{
			name: "the update VM fills the signatures and the stamp is written", skipWindows: true,
			wantCode:     cli.ExitClean,
			wantStdout:   []string{"core.ext4: installed", "signatures: updating", "signatures: ClamAV databases", "signatures: YARA-Forge core rules", "signatures: updated"},
			wantFiles:    []string{"signatures.stamp"},
			wantImage:    "new",
			wantSpec:     true,
			wantRequests: 3,
		},
		{
			name: "a new update replaces the old image", oldImage: true, skipWindows: true,
			wantCode:     cli.ExitClean,
			wantStdout:   []string{"signatures: updated"},
			wantImage:    "new",
			wantStamp:    true,
			wantSpec:     true,
			wantRequests: 3,
		},
		{
			name: "a failed update keeps the old image", oldImage: true, failure: "freshclam exited with code 52", skipWindows: true,
			wantCode:     cli.ExitError,
			wantStderr:   []string{"galahad setup: signatures: ", "the guest failed (internal): freshclam exited with code 52", "(job ", "the previous signatures, if any, are kept"},
			wantImage:    "old",
			wantStamp:    true,
			wantSpec:     true,
			wantRequests: 3,
		},
		{
			name: "a failed first update leaves no image", failure: "yarac exited with code 1", skipWindows: true,
			wantCode:     cli.ExitError,
			wantStderr:   []string{"signatures: ", "yarac exited with code 1"},
			wantNoFiles:  []string{"signatures.img", "signatures.stamp"},
			wantSpec:     true,
			wantRequests: 3,
		},
		{
			name: "no sandbox for the update", noBackend: true, skipWindows: true,
			wantCode:     cli.ExitError,
			wantStdout:   []string{"core.ext4: installed"},
			wantStderr:   []string{"galahad setup: signatures: sandbox not supported"},
			wantRequests: 3,
		},
		{name: "-h prints usage", args: []string{"-h"}, wantCode: cli.ExitClean, wantStdout: []string{"Commands:"}},
		{name: "an unknown flag", args: []string{"--nope"}, wantCode: cli.ExitUsage, wantStderr: []string{"flag provided but not defined", "Usage:"}},
		{name: "an extra argument", args: []string{"core"}, wantCode: cli.ExitUsage, wantStderr: []string{`unexpected argument "core"`}},
		{name: "an unknown image", args: []string{"--image", "huge"}, wantCode: cli.ExitUsage, wantStderr: []string{`--image "huge": want core or re`}},
		{name: "another system", goos: "darwin", goarch: "arm64", wantCode: cli.ExitError, wantStderr: []string{"darwin/arm64: Linux only until M5"}},
		{name: "another architecture", goarch: "arm64", wantCode: cli.ExitError, wantStderr: []string{"linux/arm64: Linux amd64 only until M5"}},
		{name: "pins that do not load", pinsErr: true, wantCode: cli.ExitError, wantStderr: []string{"bad pins"}},
		{name: "a state directory that cannot be made", homeIsFile: true, wantCode: cli.ExitError, wantStderr: []string{"galahad setup:"}},
		{
			name: "no Firecracker release", drop: "/fc.tgz", wantCode: cli.ExitError, wantRequests: 1,
			wantStderr:  []string{"firecracker:", "not published yet"},
			wantNoFiles: []string{"bin/firecracker"},
		},
		{
			name: "no image release", drop: "/vmlinux.gz", skipWindows: true, wantCode: cli.ExitError, wantRequests: 2,
			wantStdout:  []string{"firecracker v1.17.0: installed"},
			wantStderr:  []string{"vmlinux: vmlinux.gz: not published yet", "build the files with images/linux/build.sh"},
			wantNoFiles: []string{"images/0.0.1/vmlinux"},
		},
		{
			name: "an image that does not match the pins installs nothing", tamper: "/core.ext4.gz", skipWindows: true, wantCode: cli.ExitError, wantRequests: 3,
			wantStdout:  []string{"vmlinux: installed"},
			wantStderr:  []string{"core.ext4: core.ext4.gz: does not match the sha256"},
			wantFiles:   []string{"images/0.0.1/vmlinux"},
			wantNoFiles: []string{"images/0.0.1/core.ext4"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.skipWindows && runtime.GOOS == "windows" {
				t.Skip("the fake Firecracker is a shell script")
			}
			rel := newRelease(t)
			delete(rel.files, tt.drop)
			if z, ok := rel.files[tt.tamper]; ok {
				rel.files[tt.tamper] = bytes.Repeat([]byte("x"), len(z))
			}
			d, requests := rel.serve(t)
			home := filepath.Join(t.TempDir(), "state")
			if tt.homeIsFile {
				if err := os.WriteFile(home, nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			var machine sandbox.Spec
			env := cli.Env{
				Home: home, GOOS: orDefault(tt.goos, "linux"), GOARCH: orDefault(tt.goarch, "amd64"), Downloader: d,
				Backend: func() (sandbox.Backend, error) {
					if tt.noBackend {
						return nil, sandbox.ErrUnsupported
					}
					return updateBackend{failure: tt.failure, spec: &machine}, nil
				},
				Pins: func() (images.Pins, error) {
					if tt.pinsErr {
						return images.Pins{}, errors.New("bad pins")
					}
					return rel.pins, nil
				},
			}
			if tt.oldImage {
				for name, content := range map[string]string{"signatures.img": "old", "signatures.stamp": "2026-01-01T00:00:00Z\n"} {
					if err := os.MkdirAll(home, 0o700); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(home, name), []byte(content), 0o600); err != nil {
						t.Fatal(err)
					}
				}
			}
			if tt.first != nil {
				var o, e bytes.Buffer
				if code := cli.RunWithEnv(append([]string{"setup"}, tt.first...), &o, &e, env); code != cli.ExitClean {
					t.Fatalf("first run = %d\n%s%s", code, o.String(), e.String())
				}
				requests.Store(0)
			}

			var stdout, stderr bytes.Buffer
			code := cli.RunWithEnv(append([]string{"setup"}, tt.args...), &stdout, &stderr, env)

			if code != tt.wantCode {
				t.Errorf("exit code = %d, want %d\nstdout: %s\nstderr: %s", code, tt.wantCode, stdout.String(), stderr.String())
			}
			for _, w := range tt.wantStdout {
				if !strings.Contains(stdout.String(), w) {
					t.Errorf("stdout lacks %q: %q", w, stdout.String())
				}
			}
			for _, w := range tt.wantStderr {
				if !strings.Contains(stderr.String(), w) {
					t.Errorf("stderr lacks %q: %q", w, stderr.String())
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
			if n := int(requests.Load()); n != tt.wantRequests {
				t.Errorf("requests = %d, want %d", n, tt.wantRequests)
			}
			if got, _ := os.ReadFile(filepath.Join(home, "signatures.img")); string(got) != tt.wantImage {
				t.Errorf("signatures.img = %q, want %q", got, tt.wantImage)
			}
			if _, err := os.Stat(filepath.Join(home, "signatures.stamp")); (err == nil) != (tt.wantStamp || tt.wantImage == "new") {
				t.Errorf("signatures.stamp exists = %v, want %v", err == nil, tt.wantStamp || tt.wantImage == "new")
			}
			if tt.wantSpec && (machine.Signatures != filepath.Join(home, "signatures.img.new") || !machine.SignaturesWritable || machine.Image != "core") {
				t.Errorf("machine spec = %+v, want the writable new image and the core image", machine)
			}
			if tt.wantCode == cli.ExitError {
				// A failed run leaves no partial file behind, under any name.
				_ = filepath.WalkDir(home, func(p string, de os.DirEntry, err error) error {
					if err == nil && strings.HasSuffix(de.Name(), ".part") {
						t.Errorf("partial file left: %s", p)
					}
					return nil
				})
			}
		})
	}
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
