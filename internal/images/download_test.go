package images_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mrdhira/galahad/internal/images"
)

func sum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func gz(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// testAsset returns an asset for raw and its gzip file.
func testAsset(t *testing.T, raw []byte) (images.Asset, []byte) {
	t.Helper()
	z := gz(t, raw)
	return images.Asset{
		Name: "core.ext4.gz", File: "core.ext4",
		SHA256: sum(z), Size: int64(len(z)), RawSHA256: sum(raw), RawSize: int64(len(raw)),
	}, z
}

// listDir returns the names in dir.
func listDir(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

func TestInstallAsset(t *testing.T) {
	raw := bytes.Repeat([]byte("galahad image "), 1000)
	tests := []struct {
		name string
		// inputs
		present []byte                                         // content of the unpacked file before the call
		mutate  func(t *testing.T, a *images.Asset, z *[]byte) // changes the pin, and the gzip file the server holds
		serve   func(w http.ResponseWriter, z []byte)          // nil serves z
		timeout time.Duration                                  // 0 = 10 s
		base    string                                         // replaces the server URL
		// expectations
		wantInstalled bool
		wantRequests  int
		wantErr       string   // substring; empty means success
		wantErrIs     error    // checked when set
		wantFiles     []string // the directory after the call
	}{
		{name: "a good asset is downloaded, unpacked and renamed into place", wantInstalled: true, wantRequests: 1, wantFiles: []string{"core.ext4"}},
		{name: "a file that already verifies is not downloaded again", present: raw, wantFiles: []string{"core.ext4"}},
		{name: "a file that does not verify is replaced", present: []byte("old"), wantInstalled: true, wantRequests: 1, wantFiles: []string{"core.ext4"}},
		{
			name: "a download URL that is not https", base: "http://example.test", wantErr: "is not https",
		},
		{
			name: "a redirect loop stops", wantRequests: 6, wantErr: "stopped after 5 redirects",
			serve: func(w http.ResponseWriter, _ []byte) {
				w.Header().Set("Location", "/loop")
				w.WriteHeader(http.StatusFound)
			},
		},
		{
			name: "a redirect to a URL that is not https", wantRequests: 1, wantErr: "not https",
			serve: func(w http.ResponseWriter, _ []byte) {
				w.Header().Set("Location", "http://example.test/core.ext4.gz")
				w.WriteHeader(http.StatusFound)
			},
		},
		{
			name: "a download that takes too long", timeout: 200 * time.Millisecond, wantRequests: 1, wantErr: "deadline",
			serve: func(w http.ResponseWriter, _ []byte) {
				w.WriteHeader(http.StatusOK)
				w.(http.Flusher).Flush()
				time.Sleep(time.Second)
			},
		},
		{
			name: "a release that is not published", wantRequests: 1, wantErr: "not published yet", wantErrIs: images.ErrNotPublished,
			serve: func(w http.ResponseWriter, _ []byte) { http.NotFound(w, nil) },
		},
		{
			name: "any other HTTP status", wantRequests: 1, wantErr: "HTTP 500",
			serve: func(w http.ResponseWriter, _ []byte) { w.WriteHeader(http.StatusInternalServerError) },
		},
		{
			name: "a server that announces more than the pinned size", wantRequests: 1, wantErr: "announces",
			serve: func(w http.ResponseWriter, z []byte) {
				w.Header().Set("Content-Length", strconv.Itoa(len(z)+1))
				_, _ = w.Write(z)
				_, _ = w.Write([]byte("x"))
			},
		},
		{
			name: "a server that sends more than the pinned size", wantRequests: 1, wantErr: "more than the",
			serve: func(w http.ResponseWriter, z []byte) {
				_, _ = w.Write(z)
				w.(http.Flusher).Flush() // chunked: no Content-Length
				_, _ = w.Write(bytes.Repeat([]byte("x"), 4096))
			},
		},
		{
			name: "a connection that drops half way", wantRequests: 1, wantErr: "download stopped",
			serve: func(w http.ResponseWriter, z []byte) {
				w.Header().Set("Content-Length", strconv.Itoa(len(z)))
				_, _ = w.Write(z[:len(z)/2]) // the server closes the connection: the body is short
			},
		},
		{
			name: "a short body without a Content-Length", wantRequests: 1, wantErr: "pins.json says",
			serve: func(w http.ResponseWriter, z []byte) {
				_, _ = w.Write(z[:len(z)/2])
				w.(http.Flusher).Flush()
			},
		},
		{
			name: "a gzip file with the wrong sha256", wantRequests: 1, wantErr: "does not match the sha256",
			mutate: func(_ *testing.T, a *images.Asset, _ *[]byte) { a.SHA256 = sum([]byte("other")) },
		},
		{
			name: "a gzip bomb is cut at the pinned size", wantRequests: 1, wantErr: "size other than the pinned",
			mutate: func(t *testing.T, a *images.Asset, z *[]byte) {
				*z = gz(t, make([]byte, 8<<20)) // 8 MiB of zeros, 8 KiB packed, against a pin of 1000 bytes
				*a = images.Asset{
					Name: a.Name, File: a.File, SHA256: sum(*z), Size: int64(len(*z)),
					RawSHA256: sum(make([]byte, 1000)), RawSize: 1000,
				}
			},
		},
		{
			name: "an unpacked file with the wrong sha256", wantRequests: 1, wantErr: "raw_sha256",
			mutate: func(_ *testing.T, a *images.Asset, _ *[]byte) { a.RawSHA256 = sum([]byte("other")) },
		},
		{
			name: "a file that is not gzip", wantRequests: 1, wantErr: "not gzip",
			mutate: func(_ *testing.T, a *images.Asset, z *[]byte) {
				*z = bytes.Repeat([]byte("x"), len(*z))
				a.SHA256, a.Size = sum(*z), int64(len(*z))
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			asset, z := testAsset(t, raw)
			if tt.mutate != nil {
				tt.mutate(t, &asset, &z)
			}
			var requests atomic.Int32
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if tt.serve != nil {
					tt.serve(w, z)
					return
				}
				_, _ = w.Write(z)
			}))
			defer srv.Close()
			timeout := tt.timeout
			if timeout == 0 {
				timeout = 10 * time.Second
			}
			d := &images.Downloader{Client: images.NewClient(srv.Client().Transport, timeout), BaseURL: srv.URL}
			if tt.base != "" {
				d.BaseURL = tt.base
			}
			dir := filepath.Join(t.TempDir(), "images")
			if tt.present != nil {
				if err := os.MkdirAll(dir, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, "core.ext4"), tt.present, 0o600); err != nil {
					t.Fatal(err)
				}
			}

			got, err := d.InstallAsset(context.Background(), dir, asset)

			if tt.wantErr == "" && err != nil {
				t.Fatalf("InstallAsset: %v", err)
			}
			if tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)) {
				t.Fatalf("InstallAsset error = %v, want it to contain %q", err, tt.wantErr)
			}
			if tt.wantErrIs != nil && !errors.Is(err, tt.wantErrIs) {
				t.Fatalf("InstallAsset error = %v, want %v", err, tt.wantErrIs)
			}
			if got != tt.wantInstalled {
				t.Errorf("installed = %v, want %v", got, tt.wantInstalled)
			}
			if n := int(requests.Load()); n != tt.wantRequests {
				t.Errorf("requests = %d, want %d", n, tt.wantRequests)
			}
			if tt.wantErr == "" {
				if err := images.VerifyAsset(dir, asset); err != nil {
					t.Errorf("the installed file does not verify: %v", err)
				}
			}
			// A failed install leaves nothing behind: no partial file under any name.
			if files := listDir(t, dir); strings.Join(files, ",") != strings.Join(tt.wantFiles, ",") {
				t.Errorf("directory = %v, want %v", files, tt.wantFiles)
			}
		})
	}
}

func TestInstallAssetAfterAFailure(t *testing.T) {
	// A file that was there before a failed install is still there, and still the old one.
	raw := bytes.Repeat([]byte("galahad image "), 100)
	asset, z := testAsset(t, raw)
	asset.RawSHA256 = sum([]byte("other"))
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(z) }))
	defer srv.Close()
	d := &images.Downloader{Client: images.NewClient(srv.Client().Transport, 10*time.Second), BaseURL: srv.URL}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "core.ext4"), []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := d.InstallAsset(context.Background(), dir, asset); err == nil {
		t.Fatal("InstallAsset succeeded with a wrong raw_sha256")
	}

	got, err := os.ReadFile(filepath.Join(dir, "core.ext4"))
	if err != nil || string(got) != "old" {
		t.Errorf("core.ext4 = %q, %v; want the old content", got, err)
	}
}

func TestVerifyAsset(t *testing.T) {
	raw := []byte("unpacked image")
	asset, _ := testAsset(t, raw)
	tests := []struct {
		name string
		// inputs
		content []byte // nil: no file
		dir     bool   // a directory at the file name
		// expectations
		wantErr   string // substring; empty means success
		wantErrIs error
	}{
		{name: "the pinned content", content: raw},
		{name: "a missing file", wantErrIs: fs.ErrNotExist},
		{name: "a directory", dir: true, wantErr: "not a regular file"},
		{name: "a different size", content: []byte("short"), wantErr: "pins.json says"},
		{name: "the same size and other content", content: bytes.Repeat([]byte("x"), len(raw)), wantErr: "raw_sha256"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			switch {
			case tt.dir:
				if err := os.Mkdir(filepath.Join(dir, asset.File), 0o700); err != nil {
					t.Fatal(err)
				}
			case tt.content != nil:
				if err := os.WriteFile(filepath.Join(dir, asset.File), tt.content, 0o600); err != nil {
					t.Fatal(err)
				}
			}

			err := images.VerifyAsset(dir, asset)

			if tt.wantErr == "" && tt.wantErrIs == nil && err != nil {
				t.Errorf("VerifyAsset: %v", err)
			}
			if tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)) {
				t.Errorf("VerifyAsset error = %v, want it to contain %q", err, tt.wantErr)
			}
			if tt.wantErrIs != nil && !errors.Is(err, tt.wantErrIs) {
				t.Errorf("VerifyAsset error = %v, want %v", err, tt.wantErrIs)
			}
		})
	}
}

const fakeFirecracker = "#!/bin/sh\necho 'Firecracker v1.17.0'\necho\necho 'Supported snapshot data format versions: 1'\n"

type member struct {
	name     string
	typeflag byte
	body     string
	size     int64 // the size of the header when body is not what it holds: a run of zeros
}

// tgz builds a Firecracker-like archive.
func tgz(t *testing.T, members ...member) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for _, m := range members {
		size := int64(len(m.body))
		if m.size > 0 {
			size = m.size
		}
		if m.typeflag == tar.TypeSymlink {
			size = 0
		}
		if err := tw.WriteHeader(&tar.Header{Name: m.name, Typeflag: m.typeflag, Mode: 0o755, Size: size, Linkname: "elsewhere"}); err != nil {
			t.Fatal(err)
		}
		if m.size > 0 {
			if _, err := tw.Write(make([]byte, m.size)); err != nil {
				t.Fatal(err)
			}
		} else if _, err := tw.Write([]byte(m.body)); err != nil && m.typeflag != tar.TypeSymlink {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestInstallFirecracker(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fake Firecracker is a shell script")
	}
	const bin = "release-v1.17.0-x86_64/firecracker-v1.17.0-x86_64"
	good := tgz(t,
		member{name: "release-v1.17.0-x86_64/", typeflag: tar.TypeDir},
		member{name: "release-v1.17.0-x86_64/jailer-v1.17.0-x86_64", typeflag: tar.TypeReg, body: "jailer"},
		member{name: bin, typeflag: tar.TypeReg, body: fakeFirecracker},
	)
	tests := []struct {
		name string
		// inputs
		archive []byte                                // nil serves the good archive
		sha     string                                // pinned sha256; "" = of the archive
		present string                                // content of bin/firecracker before the call
		serve   func(w http.ResponseWriter, a []byte) // nil serves the archive
		// expectations
		wantInstalled bool
		wantRequests  int
		wantErr       string
		wantFiles     []string
	}{
		{name: "a good archive installs an executable binary", wantInstalled: true, wantRequests: 1, wantFiles: []string{"firecracker"}},
		{name: "a binary that reports the pinned version is not downloaded again", present: fakeFirecracker, wantFiles: []string{"firecracker"}},
		{name: "a binary of another version is replaced", present: "#!/bin/sh\necho 'Firecracker v0.1.0'\n", wantInstalled: true, wantRequests: 1, wantFiles: []string{"firecracker"}},
		{
			name: "a release that is not published", wantRequests: 1, wantErr: "not published yet",
			serve: func(w http.ResponseWriter, _ []byte) { http.NotFound(w, nil) },
		},
		{
			name: "an archive larger than the cap", wantRequests: 1, wantErr: "announces",
			serve: func(w http.ResponseWriter, _ []byte) { w.Header().Set("Content-Length", strconv.Itoa(70<<20)) },
		},
		{name: "an archive with the wrong sha256", sha: sum([]byte("other")), wantRequests: 1, wantErr: "does not match the sha256"},
		{name: "an archive that is not gzip", archive: []byte("plain text, not an archive"), wantRequests: 1, wantErr: "not gzip"},
		{
			name: "an archive without the binary", wantRequests: 1, wantErr: "has no firecracker-v1.17.0-x86_64",
			archive: tgz(t, member{name: "release/jailer-v1.17.0-x86_64", typeflag: tar.TypeReg, body: "jailer"}),
		},
		{
			name: "a symlink with the name of the binary is not it", wantRequests: 1, wantErr: "has no firecracker-v1.17.0-x86_64",
			archive: tgz(t, member{name: bin, typeflag: tar.TypeSymlink}),
		},
		{
			name: "a member path with ..", wantRequests: 1, wantErr: "is not allowed",
			archive: tgz(t, member{name: "../firecracker-v1.17.0-x86_64", typeflag: tar.TypeReg, body: fakeFirecracker}),
		},
		{
			name: "a binary larger than the cap", wantRequests: 1, wantErr: "more than the",
			archive: tgz(t, member{name: bin, typeflag: tar.TypeReg, size: 70 << 20}),
		},
		{
			name: "a binary that reports another version", wantRequests: 1, wantErr: "the installed Firecracker",
			archive: tgz(t, member{name: bin, typeflag: tar.TypeReg, body: "#!/bin/sh\necho 'Firecracker v0.1.0'\n"}),
		},
		{
			name: "a binary that does not run", wantRequests: 1, wantErr: "the installed Firecracker",
			archive: tgz(t, member{name: bin, typeflag: tar.TypeReg, body: "#!/bin/sh\nexit 3\n"}),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			archive := tt.archive
			if archive == nil {
				archive = good
			}
			var requests atomic.Int32
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if tt.serve != nil {
					tt.serve(w, archive)
					return
				}
				_, _ = w.Write(archive)
			}))
			defer srv.Close()
			pin := images.Firecracker{Version: "v1.17.0", URL: srv.URL + "/fc.tgz", SHA256: tt.sha}
			if pin.SHA256 == "" {
				pin.SHA256 = sum(archive)
			}
			d := &images.Downloader{Client: images.NewClient(srv.Client().Transport, 10*time.Second)}
			dir := filepath.Join(t.TempDir(), "bin")
			if tt.present != "" {
				if err := os.MkdirAll(dir, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, "firecracker"), []byte(tt.present), 0o755); err != nil { //nolint:gosec // a test script
					t.Fatal(err)
				}
			}

			got, err := d.InstallFirecracker(context.Background(), dir, pin)

			if tt.wantErr == "" && err != nil {
				t.Fatalf("InstallFirecracker: %v", err)
			}
			if tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)) {
				t.Fatalf("InstallFirecracker error = %v, want it to contain %q", err, tt.wantErr)
			}
			if got != tt.wantInstalled {
				t.Errorf("installed = %v, want %v", got, tt.wantInstalled)
			}
			if n := int(requests.Load()); n != tt.wantRequests {
				t.Errorf("requests = %d, want %d", n, tt.wantRequests)
			}
			if tt.wantErr == "" {
				if err := images.VerifyFirecracker(context.Background(), filepath.Join(dir, "firecracker"), pin); err != nil {
					t.Errorf("the installed binary does not verify: %v", err)
				}
				st, err := os.Stat(filepath.Join(dir, "firecracker"))
				if err != nil || st.Mode().Perm() != 0o755 {
					t.Errorf("firecracker mode = %v, %v; want 0755", st, err)
				}
			}
			// Nothing but the binary stays in the directory, and an old binary is replaced only on success.
			files := listDir(t, dir)
			if tt.wantErr != "" && tt.present == "" {
				if len(files) != 0 {
					t.Errorf("directory = %v, want it empty", files)
				}
			} else if strings.Join(files, ",") != strings.Join(tt.wantFiles, ",") {
				t.Errorf("directory = %v, want %v", files, tt.wantFiles)
			}
		})
	}
}

func TestVerifyFirecracker(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fake Firecracker is a shell script")
	}
	pin := images.Firecracker{Version: "v1.17.0"}
	tests := []struct {
		name string
		// inputs
		script string // "" = no file; "dir" = a directory
		// expectations
		wantErr   string // substring; empty means success
		wantErrIs error
	}{
		{name: "the pinned version", script: fakeFirecracker},
		{name: "the version without the v", script: "#!/bin/sh\necho 'Firecracker 1.17.0'\n"},
		{name: "a missing file", wantErrIs: fs.ErrNotExist},
		{name: "a directory", script: "dir", wantErr: "not a regular file"},
		{name: "a file that cannot run", script: "not a program", wantErr: "cannot run"},
		{name: "a file that fails", script: "#!/bin/sh\nexit 1\n", wantErr: "--version failed"},
		{name: "another version", script: "#!/bin/sh\necho 'Firecracker v1.170.0'\n", wantErr: "pins.json says v1.17.0"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "firecracker")
			switch tt.script {
			case "":
			case "dir":
				if err := os.Mkdir(file, 0o700); err != nil {
					t.Fatal(err)
				}
			default:
				if err := os.WriteFile(file, []byte(tt.script), 0o755); err != nil { //nolint:gosec // a test script
					t.Fatal(err)
				}
			}

			err := images.VerifyFirecracker(context.Background(), file, pin)

			if tt.wantErr == "" && tt.wantErrIs == nil && err != nil {
				t.Errorf("VerifyFirecracker: %v", err)
			}
			if tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)) {
				t.Errorf("VerifyFirecracker error = %v, want it to contain %q", err, tt.wantErr)
			}
			if tt.wantErrIs != nil && !errors.Is(err, tt.wantErrIs) {
				t.Errorf("VerifyFirecracker error = %v, want %v", err, tt.wantErrIs)
			}
		})
	}
}
