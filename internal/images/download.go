package images

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// Limits of the downloads. The size of an image comes from its pin; these cover the rest.
const (
	// DownloadTimeout is the time one download may take, redirects and body included.
	DownloadTimeout = 30 * time.Minute

	maxRedirects = 5

	// The Firecracker archive is about 3 MiB. It has no pinned size, so these only stop a runaway
	// download, a decompression bomb and an archive with a huge number of members.
	maxArchiveBytes   = 64 << 20
	maxArchiveRawSize = 256 << 20
	maxArchiveEntries = 1000
	maxBinaryBytes    = 64 << 20

	versionTimeout = 10 * time.Second
	maxVersionText = 4 << 10
)

// firecrackerArch is the architecture of the pinned Firecracker release; setup runs on linux/amd64 only.
const firecrackerArch = "x86_64"

// ErrNotPublished means the download location answered 404: the release does not exist yet.
var ErrNotPublished = errors.New("not published yet")

// baseURLOverride replaces the release URL. Only galahadtest builds set it.
var baseURLOverride string

// Downloader fetches the pinned assets over https.
type Downloader struct {
	Client  *http.Client // see NewClient
	BaseURL string       // an asset is BaseURL + "/" + its name
}

// NewDownloader returns the downloader for the release of pins: the assets of the images-* tag on GitHub.
func NewDownloader(p Pins) *Downloader {
	base := "https://github.com/mrdhira/galahad/releases/download/" + p.Tag
	if baseURLOverride != "" {
		base = baseURLOverride
	}
	return &Downloader{Client: NewClient(nil, DownloadTimeout), BaseURL: base}
}

// NewClient returns an HTTP client that gives up after timeout, follows at most 5 redirects, and
// follows them only to https URLs. A nil rt means http.DefaultTransport.
func NewClient(rt http.RoundTripper, timeout time.Duration) *http.Client {
	return &http.Client{
		Transport: rt,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > maxRedirects {
				return fmt.Errorf("stopped after %d redirects", maxRedirects)
			}
			if req.URL.Scheme != "https" {
				return fmt.Errorf("redirect to a %q URL, which is not https", req.URL.Scheme)
			}
			return nil
		},
	}
}

// VerifyAsset checks the unpacked file of a in dir against its pinned size and raw_sha256.
func VerifyAsset(dir string, a Asset) error {
	f, err := os.Open(filepath.Join(dir, a.File)) // #nosec G304 -- a pinned file name inside the state directory
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }() // read-only file
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() {
		return errors.New("not a regular file")
	}
	if st.Size() != a.RawSize {
		return fmt.Errorf("is %d bytes, pins.json says %d", st.Size(), a.RawSize)
	}
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(f, a.RawSize+1)); err != nil {
		return err
	}
	if hex.EncodeToString(h.Sum(nil)) != a.RawSHA256 {
		return errors.New("does not match the raw_sha256 in pins.json")
	}
	return nil
}

// InstallAsset makes sure dir holds the verified, unpacked file of a. It reports whether it
// installed anything: a file that already verifies is left alone. The file appears under its
// final name only after the gzip size and sha256 and the unpacked size and sha256 all matched.
func (d *Downloader) InstallAsset(ctx context.Context, dir string, a Asset) (installed bool, err error) {
	if VerifyAsset(dir, a) == nil {
		return false, nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return false, err
	}
	gz, err := os.CreateTemp(dir, "."+a.Name+".*.part")
	if err != nil {
		return false, err
	}
	defer removeFile(gz)
	if err := d.fetch(ctx, d.BaseURL+"/"+a.Name, gz, a.Size, a.SHA256, true); err != nil {
		return false, fmt.Errorf("%s: %w", a.Name, err)
	}

	raw, err := os.CreateTemp(dir, "."+a.File+".*.part")
	if err != nil {
		return false, err
	}
	defer removeFile(raw)
	if err := gunzip(gz, raw, a.RawSize, a.RawSHA256); err != nil {
		return false, fmt.Errorf("%s: %w", a.Name, err)
	}
	if err := raw.Sync(); err != nil {
		return false, err
	}
	if err := raw.Close(); err != nil {
		return false, err
	}
	if err := os.Rename(raw.Name(), filepath.Join(dir, a.File)); err != nil {
		return false, err
	}
	return true, nil
}

// fetch downloads rawURL into f and checks its sha256. At most size bytes are read; when exact is
// true the download must be exactly size bytes.
func (d *Downloader) fetch(ctx context.Context, rawURL string, f *os.File, size int64, sum string, exact bool) error {
	if u, err := url.Parse(rawURL); err != nil || u.Scheme != "https" {
		return fmt.Errorf("the download URL %q is not https", rawURL)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, http.NoBody)
	if err != nil {
		return err
	}
	resp, err := d.Client.Do(req) // #nosec G704 -- the URL is pinned or built from the pins
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }() // the body is read below
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return fmt.Errorf("%w: HTTP 404 for %s", ErrNotPublished, rawURL)
	case resp.StatusCode != http.StatusOK:
		return fmt.Errorf("HTTP %d for %s", resp.StatusCode, rawURL)
	case resp.ContentLength > size:
		return fmt.Errorf("the server announces %d bytes, more than the %d allowed", resp.ContentLength, size)
	}

	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, size+1))
	switch {
	case err != nil:
		return fmt.Errorf("download stopped after %d bytes: %w", n, err)
	case n > size:
		return fmt.Errorf("more than the %d bytes allowed", size)
	case exact && n != size:
		return fmt.Errorf("got %d bytes, pins.json says %d", n, size)
	}
	if hex.EncodeToString(h.Sum(nil)) != sum {
		return errors.New("does not match the sha256 in pins.json")
	}
	return nil
}

// gunzip unpacks src into dst, reading at most size bytes, and checks the unpacked size and sha256.
func gunzip(src, dst *os.File, size int64, sum string) error {
	if _, err := src.Seek(0, io.SeekStart); err != nil {
		return err
	}
	zr, err := gzip.NewReader(src)
	if err != nil {
		return fmt.Errorf("not gzip: %w", err)
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(dst, h), io.LimitReader(zr, size+1))
	switch {
	case err != nil:
		return fmt.Errorf("cannot unpack: %w", err)
	case n != size:
		return fmt.Errorf("unpacks to a size other than the pinned %d bytes", size)
	}
	if hex.EncodeToString(h.Sum(nil)) != sum {
		return errors.New("unpacks to data that does not match the raw_sha256 in pins.json")
	}
	return nil
}

// removeFile closes and deletes a temporary file. After a rename there is nothing left to delete.
func removeFile(f *os.File) {
	_ = f.Close()           // already closed after a successful install
	_ = os.Remove(f.Name()) // best effort
}

// VerifyFirecracker runs file with --version and checks that it is the pinned release.
func VerifyFirecracker(ctx context.Context, file string, f Firecracker) error {
	st, err := os.Stat(file)
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() {
		return errors.New("not a regular file")
	}
	ctx, cancel := context.WithTimeout(ctx, versionTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, file, "--version") // #nosec G204 -- the binary the pins install
	out, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("cannot run: %w", err)
	}
	text, _ := io.ReadAll(io.LimitReader(out, maxVersionText)) // a failed read shows up as a version mismatch
	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("--version failed: %w", err)
	}
	first, _, _ := strings.Cut(string(text), "\n")
	for _, w := range strings.Fields(first) {
		if w == f.Version || w == strings.TrimPrefix(f.Version, "v") {
			return nil
		}
	}
	return fmt.Errorf("reports %q, pins.json says %s", strings.TrimSpace(first), f.Version)
}

// InstallFirecracker makes sure binDir/firecracker is the pinned release. It downloads the archive,
// checks its sha256, extracts only firecracker-<version>-x86_64, and renames it into place after
// that binary reports the pinned version. An installed binary that does so is left alone.
func (d *Downloader) InstallFirecracker(ctx context.Context, binDir string, f Firecracker) (installed bool, err error) {
	final := filepath.Join(binDir, "firecracker")
	if VerifyFirecracker(ctx, final, f) == nil {
		return false, nil
	}
	if err := os.MkdirAll(binDir, 0o700); err != nil {
		return false, err
	}
	archive, err := os.CreateTemp(binDir, ".firecracker.*.tgz.part")
	if err != nil {
		return false, err
	}
	defer removeFile(archive)
	if err := d.fetch(ctx, f.URL, archive, maxArchiveBytes, f.SHA256, false); err != nil {
		return false, fmt.Errorf("firecracker archive: %w", err)
	}

	bin, err := os.CreateTemp(binDir, ".firecracker.*.part")
	if err != nil {
		return false, err
	}
	defer removeFile(bin)
	if err := extractFirecracker(archive, bin, "firecracker-"+f.Version+"-"+firecrackerArch); err != nil {
		return false, fmt.Errorf("firecracker archive: %w", err)
	}
	if err := bin.Chmod(0o755); err != nil { // #nosec G302 -- the binary must be executable
		return false, err
	}
	if err := bin.Sync(); err != nil {
		return false, err
	}
	if err := bin.Close(); err != nil { // a file that is open for writing cannot be executed
		return false, err
	}
	if err := VerifyFirecracker(ctx, bin.Name(), f); err != nil {
		return false, fmt.Errorf("the installed Firecracker: %w", err)
	}
	if err := os.Rename(bin.Name(), final); err != nil {
		return false, err
	}
	return true, nil
}

// extractFirecracker copies the regular file called name out of the tgz in src into dst.
func extractFirecracker(src, dst *os.File, name string) error {
	if _, err := src.Seek(0, io.SeekStart); err != nil {
		return err
	}
	zr, err := gzip.NewReader(src)
	if err != nil {
		return fmt.Errorf("not gzip: %w", err)
	}
	tr := tar.NewReader(io.LimitReader(zr, maxArchiveRawSize))
	for range maxArchiveEntries {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return fmt.Errorf("has no %s", name)
		}
		if err != nil {
			return err
		}
		if hdr.Typeflag != tar.TypeReg || path.Base(hdr.Name) != name {
			continue
		}
		// The member is copied to a file of ours; its name is never used as a path.
		if path.IsAbs(hdr.Name) || slices.Contains(strings.Split(hdr.Name, "/"), "..") {
			return fmt.Errorf("the path %q is not allowed", hdr.Name)
		}
		if hdr.Size > maxBinaryBytes {
			return fmt.Errorf("%s is %d bytes, more than the %d allowed", name, hdr.Size, maxBinaryBytes)
		}
		if _, err := io.Copy(dst, io.LimitReader(tr, hdr.Size)); err != nil {
			return err
		}
		return nil
	}
	return fmt.Errorf("has more than %d members", maxArchiveEntries)
}
