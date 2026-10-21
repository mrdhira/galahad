package ingest

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/mrdhira/galahad/internal/protocol"
)

// Limits of a download.
const (
	MaxDownload     = 1 << 30         // bytes
	DownloadTimeout = 2 * time.Minute // all requests of one download
	MaxRedirects    = 5

	maxHeaderBytes   = 64 << 10
	tunnelHandshake  = 35 * time.Second // the relay answers within 30 s
	maxTunnelReply   = 512              // bytes of a refusal that are read
	maxNameBytes     = 128
	maxExtensionSize = 16
	fallbackName     = "download"
	userAgent        = "galahad"
)

// Errors a download returns, wrapped with detail. Test for them with errors.Is.
var (
	// ErrNotAllowed means the host proxy refused a connection: the host is not on the
	// allowlist, or the address is not public.
	ErrNotAllowed = errors.New("the proxy refused the connection")
	// ErrDrivePrivate means Drive asked for a sign-in, so the file is not public.
	ErrDrivePrivate = errors.New("the Drive file is not public")
	// ErrDriveQuota means Drive refuses the download because of its quota.
	ErrDriveQuota = errors.New("the Drive download quota is exceeded")
)

// Fetcher downloads one file into a directory. The zero value dials directly and uses the
// limits above; the agent sets Dial so that every connection goes through the relay.
type Fetcher struct {
	// Dial opens each connection of a download. Nil dials directly.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// MaxBytes caps the body, and Timeout all requests. Zero means MaxDownload and DownloadTimeout.
	MaxBytes int64
	Timeout  time.Duration
	// DriveBase is the download address of Drive. Empty means the real one.
	DriveBase string
}

// File is what a download leaves in the directory. SHA256 is the hash of the bytes written.
type File struct {
	Name   string
	Size   int64
	SHA256 string
}

// URL downloads rawURL, an http or https address, into dir under a cleaned name. It follows
// at most 5 redirects and reads at most 1 GiB in 2 minutes.
func (f Fetcher) URL(ctx context.Context, rawURL, dir string) (File, error) {
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return File{}, errors.New("the target is not an http or https URL")
	}
	ctx, cancel := context.WithTimeout(ctx, f.timeout())
	defer cancel()
	resp, err := f.get(ctx, f.client(nil), u.String())
	if err != nil {
		return File{}, err
	}
	return f.save(resp, dir)
}

// client returns an HTTP client that reaches the network only through f.Dial and never uses the
// proxy variables of the environment. check, when set, sees every redirect before it is followed.
func (f Fetcher) client(check func(next *url.URL) error) *http.Client {
	tr := &http.Transport{
		DialContext:            f.Dial,
		DisableCompression:     true, // the file is saved as the server sent it
		DisableKeepAlives:      true, // one tunnel per request
		TLSHandshakeTimeout:    15 * time.Second,
		ResponseHeaderTimeout:  30 * time.Second,
		MaxResponseHeaderBytes: maxHeaderBytes,
	}
	return &http.Client{
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > MaxRedirects {
				return fmt.Errorf("more than %d redirects", MaxRedirects)
			}
			if check != nil {
				return check(req.URL)
			}
			return nil
		},
	}
}

func (f Fetcher) timeout() time.Duration {
	if f.Timeout > 0 {
		return f.Timeout
	}
	return DownloadTimeout
}

func (f Fetcher) maxBytes() int64 {
	if f.MaxBytes > 0 {
		return f.MaxBytes
	}
	return MaxDownload
}

// get sends one GET request. The caller closes the body of the response.
func (f Fetcher) get(ctx context.Context, c *http.Client, rawURL string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := c.Do(req) // #nosec G107 G704 -- the connection goes through the relay, whose host proxy applies the allowlist
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// save writes the body of a 200 response into dir, hashing it, and closes the body. The name comes
// from Content-Disposition or from the URL of the last request.
func (f Fetcher) save(resp *http.Response, dir string) (File, error) {
	defer func() { _ = resp.Body.Close() }() // the body is read below; a close error changes nothing
	if resp.StatusCode != http.StatusOK {
		return File{}, fmt.Errorf("the server answered with status %d", resp.StatusCode)
	}
	limit := f.maxBytes()
	if resp.ContentLength > limit {
		return File{}, fmt.Errorf("%w: the server announces %d bytes, the limit is %d", ErrTooLarge, resp.ContentLength, limit)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return File{}, err
	}
	defer func() { _ = root.Close() }() // the file is closed and checked below
	name := FileName(resp.Header.Get("Content-Disposition"), resp.Request.URL)
	out, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return File{}, fmt.Errorf("create the file: %w", err)
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(out, h), io.LimitReader(resp.Body, limit+1))
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	switch {
	case err != nil:
		return File{}, fmt.Errorf("download: %w", err)
	case n > limit:
		return File{}, fmt.Errorf("%w: the download is larger than %d bytes", ErrTooLarge, limit)
	}
	return File{Name: name, Size: n, SHA256: hex.EncodeToString(h.Sum(nil))}, nil
}

// FileName chooses the name of a download: the filename of the Content-Disposition header when it
// has one, else the last element of the URL path. The result is a single clean path element.
func FileName(contentDisposition string, u *url.URL) string {
	// A malformed parameter still leaves the ones before it, so the error is not checked.
	if _, params, _ := mime.ParseMediaType(contentDisposition); params["filename"] != "" {
		return CleanName(params["filename"])
	}
	return CleanName(u.Path) // already unescaped; CleanName keeps the part after the last separator
}

// CleanName makes a name from the network safe to use as a file name and to print. It keeps the
// part after the last "/" or "\", writes control and bidirectional characters and invalid UTF-8
// as visible \u and \x text, trims dots and spaces from both ends, and cuts the name to
// 128 bytes, keeping a short extension. An empty result becomes "download".
func CleanName(raw string) string {
	if i := strings.LastIndexAny(raw, `/\`); i >= 0 {
		raw = raw[i+1:]
	}
	name := strings.Trim(protocol.CleanPath(raw), ". ")
	if len(name) > maxNameBytes {
		ext := path.Ext(name)
		if len(ext) > maxExtensionSize {
			ext = ""
		}
		stem := name[:maxNameBytes-len(ext)]
		for !utf8.ValidString(stem) {
			stem = stem[:len(stem)-1]
		}
		name = stem + ext
	}
	if name == "" {
		return fallbackName
	}
	return name
}

// TunnelDialer returns a dial function that opens each connection with CONNECT through the relay
// at proxyAddr. A refusal of the relay is ErrNotAllowed with the reason of the host proxy.
func TunnelDialer(proxyAddr string) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, _, addr string) (net.Conn, error) {
		var d net.Dialer
		conn, err := d.DialContext(ctx, "tcp", proxyAddr)
		if err != nil {
			return nil, err
		}
		stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
		defer stop()
		_ = conn.SetDeadline(time.Now().Add(tunnelHandshake))
		if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", addr, addr); err != nil {
			_ = conn.Close()
			return nil, err
		}
		br := bufio.NewReader(conn)
		resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
		if err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("the relay did not answer: %w", err)
		}
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, maxTunnelReply))
			_ = conn.Close()
			if resp.StatusCode == http.StatusForbidden {
				return nil, fmt.Errorf("%w: %s %s", ErrNotAllowed, addr, strings.TrimSpace(string(body)))
			}
			return nil, fmt.Errorf("the relay answered with status %d for %s", resp.StatusCode, addr)
		}
		_ = conn.SetDeadline(time.Time{})
		return &tunnelConn{Conn: conn, r: br}, nil
	}
}

// tunnelConn reads through the buffer that read the answer of the relay, which may hold the first
// bytes of the server.
type tunnelConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *tunnelConn) Read(p []byte) (int, error) { return c.r.Read(p) }
