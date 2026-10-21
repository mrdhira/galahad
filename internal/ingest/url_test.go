package ingest_test

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/mrdhira/galahad/internal/ingest"
)

// directTo dials the test server whatever address is asked for, so a test can use any host name.
func directTo(srv *httptest.Server) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", srv.Listener.Addr().String())
	}
}

func sum(body string) string {
	s := sha256.Sum256([]byte(body))
	return hex.EncodeToString(s[:])
}

// chain redirects /r0 to /r1 and so on up to /r<n>, which serves the file.
func chain(n int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var i int
		if _, err := fmt.Sscanf(r.URL.Path, "/r%d", &i); err != nil {
			http.NotFound(w, r)
			return
		}
		if i < n {
			http.Redirect(w, r, fmt.Sprintf("/r%d", i+1), http.StatusFound)
			return
		}
		_, _ = io.WriteString(w, "payload")
	}
}

func TestFetcherURL(t *testing.T) {
	disposition := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Disposition", `attachment; filename="invoice.pdf"`)
		_, _ = io.WriteString(w, "%PDF-1.4 body")
	}
	plain := func(body string) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, body) }
	}
	tests := []struct {
		name string
		// inputs
		handler http.HandlerFunc
		target  string // http://files.test/a.bin when empty
		fetcher ingest.Fetcher
		// expectations
		wantName string
		wantRaw  string // the name before cleaning; not checked when empty
		wantBody string
		wantErr  string // substring; empty means success
		wantIs   error
	}{
		{
			name: "the name comes from Content-Disposition", handler: disposition,
			wantName: "invoice.pdf", wantBody: "%PDF-1.4 body",
		},
		{
			name: "the name comes from the URL path without Content-Disposition", handler: plain("abc"),
			target:   "http://files.test/dir/report%20v2.pdf?token=1#frag",
			wantName: "report v2.pdf", wantBody: "abc",
		},
		{
			name: "a hostile name in the header is cleaned", handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Disposition", `attachment; filename="../../etc/cron.d/evil"`)
				_, _ = io.WriteString(w, "x")
			},
			wantName: "evil", wantBody: "x",
		},
		{
			name: "the raw name keeps the bidi control the file name loses", handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Disposition", `attachment; filename*=UTF-8''dir%2Finvoice%E2%80%AEfdp.exe`)
				_, _ = io.WriteString(w, "x")
			},
			wantName: "invoice_u202efdp.exe", wantRaw: "invoice\u202efdp.exe", wantBody: "x",
		},
		{
			name: "five redirects are followed", handler: chain(5),
			target:   "http://files.test/r0",
			wantName: "r5", wantBody: "payload",
		},
		{
			name: "a sixth redirect is refused", handler: chain(6),
			target:  "http://files.test/r0",
			wantErr: "more than 5 redirects",
		},
		{
			name: "a body of exactly the limit is kept", handler: plain("0123456789"),
			fetcher:  ingest.Fetcher{MaxBytes: 10},
			wantName: "a.bin", wantBody: "0123456789",
		},
		{
			name: "a body over the limit is too large", handler: func(w http.ResponseWriter, _ *http.Request) {
				w.(http.Flusher).Flush() // no Content-Length: the size is found while reading
				_, _ = io.WriteString(w, "0123456789A")
			},
			fetcher: ingest.Fetcher{MaxBytes: 10},
			wantErr: "larger than 10 bytes", wantIs: ingest.ErrTooLarge,
		},
		{
			name: "an announced size over the limit is too large before any byte is read", handler: plain("0123456789A"),
			fetcher: ingest.Fetcher{MaxBytes: 10},
			wantErr: "announces 11 bytes", wantIs: ingest.ErrTooLarge,
		},
		{
			name: "a server that stalls runs into the time limit", handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Length", "100")
				_, _ = io.WriteString(w, "partial")
				w.(http.Flusher).Flush()
				<-r.Context().Done()
			},
			fetcher: ingest.Fetcher{Timeout: 200 * time.Millisecond},
			wantErr: "deadline exceeded", wantIs: context.DeadlineExceeded,
		},
		{
			name: "a status other than 200 is an error", handler: http.NotFound,
			wantErr: "status 404",
		},
		{
			name: "a scheme other than http and https is refused", handler: plain("x"),
			target:  "ftp://files.test/a.bin",
			wantErr: "not an http or https URL",
		},
		{
			name: "a redirect to another scheme is refused", handler: func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, "file:///etc/passwd", http.StatusFound)
			},
			wantErr: "unsupported protocol scheme",
		},
		{
			name: "a URL without a host is refused", handler: plain("x"),
			target:  "http:///a.bin",
			wantErr: "not an http or https URL",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given a server and an empty directory
			srv := httptest.NewServer(tt.handler)
			defer srv.Close()
			dir := t.TempDir()
			f := tt.fetcher
			f.Dial = directTo(srv)
			target := tt.target
			if target == "" {
				target = "http://files.test/a.bin"
			}

			// When the URL is fetched
			got, err := f.URL(context.Background(), target, dir)

			// Then the file, or the error, is as expected
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("URL error = %v, want one containing %q", err, tt.wantErr)
				}
				if tt.wantIs != nil && !errors.Is(err, tt.wantIs) {
					t.Errorf("URL error = %v, want it to wrap %v", err, tt.wantIs)
				}
				return
			}
			if err != nil {
				t.Fatalf("URL: %v", err)
			}
			if got.Name != tt.wantName || got.Size != int64(len(tt.wantBody)) || got.SHA256 != sum(tt.wantBody) {
				t.Errorf("file = %+v, want name %q, %d bytes, sha256 %s", got, tt.wantName, len(tt.wantBody), sum(tt.wantBody))
			}
			if tt.wantRaw != "" && got.RawName != tt.wantRaw {
				t.Errorf("raw name = %q, want %q", got.RawName, tt.wantRaw)
			}
			data, err := os.ReadFile(filepath.Join(dir, got.Name))
			if err != nil || string(data) != tt.wantBody {
				t.Errorf("saved file = %q, %v, want %q", data, err, tt.wantBody)
			}
		})
	}
}

func TestFileName(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		disposition string
		target      string // http://files.test/ when empty
		// expectations
		want string
	}{
		{name: "a plain filename", disposition: `attachment; filename="invoice.pdf"`, want: "invoice.pdf"},
		{name: "an extended filename is decoded", disposition: `attachment; filename*=UTF-8''na%C3%AFve.pdf`, want: "naïve.pdf"},
		{name: "the path of the header is dropped", disposition: `attachment; filename="../../etc/passwd"`, want: "passwd"},
		{name: "a Windows path is dropped", disposition: `attachment; filename="C:\\Windows\\System32\\cmd.exe"`, want: "cmd.exe"},
		{name: "a right-to-left override is written out", disposition: `attachment; filename*=UTF-8''invoice%E2%80%AEgpj.exe`, want: `invoice_u202egpj.exe`},
		{name: "a NUL is written out", disposition: `attachment; filename*=UTF-8''a%00b.txt`, want: `a_u0000b.txt`},
		{name: "invalid UTF-8 is written out", disposition: `attachment; filename*=UTF-8''%ff.txt`, want: `_xff.txt`},
		{name: "dots and spaces are trimmed", disposition: `attachment; filename="  .hidden. "`, want: "hidden"},
		{name: "only dots falls back", disposition: `attachment; filename="..."`, target: "http://files.test/", want: "download"},
		{name: "a long name keeps its extension", disposition: `attachment; filename="` + strings.Repeat("a", 300) + `.pdf"`, want: strings.Repeat("a", 124) + ".pdf"},
		{name: "a long name is cut at a character boundary", disposition: `attachment; filename*=UTF-8''` + strings.Repeat("%C3%A9", 100) + `.txt`, want: strings.Repeat("é", 62) + ".txt"},
		{name: "a header without a filename uses the URL", disposition: "inline", target: "http://files.test/a/b.zip", want: "b.zip"},
		{name: "a broken header uses the URL", disposition: `attachment; filename`, target: "http://files.test/c.zip", want: "c.zip"},
		{name: "the URL path is unescaped", target: "http://files.test/x/my%20file.txt", want: "my file.txt"},
		{name: "an encoded slash in the URL is a separator", target: "http://files.test/x/..%2f..%2fpasswd", want: "passwd"},
		{name: "an encoded backslash in the URL is a separator", target: "http://files.test/x/..%5c..%5cevil.exe", want: "evil.exe"},
		{name: "the query is not part of the name", target: "http://files.test/a.pdf?name=other.exe", want: "a.pdf"},
		{name: "a path that ends in a slash falls back", target: "http://files.test/dir/", want: "download"},
		{name: "no path falls back", target: "http://files.test", want: "download"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target := tt.target
			if target == "" {
				target = "http://files.test/"
			}
			u, err := url.Parse(target)
			if err != nil {
				t.Fatal(err)
			}

			got := ingest.FileName(tt.disposition, u)

			if got != tt.want {
				t.Errorf("FileName = %q, want %q", got, tt.want)
			}
			if len(got) > 128 || !utf8.ValidString(got) || strings.Contains(got, "/") {
				t.Errorf("FileName = %q: want valid UTF-8 of at most 128 bytes without a slash", got)
			}
		})
	}
}

// fakeRelay answers CONNECT like the relay of the agent: 200 and a tunnel to the backend for the hosts in
// allowed, and the given status and body for any other.
func fakeRelay(t *testing.T, backend *httptest.Server, allowed map[string]bool, status int, body string) (addr string, requests func() []string) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var seen []string
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = c.Close() }()
				br := bufio.NewReader(c)
				req, err := http.ReadRequest(br)
				if err != nil || req.Method != http.MethodConnect {
					return
				}
				mu.Lock()
				seen = append(seen, req.Host)
				mu.Unlock()
				host, _, _ := net.SplitHostPort(req.Host)
				if !allowed[host] {
					if status == 0 {
						return // closes without an answer
					}
					_, _ = fmt.Fprintf(c, "HTTP/1.1 %d X\r\nContent-Length: %d\r\n\r\n%s", status, len(body), body)
					return
				}
				up, err := net.Dial("tcp", backend.Listener.Addr().String())
				if err != nil {
					return
				}
				defer func() { _ = up.Close() }()
				_, _ = io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n")
				done := make(chan struct{})
				go func() { _, _ = io.Copy(up, br); close(done) }()
				_, _ = io.Copy(c, up)
				<-done
			}()
		}
	}()
	t.Cleanup(func() { _ = l.Close() })
	return l.Addr().String(), func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), seen...)
	}
}

func TestTunnelDialer(t *testing.T) {
	redirect := func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			http.Redirect(w, r, "http://evil.test/next", http.StatusFound)
			return
		}
		_, _ = io.WriteString(w, "through the tunnel")
	}
	tests := []struct {
		name string
		// inputs
		target       string
		allowed      map[string]bool
		refuseStatus int // answer for a host that is not allowed; 0 closes the connection
		refuseBody   string
		// expectations
		wantBody     string
		wantErr      string // substring; empty means success
		wantNotAllow bool   // the error wraps ErrNotAllowed
		wantRequests []string
	}{
		{
			name: "an allowed host is reached through CONNECT", target: "http://files.test/a.bin",
			allowed: map[string]bool{"files.test": true}, wantBody: "through the tunnel", wantRequests: []string{"files.test:80"},
		},
		{
			name: "a redirect to a host that is not allowed is refused with the reason", target: "http://files.test/start",
			allowed: map[string]bool{"files.test": true}, refuseStatus: 403, refuseBody: "denied: host not allowed\n",
			wantErr: "evil.test:80 denied: host not allowed", wantNotAllow: true, wantRequests: []string{"files.test:80", "evil.test:80"},
		},
		{
			name: "a refusal for an address that is not public is refused with the reason", target: "http://meta.test/a.bin",
			refuseStatus: 403, refuseBody: "denied: metadata\n",
			wantErr: "meta.test:80 denied: metadata", wantNotAllow: true, wantRequests: []string{"meta.test:80"},
		},
		{
			name: "a relay that cannot reach the host proxy is not a refusal", target: "http://files.test/a.bin",
			refuseStatus: 502, refuseBody: "the host proxy is not reachable\n",
			wantErr: "status 502",
		},
		{
			name: "a relay that closes without an answer is an error", target: "http://files.test/a.bin",
			wantErr: "did not answer",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given a relay in front of a server
			srv := httptest.NewServer(http.HandlerFunc(redirect))
			defer srv.Close()
			relay, requests := fakeRelay(t, srv, tt.allowed, tt.refuseStatus, tt.refuseBody)
			f := ingest.Fetcher{Dial: ingest.TunnelDialer(relay)}

			// When the URL is fetched through it
			got, err := f.URL(context.Background(), tt.target, t.TempDir())

			// Then the file or the refusal is as expected
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("URL error = %v, want one containing %q", err, tt.wantErr)
				}
				if errors.Is(err, ingest.ErrNotAllowed) != tt.wantNotAllow {
					t.Errorf("URL error = %v, wraps ErrNotAllowed: %v, want %v", err, errors.Is(err, ingest.ErrNotAllowed), tt.wantNotAllow)
				}
			} else if err != nil || got.SHA256 != sum(tt.wantBody) {
				t.Fatalf("URL = %+v, %v, want sha256 %s", got, err, sum(tt.wantBody))
			}
			if tt.wantRequests != nil && fmt.Sprint(requests()) != fmt.Sprint(tt.wantRequests) {
				t.Errorf("CONNECT requests = %v, want %v", requests(), tt.wantRequests)
			}
		})
	}
}
