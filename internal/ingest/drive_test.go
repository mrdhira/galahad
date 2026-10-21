package ingest_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mrdhira/galahad/internal/ingest"
)

const (
	driveID   = "1AbCdEfGhIjKlMnOp"
	driveUUID = "3f0c2b1e-5d7a-4c11-9a52-0e6f1f0b7a11"
)

// page is the text of a Drive page for a test server at the given address.
type page func(origin string) string

// fixture reads a hand-written Drive page from testdata/drive. @ORIGIN@ in it is the address of the test server.
func fixture(t *testing.T, name string) page {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "drive", name))
	if err != nil {
		t.Fatal(err)
	}
	return func(origin string) string { return strings.ReplaceAll(string(data), "@ORIGIN@", origin) }
}

// driveHandler serves one request of a Drive test, with the address of the test server.
type driveHandler func(w http.ResponseWriter, r *http.Request, origin string)

func servePage(p page) driveHandler {
	return func(w http.ResponseWriter, _ *http.Request, origin string) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, p(origin))
	}
}

func serveDriveFile(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", `attachment; filename="report.pdf"; filename*=UTF-8''report.pdf`)
	_, _ = io.WriteString(w, body)
}

// flow is Drive: the first request gets the warning page, and the request that carries the hidden
// fields of the page gets the file. Any other request is wrong.
func flow(p page) driveHandler {
	return func(w http.ResponseWriter, r *http.Request, origin string) {
		q := r.URL.Query()
		switch {
		case r.URL.Path != "/download":
			http.NotFound(w, r)
		case q.Get("id") != driveID || q.Get("export") != "download":
			http.Error(w, "bad id or export", http.StatusBadRequest)
		case q.Get("confirm") == "":
			servePage(p)(w, r, origin)
		case q.Get("confirm") != "t" || q.Get("uuid") != driveUUID || q.Get("authuser") != "0":
			http.Error(w, "the hidden fields were not sent back", http.StatusBadRequest)
		default:
			serveDriveFile(w, "%PDF-1.4 big")
		}
	}
}

func TestFetcherDrive(t *testing.T) {
	const link = "https://drive.google.com/file/d/" + driveID + "/view?usp=sharing"
	redirectTo := func(location string) driveHandler {
		return func(w http.ResponseWriter, r *http.Request, _ string) {
			http.Redirect(w, r, location, http.StatusFound)
		}
	}
	status := func(code int) driveHandler {
		return func(w http.ResponseWriter, _ *http.Request, _ string) { w.WriteHeader(code) }
	}
	warning := fixture(t, "warning.html")
	// padded is the warning page followed by an HTML comment, so that the page is size bytes long.
	padded := func(size int) page {
		return func(origin string) string {
			p := warning(origin)
			return p + "<!--" + strings.Repeat("x", size-len(p)-len("<!---->")) + "-->"
		}
	}
	manyFields := func(origin string) string {
		var b strings.Builder
		b.WriteString(`<form action="` + origin + `/download"><input type="hidden" name="confirm" value="t">`)
		for i := range 40 {
			fmt.Fprintf(&b, `<input type="hidden" name="f%d" value="v">`, i)
		}
		b.WriteString(`</form>`)
		return b.String()
	}
	repeated := func(origin string) string { // one name, many values
		return `<form action="` + origin + `/download"><input type="hidden" name="confirm" value="t">` +
			strings.Repeat(`<input type="hidden" name="x" value="v">`, 40) + `</form>`
	}
	unclosed := func(string) string {
		return `<form action="/download"><input type="hidden" name="id" value="` + driveID + `"><input type="hidden" name="export" value="download">` +
			`<input type="hidden" name="authuser" value="0"><input type="hidden" name="confirm" value="t"><input type="hidden" name="uuid" value="` + driveUUID + `">`
	}
	tests := []struct {
		name string
		// inputs
		handler driveHandler
		target  string // link when empty
		fetcher ingest.Fetcher
		// expectations
		wantName string
		wantBody string
		wantErr  string // substring; empty means success
		wantIs   error
	}{
		{
			name: "a small file comes straight", wantName: "report.pdf", wantBody: "%PDF-1.4 small",
			handler: func(w http.ResponseWriter, r *http.Request, _ string) {
				if q := r.URL.Query(); r.URL.Path != "/download" || q.Get("id") != driveID || q.Get("export") != "download" || len(q) != 2 {
					http.Error(w, "bad request", http.StatusBadRequest)
					return
				}
				serveDriveFile(w, "%PDF-1.4 small")
			},
		},
		{
			name: "a large file comes behind the warning page", handler: flow(warning),
			wantName: "report.pdf", wantBody: "%PDF-1.4 big",
		},
		{
			name: "a uc link downloads the same file", handler: flow(warning),
			target:   "https://drive.google.com/uc?export=download&id=" + driveID,
			wantName: "report.pdf", wantBody: "%PDF-1.4 big",
		},
		{
			name: "a warning page of exactly 1 MiB is read", handler: flow(padded(ingest.MaxDrivePage)),
			wantName: "report.pdf", wantBody: "%PDF-1.4 big",
		},
		{
			name: "a form that is never closed still counts", handler: flow(unclosed),
			wantName: "report.pdf", wantBody: "%PDF-1.4 big",
		},
		{
			name: "a redirect that stays on Drive is followed", wantName: "report.pdf", wantBody: "moved",
			handler: func(w http.ResponseWriter, r *http.Request, _ string) {
				if r.URL.Path == "/download" {
					http.Redirect(w, r, "/final", http.StatusSeeOther)
					return
				}
				serveDriveFile(w, "moved")
			},
		},
		{
			name: "a file without a name is named by the URL", wantName: "download", wantBody: "raw",
			handler: func(w http.ResponseWriter, _ *http.Request, _ string) { _, _ = io.WriteString(w, "raw") },
		},
		{
			name: "a file over the limit is too large", handler: flow(warning),
			fetcher: ingest.Fetcher{MaxBytes: 5},
			wantErr: "announces 12 bytes", wantIs: ingest.ErrTooLarge,
		},
		{
			name: "a target that is not a Drive file link is refused", handler: servePage(func(string) string { return "x" }),
			target:  "https://example.com/file/d/" + driveID,
			wantErr: "not a Google Drive file link",
		},
		{
			name:    "a redirect to the sign-in page means the file is private",
			handler: redirectTo("https://accounts.google.com/ServiceLogin?continue=https%3A%2F%2Fdrive.google.com"),
			wantErr: "sign-in page", wantIs: ingest.ErrDrivePrivate,
		},
		{
			name:    "a redirect to a quota page",
			handler: redirectTo("/quota-exceeded?id=" + driveID),
			wantErr: "quota page", wantIs: ingest.ErrDriveQuota,
		},
		{
			name: "the status 403 means the file is private", handler: status(http.StatusForbidden),
			wantErr: "status 403", wantIs: ingest.ErrDrivePrivate,
		},
		{
			name: "the status 429 is the quota", handler: status(http.StatusTooManyRequests),
			wantErr: "status 429", wantIs: ingest.ErrDriveQuota,
		},
		{
			name: "any other status is a plain error", handler: status(http.StatusNotFound),
			wantErr: "status 404",
		},
		{
			name: "a quota page without a form is the quota", handler: flow(fixture(t, "quota.html")),
			wantErr: "the Drive page says so", wantIs: ingest.ErrDriveQuota,
		},
		{
			name: "a page without a form is an error", handler: flow(fixture(t, "warning-no-form.html")),
			wantErr: "no download form with a confirm field",
		},
		{
			name: "a form without a confirm field is an error", handler: flow(fixture(t, "warning-no-confirm.html")),
			wantErr: "no download form with a confirm field",
		},
		{
			name: "a form that leads to another host is refused", handler: flow(fixture(t, "warning-foreign-action.html")),
			wantErr: "another host",
		},
		{
			name: "a form with too many fields is refused", handler: flow(manyFields),
			wantErr: "too many or too long fields",
		},
		{
			name: "a form that repeats one field name too often is refused", handler: flow(repeated),
			wantErr: "too many or too long fields",
		},
		{
			name: "a warning page over 1 MiB is refused", handler: flow(padded(ingest.MaxDrivePage + 1)),
			wantErr: "larger than 1048576 bytes",
		},
		{
			name: "a second warning page is refused", handler: servePage(warning),
			wantErr: "confirmation twice",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given a server that plays Drive, and an empty directory
			var srv *httptest.Server
			srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				tt.handler(w, r, srv.URL)
			}))
			defer srv.Close()
			dir := t.TempDir()
			f := tt.fetcher
			f.Dial, f.DriveBase = directTo(srv), srv.URL+"/download"
			target := tt.target
			if target == "" {
				target = link
			}

			// When the file is fetched
			got, err := f.Drive(context.Background(), target, dir)

			// Then the file, or the error, is as expected
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("Drive error = %v, want one containing %q", err, tt.wantErr)
				}
				if tt.wantIs != nil && !errors.Is(err, tt.wantIs) {
					t.Errorf("Drive error = %v, want it to wrap %v", err, tt.wantIs)
				}
				for _, sentinel := range []error{ingest.ErrDrivePrivate, ingest.ErrDriveQuota, ingest.ErrNotAllowed} {
					if sentinel != tt.wantIs && errors.Is(err, sentinel) {
						t.Errorf("Drive error = %v, must not wrap %v", err, sentinel)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("Drive: %v", err)
			}
			if got.Name != tt.wantName || got.SHA256 != sum(tt.wantBody) || got.Size != int64(len(tt.wantBody)) {
				t.Errorf("file = %+v, want name %q, %d bytes, sha256 %s", got, tt.wantName, len(tt.wantBody), sum(tt.wantBody))
			}
			if data, err := os.ReadFile(filepath.Join(dir, got.Name)); err != nil || string(data) != tt.wantBody {
				t.Errorf("saved file = %q, %v, want %q", data, err, tt.wantBody)
			}
		})
	}
}
