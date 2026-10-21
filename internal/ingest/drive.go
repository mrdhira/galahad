package ingest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/net/html"

	"github.com/mrdhira/galahad/internal/protocol"
)

// Limits and fixed addresses of a Drive download.
const (
	// MaxDrivePage is the most bytes read of the large-file warning page.
	MaxDrivePage = 1 << 20

	driveBase     = "https://drive.usercontent.google.com/download"
	accountsHost  = "accounts.google.com"
	maxFormFields = 32
	maxFieldBytes = 2048
)

// Drive downloads the public Drive file of a share link into dir under a cleaned name. It asks
// drive.usercontent.google.com for the file by its ID. For a file too large to be scanned for
// viruses, Drive answers with a warning page instead; the page is parsed and its hidden form
// fields are sent back once. A redirect to the sign-in page ends in ErrDrivePrivate, and a quota page in
// ErrDriveQuota. The limits are those of URL.
func (f Fetcher) Drive(ctx context.Context, rawURL, dir string) (File, error) {
	id, ok := protocol.DriveFileID(rawURL)
	if !ok {
		return File{}, errors.New("the target is not a Google Drive file link")
	}
	ctx, cancel := context.WithTimeout(ctx, f.timeout())
	defer cancel()
	base := f.DriveBase
	if base == "" {
		base = driveBase
	}
	client := f.client(driveRedirect)
	resp, err := f.driveGet(ctx, client, base+"?"+url.Values{"id": {id}, "export": {"download"}}.Encode())
	if err != nil {
		return File{}, err
	}
	if isWarningPage(resp) {
		next, err := confirmURL(resp)
		if err != nil {
			return File{}, err
		}
		if resp, err = f.driveGet(ctx, client, next); err != nil {
			return File{}, err
		}
		if isWarningPage(resp) {
			_ = resp.Body.Close() // not read; the answer is an error
			return File{}, errors.New("the Drive page asks for the confirmation twice")
		}
	}
	return f.save(resp, dir)
}

// driveRedirect refuses a redirect to the sign-in page, which means the file is private, and one
// to a quota page.
func driveRedirect(next *url.URL) error {
	switch {
	case strings.EqualFold(next.Hostname(), accountsHost):
		return fmt.Errorf("%w: Drive redirects to the sign-in page", ErrDrivePrivate)
	case strings.Contains(strings.ToLower(next.Path), "quota"):
		return fmt.Errorf("%w: Drive redirects to a quota page", ErrDriveQuota)
	}
	return nil
}

// driveGet is get with the statuses Drive uses for a private file and for the quota.
func (f Fetcher) driveGet(ctx context.Context, c *http.Client, rawURL string) (*http.Response, error) {
	resp, err := f.get(ctx, c, rawURL)
	if err != nil {
		return nil, err
	}
	var why error
	switch resp.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden:
		why = ErrDrivePrivate
	case http.StatusTooManyRequests:
		why = ErrDriveQuota
	default:
		return resp, nil
	}
	_ = resp.Body.Close() // not read; the answer is an error
	return nil, fmt.Errorf("%w: Drive answered with status %d", why, resp.StatusCode)
}

// isWarningPage reports whether resp is an HTML page and not a file. A file comes with a
// Content-Disposition header, even an HTML one.
func isWarningPage(resp *http.Response) bool {
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Disposition") != "" {
		return false
	}
	mediaType, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	return mediaType == "text/html"
}

// confirmURL reads the warning page and closes the body. It returns the address that the form of
// the page leads to, with the hidden fields as its query.
func confirmURL(resp *http.Response) (string, error) {
	defer func() { _ = resp.Body.Close() }() // the page is read below; a close error changes nothing
	page, err := io.ReadAll(io.LimitReader(resp.Body, MaxDrivePage+1))
	if err != nil {
		return "", fmt.Errorf("read the Drive page: %w", err)
	}
	if len(page) > MaxDrivePage {
		return "", fmt.Errorf("the Drive page is larger than %d bytes", MaxDrivePage)
	}
	action, fields, err := warningForm(page)
	if err != nil {
		return "", err
	}
	u, err := resp.Request.URL.Parse(action)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host != resp.Request.URL.Host {
		return "", errors.New("the Drive form leads to another host")
	}
	u.RawQuery, u.Fragment = fields.Encode(), ""
	return u.String(), nil
}

// warningForm finds the form of the Drive warning page that has a hidden "confirm" field, and
// returns its action and its hidden fields (confirm, uuid, id and the others). A page without
// such a form that talks about a quota is ErrDriveQuota.
func warningForm(page []byte) (action string, fields url.Values, err error) {
	z := html.NewTokenizer(bytes.NewReader(page))
	var cur url.Values // the fields of the open form
	var curAction string
	values := 0 // values in cur, counted with repeats
	quota := false
	for {
		switch z.Next() {
		case html.ErrorToken: // the end of the page; a bytes.Reader has no other error
			if cur.Has("confirm") { // the form was never closed
				return curAction, cur, nil
			}
			if quota {
				return "", nil, fmt.Errorf("%w: the Drive page says so", ErrDriveQuota)
			}
			return "", nil, errors.New("the Drive page has no download form with a confirm field")
		case html.TextToken:
			quota = quota || bytes.Contains(bytes.ToLower(z.Text()), []byte("quota"))
		case html.StartTagToken, html.SelfClosingTagToken:
			name, more := z.TagName()
			attrs := map[string]string{}
			for more {
				var k, v []byte
				k, v, more = z.TagAttr()
				attrs[string(k)] = string(v)
			}
			switch string(name) {
			case "form":
				cur, curAction, values = url.Values{}, attrs["action"], 0
			case "input":
				if cur == nil || !strings.EqualFold(attrs["type"], "hidden") || attrs["name"] == "" {
					continue
				}
				if values >= maxFormFields || len(attrs["name"]) > maxFieldBytes || len(attrs["value"]) > maxFieldBytes {
					return "", nil, errors.New("the Drive form has too many or too long fields")
				}
				cur.Add(attrs["name"], attrs["value"])
				values++
			}
		case html.EndTagToken:
			if name, _ := z.TagName(); string(name) == "form" && cur != nil {
				if cur.Has("confirm") {
					return curAction, cur, nil
				}
				cur = nil
			}
		}
	}
}
