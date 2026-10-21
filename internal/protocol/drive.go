package protocol

import (
	"net/url"
	"regexp"
	"strings"
)

// Hosts of the Google Drive links a scan accepts. Only the first has share links with the ID in the
// path; all three take the ID in the query.
const (
	DriveHost         = "drive.google.com"
	driveDocsHost     = "docs.google.com"
	driveDownloadHost = "drive.usercontent.google.com"
)

// IsDriveHost reports whether host is one of the hosts of Drive links. A link to one of them is
// a Drive link or an error, never a plain URL: Drive answers a large file with a warning page that
// a plain download would scan as if it were the file.
func IsDriveHost(host string) bool {
	switch strings.ToLower(host) {
	case DriveHost, driveDocsHost, driveDownloadHost:
		return true
	}
	return false
}

var (
	driveIDRe   = regexp.MustCompile(`^[A-Za-z0-9_-]{10,128}$`)
	driveFileRe = regexp.MustCompile(`^/file/(?:u/[0-9]{1,3}/)?d/([A-Za-z0-9_-]{10,128})(?:/[^/]*)?$`)
)

// DriveFileID returns the file ID of a Google Drive share link, and false when raw is not
// one. The forms are https://drive.google.com/file/d/<id>/view, /open?id=<id> and /uc?id=<id>;
// docs.google.com and drive.usercontent.google.com take /uc?id=<id> and /download?id=<id> too.
// http is accepted too. The host, which classifies the target, and the guest, which downloads
// it, both use this one function.
func DriveFileID(raw string) (string, bool) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil ||
		u.Port() != "" || !IsDriveHost(u.Hostname()) {
		return "", false
	}
	switch u.Path {
	case "/open", "/uc", "/download":
		ids := u.Query()["id"]
		if len(ids) == 1 && driveIDRe.MatchString(ids[0]) {
			return ids[0], true
		}
		return "", false
	}
	if !strings.EqualFold(u.Hostname(), DriveHost) {
		return "", false
	}
	if m := driveFileRe.FindStringSubmatch(u.Path); m != nil {
		return m[1], true
	}
	return "", false
}
