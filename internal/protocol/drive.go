package protocol

import (
	"net/url"
	"regexp"
	"strings"
)

// DriveHost is the host of the share links of Google Drive.
const DriveHost = "drive.google.com"

var (
	driveIDRe   = regexp.MustCompile(`^[A-Za-z0-9_-]{10,128}$`)
	driveFileRe = regexp.MustCompile(`^/file/(?:u/[0-9]{1,3}/)?d/([A-Za-z0-9_-]{10,128})(?:/[^/]*)?$`)
)

// DriveFileID returns the file ID of a Google Drive share link, and false when raw is not
// one. The forms are https://drive.google.com/file/d/<id>/view, /open?id=<id> and /uc?id=<id>;
// http is accepted too. The host, which classifies the target, and the guest, which downloads
// it, both use this one function.
func DriveFileID(raw string) (string, bool) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil ||
		u.Port() != "" || strings.ToLower(u.Hostname()) != DriveHost {
		return "", false
	}
	switch u.Path {
	case "/open", "/uc":
		ids := u.Query()["id"]
		if len(ids) == 1 && driveIDRe.MatchString(ids[0]) {
			return ids[0], true
		}
		return "", false
	}
	if m := driveFileRe.FindStringSubmatch(u.Path); m != nil {
		return m[1], true
	}
	return "", false
}
