package cli

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/mrdhira/galahad/internal/protocol"
)

// target is what "galahad scan" was asked to scan.
type target struct {
	source string // protocol.SourceLocal, SourceURL or SourceDrive
	value  string // the path or the link, as given
}

// schemeRe matches the start of a link: a scheme and "://". A path such as "C:\dir" or "a:b" does not.
var schemeRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*://`)

// classifyTarget decides what arg names: a local path, a Google Drive file link, or an http or
// https link. It only reads the text of arg; it does not touch the file system or the network.
//
// The order of the checks matters. T2.7b adds Git detection (the --git flag, and the Git forge hosts
// github.com, gitlab.com, bitbucket.org and codeberg.org) to this function: it belongs after the
// Drive check and before the generic link, and returns a target with protocol.SourceGit.
func classifyTarget(arg string) (target, error) {
	if !schemeRe.MatchString(arg) {
		return target{source: protocol.SourceLocal, value: arg}, nil
	}
	shown := protocol.CleanPath(arg)
	u, err := url.Parse(arg)
	switch {
	case err != nil:
		return target{}, fmt.Errorf("%q is not a valid link", shown)
	case strings.ContainsFunc(arg, func(r rune) bool { return r < '!' || r > '~' }):
		return target{}, fmt.Errorf("%q has a space, a control character or a character that is not ASCII; percent-encode it", shown)
	case u.Scheme != "http" && u.Scheme != "https":
		return target{}, fmt.Errorf("%q: only http and https links are supported", shown)
	case len(arg) > protocol.MaxURL:
		return target{}, fmt.Errorf("the link is %d bytes, the most is %d", len(arg), protocol.MaxURL)
	case u.Hostname() == "":
		return target{}, fmt.Errorf("%q has no host", shown)
	case u.User != nil:
		return target{}, errors.New("a link with a user name or password is not supported")
	}
	if strings.EqualFold(u.Hostname(), protocol.DriveHost) {
		if _, ok := protocol.DriveFileID(arg); !ok {
			return target{}, fmt.Errorf("%q is not a Google Drive file link; use /file/d/<id>, /open?id=<id> or /uc?id=<id>", shown)
		}
		return target{source: protocol.SourceDrive, value: arg}, nil
	}
	return target{source: protocol.SourceURL, value: arg}, nil
}
