package cli

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/mrdhira/galahad/internal/protocol"
)

// target is what "galahad scan" was asked to scan.
type target struct {
	source string // protocol.SourceLocal, SourceURL, SourceDrive or SourceGit
	value  string // the path or the link, as given
}

// schemeRe matches the start of a link: a scheme and "://". A path such as "C:\dir" or "a:b" does not.
var schemeRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*://`)

// Forms of a Git address that have no scheme and that Git itself would use over ssh or a helper
// program: "ext::sh -c ...", "fd::17", and scp-style "user@host:path".
var (
	transportRe = regexp.MustCompile(`^[A-Za-z0-9]+::`)
	scpRe       = regexp.MustCompile(`^[A-Za-z0-9._-]+@[A-Za-z0-9.-]+:`)
)

// forgeHosts are the Git hosts whose repository links (host/owner/repo, with or without ".git") are
// recognized without the --git flag.
var forgeHosts = []string{"github.com", "gitlab.com", "bitbucket.org", "codeberg.org"}

// classifyTarget decides what arg names: a local path, a Git repository, a Google Drive file link, or
// an http or https link. It only reads the text of arg; it does not touch the file system or the
// network. forceGit (--git) makes any https link a Git repository.
//
// The order of the checks matters: --git first, then Drive, then the Git forms, then the generic link.
func classifyTarget(arg string, forceGit bool) (target, error) {
	if !schemeRe.MatchString(arg) {
		switch {
		case transportRe.MatchString(arg), scpRe.MatchString(arg):
			return target{}, fmt.Errorf("%q is a Git transport or ssh address; only https Git URLs are supported", protocol.CleanPath(arg))
		case forceGit:
			return target{}, errors.New("--git needs an https link")
		}
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
	repoPath := strings.HasSuffix(u.Path, ".git") && u.RawQuery == "" && u.Fragment == ""
	switch {
	case forceGit || repoPath:
		if u.Scheme != "https" && !protocol.GitHTTPHost(u.Hostname()) {
			return target{}, fmt.Errorf("%q: a Git repository needs an https link", shown)
		}
		return target{source: protocol.SourceGit, value: u.String()}, nil
	case protocol.IsDriveHost(u.Hostname()):
		if _, ok := protocol.DriveFileID(arg); !ok {
			if strings.EqualFold(u.Hostname(), "docs.google.com") && isDocsPage(u.Path) {
				return target{}, fmt.Errorf("%q is not a Google Drive file link: Google Docs, Sheets, Slides and Forms pages are not supported yet", shown)
			}
			return target{}, fmt.Errorf("%q is not a Google Drive file link; use /file/d/<id>, /open?id=<id> or /uc?id=<id>", shown)
		}
		return target{source: protocol.SourceDrive, value: arg}, nil
	case u.Scheme == "https" && isForgeRepo(u):
		return target{source: protocol.SourceGit, value: u.String()}, nil
	}
	return target{source: protocol.SourceURL, value: arg}, nil
}

// isForgeRepo reports whether u is the page of a repository on a known Git host: owner and repository
// on GitHub, Bitbucket and Codeberg, and a group path of two or more names on GitLab, with no "-"
// (the part of a GitLab link that names a page of the repository) and no query.
func isForgeRepo(u *url.URL) bool {
	host := strings.ToLower(u.Hostname())
	if u.RawQuery != "" || u.Fragment != "" || !slices.Contains(forgeHosts, host) {
		return false
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if slices.Contains(parts, "") {
		return false
	}
	if host == "gitlab.com" {
		return len(parts) >= 2 && !slices.Contains(parts, "-")
	}
	return len(parts) == 2
}

// isDocsPage reports a path of a Google Docs, Forms, Sheets or Slides page.
func isDocsPage(p string) bool {
	for _, prefix := range []string{"/document/", "/forms/", "/spreadsheets/", "/presentation/"} {
		if strings.HasPrefix(p, prefix) {
			return true
		}
	}
	return false
}
