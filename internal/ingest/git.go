package ingest

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os/exec"
	"strings"
	"time"

	"github.com/mrdhira/galahad/internal/protocol"
)

// Limits of a Git clone.
const (
	GitTimeout = 5 * time.Minute // each git command; the size cap is the scratch disk

	maxGitOutput = 16 << 10        // bytes kept of what one git command wrote to one stream, the end of it
	maxGitLines  = 50              // lines of one stream that go to the log
	gitWaitDelay = 5 * time.Second // how long after a kill the pipes of git's helper processes are waited for
)

// Git clones a repository without letting anything in it run. The zero value uses the git on PATH,
// and Relay must be set.
type Git struct {
	// Path is the git program. Empty means "git".
	Path string
	// Relay is the address of the relay, host:port: the one route git has to the network.
	Relay string
	// Timeout is the time limit of each git command. Zero means GitTimeout.
	Timeout time.Duration
}

func (g Git) path() string {
	if g.Path != "" {
		return g.Path
	}
	return "git"
}

func (g Git) timeout() time.Duration {
	if g.Timeout > 0 {
		return g.Timeout
	}
	return GitTimeout
}

// allowHTTP reports whether the command may use plain http for the URL, which only galahadtest builds
// allow, and only for .test hosts.
func allowHTTP(rawURL string) bool {
	u, err := url.Parse(rawURL)
	return err == nil && u.Scheme == "http" && protocol.GitHTTPHost(u.Hostname())
}

// config returns the -c options of every git command: no protocol but https, no hooks, no fsmonitor,
// no symlinks, no LFS filters, a check of every object, no submodule recursion, no password prompt, and the relay.
func (g Git) config(rawURL string) []string {
	cfg := []string{"protocol.allow=never", "protocol.https.allow=always"}
	if allowHTTP(rawURL) {
		cfg = append(cfg, "protocol.http.allow=always")
	}
	cfg = append(cfg,
		"core.hooksPath=/dev/null", "core.fsmonitor=false", "core.symlinks=false",
		"filter.lfs.process=", "filter.lfs.smudge=", "transfer.fsckObjects=true",
		"submodule.recurse=false", "core.askPass=/bin/false", "http.proxy="+g.Relay)
	args := make([]string, 0, 2*len(cfg))
	for _, c := range cfg {
		args = append(args, "-c", c)
	}
	return args
}

// CloneArgs returns the arguments of the clone of rawURL into dest. The URL and the directory come
// after "--", so they can never be read as options.
func (g Git) CloneArgs(rawURL, dest string) []string {
	return append(g.config(rawURL), "clone", "--depth", "1", "--no-tags", "--single-branch",
		"--no-recurse-submodules", "--template=", "--", rawURL, dest)
}

// SubmoduleArgs returns the arguments of the submodule update, which runs inside the clone.
func (g Git) SubmoduleArgs(rawURL string) []string {
	return append(g.config(rawURL), "submodule", "update", "--init", "--depth", "1")
}

// Env returns the whole environment of a git command. Nothing of the agent's own environment is
// passed on. GIT_ALLOW_PROTOCOL holds the same protocols as the -c options allow.
func (g Git) Env(rawURL string) []string {
	protocols := "https"
	if allowHTTP(rawURL) {
		protocols = "https:http"
	}
	proxy := "http://" + g.Relay
	return []string{
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_TERMINAL_PROMPT=0",
		"GIT_LFS_SKIP_SMUDGE=1",
		"GIT_ALLOW_PROTOCOL=" + protocols,
		"http_proxy=" + proxy,
		"https_proxy=" + proxy,
	}
}

// Clone fetches the head of rawURL, an https address, into the empty directory dest. With submodules
// it then updates them, and a submodule that fails is only logged. The returned text is the cleaned
// log for ingest.log; it is set on failure too. A full disk is ErrTooLarge, a refusal of the
// relay is ErrNotAllowed, and a command that outlasts its limit is context.DeadlineExceeded.
func (g Git) Clone(ctx context.Context, rawURL, dest string, submodules bool) (string, error) {
	if u, err := url.Parse(rawURL); err != nil || u.Hostname() == "" || u.User != nil ||
		(u.Scheme != "https" && !allowHTTP(rawURL)) {
		return "", errors.New("the target is not an https URL")
	}
	var log strings.Builder
	out, err := g.run(ctx, "git clone", g.CloneArgs(rawURL, dest), rawURL, "")
	out.writeTo(&log, "git clone", err)
	if err != nil {
		return log.String(), err
	}
	if !submodules {
		return log.String(), nil
	}
	out, err = g.run(ctx, "git submodule update", g.SubmoduleArgs(rawURL), rawURL, dest)
	out.writeTo(&log, "git submodule update", err)
	if err != nil && (errors.Is(err, ErrTooLarge) || ctx.Err() != nil) {
		return log.String(), err // a full disk or the end of the time is not a submodule failing
	}
	if err != nil {
		log.WriteString("the scan goes on without the submodules that failed\n")
	}
	return log.String(), nil
}

// gitOutput is the end of what a git command wrote.
type gitOutput struct {
	stdout, stderr tail
}

// run starts git with args and the scrubbed environment, and waits for it within the time limit.
// The error says why git failed, in the terms of this package.
func (g Git) run(ctx context.Context, name string, args []string, rawURL, dir string) (gitOutput, error) {
	ctx, cancel := context.WithTimeout(ctx, g.timeout())
	defer cancel()
	var out gitOutput
	cmd := exec.CommandContext(ctx, g.path(), args...) // #nosec G204 -- the program is git, the arguments are fixed options, and the untrusted URL follows "--"
	cmd.Env = g.Env(rawURL)
	cmd.Dir = dir
	cmd.Stdout, cmd.Stderr = &out.stdout, &out.stderr
	cmd.WaitDelay = gitWaitDelay
	err := cmd.Run()
	if err == nil {
		return out, nil
	}
	stderr := strings.ToLower(string(out.stderr.buf))
	var exit *exec.ExitError
	switch {
	case ctx.Err() != nil:
		return out, fmt.Errorf("%s: %w", name, ctx.Err())
	case strings.Contains(stderr, "no space left on device"):
		return out, fmt.Errorf("%w: %s ran out of disk space", ErrTooLarge, name)
	case strings.Contains(stderr, "connect tunnel failed, response 403"), strings.Contains(stderr, "http code 403 from proxy after connect"):
		return out, fmt.Errorf("%w: %s", ErrNotAllowed, name)
	case !errors.As(err, &exit):
		return out, fmt.Errorf("%s: %w", name, err)
	}
	if last := out.stderr.last(); last != "" {
		return out, fmt.Errorf("%s: %w: %s", name, err, last)
	}
	return out, fmt.Errorf("%s: %w", name, err)
}

// writeTo adds the result of one command to log: a header line and the end of each stream, one
// cleaned line at a time.
func (o *gitOutput) writeTo(log *strings.Builder, name string, err error) {
	if err == nil {
		fmt.Fprintf(log, "%s: ok\n", name)
	} else {
		fmt.Fprintf(log, "%s\n", protocol.Snippet(err.Error()))
	}
	for _, s := range []struct {
		label string
		t     *tail
	}{{"stderr", &o.stderr}, {"stdout", &o.stdout}} {
		if s.t.dropped {
			fmt.Fprintf(log, "  %s: (earlier output dropped)\n", s.label)
		}
		for _, line := range s.t.lines(maxGitLines) {
			fmt.Fprintf(log, "  %s: %s\n", s.label, protocol.Snippet(line))
		}
	}
}

// tail keeps the last maxGitOutput bytes written to it. The end of the output is where git says why it failed.
type tail struct {
	buf     []byte
	dropped bool
}

func (t *tail) Write(p []byte) (int, error) {
	t.buf = append(t.buf, p...)
	if len(t.buf) > maxGitOutput {
		n := copy(t.buf, t.buf[len(t.buf)-maxGitOutput:])
		t.buf, t.dropped = t.buf[:n], true
	}
	return len(p), nil
}

// lines returns the last n non-empty lines. Git redraws progress with a carriage return, so that ends a line too.
func (t *tail) lines(n int) []string {
	all := strings.FieldsFunc(string(t.buf), func(r rune) bool { return r == '\n' || r == '\r' })
	if t.dropped && len(all) > 0 {
		all = all[1:] // the first line may be cut
	}
	if len(all) > n {
		all = all[len(all)-n:]
	}
	return all
}

// last returns the last line, cleaned, or "" when there is none.
func (t *tail) last() string {
	if l := t.lines(1); len(l) > 0 {
		return protocol.Snippet(l[0])
	}
	return ""
}
