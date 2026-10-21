package ingest_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mrdhira/galahad/internal/ingest"
)

const (
	gitURL   = "https://example.com/owner/repo.git"
	gitRelay = "127.0.0.1:3128"
)

func TestGitCommands(t *testing.T) {
	const config = "-c protocol.allow=never -c protocol.https.allow=always -c core.hooksPath=/dev/null -c core.fsmonitor=false " +
		"-c core.symlinks=false -c filter.lfs.process= -c filter.lfs.smudge= -c transfer.fsckObjects=true " +
		"-c submodule.recurse=false -c core.askPass=/bin/false -c http.proxy="
	tests := []struct {
		name string
		// inputs
		build func(g ingest.Git) []string
		relay string
		// expectations
		want string // the arguments or the environment, joined with a space
	}{
		{
			name: "the clone is the command of the card", relay: gitRelay,
			build: func(g ingest.Git) []string { return g.CloneArgs(gitURL, "/work/input") },
			want: config + gitRelay + " clone --depth 1 --no-tags --single-branch --no-recurse-submodules --template= -- " +
				gitURL + " /work/input",
		},
		{
			name: "the relay address is the actual one", relay: "127.0.0.1:41234",
			build: func(g ingest.Git) []string { return g.CloneArgs(gitURL, "/work/input") },
			want: config + "127.0.0.1:41234 clone --depth 1 --no-tags --single-branch --no-recurse-submodules --template= -- " +
				gitURL + " /work/input",
		},
		{
			name: "an address that looks like an option stays after the double dash", relay: gitRelay,
			build: func(g ingest.Git) []string { return g.CloneArgs("https://example.com/--upload-pack=x", "-dest") },
			want: config + gitRelay + " clone --depth 1 --no-tags --single-branch --no-recurse-submodules --template= -- " +
				"https://example.com/--upload-pack=x -dest",
		},
		{
			name: "the submodule update has the same settings", relay: gitRelay,
			build: func(g ingest.Git) []string { return g.SubmoduleArgs(gitURL) },
			want:  config + gitRelay + " submodule update --init --depth 1",
		},
		{
			name: "the environment is the list of the card and nothing else", relay: gitRelay,
			build: func(g ingest.Git) []string { return g.Env(gitURL) },
			want: "GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_TERMINAL_PROMPT=0 GIT_LFS_SKIP_SMUDGE=1 GIT_ALLOW_PROTOCOL=https " +
				"http_proxy=http://127.0.0.1:3128 https_proxy=http://127.0.0.1:3128",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := strings.Join(tt.build(ingest.Git{Relay: tt.relay}), " ")
			if got != tt.want {
				t.Errorf("got\n%s\nwant\n%s", got, tt.want)
			}
		})
	}
}

// stubGit writes a shell script that stands in for git and returns its path.
func stubGit(t *testing.T, script string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the git stub is a shell script")
	}
	path := filepath.Join(t.TempDir(), "git")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+script), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o700); err != nil { // #nosec G302 -- the stub must be executable
		t.Fatal(err)
	}
	return path
}

func TestGitClone(t *testing.T) {
	// The recording stub writes its directory, its arguments and its environment for each run.
	record := `{ echo "pwd=$(pwd)"; echo "args=$*"; env | grep -v -e '^PWD=' -e '^SHLVL=' -e '^_=' -e '^OLDPWD=' | sed 's/^/env=/'; } >> RECORD` + "\n"
	tests := []struct {
		name string
		// inputs
		script      string // the stub; empty means a git that does not exist
		url         string // gitURL when empty
		submodules  bool
		timeout     time.Duration
		cancelAfter time.Duration // the context ends this long after the start, when not zero
		// expectations
		wantErr   string // substring; empty means success
		wantIs    error
		wantLog   []string
		wantCalls int // runs of git, when the stub records them
		wantRows  int // most lines of the log, when not zero
	}{
		{
			name: "a clone runs with the environment of the card", script: record,
			wantLog: []string{"git clone: ok"}, wantCalls: 1,
		},
		{
			name: "the submodule update runs inside the clone", script: record, submodules: true,
			wantLog: []string{"git clone: ok", "git submodule update: ok"}, wantCalls: 2,
		},
		{
			name: "a URL that is not https is refused", script: record, url: "http://example.com/x.git",
			wantErr: "not an https URL",
		},
		{
			name: "an ext address is refused", script: record, url: "ext::sh -c touch% /tmp/x",
			wantErr: "not an https URL",
		},
		{
			name: "a URL with a password is refused", script: record, url: "https://user:secret@example.com/x.git",
			wantErr: "not an https URL",
		},
		{
			name: "a failed clone says why, cleaned", submodules: true,
			script:  "printf 'fatal: \\033]0;PWNED\\007repository not found\\n' >&2\nexit 128\n",
			wantErr: `exit status 128: fatal: \u001b]0;PWNED\u0007repository not found`,
			wantLog: []string{`git clone: exit status 128: fatal:`, `stderr: fatal: \u001b]0;PWNED\u0007repository not found`},
		},
		{
			name: "a clone over the time limit is a timeout", timeout: 300 * time.Millisecond,
			script: "exec sleep 30\n", wantErr: "deadline exceeded", wantIs: context.DeadlineExceeded,
			wantLog: []string{"git clone: context deadline exceeded"},
		},
		{
			name: "a full disk is too large", script: "echo 'fatal: write error: No space left on device' >&2\nexit 128\n",
			wantErr: "ran out of disk space", wantIs: ingest.ErrTooLarge,
		},
		{
			name: "a refusal of the relay is not allowed", script: "echo 'fatal: unable to access: CONNECT tunnel failed, response 403' >&2\nexit 128\n",
			wantErr: "git clone", wantIs: ingest.ErrNotAllowed,
		},
		{
			name: "a git that does not start", wantErr: "git clone: fork/exec", wantLog: []string{"git clone: fork/exec"},
		},
		{
			name: "a submodule that fails is only logged", submodules: true,
			script:  `case "$*" in *" submodule update"*) echo "fatal: unable to access 'https://169.254.169.254/x.git': CONNECT tunnel failed, response 403" >&2; exit 1;; esac` + "\n",
			wantLog: []string{"git clone: ok", "the proxy refused the connection: git submodule update", "CONNECT tunnel failed, response 403", "the scan goes on"},
		},
		{
			name: "a full disk in a submodule is too large", submodules: true,
			script:  `case "$*" in *" submodule update"*) echo "error: No space left on device" >&2; exit 1;; esac` + "\n",
			wantErr: "ran out of disk space", wantIs: ingest.ErrTooLarge,
			wantLog: []string{"git clone: ok", "input too large: git submodule update"},
		},
		{
			name: "a submodule update over its time limit is only logged", submodules: true, timeout: time.Second,
			script:  `case "$*" in *" submodule update"*) exec sleep 30;; esac` + "\n",
			wantLog: []string{"git clone: ok", "git submodule update: context deadline exceeded", "the scan goes on"},
		},
		{
			name: "the end of the job during a submodule update stops the scan", submodules: true, cancelAfter: 500 * time.Millisecond,
			script:  `case "$*" in *" submodule update"*) exec sleep 30;; esac` + "\n",
			wantErr: "context canceled", wantIs: context.Canceled,
		},
		{
			name:    "output is capped and cleaned",
			script:  `i=0; while [ $i -lt 20000 ]; do echo "remote: line $i padding padding padding"; i=$((i+1)); done >&2` + "\n" + "printf 'fatal: \\033[2Jthe end\\n' >&2\nexit 128\n",
			wantErr: `fatal: \u001b[2Jthe end`,
			wantLog: []string{"stderr: (earlier output dropped)", `stderr: fatal: \u001b[2Jthe end`}, wantRows: 55,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given a git that behaves as the case says
			record := filepath.Join(t.TempDir(), "calls")
			g := ingest.Git{Path: filepath.Join(t.TempDir(), "no-git"), Relay: gitRelay, Timeout: tt.timeout}
			if tt.script != "" {
				g.Path = stubGit(t, strings.ReplaceAll(tt.script, "RECORD", record))
			}
			dest := t.TempDir()
			ctx := context.Background()
			if tt.cancelAfter > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				defer cancel()
				stop := time.AfterFunc(tt.cancelAfter, cancel)
				defer stop.Stop()
			}
			url := tt.url
			if url == "" {
				url = gitURL
			}

			// When it clones
			log, err := g.Clone(ctx, url, dest, tt.submodules)

			// Then the error, the log and the runs are as expected
			if (tt.wantErr == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), tt.wantErr)) {
				t.Fatalf("error = %v, want one with %q", err, tt.wantErr)
			}
			if tt.wantIs != nil && !errors.Is(err, tt.wantIs) {
				t.Errorf("error = %v, want %v", err, tt.wantIs)
			}
			for _, w := range tt.wantLog {
				if !strings.Contains(log, w) {
					t.Errorf("log lacks %q:\n%s", w, log)
				}
			}
			if strings.ContainsAny(log, "\x1b\a\r") || strings.Contains(log, "secret") {
				t.Errorf("log has control characters or a secret:\n%q", log)
			}
			if tt.wantRows > 0 && strings.Count(log, "\n") > tt.wantRows {
				t.Errorf("log has %d lines, want at most %d", strings.Count(log, "\n"), tt.wantRows)
			}
			if tt.wantCalls > 0 {
				checkCalls(t, record, dest, tt.wantCalls)
			}
		})
	}
}

// checkCalls checks what the recording stub wrote: n runs, each with the environment of a git
// command and nothing else, and the update inside dest.
func checkCalls(t *testing.T, record, dest string, n int) {
	t.Helper()
	data, err := os.ReadFile(record) // #nosec G304 -- test file under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	calls := strings.Split("\n"+string(data), "\npwd=")[1:]
	if len(calls) != n {
		t.Fatalf("git ran %d times, want %d:\n%s", len(calls), n, data)
	}
	wantEnv := []string{
		"env=GIT_ALLOW_PROTOCOL=https", "env=GIT_CONFIG_GLOBAL=/dev/null", "env=GIT_CONFIG_NOSYSTEM=1", "env=GIT_LFS_SKIP_SMUDGE=1",
		"env=GIT_TERMINAL_PROMPT=0", "env=http_proxy=http://" + gitRelay, "env=https_proxy=http://" + gitRelay,
	}
	wantDir, err := filepath.EvalSymlinks(dest)
	if err != nil {
		t.Fatal(err)
	}
	for i, call := range calls {
		lines := strings.Split(strings.TrimSpace(call), "\n")
		gotEnv := slices.Sorted(slices.Values(lines[2:]))
		if !slices.Equal(gotEnv, wantEnv) {
			t.Errorf("run %d environment = %q, want %q", i, gotEnv, wantEnv)
		}
		args := strings.TrimPrefix(lines[1], "args=")
		switch i {
		case 0:
			if !strings.Contains(args, " clone --depth 1 --no-tags --single-branch --no-recurse-submodules --template= -- "+gitURL+" "+dest) {
				t.Errorf("run 0 arguments = %q, want the clone", args)
			}
		default:
			if !strings.HasSuffix(args, " submodule update --init --depth 1") || lines[0] != wantDir {
				t.Errorf("run %d = %q in %q, want the submodule update in %q", i, args, lines[0], wantDir)
			}
		}
	}
}
