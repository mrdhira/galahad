package agent_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/mrdhira/galahad/internal/agent"
	"github.com/mrdhira/galahad/internal/protocol"
)

func TestGuestClone(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the git stub is a shell script")
	}
	const clone = "for last; do :; done\necho hello > \"$last/README.md\"\necho 'Cloning into the input' >&2\n"
	tests := []struct {
		name string
		// inputs
		script  string // the git on PATH
		url     string // https://allowed.example.com/team/tools.git when empty
		noProxy bool   // no --proxy
		// expectations
		wantErrCode string // an Error frame instead of a Result
		wantMessage string // substring of the Error message
		wantLog     string // substring of ingest.log
		wantFiles   int
	}{
		{
			name: "a git job clones into the input folder and analyzes it", script: clone,
			wantLog: "git clone: ok", wantFiles: 1,
		},
		{
			name: "a git job without a proxy channel fails", script: clone, noProxy: true,
			wantErrCode: protocol.CodeIngest, wantMessage: "needs the network",
		},
		{
			name: "a URL that is not https fails before git runs", script: clone, url: "http://allowed.example.com/x.git",
			wantErrCode: protocol.CodeIngest, wantMessage: "not an https URL",
		},
		{
			name: "a failed clone is an ingest error with the log", script: "echo 'fatal: repository not found' >&2\nexit 128\n",
			wantErrCode: protocol.CodeIngest, wantMessage: "exit status 128: fatal: repository not found",
			wantLog: "stderr: fatal: repository not found",
		},
		{
			name: "a full disk is too_large", script: "echo 'fatal: write error: No space left on device' >&2\nexit 128\n",
			wantErrCode: protocol.CodeTooLarge, wantLog: "No space left on device",
		},
		{
			name: "a refusal of the relay is not_allowed", script: "echo 'fatal: unable to access: CONNECT tunnel failed, response 403' >&2\nexit 128\n",
			wantErrCode: protocol.CodeNotAllowed,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given a git on PATH, a relay and a git job with an empty input
			bin := t.TempDir()
			if err := os.WriteFile(filepath.Join(bin, "git"), []byte("#!/bin/sh\n"+tt.script), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(filepath.Join(bin, "git"), 0o700); err != nil { // #nosec G302 -- the stub must be executable
				t.Fatal(err)
			}
			t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
			var args []string
			if !tt.noProxy {
				addr, _ := newBackend(t)
				args = []string{"--proxy", "tcp:" + hostProxyAt(t, addr)}
			}
			job := testJob("", 300)
			job.Source, job.URL = protocol.SourceGit, "https://allowed.example.com/team/tools.git"
			if tt.url != "" {
				job.URL = tt.url
			}

			// When the host sends the job and an empty stream
			c, exit := startGuestWith(t, agent.Env{Setenv: func(string, string) {}}, args...)
			go func() {
				if writeJSON(c, protocol.FrameJob, job) == nil {
					_ = writeJSON(c, protocol.FrameEnd, endOf(nil))
				}
			}()
			got := readGuest(t, c)
			ex := <-exit

			// Then the Result is for the folder, or the Error has the code, and ingest.log has the clone
			if !strings.Contains(string(got.ingest), tt.wantLog) {
				t.Errorf("ingest.log = %q, want it to contain %q", got.ingest, tt.wantLog)
			}
			if tt.wantErrCode != "" {
				if got.errMsg == nil || got.errMsg.Code != tt.wantErrCode || !strings.Contains(got.errMsg.Message, tt.wantMessage) || ex.code != agent.ExitError {
					t.Fatalf("error frame = %+v, exit = %d, want code %q, a message with %q and exit %d", got.errMsg, ex.code, tt.wantErrCode, tt.wantMessage, agent.ExitError)
				}
				return
			}
			if got.result == nil || ex.code != agent.ExitClean {
				t.Fatalf("result = %v, error = %+v, exit = %d; stderr %q", got.result, got.errMsg, ex.code, ex.stderr)
			}
			if tg := got.result.Target; tg.Kind != protocol.TargetDir || tg.FileCount != tt.wantFiles {
				t.Errorf("target = %+v, want a folder with %d file", tg, tt.wantFiles)
			}
		})
	}
}
