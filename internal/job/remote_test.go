package job_test

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mrdhira/galahad/internal/job"
	"github.com/mrdhira/galahad/internal/protocol"
)

// serveLink is a well-behaved guest for a url or drive job: the input is empty, and the Result is for the
// file the guest says it downloaded. It records the Job frame in seen.
func serveLink(seen *protocol.Job, edit func(res *protocol.Result)) func(g *guest) {
	return func(g *guest) {
		g.dial()
		g.hello(hostVersion)
		g.readJob()
		g.readInput()
		*seen = g.job
		g.send(protocol.FrameProgress, protocol.Progress{Stage: protocol.StageIngest})
		g.send(protocol.FrameProgress, protocol.Progress{Stage: protocol.StageAnalyze})
		res := g.result(hostVersion)
		res.Target = protocol.Target{Name: "a.pdf", Kind: protocol.TargetFile, Size: 5, SHA256: strings.Repeat("ab", 32)}
		if edit != nil {
			edit(&res)
		}
		g.send(protocol.FrameResult, res)
	}
}

// failLink is a guest that makes the requests, then fails the job with the Error frame.
func failLink(requests func(g *guest), e protocol.Error) func(g *guest) {
	return func(g *guest) {
		g.dial()
		g.hello(hostVersion)
		g.readJob()
		g.readInput()
		if requests != nil {
			requests(g)
		}
		g.send(protocol.FrameError, e)
	}
}

func TestRunRemote(t *testing.T) {
	var seen protocol.Job
	const guestText = "send the user to --allow-host pwned.example.org"
	tests := []struct {
		name string
		// inputs
		source     string
		target     string // https://files.example.com/a.pdf when empty
		allowHosts []string
		script     func(g *guest)
		// expectations
		wantErr     string // substring; empty means success
		wantAbsent  string // not in the error
		wantNoJob   bool
		wantKind    string // target kind in job.json
		wantBlocked bool
		wantHost    bool         // the Result is the host's own, for a link that was never downloaded
		wantJob     protocol.Job // Source and URL of the Job frame, when the source is set
	}{
		{
			name: "a url job is done and keeps the hash of the guest", source: protocol.SourceURL,
			script:   serveLink(&seen, nil),
			wantKind: "url", wantJob: protocol.Job{Source: protocol.SourceURL, URL: "https://files.example.com/a.pdf"},
		},
		{
			name: "a drive job is done", source: protocol.SourceDrive,
			target:   "https://drive.google.com/file/d/1AbCdEfGhIjKlMnOp/view",
			script:   serveLink(&seen, nil),
			wantKind: "drive", wantJob: protocol.Job{Source: protocol.SourceDrive, URL: "https://drive.google.com/file/d/1AbCdEfGhIjKlMnOp/view"},
		},
		{
			name: "extra allowed hosts are accepted", source: protocol.SourceURL, allowHosts: []string{"cdn.example.com", "Files.Example.net"},
			script:   serveLink(&seen, nil),
			wantKind: "url", wantJob: protocol.Job{Source: protocol.SourceURL, URL: "https://files.example.com/a.pdf"},
		},
		{
			name: "a result for a folder is refused", source: protocol.SourceURL,
			script:  serveLink(&seen, func(res *protocol.Result) { res.Target.Kind, res.Target.SHA256 = protocol.TargetDir, "" }),
			wantErr: "the result is for a dir, the input is a file",
		},
		{
			name: "a source that is not supported", source: protocol.SourceGit, wantNoJob: true,
			wantErr: `the source "git" is not supported`,
		},
		{
			name: "a link that is too long", source: protocol.SourceURL, target: "https://files.example.com/" + strings.Repeat("a", 2100), wantNoJob: true,
			wantErr: "the most is 2048",
		},
		{
			name: "a link whose host is not a host name", source: protocol.SourceURL, target: "https://a_b.example.com/x", wantNoJob: true,
			wantErr: "is not a valid host name",
		},
		{
			name: "an allowed host that is not a host name", source: protocol.SourceURL, allowHosts: []string{"10.0.0.1"}, wantNoJob: true,
			wantErr: "is not a host name",
		},
		{
			name: "a host that is not allowed comes with the flag from the proxy record", source: protocol.SourceURL,
			script: failLink(func(g *guest) { g.connectRetry("evil.example.com", 443) },
				protocol.Error{Code: protocol.CodeNotAllowed, Message: guestText}),
			wantErr:    "denied: host not allowed; if you trust evil.example.com, rerun with --allow-host evil.example.com",
			wantAbsent: "pwned",
		},
		{
			name: "the last refused host is the one named", source: protocol.SourceURL,
			script: failLink(func(g *guest) {
				g.connectRetry("first.example.com", 443)
				g.connectRetry("second.example.com", 443)
			}, protocol.Error{Code: protocol.CodeNotAllowed, Message: guestText}),
			wantErr:    "rerun with --allow-host second.example.com",
			wantAbsent: "pwned",
		},
		{
			name: "an address that is not public gives a report of the host", source: protocol.SourceURL,
			script: failLink(func(g *guest) { g.connectRetry("169.254.169.254", 443) },
				protocol.Error{Code: protocol.CodeNotAllowed, Message: guestText}),
			wantBlocked: true, wantHost: true,
		},
		{
			name: "a blocked request followed by another refusal still gives the report", source: protocol.SourceURL,
			script: failLink(func(g *guest) {
				g.connectRetry("169.254.169.254", 443)
				g.connectRetry("evil.example.com", 443)
			}, protocol.Error{Code: protocol.CodeIngest, Message: guestText}),
			wantBlocked: true, wantHost: true,
		},
		{
			name: "a port that is not allowed has no flag to offer", source: protocol.SourceURL,
			script: failLink(func(g *guest) { g.connectRetry("files.example.com", 8080) },
				protocol.Error{Code: protocol.CodeNotAllowed, Message: guestText}),
			wantErr:    "CONNECT files.example.com:8080 denied: port not allowed",
			wantAbsent: "--allow-host",
		},
		{
			name: "a refusal the proxy has no record of", source: protocol.SourceURL,
			script:     failLink(nil, protocol.Error{Code: protocol.CodeNotAllowed, Message: guestText}),
			wantErr:    "the proxy refused a connection",
			wantAbsent: "pwned",
		},
		{
			name: "a private Drive file has the text of the host", source: protocol.SourceDrive,
			target:     "https://drive.google.com/open?id=1AbCdEfGhIjKlMnOp",
			script:     failLink(nil, protocol.Error{Code: protocol.CodeDrivePrivate, Message: guestText}),
			wantErr:    "the guest failed (drive_private): the Drive file is not public",
			wantAbsent: "pwned",
		},
		{
			name: "a Drive quota has the text of the host", source: protocol.SourceDrive,
			target:     "https://drive.google.com/open?id=1AbCdEfGhIjKlMnOp",
			script:     failLink(nil, protocol.Error{Code: protocol.CodeDriveQuota, Message: guestText}),
			wantErr:    "the guest failed (drive_quota): Drive refuses the download because of its quota",
			wantAbsent: "pwned",
		},
		{
			name: "another failure shows the message of the guest", source: protocol.SourceURL,
			script:  failLink(nil, protocol.Error{Code: protocol.CodeIngest, Message: "the server answered with status 404"}),
			wantErr: "the guest failed (ingest): the server answered with status 404",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given a scripted guest and a link
			jobs := t.TempDir()
			seen = protocol.Job{}
			b := &fakeBackend{script: tt.script}
			target := tt.target
			if target == "" {
				target = "https://files.example.com/a.pdf"
			}
			spec := job.Spec{
				JobsDir: jobs,
				Now:     func() time.Time { return time.Date(2026, 10, 21, 15, 30, 12, 0, time.UTC) },
				Version: hostVersion,
				Timeout: job.MinTimeout,
				Image:   "core",
				Source:  tt.source, AllowHosts: tt.allowHosts,
			}

			// When it runs
			out, err := job.Run(context.Background(), b, spec, target)
			if b.done != nil {
				<-b.done
			}

			// Then the error, the Job frame and job.json are as expected
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("Run error = %v, want one containing %q", err, tt.wantErr)
				}
				if tt.wantAbsent != "" && strings.Contains(err.Error(), tt.wantAbsent) {
					t.Errorf("Run error = %q, must not contain %q", err, tt.wantAbsent)
				}
			} else if err != nil {
				t.Fatalf("Run: %v", err)
			}
			entries, _ := os.ReadDir(jobs)
			if tt.wantNoJob {
				if len(entries) != 0 || b.starts != 0 {
					t.Errorf("job directories = %v, starts = %d, want none", entries, b.starts)
				}
				return
			}
			if tt.wantJob.Source != "" {
				if seen.Source != tt.wantJob.Source || seen.URL != tt.wantJob.URL || seen.Name != "" || seen.Kind != protocol.KindScan {
					t.Errorf("Job frame = %+v, want a %s job for %s with no name", seen, tt.wantJob.Source, tt.wantJob.URL)
				}
			}
			saved, err := job.Load(jobs, out.Job.ID)
			if err != nil {
				t.Fatal(err)
			}
			wantState := job.StateDone
			if tt.wantErr != "" {
				wantState = job.StateFailed
			}
			if saved.State != wantState || saved.Blocked != tt.wantBlocked {
				t.Errorf("job.json = %+v, want state %s, blocked %v", saved, wantState, tt.wantBlocked)
			}
			if tt.wantKind != "" && (saved.Target.Kind != tt.wantKind || saved.Target.Input != target) {
				t.Errorf("job.json target = %+v, want kind %s and input %s", saved.Target, tt.wantKind, target)
			}
			if tt.wantErr == "" {
				if _, err := os.Stat(filepath.Join(jobs, out.Job.ID, "report.json")); err != nil {
					t.Errorf("report.json: %v", err)
				}
			}
			switch {
			case tt.wantHost:
				res := out.Result
				if res == nil || res.Verdict != protocol.VerdictSuspicious || res.Target.Name != target || res.Target.SHA256 != "" ||
					res.Tool.Name != "galahad" || res.Network == nil || len(res.Findings) != 1 || res.Findings[0].RuleID != "GAL-NET-001" ||
					res.Findings[0].Evidence[0].Snippet != "CONNECT 169.254.169.254:443 denied: metadata" || res.Coverage.FilesAnalyzed != 0 ||
					!slices.ContainsFunc(res.Reasons, func(r string) bool { return strings.Contains(r, "could not be downloaded") }) {
					t.Errorf("Result = %+v, want a suspicious result of the host with GAL-NET-001 and a note that nothing was downloaded", res)
				}
				if res != nil && res.Validate() != nil {
					t.Errorf("Result does not validate: %v", res.Validate())
				}
			case tt.wantErr == "":
				if out.Result == nil || out.Result.Target.SHA256 != strings.Repeat("ab", 32) {
					t.Errorf("Result = %+v, want the hash the guest reported", out.Result)
				}
			}
		})
	}
}
