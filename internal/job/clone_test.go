package job_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mrdhira/galahad/internal/job"
	"github.com/mrdhira/galahad/internal/protocol"
)

// serveRepo is a well-behaved guest for a git job: the input is empty, the guest clones through the
// proxy (the requests), logs the clone as ingest.log, and sends a Result for a folder that edit changes.
// It records the Job frame in seen.
func serveRepo(seen *protocol.Job, requests func(g *guest), edit func(res *protocol.Result)) func(g *guest) {
	return func(g *guest) {
		g.dial()
		g.hello(hostVersion)
		g.readJob()
		g.readInput()
		*seen = g.job
		g.send(protocol.FrameProgress, protocol.Progress{Stage: protocol.StageIngest})
		if requests != nil {
			requests(g)
		}
		g.sendRaw(protocol.FrameArtifact, protocol.Artifact{ID: protocol.ArtifactIngestLog, Data: []byte("git clone: ok\n")}.Marshal())
		g.send(protocol.FrameProgress, protocol.Progress{Stage: protocol.StageAnalyze})
		res := g.result(hostVersion)
		res.Target.Name = "input"
		if edit != nil {
			edit(&res)
		}
		g.send(protocol.FrameResult, res)
	}
}

func TestRunGit(t *testing.T) {
	var seen protocol.Job
	const repo = "https://git.example.com/team/tools.git"
	tests := []struct {
		name string
		// inputs
		target     string // repo when empty
		submodules bool
		allowHosts []string
		script     func(g *guest)
		// expectations
		wantErr      string // substring; empty means success
		wantNoJob    bool
		wantSubmod   bool
		wantBlocked  bool
		wantEvidence string // snippet of GAL-NET-001, when not empty
		wantLog      string // content of ingest.log
	}{
		{
			name:    "a git job is done: the guest gets the address and the log is kept",
			script:  serveRepo(&seen, nil, nil),
			wantLog: "git clone: ok\n",
		},
		{
			name: "the submodule option reaches the guest", submodules: true,
			script:     serveRepo(&seen, nil, nil),
			wantSubmod: true, wantLog: "git clone: ok\n",
		},
		{
			name: "a submodule at an address that is not public is blocked and reported", submodules: true,
			script: serveRepo(&seen, func(g *guest) {
				if reply := g.connectRetry("169.254.169.254", 443); reply.OK {
					t.Error("the proxy let the metadata address through")
				}
			}, nil),
			wantSubmod: true, wantBlocked: true, wantEvidence: "CONNECT 169.254.169.254:443 denied: metadata", wantLog: "git clone: ok\n",
		},
		{
			name: "a result for a file is refused",
			script: serveRepo(&seen, nil, func(res *protocol.Result) {
				res.Target.Kind, res.Target.SHA256 = protocol.TargetFile, strings.Repeat("ab", 32)
			}),
			wantErr: "the result is for a file, the input is a dir",
		},
		{
			name: "a link that is too long", target: "https://git.example.com/" + strings.Repeat("a", 2100), wantNoJob: true,
			wantErr: "the most is 2048",
		},
		{
			name: "an address that is not http or https", target: "ssh://git.example.com/x.git", wantNoJob: true,
			wantErr: "is not an http or https URL",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given a scripted guest and a repository link
			jobs := t.TempDir()
			seen = protocol.Job{}
			b := &fakeBackend{script: tt.script}
			target := tt.target
			if target == "" {
				target = repo
			}
			spec := job.Spec{
				JobsDir: jobs,
				Now:     func() time.Time { return time.Date(2026, 10, 21, 15, 30, 12, 0, time.UTC) },
				Version: hostVersion,
				Timeout: job.MinTimeout,
				Image:   "core",
				Source:  protocol.SourceGit, Submodules: tt.submodules, AllowHosts: tt.allowHosts,
			}

			// When it runs
			out, err := job.Run(context.Background(), b, spec, target)
			if b.done != nil {
				<-b.done
			}

			// Then the error, the Job frame, the report and the log are as expected
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("Run error = %v, want one containing %q", err, tt.wantErr)
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
			if tt.wantErr != "" {
				return
			}
			if seen.Source != protocol.SourceGit || seen.URL != target || seen.Name != "" || seen.Submodules != tt.wantSubmod || seen.Kind != protocol.KindScan {
				t.Errorf("Job frame = %+v, want a git job for %s with submodules %v and no name", seen, target, tt.wantSubmod)
			}
			saved, err := job.Load(jobs, out.Job.ID)
			if err != nil {
				t.Fatal(err)
			}
			if saved.State != job.StateDone || saved.Blocked != tt.wantBlocked || saved.Target.Kind != "git" || saved.Target.Input != target {
				t.Errorf("job.json = %+v, want state done, blocked %v and a git target %s", saved, tt.wantBlocked, target)
			}
			log, err := os.ReadFile(filepath.Join(jobs, out.Job.ID, "artifacts", "ingest.log")) // #nosec G304 -- path below t.TempDir()
			if err != nil || string(log) != tt.wantLog {
				t.Errorf("ingest.log = %q, %v, want %q", log, err, tt.wantLog)
			}
			var evidence string
			for _, f := range out.Result.Findings {
				if f.RuleID == "GAL-NET-001" {
					for _, e := range f.Evidence {
						evidence += e.Snippet + "\n"
					}
				}
			}
			if (tt.wantEvidence == "") != (evidence == "") || !strings.Contains(evidence, tt.wantEvidence) {
				t.Errorf("GAL-NET-001 evidence = %q, want it to contain %q", evidence, tt.wantEvidence)
			}
		})
	}
}
