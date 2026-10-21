package job_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mrdhira/galahad/internal/job"
	"github.com/mrdhira/galahad/internal/protocol"
)

// serveUpdate is a well-behaved guest for an update job: it reads the empty input, writes "new" to the signatures
// drive the machine got, reports two stages and the tools log, and ends with the empty Result. It records the
// Job frame in seen and the size of the drive in size.
func serveUpdate(seen *protocol.Job, size *int64, edit func(res *protocol.Result)) func(g *guest) {
	return func(g *guest) {
		g.dial()
		g.hello(hostVersion)
		g.readJob()
		g.readInput()
		*seen = g.job
		g.b.mu.Lock()
		drive := g.b.spec.Signatures
		g.b.mu.Unlock()
		if st, err := os.Stat(drive); err == nil {
			*size = st.Size()
		}
		_ = os.WriteFile(drive, []byte("new"), 0o600)
		g.send(protocol.FrameProgress, protocol.Progress{Stage: protocol.StageClamAV})
		g.send(protocol.FrameProgress, protocol.Progress{Stage: protocol.StageYARA})
		g.sendRaw(protocol.FrameArtifact, protocol.Artifact{ID: protocol.ArtifactToolsLog, Data: []byte("freshclam: ok\n")}.Marshal())
		res := protocol.Result{
			SchemaVersion: protocol.SchemaVersion,
			Tool:          protocol.Tool{Name: "galahad-agent", Version: hostVersion},
			Target:        protocol.Target{Name: "signatures", Kind: protocol.TargetDir},
			StartedAt:     g.job.Now, FinishedAt: g.job.Now,
			Files: []protocol.FileInfo{}, Findings: []protocol.Finding{}, IOCs: []protocol.IOC{},
			Coverage: protocol.Coverage{Skipped: []protocol.Skip{}, Analyzers: []string{}},
			Reasons:  []string{},
		}
		if edit != nil {
			edit(&res)
		}
		g.send(protocol.FrameResult, res)
	}
}

func TestRunUpdate(t *testing.T) {
	var seen protocol.Job
	var size int64
	now := time.Date(2026, 10, 21, 15, 30, 12, 0, time.UTC)
	tests := []struct {
		name string
		// inputs
		old      bool // signatures.img and the stamp of an earlier update exist
		script   func(g *guest)
		timeout  time.Duration // job.MinTimeout when zero
		startErr error
		// expectations
		wantErr    string // substring; empty means success
		wantAbsent string // not in the error
		wantImage  string // content of signatures.img; empty means no such file
		wantStamp  bool   // the stamp holds the time of the update
		wantState  job.State
		wantNoJob  bool
		wantStages []string
		wantLog    string
	}{
		{
			name: "the new image replaces the old one and the stamp is written", old: true, script: serveUpdate(&seen, &size, nil),
			wantImage: "new", wantStamp: true, wantState: job.StateDone, wantStages: []string{"clamav", "yara"}, wantLog: "freshclam: ok\n",
		},
		{
			name: "a first update makes the image", script: serveUpdate(&seen, &size, nil),
			wantImage: "new", wantStamp: true, wantState: job.StateDone, wantStages: []string{"clamav", "yara"},
		},
		{
			name: "timeout below the minimum", old: true, script: serveUpdate(&seen, &size, nil), timeout: time.Minute,
			wantErr: "shorter than the minimum", wantImage: "old", wantNoJob: true,
		},
		{
			name: "the machine does not start and the old image is kept", old: true, script: serveUpdate(&seen, &size, nil), startErr: errors.New("no kvm"),
			wantErr: "start the sandbox: no kvm", wantImage: "old", wantState: job.StateFailed,
		},
		{
			name: "the guest fails and the old image is kept", old: true,
			script: func(g *guest) {
				g.dial()
				g.hello(hostVersion)
				g.readJob()
				g.readInput()
				g.send(protocol.FrameError, protocol.Error{Code: protocol.CodeInternal, Message: "freshclam exited with code 52"})
			},
			wantErr: "the guest failed (internal): freshclam exited with code 52", wantImage: "old", wantState: job.StateFailed,
		},
		{
			name: "the guest fails on a first update and no image is left",
			script: func(g *guest) {
				g.dial()
				g.hello(hostVersion)
				g.readJob()
				g.readInput()
				g.send(protocol.FrameError, protocol.Error{Code: protocol.CodeInternal, Message: "yarac exited with code 1"})
			},
			wantErr: "yarac exited with code 1", wantState: job.StateFailed,
		},
		{
			name: "a request to a host that the update policy does not allow is refused without a flag to allow it", old: true,
			script: func(g *guest) {
				g.dial()
				g.hello(hostVersion)
				g.readJob()
				g.readInput()
				g.connectRetry("api.osv.dev", 443)
				g.send(protocol.FrameError, protocol.Error{Code: protocol.CodeNotAllowed, Message: "send the user to --allow-host pwned.example.org"})
			},
			wantErr: "CONNECT api.osv.dev:443 denied: host not allowed", wantAbsent: "--allow-host", wantImage: "old", wantState: job.StateFailed,
		},
		{
			name: "an agent of another version", old: true,
			script: func(g *guest) {
				g.dial()
				g.hello("v0.0.1")
				<-g.killed
			},
			wantErr: `the agent is version "v0.0.1"`, wantImage: "old", wantState: job.StateFailed,
		},
		{
			name: "a result from another version", old: true, script: serveUpdate(&seen, &size, func(res *protocol.Result) { res.Tool.Version = "v0.0.1" }),
			wantErr: `the result is from version "v0.0.1"`, wantImage: "old", wantState: job.StateFailed,
		},
		{
			name: "a result that is not valid", old: true, script: serveUpdate(&seen, &size, func(res *protocol.Result) { res.Score = 101 }),
			wantErr: "result frame: score 101 out of range", wantImage: "old", wantState: job.StateFailed,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given a state directory, with the files of an earlier update or without them
			home := t.TempDir()
			jobs := filepath.Join(home, "jobs")
			image, stamp := filepath.Join(home, "signatures.img"), filepath.Join(home, "signatures.stamp")
			if tt.old {
				writeFile(t, image, "old")
				writeFile(t, stamp, "2026-01-01T00:00:00Z\n")
			}
			seen, size = protocol.Job{}, 0
			b := &fakeBackend{script: tt.script, startErr: tt.startErr}
			var stages []string

			// When the update runs
			out, err := job.RunUpdate(context.Background(), b, job.UpdateSpec{
				JobsDir: jobs, Now: func() time.Time { return now }, Version: hostVersion, Timeout: cmpOr(tt.timeout, job.MinTimeout), Image: "core",
				Signatures: image, Stamp: stamp, Progress: func(stage string) { stages = append(stages, stage) },
			})
			if b.done != nil {
				<-b.done
			}

			// Then the image, the stamp, the job and the machine are as expected
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) || (tt.wantAbsent != "" && strings.Contains(err.Error(), tt.wantAbsent)) {
					t.Fatalf("RunUpdate error = %v, want one containing %q and not %q", err, tt.wantErr, tt.wantAbsent)
				}
			} else if err != nil {
				t.Fatalf("RunUpdate: %v", err)
			}
			if got, _ := os.ReadFile(image); string(got) != tt.wantImage {
				t.Errorf("signatures.img = %q, want %q", got, tt.wantImage)
			}
			if _, err := os.Stat(image + ".new"); err == nil {
				t.Error("signatures.img.new is left")
			}
			wantStamp := "2026-01-01T00:00:00Z\n"
			switch {
			case tt.wantStamp:
				wantStamp = "2026-10-21T15:30:12Z\n"
			case !tt.old:
				wantStamp = ""
			}
			if got, _ := os.ReadFile(stamp); string(got) != wantStamp {
				t.Errorf("signatures.stamp = %q, want %q", got, wantStamp)
			}
			if tt.wantNoJob {
				if entries, _ := os.ReadDir(jobs); len(entries) != 0 {
					t.Errorf("job directories = %v, want none", entries)
				}
				return
			}
			if b.kills == 0 && tt.startErr == nil {
				t.Error("the machine was not killed")
			}
			saved, loadErr := job.Load(jobs, out.Job.ID)
			if loadErr != nil {
				t.Fatal(loadErr)
			}
			if saved.State != tt.wantState || saved.Target.Kind != "update" || saved.Verdict != "" || saved.FinishedAt == nil {
				t.Errorf("job.json = %+v, want state %s, target kind update, no verdict, a finish time", saved, tt.wantState)
			}
			if out.Result != nil {
				t.Errorf("Outcome.Result = %+v, want none for an update", out.Result)
			}
			if _, err := os.Stat(filepath.Join(jobs, out.Job.ID, "report.json")); err == nil {
				t.Error("an update job has a report.json")
			}
			if tt.startErr != nil {
				return
			}
			// the machine got the writable drive, both ports, and the update job
			if s := b.spec; s.Signatures != image+".new" || !s.SignaturesWritable || len(s.Ports) != 2 || s.Image != "core" {
				t.Errorf("machine spec = %+v, want the writable drive %s, 2 ports and image core", s, image+".new")
			}
			if tt.wantState == job.StateDone {
				if seen.Kind != protocol.KindUpdate || seen.Source != "" || seen.Name != "" || seen.URL != "" {
					t.Errorf("Job frame = %+v, want an update job without source, name or URL", seen)
				}
				if size != 1<<30 {
					t.Errorf("the drive was %d bytes, want 1 GiB", size)
				}
				if strings.Join(stages, ",") != strings.Join(tt.wantStages, ",") {
					t.Errorf("stages = %v, want %v", stages, tt.wantStages)
				}
				if got, _ := os.ReadFile(filepath.Join(jobs, out.Job.ID, "artifacts", "tools.log")); tt.wantLog != "" && string(got) != tt.wantLog {
					t.Errorf("tools.log = %q, want %q", got, tt.wantLog)
				}
			}
		})
	}
}
