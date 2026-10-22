//go:build galahadtest

package job_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mrdhira/galahad/internal/job"
	"github.com/mrdhira/galahad/internal/protocol"
)

// bigTarget is a folder with a file too big for the pipe of the test, so the host is still writing it
// when the guest answers.
func bigTarget(t *testing.T) string {
	dir := filepath.Join(t.TempDir(), "proj")
	writeFile(t, filepath.Join(dir, "big.bin"), strings.Repeat("x", 3<<20))
	return dir
}

func TestRunProbe(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		target   func(t *testing.T) string // nil: the probe has no input
		requests func(g *guest)            // the requests the probe makes
		answer   func(g *guest)            // instead of a guest that reads the input first
		// expectations
		wantErr     string // substring; empty means success
		wantEntries []string
		wantBlocked bool
	}{
		{
			name:        "a probe job without input has an empty stream and ends done without a report",
			wantEntries: []string{},
		},
		{
			name:        "a probe job with a target sends it as the input",
			target:      dirTarget,
			wantEntries: []string{"proj/", "proj/main.go", "proj/sub/", "proj/sub/a.txt"},
		},
		{
			name:        "a request the host proxy blocks is noted in job.json",
			requests:    func(g *guest) { g.connectRetry("10.1.2.3", 443) },
			wantEntries: []string{},
			wantBlocked: true,
		},
		{
			name:   "a Result before the end of the input fails the job",
			target: bigTarget,
			answer: func(g *guest) {
				g.dial()
				g.hello(hostVersion)
				g.readJob()
				g.send(protocol.FrameResult, g.result(hostVersion))
			},
			wantErr: "before the end of the input",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given a probe job and a scripted guest
			b := &fakeBackend{}
			var seen protocol.Job
			b.script = serveNet(func(g *guest) {
				seen = g.job
				if tt.requests != nil {
					tt.requests(g)
				}
			}, nil)
			if tt.answer != nil {
				b.script = tt.answer
			}
			spec := job.Spec{
				JobsDir: t.TempDir(),
				Now:     func() time.Time { return time.Date(2026, 10, 21, 15, 30, 12, 0, time.UTC) },
				Version: hostVersion,
				Timeout: job.MinTimeout,
				Image:   "core",
				Probe:   "proxy",
			}
			target := ""
			if tt.target != nil {
				target = tt.target(t)
			}

			// When it runs
			out, err := job.Run(context.Background(), b, spec, target)
			<-b.done

			// Then the guest got a probe job, and the job ends done with no Result, or fails
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want one with %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if seen.Kind != protocol.KindProbe || seen.Name != "proxy" || seen.Source != "" {
				t.Errorf("job = %+v, want kind %s, name proxy, no source", seen, protocol.KindProbe)
			}
			if out.Result != nil || out.Job.State != job.StateDone || out.Job.ExitCode != 0 {
				t.Errorf("result = %v, state = %s, exit = %d, want no result, done and 0", out.Result, out.Job.State, out.Job.ExitCode)
			}
			if out.Job.Target != (job.Target{Input: "proxy", Kind: "probe"}) {
				t.Errorf("target = %+v, want the probe", out.Job.Target)
			}
			if out.Job.Blocked != tt.wantBlocked {
				t.Errorf("blocked = %v, want %v", out.Job.Blocked, tt.wantBlocked)
			}
			var entries []string
			for name := range b.input {
				entries = append(entries, name)
			}
			if len(entries) != len(tt.wantEntries) {
				t.Errorf("input entries = %v, want %v", entries, tt.wantEntries)
			}
			for _, e := range tt.wantEntries {
				if _, ok := b.input[e]; !ok {
					t.Errorf("input has no entry %q: %v", e, entries)
				}
			}
		})
	}
}
