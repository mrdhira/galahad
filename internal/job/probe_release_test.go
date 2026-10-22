//go:build !galahadtest

package job_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/mrdhira/galahad/internal/job"
)

func TestRunProbeIsNotInRelease(t *testing.T) {
	tests := []struct {
		name string
		// expectations
		wantErr string
	}{
		{name: "a probe job is refused before anything starts", wantErr: "not available in this build"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := &fakeBackend{}
			spec := job.Spec{
				JobsDir: t.TempDir(),
				Now:     func() time.Time { return time.Date(2026, 10, 21, 15, 30, 12, 0, time.UTC) },
				Version: hostVersion,
				Timeout: job.MinTimeout,
				Image:   "core",
				Probe:   "proxy",
			}

			_, err := job.Run(context.Background(), b, spec, "")

			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %v, want one with %q", err, tt.wantErr)
			}
			if b.starts != 0 {
				t.Errorf("starts = %d, want 0", b.starts)
			}
		})
	}
}
