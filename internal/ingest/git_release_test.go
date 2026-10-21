//go:build !galahadtest

package ingest_test

import (
	"context"
	"strings"
	"testing"

	"github.com/mrdhira/galahad/internal/ingest"
)

func TestGitHTTPIsNotInRelease(t *testing.T) {
	const testURL = "http://git.test/x.git"
	tests := []struct {
		name string
		// inputs
		build func(g ingest.Git) []string // the arguments, the environment, or the error of a clone
		// expectations
		wantHas    string
		wantAbsent string
	}{
		{
			name:    "the clone does not allow http for a .test host",
			build:   func(g ingest.Git) []string { return g.CloneArgs(testURL, "/work/input") },
			wantHas: "protocol.https.allow=always", wantAbsent: "protocol.http.allow",
		},
		{
			name:    "the environment does not allow http for a .test host",
			build:   func(g ingest.Git) []string { return g.Env(testURL) },
			wantHas: "GIT_ALLOW_PROTOCOL=https ", wantAbsent: "https:http",
		},
		{
			name: "a clone of a .test host over http is refused",
			build: func(g ingest.Git) []string {
				_, err := g.Clone(context.Background(), testURL, t.TempDir(), false)
				return []string{err.Error()}
			},
			wantHas: "not an https URL", wantAbsent: "git clone",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := strings.Join(tt.build(ingest.Git{Relay: gitRelay}), " ") + " "
			if !strings.Contains(got, tt.wantHas) || strings.Contains(got, tt.wantAbsent) {
				t.Errorf("got %q, want it to have %q and not %q", got, tt.wantHas, tt.wantAbsent)
			}
		})
	}
}
