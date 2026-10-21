package agent

import (
	"context"
	"fmt"

	"github.com/mrdhira/galahad/internal/ingest"
	"github.com/mrdhira/galahad/internal/protocol"
)

// cloneRepo clones the git target of job into dir through the relay at relayAddr, and sends the
// log of the clone to the host as ingest.log, also when the clone failed.
func cloneRepo(ctx context.Context, host *hostConn, job protocol.Job, relayAddr, dir string) error {
	log, err := ingest.Git{Relay: relayAddr}.Clone(ctx, job.URL, dir, job.Submodules)
	if log != "" {
		a := protocol.Artifact{ID: protocol.ArtifactIngestLog, Data: []byte(log)}
		if sendErr := host.send(protocol.FrameArtifact, a.Marshal()); sendErr != nil && err == nil {
			return fmt.Errorf("send ingest.log: %w", sendErr)
		}
	}
	return err
}
