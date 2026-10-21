//go:build galahadtest

package job

import "github.com/mrdhira/galahad/internal/protocol"

func init() {
	artifactNames[protocol.ArtifactProbeJSON] = "probe.json"
}
