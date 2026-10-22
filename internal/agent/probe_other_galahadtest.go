//go:build galahadtest && !linux

package agent

import "errors"

// The probes that start processes or change mounts work on Linux only, where the guest runs.
var errProbeLinux = errors.New("this probe runs on Linux only")

func forkBomb(probeEnv) (map[string]any, error)    { return nil, errProbeLinux }
func memoryHog(probeEnv) (map[string]any, error)   { return nil, errProbeLinux }
func rootfsWrite(probeEnv) (map[string]any, error) { return nil, errProbeLinux }
