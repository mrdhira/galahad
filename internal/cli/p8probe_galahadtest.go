//go:build galahadtest

package cli

import "flag"

// addProbeFlag adds the hidden --p8-probe flag of "galahad scan": run the named P8 isolation probe
// in the sandbox instead of scanning. It is not in the usage text. The scan then takes at most one
// argument, an input for the probe.
func addProbeFlag(fs *flag.FlagSet) *string {
	return fs.String("p8-probe", "", "")
}
