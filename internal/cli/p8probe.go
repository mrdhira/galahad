//go:build !galahadtest

package cli

import "flag"

// addProbeFlag adds the hidden --p8-probe flag of "galahad scan". A release build has none, so the
// flag is rejected as unknown. The returned name is always empty.
func addProbeFlag(*flag.FlagSet) *string { return new(string) }
