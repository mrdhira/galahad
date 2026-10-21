//go:build galahadtest

package protocol

import "strings"

// GitHTTPHost reports whether a Git job may use plain http for host. In galahadtest builds the
// .test hosts may, so that the tests can serve a repository from a local server. The host proxy
// still applies its allowlist.
func GitHTTPHost(host string) bool { return strings.HasSuffix(strings.ToLower(host), ".test") }
