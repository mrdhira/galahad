//go:build galahadtest

package agent

import "os"

// testSigDir is the signatures directory of an update outside the VM. In galahadtest builds,
// GALAHAD_TEST_SIG_DIR names it: the same variable that points the guest tools at their signatures.
func testSigDir() string { return os.Getenv("GALAHAD_TEST_SIG_DIR") }

// yaraForgeURL is the download address of the YARA-Forge rules. In galahadtest builds,
// GALAHAD_TEST_YARA_URL replaces the real one, so that the tests can serve a zip from a local server.
// The host proxy still applies its allowlist.
func yaraForgeURL() string {
	if u := os.Getenv("GALAHAD_TEST_YARA_URL"); u != "" {
		return u
	}
	return yaraForgeCoreURL
}
