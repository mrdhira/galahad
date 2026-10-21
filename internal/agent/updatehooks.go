//go:build !galahadtest

package agent

// testSigDir is the signatures directory of an update outside the VM. A release build has none.
func testSigDir() string { return "" }

// yaraForgeURL is the download address of the YARA-Forge rules.
func yaraForgeURL() string { return yaraForgeCoreURL }
