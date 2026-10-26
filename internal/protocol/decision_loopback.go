//go:build !galahadtest

package protocol

// DecisionLoopback reports whether a decision provider may use plain http for host. A release
// build never does.
func DecisionLoopback(string) bool { return false }
