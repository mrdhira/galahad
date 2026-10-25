//go:build galahadtest

package protocol

// DecisionLoopback reports whether a decision provider may use plain http for host. In
// galahadtest builds the loopback addresses may, so that the tests can serve the API from a local
// httptest server.
func DecisionLoopback(host string) bool { return host == "127.0.0.1" || host == "::1" }
