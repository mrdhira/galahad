//go:build !linux

package acceptance_test

// watchRSS has nothing honest to measure outside Linux: the rusage of a wait status includes the children, and
// macOS and Windows have no /proc. The returned function says -1, which the tests read as "not measured".
func watchRSS(int) (stop func() int64) { return func() int64 { return -1 } }
