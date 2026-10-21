//go:build !unix

package tools

import "os/exec"

// ownGroup does nothing here: the tools only run in the Linux guest, and the kill reaches the
// process itself.
func ownGroup(*exec.Cmd) {}
