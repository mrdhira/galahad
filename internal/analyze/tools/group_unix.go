//go:build unix

package tools

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
)

// ownGroup runs cmd in a process group of its own and makes the kill on a timeout or an
// overflow reach the whole group, so that no child of a tool keeps running or holds the pipes.
func ownGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone // the group is already gone
		}
		return err
	}
}
