//go:build linux

package agent

import (
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// dropPrivileges makes the whole process uid and gid 1000 with no supplementary groups, and sets
// no_new_privs, so that nothing it runs can gain privileges again. It checks the result and fails
// if the process could still become root; the caller must not go on then. It uses the syscall
// package for the ids and for no_new_privs, because those versions apply to every thread of the
// process. unix.Setgroups and unix.Prctl change the calling thread only. A build with cgo cannot do
// no_new_privs for every thread, so the agent is built with CGO_ENABLED=0 and this call fails otherwise.
func dropPrivileges() error {
	if err := syscall.Setgroups(nil); err != nil {
		return fmt.Errorf("setgroups: %w", err)
	}
	if err := syscall.Setgid(guestID); err != nil {
		return fmt.Errorf("setgid: %w", err)
	}
	if err := syscall.Setuid(guestID); err != nil {
		return fmt.Errorf("setuid: %w", err)
	}
	if _, _, e := syscall.AllThreadsSyscall6(unix.SYS_PRCTL, unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0, 0); e != 0 {
		return fmt.Errorf("no_new_privs: %w", e)
	}
	return CheckDropped(IDs{os.Getuid, os.Geteuid, os.Getgid, os.Getegid, syscall.Setuid}, guestID, guestID)
}
