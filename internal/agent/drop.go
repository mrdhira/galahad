package agent

import (
	"errors"
	"fmt"
)

// guestID is the uid and gid of the user galahad in the guest image, which the agent runs as.
const guestID = 1000

// IDs are the user and group ids of a process and the call that tries to become root again. They are
// functions so that the check can run in a test without root.
type IDs struct {
	Getuid, Geteuid, Getgid, Getegid func() int
	// Setuid tries to change the uid of the process. After a drop it must fail.
	Setuid func(uid int) error
}

// CheckDropped says whether the process has dropped to uid and gid: all four ids are those, and it
// cannot become root again. The error says which check failed.
func CheckDropped(ids IDs, uid, gid int) error {
	for _, c := range []struct {
		name string
		got  int
		want int
	}{
		{"uid", ids.Getuid(), uid},
		{"euid", ids.Geteuid(), uid},
		{"gid", ids.Getgid(), gid},
		{"egid", ids.Getegid(), gid},
	} {
		if c.got != c.want {
			return fmt.Errorf("the %s is %d, want %d", c.name, c.got, c.want)
		}
	}
	if err := ids.Setuid(0); err == nil {
		return errors.New("the process can still become uid 0")
	}
	return nil
}
