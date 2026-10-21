package cli

import "golang.org/x/sys/unix"

// freeBytes returns the space available to this user on the file system that holds dir.
func freeBytes(dir string) (uint64, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return 0, err
	}
	return st.Bavail * uint64(st.Bsize), nil // #nosec G115 -- a block size is positive
}
