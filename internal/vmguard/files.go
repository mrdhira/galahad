package vmguard

import (
	"io"
	"os"
	"strings"
)

// exists reports whether path exists.
func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// readSmall returns at most 64 KiB of the file, trimmed, or "" when it cannot be read.
func readSmall(path string) string {
	f, err := os.Open(path) // #nosec G304 -- fixed system paths
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }() // read-only file
	b, _ := io.ReadAll(io.LimitReader(f, 64<<10))
	return strings.TrimSpace(string(b))
}

// maxMounts is the most WindowsMounts reads. /proc/mounts is a trusted kernel file, so the limit is generous.
const maxMounts = 16 << 20

// WindowsMounts reports whether mounts, in /proc/mounts format, lists a mount of a Windows drive: a source
// such as C:\ (shown as C:\134), drvfs, 9p with aname=drvfs, or 9p or virtiofs at /mnt/<letter>.
// Input longer than 16 MiB counts as a Windows mount, because the rest cannot be checked.
func WindowsMounts(mounts io.Reader) bool {
	b, _ := io.ReadAll(io.LimitReader(mounts, maxMounts+1))
	if len(b) > maxMounts {
		return true
	}
	for line := range strings.SplitSeq(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		source, point, fstype, opts := f[0], f[1], f[2], f[3]
		if isDriveSource(source) || fstype == "drvfs" ||
			(fstype == "9p" && strings.Contains(opts, "aname=drvfs")) ||
			((fstype == "9p" || fstype == "virtiofs") && isDriveMount(point)) {
			return true
		}
	}
	return false
}

// isDriveSource reports whether source starts with a drive letter and a colon.
func isDriveSource(source string) bool {
	return len(source) >= 2 && source[1] == ':' && isLetter(source[0])
}

// isDriveMount reports whether point is /mnt/<letter>.
func isDriveMount(point string) bool {
	letter, ok := strings.CutPrefix(point, "/mnt/")
	return ok && len(letter) == 1 && isLetter(letter[0])
}

func isLetter(c byte) bool { return c|0x20 >= 'a' && c|0x20 <= 'z' }
