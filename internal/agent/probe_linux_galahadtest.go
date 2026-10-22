//go:build galahadtest && linux

package agent

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Limits of the probes that start processes.
const (
	bombTime       = 10 * time.Second
	bombSample     = 200 * time.Millisecond
	bombIterations = 3000 // the shell starts at most this many sleeps, even if the system allowed it
	bombHeadroom   = 32   // processes of the user that the bomb leaves to the agent, which has threads of its own
	hogEnv         = "GALAHAD_PROBE_CHILD"
	hogStep        = 64 << 20 // bytes allocated and touched at a time
	hogMax         = 4 << 30  // the guest has less memory than this, so the kernel ends the hog first
	hogTime        = 45 * time.Second
)

// bombScript starts sleeps in the background as fast as the shell can, at most bombIterations of them.
// The arguments are the process limit of the shell and the number of iterations. Each sleep ends after
// 30 s on its own, and the probe kills the whole process group after bombTime.
const bombScript = `ulimit -u %d; i=0; while [ "$i" -lt %d ]; do /bin/busybox sleep 30 & i=$((i+1)); done; wait`

// forkBomb runs a shell, with the credentials of the agent, that starts processes in a loop, and counts
// the processes of that user. The process limit that galahad-init sets has to hold the count. The agent
// is a thread-using process of the same user, so the shell lowers its own limit by bombHeadroom: the
// agent must be able to start a thread while the bomb is at its limit.
func forkBomb(env probeEnv) (map[string]any, error) {
	var lim unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NPROC, &lim); err != nil {
		return nil, fmt.Errorf("read the process limit: %w", err)
	}
	script := fmt.Sprintf(bombScript, int64(lim.Cur)-bombHeadroom, bombIterations)
	cmd := exec.Command("/bin/busybox", "sh", "-c", script) // #nosec G204 -- a fixed script
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start the fork bomb: %w", err)
	}
	// Read at once: the shell exits when a fork fails, which can be before the first sample.
	identity := procIdentity(fmt.Sprintf("/proc/%d/status", cmd.Process.Pid))
	exited := make(chan struct{})
	go func() {
		_ = cmd.Wait() // how the shell ended does not matter; the count says what happened
		close(exited)
	}()

	peak := 0
	tick := time.NewTicker(bombSample)
	defer tick.Stop()
	end := time.NewTimer(min(bombTime, time.Until(env.deadline)))
	defer end.Stop()
sampling:
	for {
		select {
		case <-tick.C:
			peak = max(peak, countProcesses(os.Getuid()))
		case <-end.C:
			break sampling
		}
	}
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) // the shell and its sleeps; best effort
	<-exited
	return map[string]any{"peak_processes": peak, "rlimit_nproc": lim.Cur, "bomb": identity}, nil
}

// countProcesses counts the processes whose real user is uid, by the Uid line of /proc/<pid>/status.
func countProcesses(uid int) int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0
	}
	want := "Uid:\t" + strconv.Itoa(uid) + "\t"
	n := 0
	for _, e := range entries {
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		status, err := os.ReadFile("/proc/" + e.Name() + "/status") // #nosec G304 -- /proc
		if err != nil {
			continue // the process is gone
		}
		for line := range strings.Lines(string(status)) {
			if strings.HasPrefix(line, "Uid:") {
				if strings.HasPrefix(line, want) {
					n++
				}
				break
			}
		}
	}
	return n
}

// init turns the agent into the memory hog when memoryHog started it as a child.
func init() {
	if os.Getenv(hogEnv) == "hog" {
		runHog()
	}
}

// runHog allocates and touches memory in steps of hogStep, up to hogMax, and prints the MiB it holds
// after each step. It asks the kernel to pick it first when memory runs out. It does not return.
func runHog() {
	_ = os.WriteFile("/proc/self/oom_score_adj", []byte("1000"), 0o600) // best effort
	held := make([][]byte, 0, hogMax/hogStep)
	for total := 0; total < hogMax; total += hogStep {
		b := make([]byte, hogStep)
		for i := 0; i < len(b); i += os.Getpagesize() {
			b[i] = 1
		}
		held = append(held, b)
		fmt.Println((total + hogStep) >> 20)
	}
	_ = held
	os.Exit(0)
}

// memoryHog runs the agent as a child that eats memory, and reports how far it got and how it ended.
// The child is the one the kernel kills, so the agent lives on to report. The child is also cut off
// at hogTime and at hogMax.
func memoryHog(env probeEnv) (map[string]any, error) {
	exe, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("find the agent: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), min(hogTime, time.Until(env.deadline)))
	defer cancel()
	cmd := exec.CommandContext(ctx, exe) // #nosec G204 -- the agent itself
	cmd.Env = []string{hogEnv + "=hog"}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("pipe the hog: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start the hog: %w", err)
	}
	peak := 0
	sc := bufio.NewScanner(out)
	for sc.Scan() {
		if n, err := strconv.Atoi(sc.Text()); err == nil {
			peak = max(peak, n)
		}
	}
	err = cmd.Wait()
	endedBy := "cap"
	var exit *exec.ExitError
	switch {
	case ctx.Err() != nil:
		endedBy = "deadline"
	case errors.As(err, &exit):
		if ws, ok := exit.Sys().(syscall.WaitStatus); ok && ws.Signaled() && ws.Signal() == syscall.SIGKILL {
			endedBy = "killed"
		} else {
			endedBy = "exit: " + exit.Error()
		}
	case err != nil:
		return nil, fmt.Errorf("wait for the hog: %w", err)
	}
	return map[string]any{"peak_mib": peak, "cap_mib": hogMax >> 20, "ended_by": endedBy}, nil
}

// rootfsWrite tries to change the root filesystem in every way it can: create files, open a file for
// writing, write to the root drive itself, and remount read-write. Every try has to fail.
func rootfsWrite(probeEnv) (map[string]any, error) {
	obs := map[string]any{}
	for _, p := range []string{"/galahad-p8", "/etc/galahad-p8", "/usr/bin/galahad-p8"} {
		f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- fixed names
		if err != nil {
			obs["create "+p] = errName(err)
			continue
		}
		_ = f.Close()
		_ = os.Remove(p)
		obs["create "+p] = "ok"
	}
	obs["open /etc/passwd for writing"] = openForWriting("/etc/passwd", nil)
	// The first sector of an ext4 drive is unused, so a write that went through would leave it working.
	obs["write /dev/vda"] = openForWriting("/dev/vda", []byte("galahad p8 probe: the root drive was writable\n"))
	if err := syscall.Mount("", "/", "", syscall.MS_REMOUNT, ""); err != nil {
		obs["remount read-write"] = errName(err)
	} else {
		obs["remount read-write"] = "ok"
		_ = syscall.Mount("", "/", "", syscall.MS_REMOUNT|syscall.MS_RDONLY, "") // put it back
	}
	// The agent is not root, so the creates see EACCES as well as EROFS. These two show that the file
	// system itself is read-only.
	obs["root mount options"] = rootMountOptions()
	ro, err := os.ReadFile("/sys/block/vda/ro")
	if err != nil {
		return nil, err
	}
	obs["/sys/block/vda/ro"] = strings.TrimSpace(string(ro))
	return obs, nil
}

// rootMountOptions returns the options of the last mount of "/" in /proc/mounts.
func rootMountOptions() string {
	data, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return errName(err)
	}
	options := "no mount of /"
	for line := range strings.Lines(string(data)) {
		if f := strings.Fields(line); len(f) >= 4 && f[1] == "/" {
			options = f[3]
		}
	}
	return options
}

// openForWriting opens path for writing and writes data to it if it is not nil. It says what failed, or "ok".
func openForWriting(path string, data []byte) string {
	f, err := os.OpenFile(path, os.O_WRONLY, 0) // #nosec G304 -- fixed names
	if err != nil {
		return errName(err)
	}
	defer func() { _ = f.Close() }() // never written unless the write below went through
	if data != nil {
		if _, err := f.WriteAt(data, 0); err != nil {
			return errName(err)
		}
	}
	return "ok"
}
