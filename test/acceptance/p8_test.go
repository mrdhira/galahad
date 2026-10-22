//go:build vm

package acceptance_test

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// These tests run the P8 probes through the real Firecracker backend, so they need the KVM runner of
// .github/workflows/vm.yml: GALAHAD_HOME holds the pinned images and Firecracker, and galahad-agent is built
// next to galahad by TestMain. Each probe runs in its own VM. The guest observes itself and writes
// artifacts/probe.json; the host side is checked here: the job state, the files on the host, and the host process.

const (
	scratchBytes = 4 << 30 // the scratch drive: a sparse file of 4 GiB
	timeoutSlack = time.Minute
)

// vmHome returns the state directory of the vm job, with the jobs of earlier cases removed.
func vmHome(t *testing.T) string {
	t.Helper()
	home := os.Getenv("GALAHAD_HOME")
	if home == "" {
		t.Fatal("GALAHAD_HOME is not set: these tests need the state directory that scripts/vm/images.sh fills")
	}
	t.Setenv("GALAHAD_SANDBOX", "") // anything but "fake" selects Firecracker
	if err := os.RemoveAll(filepath.Join(home, "jobs")); err != nil {
		t.Fatal(err)
	}
	return home
}

// rootfsSHA256 returns the sha256 of the core image, which the guest boots as its read-only root drive.
func rootfsSHA256(t *testing.T, home string) string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(home, "images", "*", "core.ext4"))
	if err != nil || len(matches) != 1 {
		t.Fatalf("core.ext4 under %s = %v, %v, want exactly one", home, matches, err)
	}
	f, err := os.Open(matches[0]) // #nosec G304 -- the path comes from a glob below the state directory
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }() // read-only
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// scratchStats is the largest scratch.img that was seen while a job ran: its size, and the bytes the host file
// system gave it. A sparse file takes no blocks until the guest writes.
type scratchStats struct {
	size, allocated int64
}

// watchScratch looks at the scratch disks below home every 50 ms until the returned function is called.
func watchScratch(home string) (stop func() scratchStats) {
	var st scratchStats
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		tick := time.NewTicker(50 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-done:
				return
			case <-tick.C:
				matches, _ := filepath.Glob(filepath.Join(home, "jobs", "*", "scratch.img"))
				for _, m := range matches {
					fi, err := os.Stat(m)
					if err != nil {
						continue
					}
					st.size = max(st.size, fi.Size())
					if sys, ok := fi.Sys().(*syscall.Stat_t); ok {
						st.allocated = max(st.allocated, sys.Blocks*512)
					}
				}
			}
		}
	}()
	return func() scratchStats {
		close(done)
		wg.Wait()
		return st
	}
}

// firecrackerRunning reports whether a process named firecracker exists.
func firecrackerRunning() bool {
	comms, _ := filepath.Glob("/proc/[0-9]*/comm")
	for _, c := range comms {
		if b, err := os.ReadFile(c); err == nil && strings.TrimSpace(string(b)) == "firecracker" { // #nosec G304 -- /proc
			return true
		}
	}
	return false
}

// transientFiles lists what Kill has to remove from the job directory.
func transientFiles(t *testing.T, dir string) []string {
	t.Helper()
	var left []string
	for _, pattern := range []string{"fc.sock*", "v.sock*", "scratch.img", "agent.img"} {
		matches, err := filepath.Glob(filepath.Join(dir, pattern))
		if err != nil {
			t.Fatal(err)
		}
		left = append(left, matches...)
	}
	return left
}

func checkForkBomb(t *testing.T, dir string) {
	t.Helper()
	var obs struct {
		Peak  int `json:"peak_processes"`
		Limit int `json:"rlimit_nproc"`
	}
	readProbe(t, dir, "fork-bomb", &obs)
	if obs.Limit != 512 || obs.Peak > obs.Limit || obs.Peak < 100 {
		t.Errorf("fork bomb peak = %d processes, limit = %d, want a peak from 100 up to the limit of 512", obs.Peak, obs.Limit)
	}
}

func checkMemory(t *testing.T, dir string) {
	t.Helper()
	var obs struct {
		PeakMiB int    `json:"peak_mib"`
		CapMiB  int    `json:"cap_mib"`
		EndedBy string `json:"ended_by"`
	}
	readProbe(t, dir, "memory", &obs)
	t.Logf("the memory hog held %d MiB and ended by %q", obs.PeakMiB, obs.EndedBy)
	if obs.PeakMiB <= 0 || obs.PeakMiB >= obs.CapMiB {
		t.Errorf("memory hog held %d MiB of its cap of %d MiB (ended by %q), want the guest to stop it first", obs.PeakMiB, obs.CapMiB, obs.EndedBy)
	}
}

func checkDiskFill(t *testing.T, dir string) {
	t.Helper()
	var obs struct {
		Written   int64  `json:"bytes_written"`
		StoppedBy string `json:"stopped_by"`
	}
	readProbe(t, dir, "disk-fill", &obs)
	if obs.StoppedBy != "ENOSPC" || obs.Written <= 0 || obs.Written > scratchBytes {
		t.Errorf("disk fill wrote %d bytes and stopped by %q, want ENOSPC within the 4 GiB drive", obs.Written, obs.StoppedBy)
	}
}

func checkRootfsWrite(t *testing.T, dir string) {
	t.Helper()
	var obs map[string]string
	readProbe(t, dir, "rootfs-write", &obs)
	for _, key := range []string{"create /galahad-p8", "create /etc/galahad-p8", "create /usr/bin/galahad-p8", "open /etc/passwd for writing"} {
		if obs[key] != "EROFS" {
			t.Errorf("%s = %q, want EROFS", key, obs[key])
		}
	}
	for _, key := range []string{"write /dev/vda", "remount read-write"} {
		if v, ok := obs[key]; !ok || v == "ok" {
			t.Errorf("%s = %q, want it refused", key, v)
		}
	}
}

func checkMounts(t *testing.T, dir string) {
	t.Helper()
	var obs struct {
		FSTypes      []string `json:"fs_types"`
		BlockDevices []string `json:"block_devices"`
	}
	readProbe(t, dir, "mounts", &obs)
	for _, fs := range []string{"9p", "virtiofs", "fuse", "nfs", "cifs"} {
		if slices.Contains(obs.FSTypes, fs) {
			t.Errorf("file system types = %v, want no %s", obs.FSTypes, fs)
		}
	}
	drive := regexp.MustCompile(`^vd[a-d]$`)
	for _, d := range obs.BlockDevices {
		if !drive.MatchString(d) {
			t.Errorf("block devices = %v, want only vda to vdd", obs.BlockDevices)
		}
	}
	for _, d := range []string{"vda", "vdb", "vdc"} {
		if !slices.Contains(obs.BlockDevices, d) {
			t.Errorf("block devices = %v, want %s among them", obs.BlockDevices, d)
		}
	}
}

func checkDirectConnect(t *testing.T, dir string) {
	t.Helper()
	var obs map[string]string
	readProbe(t, dir, "direct-connect", &obs)
	if len(obs) != 2 {
		t.Errorf("direct connects = %v, want 2", obs)
	}
	for addr, got := range obs {
		if got != "ENETUNREACH" {
			t.Errorf("connect to %s = %q, want ENETUNREACH", addr, got)
		}
	}
}

func checkVsock(t *testing.T, dir string) {
	t.Helper()
	var obs map[string]string
	readProbe(t, dir, "vsock", &obs)
	if len(obs) != 11 {
		t.Errorf("vsock dials = %v, want 11", obs)
	}
	for addr, got := range obs {
		t.Logf("vsock %s: %s", addr, got)
		if got == "connected" {
			t.Errorf("vsock %s connected, want it refused", addr)
		}
	}
}

// TestP8VM is the P8 table of docs/milestones/M2.md. The probes that ask for "contained" may end in a Result
// or in a timeout within the time limit; every probe leaves nothing behind on the host.
func TestP8VM(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		probe   string
		timeout time.Duration // --timeout
		input   func(t *testing.T) string
		resolve string // GALAHAD_TEST_RESOLVE
		args    []string
		// expectations
		wantCodes   []int    // exit codes that the row accepts
		wantStates  []string // job states that the row accepts
		wantStderr  string
		wantMinTime time.Duration // the job ran at least this long
		wantProbe   func(t *testing.T, dir string)
	}{
		{
			name:  "fork bomb: the process limit holds and the host gets a Result or a timeout",
			probe: "fork-bomb", timeout: 2 * time.Minute,
			wantCodes: []int{0, 1}, wantStates: []string{"done", "timeout"}, wantProbe: checkForkBomb,
		},
		{
			name:  "memory exhaustion: the guest stops the hog and the host gets a Result or a timeout",
			probe: "memory", timeout: 2 * time.Minute,
			wantCodes: []int{0, 1}, wantStates: []string{"done", "timeout"}, wantProbe: checkMemory,
		},
		{
			name:  "fill the disk: ENOSPC at the scratch drive, and the file is gone after the job",
			probe: "disk-fill", timeout: 5 * time.Minute,
			wantCodes: []int{0}, wantStates: []string{"done"}, wantProbe: checkDiskFill,
		},
		{
			name:  "write to the root filesystem: EROFS, and the image on the host is unchanged",
			probe: "rootfs-write", timeout: 2 * time.Minute,
			wantCodes: []int{0}, wantStates: []string{"done"}, wantProbe: checkRootfsWrite,
		},
		{
			name:  "list mounts and block devices: only vda to vdd, no 9p or virtiofs",
			probe: "mounts", timeout: 2 * time.Minute,
			wantCodes: []int{0}, wantStates: []string{"done"}, wantProbe: checkMounts,
		},
		{
			name:  "direct connect to 1.1.1.1 and 169.254.169.254: ENETUNREACH",
			probe: "direct-connect", timeout: 2 * time.Minute,
			wantCodes: []int{0}, wantStates: []string{"done"}, wantProbe: checkDirectConnect,
		},
		{
			name:  "proxy to metadata, 10/8, localhost and a rebinding name: denied and logged",
			probe: "proxy", timeout: 2 * time.Minute,
			args: []string{"--allow-host", "localhost", "--allow-host", "rebind.test"}, resolve: "rebind.test=10.0.0.1",
			wantCodes: []int{0}, wantStates: []string{"done"}, wantProbe: checkProxyProbe,
		},
		{
			name:  "vsock to other host ports and CIDs: refused",
			probe: "vsock", timeout: 2 * time.Minute,
			wantCodes: []int{0}, wantStates: []string{"done"}, wantProbe: checkVsock,
		},
		{
			name:  "sleep forever: state timeout, exit 1, nothing left behind",
			probe: "sleep", timeout: 2 * time.Minute,
			wantCodes: []int{1}, wantStates: []string{"timeout"}, wantStderr: "timed out", wantMinTime: 2*time.Minute - 2*time.Second,
		},
		{
			name:  "oversize Result: exit 1 and no report",
			probe: "result-oversize", timeout: 2 * time.Minute,
			wantCodes: []int{1}, wantStates: []string{"failed"}, wantStderr: "result frame is 67108865 bytes",
		},
		{
			name:  "Result with an unknown field: exit 1 and no report",
			probe: "result-unknown-field", timeout: 2 * time.Minute,
			wantCodes: []int{1}, wantStates: []string{"failed"}, wantStderr: `unknown field "bogus"`,
		},
		{
			name:  "Result out of order: exit 1 and no report",
			probe: "result-early", timeout: 2 * time.Minute, input: bigInput,
			wantCodes: []int{1}, wantStates: []string{"failed"}, wantStderr: "before the end of the input",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given the image of the root drive, an empty job directory and a probe job
			home := vmHome(t)
			rootfsBefore := rootfsSHA256(t, home)
			if tt.resolve != "" {
				t.Setenv("GALAHAD_TEST_RESOLVE", tt.resolve)
			}
			args := append([]string{"--p8-probe", tt.probe, "--timeout", tt.timeout.String()}, tt.args...)
			if tt.input != nil {
				args = append(args, tt.input(t))
			}

			// When it runs in a real VM, while the scratch disk is watched
			stop := watchScratch(home)
			got := runP8(t, tt.timeout+3*timeoutSlack, args...)
			scratch := stop()

			// Then the host got what the row expects, and left nothing behind
			if !slices.Contains(tt.wantCodes, got.code) {
				t.Fatalf("exit = %d, want one of %v\nstdout: %s\nstderr: %s", got.code, tt.wantCodes, got.stdout, got.stderr)
			}
			if !strings.Contains(got.stderr, tt.wantStderr) {
				t.Errorf("stderr = %q, want it to contain %q", got.stderr, tt.wantStderr)
			}
			if got.elapsed > tt.timeout+timeoutSlack || got.elapsed < tt.wantMinTime {
				t.Errorf("the job took %s, want %s to %s", got.elapsed, tt.wantMinTime, tt.timeout+timeoutSlack)
			}
			dir := onlyJob(t, home)
			state := readJob(t, dir).State
			if !slices.Contains(tt.wantStates, state) {
				t.Errorf("state = %q, want one of %v", state, tt.wantStates)
			}
			if _, err := os.Stat(filepath.Join(dir, "report.json")); err == nil {
				t.Error("report.json exists, want none")
			}
			if got.rss > maxHostRSS {
				t.Errorf("host peak RSS = %d bytes, want under %d", got.rss, int64(maxHostRSS))
			}
			if firecrackerRunning() {
				t.Error("a firecracker process is left")
			}
			if left := transientFiles(t, dir); len(left) > 0 {
				t.Errorf("transient files are left in the job directory: %v", left)
			}
			if scratch.size == 0 || scratch.size > scratchBytes || scratch.allocated > scratchBytes {
				t.Errorf("scratch.img was seen at %d bytes with %d allocated, want it seen and at most %d", scratch.size, scratch.allocated, int64(scratchBytes))
			}
			if after := rootfsSHA256(t, home); after != rootfsBefore {
				t.Errorf("the root image changed: sha256 %s, was %s", after, rootfsBefore)
			}
			if tt.wantProbe != nil && state == "done" {
				tt.wantProbe(t, dir)
			}
		})
	}
}
