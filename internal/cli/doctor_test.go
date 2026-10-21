package cli_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/mrdhira/galahad/internal/cli"
	"github.com/mrdhira/galahad/internal/images"
)

func TestDoctor(t *testing.T) {
	const gib = 1 << 30
	tests := []struct {
		name string
		// inputs
		args        []string
		goos        string      // "" = linux
		goarch      string      // "" = amd64
		pinsErr     bool        //
		homeMode    os.FileMode // 0 = 0700
		homeName    string      // "" = state
		noHome      bool
		homeIsFile  bool
		omit        string // a file the host lacks: firecracker, vmlinux, core.ext4, re.ext4, agent
		corrupt     string // a file with other content than the pins: core.ext4, re.ext4
		fcScript    string // "" = the pinned version
		agentScript string // "" = an agent that prints the version of galahad
		version     string // of galahad; "" = v1.2.3
		stamp       string // content of signatures.stamp; "" = one hour before the clock; "none" = no file
		noSigImage  bool   // signatures.img is missing
		kvm         string // "" = a file that can be opened; "missing", "dir", "denied"
		free        uint64 // 0 = 10 GiB
		freeErr     bool
		skipWindows bool
		skipRoot    bool // root opens any file
		// expectations
		wantCode   int
		wantStdout []string
		wantAbsent []string
	}{
		{
			name: "a ready host passes every check", skipWindows: true,
			wantCode: cli.ExitClean,
			wantStdout: []string{
				"PASS  platform: linux/amd64", "PASS  state directory:", "(0700)", "kvm: readable and writable", "PASS  firecracker: v1.17.0",
				"PASS  vmlinux:", "PASS  core.ext4:", "PASS  re.ext4:", "PASS  signatures: updated 2026-10-21T11:30:12Z",
				"PASS  galahad-agent:", "(version v1.2.3)", "PASS  disk space: 10.0 GiB free",
			},
			wantAbsent: []string{"FAIL", "WARN", "fix:"},
		},
		{
			name: "a missing re image is only a warning", omit: "re.ext4", skipWindows: true,
			wantCode:   cli.ExitClean,
			wantStdout: []string{"WARN  re.ext4:", "is missing; scan --image re needs it", "fix: run galahad setup --image re"},
			wantAbsent: []string{"FAIL"},
		},
		{
			name: "signatures updated six days ago pass", stamp: "2026-10-15T12:30:12Z\n", skipWindows: true,
			wantCode:   cli.ExitClean,
			wantStdout: []string{"PASS  signatures: updated 2026-10-15T12:30:12Z"},
			wantAbsent: []string{"WARN"},
		},
		{
			name: "signatures older than seven days are a warning", stamp: "2026-10-14T12:30:11Z\n", skipWindows: true,
			wantCode:   cli.ExitClean,
			wantStdout: []string{"WARN  signatures: updated 7 days ago, at 2026-10-14T12:30:11Z", "fix: run galahad setup"},
			wantAbsent: []string{"FAIL"},
		},
		{
			name: "signatures that were never updated are a warning", stamp: "none", skipWindows: true,
			wantCode:   cli.ExitClean,
			wantStdout: []string{"WARN  signatures:", "signatures.stamp is missing; ClamAV and YARA are left out of scans", "fix: run galahad setup"},
			wantAbsent: []string{"FAIL"},
		},
		{
			name: "a stamp that holds no time is a warning", stamp: "yesterday\n", skipWindows: true,
			wantCode:   cli.ExitClean,
			wantStdout: []string{"WARN  signatures:", "does not hold a time"},
		},
		{
			name: "a stamp in the future is a warning", stamp: "2026-10-22T12:30:12Z\n", skipWindows: true,
			wantCode:   cli.ExitClean,
			wantStdout: []string{"WARN  signatures: the update time 2026-10-22T12:30:12Z is in the future"},
		},
		{
			name: "a stamp without the image is a warning", noSigImage: true, skipWindows: true,
			wantCode:   cli.ExitClean,
			wantStdout: []string{"WARN  signatures:", "signatures.img is missing", "fix: run galahad setup"},
		},
		{
			name: "an agent of another version fails", agentScript: "#!/bin/sh\necho 'galahad-agent v1.0.0 (abc, go1.27.3, linux/amd64)'\n", skipWindows: true,
			wantCode:   cli.ExitError,
			wantStdout: []string{"FAIL  galahad-agent:", "is version v1.0.0, galahad is v1.2.3", "fix: put the galahad-agent of this release next to galahad"},
		},
		{
			name: "a dev galahad takes any agent version", version: "dev", agentScript: "#!/bin/sh\necho 'galahad-agent v1.0.0 (abc, go1.27.3, linux/amd64)'\n", skipWindows: true,
			wantCode:   cli.ExitClean,
			wantStdout: []string{"PASS  galahad-agent:", "(version v1.0.0)"},
			wantAbsent: []string{"FAIL"},
		},
		{
			name: "an agent that does not run fails", agentScript: "#!/bin/sh\nexit 3\n", skipWindows: true,
			wantCode:   cli.ExitError,
			wantStdout: []string{"FAIL  galahad-agent:", "version failed: exit status 3"},
		},
		{
			name: "an agent that prints something else fails", agentScript: "#!/bin/sh\necho 'hello\\033[2J'\n", skipWindows: true,
			wantCode:   cli.ExitError,
			wantStdout: []string{"FAIL  galahad-agent:", `version printed "hello`},
			wantAbsent: []string{"\x1b"},
		},
		{
			name: "an agent that prints a lot is cut", agentScript: "#!/bin/sh\nyes galahad-agent | head -c 1000000\n", skipWindows: true,
			wantCode:   cli.ExitError,
			wantStdout: []string{"FAIL  galahad-agent:", "version prints more than 4096 bytes"},
		},
		{name: "an extra argument", args: []string{"now"}, wantCode: cli.ExitUsage},
		{
			name: "another system fails and stops", goos: "windows", goarch: "arm64", wantCode: cli.ExitError,
			wantStdout: []string{"FAIL  platform: windows/arm64: Linux only until M5"},
			wantAbsent: []string{"state directory", "PASS"},
		},
		{
			name: "another architecture fails and stops", goarch: "arm64", wantCode: cli.ExitError,
			wantStdout: []string{"FAIL  platform: linux/arm64: Linux amd64 only until M5"},
			wantAbsent: []string{"state directory"},
		},
		{name: "pins that do not load", pinsErr: true, wantCode: cli.ExitError, wantStdout: []string{"FAIL  pins: bad pins"}},
		{
			name: "a state directory that does not exist", noHome: true, wantCode: cli.ExitError,
			wantStdout: []string{"FAIL  state directory:", "does not exist", "fix: run galahad setup"},
		},
		{
			name: "a state directory that is a file", homeIsFile: true, wantCode: cli.ExitError,
			wantStdout: []string{"FAIL  state directory:", "is not a directory"},
		},
		{
			name: "a state directory that others can read", homeMode: 0o755, skipWindows: true, wantCode: cli.ExitError,
			wantStdout: []string{"FAIL  state directory:", "has mode 0755", "fix: chmod 700 "},
		},
		{
			name: "no KVM device", kvm: "missing", wantCode: cli.ExitError,
			wantStdout: []string{"FAIL  ", "does not exist", "VT-x or AMD-V"},
		},
		{
			name: "a KVM device that this user cannot open", kvm: "denied", skipWindows: true, skipRoot: true, wantCode: cli.ExitError,
			wantStdout: []string{"permission denied", "fix: add your user to the kvm group with 'sudo usermod -aG kvm $USER'"},
		},
		{
			name: "a KVM device that fails in another way", kvm: "dir", wantCode: cli.ExitError,
			wantStdout: []string{"FAIL  ", "fix: check that the kvm kernel module is loaded"},
		},
		{
			name: "Firecracker is missing", omit: "firecracker", wantCode: cli.ExitError,
			wantStdout: []string{"FAIL  firecracker:", "is missing", "fix: run galahad setup"},
		},
		{
			name: "Firecracker of another version", fcScript: "#!/bin/sh\necho 'Firecracker v0.1.0'\n", skipWindows: true, wantCode: cli.ExitError,
			wantStdout: []string{"FAIL  firecracker:", `reports "Firecracker v0.1.0", pins.json says v1.17.0`},
		},
		{
			name: "an image file is missing", omit: "vmlinux", skipWindows: true, wantCode: cli.ExitError,
			wantStdout: []string{"FAIL  vmlinux:", "is missing", "fix: run galahad setup"},
			wantAbsent: []string{"FAIL  core.ext4"},
		},
		{
			name: "an image file that does not match the pins", corrupt: "core.ext4", skipWindows: true, wantCode: cli.ExitError,
			wantStdout: []string{"FAIL  core.ext4:", "does not match the raw_sha256", "fix: run galahad setup"},
		},
		{
			name: "a re image that does not match the pins", corrupt: "re.ext4", skipWindows: true, wantCode: cli.ExitError,
			wantStdout: []string{"FAIL  re.ext4:", "fix: run galahad setup --image re"},
		},
		{
			name: "the agent is not next to the executable", omit: "agent", skipWindows: true, wantCode: cli.ExitError,
			wantStdout: []string{"FAIL  galahad-agent:", "is missing", "fix: put galahad-agent in the directory of galahad"},
		},
		{
			name: "too little free space", free: 4 * gib, skipWindows: true, wantCode: cli.ExitError,
			wantStdout: []string{"FAIL  disk space: 4.0 GiB free", "want at least 5 GiB", "fix: free some space"},
		},
		{
			name: "free space that cannot be read", freeErr: true, skipWindows: true, wantCode: cli.ExitError,
			wantStdout: []string{"FAIL  disk space: cannot read the free space of"},
		},
		{
			name: "a path with control characters is cleaned", homeName: "bad\tname", noHome: true, skipWindows: true, wantCode: cli.ExitError,
			wantStdout: []string{`bad\u0009name does not exist`},
			wantAbsent: []string{"\t"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.skipWindows && runtime.GOOS == "windows" {
				t.Skip("needs a shell script or Unix file modes")
			}
			if tt.skipRoot && os.Geteuid() == 0 {
				t.Skip("root can open any file")
			}
			rel := newRelease(t)
			base := t.TempDir()
			home := filepath.Join(base, orDefault(tt.homeName, "state"))
			exe := filepath.Join(base, "bin", "galahad")
			write := func(path string, data []byte, mode os.FileMode) {
				t.Helper()
				if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, data, mode); err != nil { //nolint:gosec // test files; some are scripts
					t.Fatal(err)
				}
			}
			switch {
			case tt.homeIsFile:
				write(home, nil, 0o600)
			case !tt.noHome:
				write(filepath.Join(home, "bin", "firecracker"), []byte(orDefault(tt.fcScript, fakeFirecrackerScript)), 0o755)
				for _, name := range []string{"vmlinux", "core.ext4", "re.ext4"} {
					content := rel.raw[name]
					if tt.corrupt == name {
						content = bytes.Repeat([]byte("x"), len(content))
					}
					write(filepath.Join(home, "images", rel.pins.Version, name), content, 0o600)
				}
				if tt.omit != "" {
					omitted := filepath.Join(home, "images", rel.pins.Version, tt.omit)
					if tt.omit == "firecracker" {
						omitted = filepath.Join(home, "bin", "firecracker")
					}
					if tt.omit != "agent" {
						if err := os.Remove(omitted); err != nil {
							t.Fatal(err)
						}
					}
				}
				if err := os.Chmod(home, orMode(tt.homeMode, 0o700)); err != nil {
					t.Fatal(err)
				}
			}
			if tt.omit != "agent" {
				write(filepath.Join(base, "bin", "galahad-agent"), []byte(orDefault(tt.agentScript, "#!/bin/sh\necho 'galahad-agent v1.2.3 (abc, go1.27.3, linux/amd64)'\n")), 0o755)
			}
			now := time.Date(2026, 10, 21, 12, 30, 12, 0, time.UTC)
			if !tt.noHome && !tt.homeIsFile {
				if !tt.noSigImage {
					write(filepath.Join(home, "signatures.img"), []byte("sig"), 0o600)
				}
				if tt.stamp != "none" {
					write(filepath.Join(home, "signatures.stamp"), []byte(orDefault(tt.stamp, now.Add(-time.Hour).Format(time.RFC3339)+"\n")), 0o600)
				}
				if err := os.Chmod(home, orMode(tt.homeMode, 0o700)); err != nil {
					t.Fatal(err)
				}
			}
			kvm := filepath.Join(base, "kvm")
			switch tt.kvm {
			case "missing":
				kvm = filepath.Join(base, "no-kvm")
			case "dir":
				if err := os.Mkdir(kvm, 0o700); err != nil {
					t.Fatal(err)
				}
			case "denied":
				write(kvm, nil, 0o000)
			default:
				write(kvm, nil, 0o600)
			}
			free := tt.free
			if free == 0 {
				free = 10 * gib
			}
			env := cli.Env{
				Home: home, GOOS: orDefault(tt.goos, "linux"), GOARCH: orDefault(tt.goarch, "amd64"), KVM: kvm, Exe: exe,
				Version: orDefault(tt.version, "v1.2.3"), Now: func() time.Time { return now },
				Pins: func() (images.Pins, error) {
					if tt.pinsErr {
						return images.Pins{}, errors.New("bad pins")
					}
					return rel.pins, nil
				},
				FreeBytes: func(string) (uint64, error) {
					if tt.freeErr {
						return 0, errors.New("statfs failed")
					}
					return free, nil
				},
			}

			var stdout, stderr bytes.Buffer
			code := cli.RunWithEnv(append([]string{"doctor"}, tt.args...), &stdout, &stderr, env)

			if code != tt.wantCode {
				t.Errorf("exit code = %d, want %d\nstdout: %s\nstderr: %s", code, tt.wantCode, stdout.String(), stderr.String())
			}
			for _, w := range tt.wantStdout {
				if !strings.Contains(stdout.String(), w) {
					t.Errorf("stdout lacks %q:\n%s", w, stdout.String())
				}
			}
			for _, w := range tt.wantAbsent {
				if strings.Contains(stdout.String(), w) {
					t.Errorf("stdout has %q:\n%s", w, stdout.String())
				}
			}
		})
	}
}

func orMode(m, def os.FileMode) os.FileMode {
	if m == 0 {
		return def
	}
	return m
}
