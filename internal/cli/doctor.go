package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/mrdhira/galahad/internal/config"
	"github.com/mrdhira/galahad/internal/images"
	"github.com/mrdhira/galahad/internal/protocol"
)

// minFreeBytes is the free space doctor asks for: the images unpack to about 0.4 GiB (core) or
// 1.6 GiB (re), and a scan needs a scratch disk.
const minFreeBytes = 5 << 30

const kvmDevice = "/dev/kvm"

// Statuses of a doctor line. Only a FAIL makes doctor exit with 1.
const (
	pass = "PASS"
	warn = "WARN"
	fail = "FAIL"
)

// finding is one line of the doctor report.
type finding struct {
	status string
	name   string
	detail string
	fix    string // what to do about a WARN or FAIL
}

// runDoctor checks the host and prints one PASS, WARN or FAIL line per check. It exits with 1
// when a check fails.
func runDoctor(args []string, stdout, stderr io.Writer, env Env) int {
	flags := flag.NewFlagSet("doctor", flag.ContinueOnError)
	pos, code, done := parseArgs("doctor", flags, args, stdout, stderr)
	if done {
		return code
	}
	if len(pos) > 0 {
		fmt.Fprintf(stderr, "galahad doctor: unexpected argument %q\n\n%s", protocol.CleanPath(pos[0]), usage)
		return ExitUsage
	}

	var findings []finding
	if name, problem := env.platform(); problem != "" {
		// Nothing else applies on this system.
		findings = []finding{{fail, "platform", name + ": " + problem, ""}}
	} else {
		findings = append(findings, finding{pass, "platform", name, ""})
		findings = append(findings, env.doctorHost()...)
	}

	code = ExitClean
	for _, f := range findings {
		fmt.Fprintln(stdout, protocol.CleanPath(fmt.Sprintf("%-4s  %s: %s", f.status, f.name, f.detail)))
		if f.fix != "" {
			fmt.Fprintln(stdout, protocol.CleanPath("      fix: "+f.fix))
		}
		if f.status == fail {
			code = ExitError
		}
	}
	return code
}

// doctorHost runs the checks that need Linux, in the order they are printed.
func (e Env) doctorHost() []finding {
	home, err := e.home()
	if err != nil {
		return []finding{{fail, "state directory", err.Error(), "set GALAHAD_HOME"}}
	}
	pins, err := e.pins()
	if err != nil {
		return []finding{{fail, "pins", err.Error(), "reinstall galahad"}}
	}
	fcPath := filepath.Join(config.BinDir(home), "firecracker")

	out := []finding{e.checkHome(home), e.checkKVM()}
	out = append(out, checkFirecracker(fcPath, pins.Firecracker))
	out = append(out, checkImages(filepath.Join(config.ImagesDir(home), pins.Version), pins)...)
	out = append(out, e.checkSignatures(home), e.checkAgent(), e.checkDisk(home))
	return out
}

// checkHome wants a directory that nobody but the owner can use, as setup makes it.
func (e Env) checkHome(home string) finding {
	st, err := os.Stat(home)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return finding{fail, "state directory", home + " does not exist", "run galahad setup"}
	case err != nil:
		return finding{fail, "state directory", err.Error(), "make " + home + " a directory you own, mode 0700"}
	case !st.IsDir():
		return finding{fail, "state directory", home + " is not a directory", "move it away, then run galahad setup"}
	case st.Mode().Perm()&0o077 != 0:
		return finding{fail, "state directory", fmt.Sprintf("%s has mode %04o, others can read it", home, st.Mode().Perm()), "chmod 700 " + home}
	}
	return finding{pass, "state directory", home + " (0700)", ""}
}

// checkKVM opens the device read-write, as Firecracker does.
func (e Env) checkKVM() finding {
	dev := e.KVM
	if dev == "" {
		dev = kvmDevice
	}
	f, err := os.OpenFile(dev, os.O_RDWR, 0) // #nosec G304 -- the device path is /dev/kvm, or set by a test
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return finding{fail, dev, "does not exist",
			"turn on VT-x or AMD-V in the BIOS and load the kvm_intel or kvm_amd module; in a virtual machine, turn on nested virtualization"}
	case errors.Is(err, fs.ErrPermission):
		return finding{fail, dev, "cannot be opened for reading and writing: permission denied",
			"add your user to the kvm group with 'sudo usermod -aG kvm $USER', then log out and in again"}
	case err != nil:
		return finding{fail, dev, err.Error(), "check that the kvm kernel module is loaded"}
	}
	_ = f.Close() // opened only to see that it can be
	return finding{pass, dev, "readable and writable", ""}
}

func checkFirecracker(path string, pin images.Firecracker) finding {
	err := images.VerifyFirecracker(context.Background(), path, pin)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return finding{fail, "firecracker", path + " is missing", "run galahad setup"}
	case err != nil:
		return finding{fail, "firecracker", path + ": " + err.Error(), "run galahad setup"}
	}
	return finding{pass, "firecracker", pin.Version + " at " + path, ""}
}

// checkImages verifies each pinned image file. The re image is optional.
func checkImages(dir string, pins images.Pins) []finding {
	var out []finding
	for _, a := range pins.Assets {
		path := filepath.Join(dir, a.File)
		optional := a.File == "re.ext4"
		err := images.VerifyAsset(dir, a)
		switch {
		case err == nil:
			out = append(out, finding{pass, a.File, path + " matches the pins", ""})
		case errors.Is(err, fs.ErrNotExist) && optional:
			out = append(out, finding{warn, a.File, path + " is missing; scan --image re needs it", "run galahad setup --image re"})
		case errors.Is(err, fs.ErrNotExist):
			out = append(out, finding{fail, a.File, path + " is missing", "run galahad setup"})
		default:
			fix := "run galahad setup"
			if optional {
				fix += " --image re"
			}
			out = append(out, finding{fail, a.File, path + ": " + err.Error(), fix})
		}
	}
	return out
}

// Limits of the check of the agent: it only has to print its version.
const (
	agentVersionTimeout = 10 * time.Second
	maxAgentVersionText = 4 << 10
)

// checkAgent looks for galahad-agent next to this executable, where the sandbox expects it, runs
// "galahad-agent version" and compares the version with this program. A dev build of this program
// takes any agent version, as the job runner does.
func (e Env) checkAgent() finding {
	exe := e.Exe
	if exe == "" {
		var err error
		if exe, err = os.Executable(); err != nil {
			return finding{fail, "galahad-agent", "cannot find this executable: " + err.Error(), ""}
		}
	}
	agent := filepath.Join(filepath.Dir(exe), "galahad-agent")
	if st, err := os.Stat(agent); err != nil || !st.Mode().IsRegular() {
		return finding{fail, "galahad-agent", agent + " is missing", "put galahad-agent in the directory of galahad ('make build' writes both to bin/)"}
	}
	got, err := agentVersion(agent)
	if err != nil {
		return finding{fail, "galahad-agent", agent + ": " + err.Error(), "put the galahad-agent of this release next to galahad ('make build' writes both to bin/)"}
	}
	if want := e.version(); want != "dev" && got != want {
		return finding{fail, "galahad-agent", fmt.Sprintf("%s is version %s, galahad is %s", agent, got, want),
			"put the galahad-agent of this release next to galahad ('make build' writes both to bin/)"}
	}
	return finding{pass, "galahad-agent", fmt.Sprintf("%s (version %s)", agent, got), ""}
}

// agentVersion runs the agent with "version" and returns the version it prints in its first line,
// "galahad-agent <version> (...)". The run has a time limit and the output is capped.
func agentVersion(agent string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), agentVersionTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, agent, "version") // #nosec G204 -- the agent next to this executable
	out, err := cmd.StdoutPipe()
	if err != nil {
		return "", err
	}
	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("cannot run: %w", err)
	}
	text, _ := io.ReadAll(io.LimitReader(out, maxAgentVersionText+1)) // a failed read shows up as unexpected output
	if len(text) > maxAgentVersionText {
		cancel() // it would block on a full pipe until the time limit
		_ = cmd.Wait()
		return "", fmt.Errorf("version prints more than %d bytes", maxAgentVersionText)
	}
	if err := cmd.Wait(); err != nil {
		return "", fmt.Errorf("version failed: %w", err)
	}
	first, _, _ := strings.Cut(string(text), "\n")
	fields := strings.Fields(first)
	if len(fields) < 2 || fields[0] != "galahad-agent" {
		return "", fmt.Errorf("version printed %q, want \"galahad-agent <version> ...\"", protocol.CleanPath(first))
	}
	return fields[1], nil
}

// signaturesMaxAge is how old the signatures may get before doctor warns. ClamAV publishes daily.
const signaturesMaxAge = 7 * 24 * time.Hour

// maxStampBytes is how much of the stamp file is read.
const maxStampBytes = 64

// checkSignatures reads the stamp the host writes after a good update. The signatures image is
// written by the guest, so the host never reads it. A missing or old stamp is only a warning:
// scans still run, and the report says which tools were left out.
func (e Env) checkSignatures(home string) finding {
	const fix = "run galahad setup"
	stamp := config.SignaturesStamp(home)
	f, err := os.Open(stamp) // #nosec G304 -- a fixed name in the state directory
	if errors.Is(err, fs.ErrNotExist) {
		return finding{warn, "signatures", stamp + " is missing; ClamAV and YARA are left out of scans", fix}
	}
	if err != nil {
		return finding{warn, "signatures", err.Error(), fix}
	}
	text, err := io.ReadAll(io.LimitReader(f, maxStampBytes))
	_ = f.Close() // read-only
	if err != nil {
		return finding{warn, "signatures", err.Error(), fix}
	}
	at, err := time.Parse(time.RFC3339, strings.TrimSpace(string(text)))
	if err != nil {
		return finding{warn, "signatures", stamp + " does not hold a time", fix}
	}
	if st, err := os.Stat(config.SignaturesPath(home)); err != nil || !st.Mode().IsRegular() {
		return finding{warn, "signatures", config.SignaturesPath(home) + " is missing", fix}
	}
	age := e.Now().Sub(at)
	switch {
	case age < 0:
		return finding{warn, "signatures", "the update time " + at.Format(time.RFC3339) + " is in the future", fix}
	case age > signaturesMaxAge:
		return finding{warn, "signatures", fmt.Sprintf("updated %d days ago, at %s", int(age.Hours()/24), at.Format(time.RFC3339)), fix}
	}
	return finding{pass, "signatures", "updated " + at.Format(time.RFC3339), ""}
}

// checkDisk wants minFreeBytes free where the state directory is, or would be.
func (e Env) checkDisk(home string) finding {
	free := e.FreeBytes
	if free == nil {
		free = freeBytes
	}
	dir := home
	for {
		if _, err := os.Stat(dir); err == nil {
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	n, err := free(dir)
	switch {
	case err != nil:
		return finding{fail, "disk space", "cannot read the free space of " + dir + ": " + err.Error(), ""}
	case n < minFreeBytes:
		return finding{fail, "disk space", fmt.Sprintf("%.1f GiB free at %s, want at least %d GiB", float64(n)/(1<<30), dir, minFreeBytes>>30),
			"free some space, or set GALAHAD_HOME to a directory on a larger disk"}
	}
	return finding{pass, "disk space", fmt.Sprintf("%.1f GiB free at %s", float64(n)/(1<<30), dir), ""}
}
