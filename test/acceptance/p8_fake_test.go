package acceptance_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// P8 answers "does a compromised guest or a hostile input stay contained, and is it reported?". The probes
// of the guest (internal/agent/probe*.go, galahadtest builds only) run through "galahad scan --p8-probe NAME".
// The probes that push at the limits of a machine run only in a VM, so p8_test.go (the vm tag) runs them
// through Firecracker. The ones below also run through the fake sandbox, so the gate covers them: the
// requests through the proxy, the Results the host has to refuse, and the refusal to run the others here.

const (
	p8Timeout  = 2 * time.Minute // the shortest time limit of a job
	maxHostRSS = 1 << 30         // bytes; the host must not grow with what a hostile guest sends
)

// p8Run is one run of "galahad scan --p8-probe".
type p8Run struct {
	stdout, stderr string
	code           int
	rss            int64 // peak resident set of the galahad process in bytes; -1 when the system does not say
	elapsed        time.Duration
}

// runP8 runs "galahad scan args..." and waits at most limit.
func runP8(t *testing.T, limit time.Duration, args ...string) p8Run {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), limit)
	defer cancel()
	cmd := exec.CommandContext(ctx, binPath, append([]string{"scan"}, args...)...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	start := time.Now()
	err := cmd.Run()
	if ctx.Err() != nil {
		t.Fatalf("scan %v: still running after %s\nstderr: %s", args, limit, stderr.String())
	}
	run := p8Run{stdout: stdout.String(), stderr: stderr.String(), elapsed: time.Since(start), rss: maxRSS(cmd.ProcessState)}
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			t.Fatalf("scan %v: %v", args, err)
		}
		run.code = ee.ExitCode()
	}
	return run
}

// readProbe decodes artifacts/probe.json of the job in dir, checks that it is the file of the probe name, and
// decodes its observations into observations. Only tests parse this file.
func readProbe(t *testing.T, dir, name string, observations any) {
	t.Helper()
	var rep struct {
		Probe        string          `json:"probe"`
		Observations json.RawMessage `json:"observations"`
	}
	data := readFile(t, filepath.Join(dir, "artifacts", "probe.json"))
	if err := json.Unmarshal([]byte(data), &rep); err != nil {
		t.Fatalf("probe.json %q: %v", data, err)
	}
	if rep.Probe != name {
		t.Fatalf("probe.json is for probe %q, want %q", rep.Probe, name)
	}
	if err := json.Unmarshal(rep.Observations, observations); err != nil {
		t.Fatalf("observations %s: %v", rep.Observations, err)
	}
}

// p8Denied is what the host proxy must say about each request of the proxy probe.
var p8Denied = map[string]string{
	"169.254.169.254:443": "metadata",
	"10.1.2.3:443":        "private",
	"localhost:443":       "loopback",
	"rebind.test:443":     "private",
}

// proxyLogLine mirrors the parts of a line of proxy.log that the tests read.
type proxyLogLine struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Decision string `json:"decision"`
	Reason   string `json:"reason"`
}

// checkProxyProbe checks the four requests of the proxy probe: the guest was told "denied", the host logged each
// one in proxy.log, and job.json says that a request was blocked.
func checkProxyProbe(t *testing.T, dir string) {
	t.Helper()
	var obs map[string]probeResult
	readProbe(t, dir, "proxy", &obs)
	if len(obs) != len(p8Denied) {
		t.Errorf("observations = %+v, want %d requests", obs, len(p8Denied))
	}
	var logged []proxyLogLine
	for _, line := range strings.Split(strings.TrimSpace(readFile(t, filepath.Join(dir, "proxy.log"))), "\n") {
		var e proxyLogLine
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("proxy.log line %q: %v", line, err)
		}
		logged = append(logged, e)
	}
	for target, reason := range p8Denied {
		if got := obs[target]; got.Status != 403 || got.Body != "denied: "+reason || got.Error != "" {
			t.Errorf("guest saw %s = %+v, want 403 denied: %s", target, got, reason)
		}
		host, _, _ := strings.Cut(target, ":")
		found := false
		for _, e := range logged {
			found = found || (e.Host == host && e.Port == 443 && e.Decision == "denied" && e.Reason == reason)
		}
		if !found {
			t.Errorf("proxy.log has no denial of %s for %q: %+v", target, reason, logged)
		}
	}
	if !readJob(t, dir).Blocked {
		t.Error("job.json does not say that a request was blocked")
	}
}

// bigInput is a file too big for the buffers between the host and the guest, so the host is still sending it
// when the guest answers.
func bigInput(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "big.bin")
	f, err := os.Create(p) // #nosec G304 -- test fixture path under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(64 << 20); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestP8Fake(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		probe   string
		args    []string
		input   func(t *testing.T) string // the argument after the flags; nil means none
		resolve string                    // GALAHAD_TEST_RESOLVE
		// expectations
		wantCode   int
		wantStdout string
		wantStderr string
		wantState  string
		wantProbe  func(t *testing.T, dir string) // nil means that the guest sent no probe.json
	}{
		{
			name:  "the proxy denies the metadata address, a private address, localhost and a name that resolves to a private address",
			probe: "proxy", args: []string{"--allow-host", "localhost", "--allow-host", "rebind.test"}, resolve: "rebind.test=10.0.0.1",
			wantCode: 0, wantStdout: "probe proxy done", wantState: "done", wantProbe: checkProxyProbe,
		},
		{
			name:  "an oversize Result is refused from its header",
			probe: "result-oversize", wantCode: 1, wantStderr: "result frame is 67108865 bytes", wantState: "failed",
		},
		{
			name:  "a Result with an unknown field is refused",
			probe: "result-unknown-field", wantCode: 1, wantStderr: `unknown field "bogus"`, wantState: "failed",
		},
		{
			name:  "a Result before the end of the input is refused",
			probe: "result-early", input: bigInput, wantCode: 1, wantStderr: "before the end of the input", wantState: "failed",
		},
		{
			name:  "an unknown probe fails the job",
			probe: "no-such-probe", wantCode: 1, wantStderr: "unknown probe", wantState: "failed",
		},
		{
			name:  "the fork bomb is not run outside a VM",
			probe: "fork-bomb", wantCode: 1, wantStderr: "runs only in a VM", wantState: "failed",
		},
		{
			name:  "the memory hog is not run outside a VM",
			probe: "memory", wantCode: 1, wantStderr: "runs only in a VM", wantState: "failed",
		},
		{
			name:  "the disk fill is not run outside a VM",
			probe: "disk-fill", wantCode: 1, wantStderr: "runs only in a VM", wantState: "failed",
		},
		{
			name:  "the root filesystem writes are not tried outside a VM",
			probe: "rootfs-write", wantCode: 1, wantStderr: "runs only in a VM", wantState: "failed",
		},
		{
			name:  "the sleep is not run outside a VM",
			probe: "sleep", wantCode: 1, wantStderr: "runs only in a VM", wantState: "failed",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given the fake sandbox and a probe job
			home := t.TempDir()
			t.Setenv("GALAHAD_HOME", home)
			t.Setenv("GALAHAD_SANDBOX", "fake")
			if tt.resolve != "" {
				t.Setenv("GALAHAD_TEST_RESOLVE", tt.resolve)
			}
			args := append([]string{"--p8-probe", tt.probe}, tt.args...)
			if tt.input != nil {
				args = append(args, tt.input(t))
			}

			// When it runs
			got := runP8(t, p8Timeout, args...)

			// Then the exit code, the job state and the files are as expected, and the host did not grow
			if got.code != tt.wantCode {
				t.Fatalf("exit = %d, want %d\nstdout: %s\nstderr: %s", got.code, tt.wantCode, got.stdout, got.stderr)
			}
			if !strings.Contains(got.stdout, tt.wantStdout) || !strings.Contains(got.stderr, tt.wantStderr) {
				t.Errorf("stdout = %q, stderr = %q, want them to contain %q and %q", got.stdout, got.stderr, tt.wantStdout, tt.wantStderr)
			}
			dir := onlyJob(t, home)
			if state := readJob(t, dir).State; state != tt.wantState {
				t.Errorf("state = %q, want %q", state, tt.wantState)
			}
			if _, err := os.Stat(filepath.Join(dir, "report.json")); err == nil {
				t.Error("report.json exists, want none")
			}
			if got.rss > maxHostRSS {
				t.Errorf("host peak RSS = %d bytes, want under %d", got.rss, int64(maxHostRSS))
			}
			if tt.wantProbe != nil {
				tt.wantProbe(t, dir)
			} else if _, err := os.Stat(filepath.Join(dir, "artifacts", "probe.json")); err == nil {
				t.Error("probe.json exists, want none")
			}
		})
	}
}
