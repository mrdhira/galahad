package cli_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mrdhira/galahad/internal/cli"
	"github.com/mrdhira/galahad/internal/config"
	"github.com/mrdhira/galahad/internal/sandbox"
)

// TestRunScanDecision runs "scan --decision". Every refusal comes before the backend is asked for a
// machine and before a job directory is made.
func TestRunScanDecision(t *testing.T) {
	file := filepath.Join(t.TempDir(), "a.txt")
	if err := os.WriteFile(file, []byte("hello\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("hello\n"))
	mock := config.Provider{Name: "mock", URL: "https://api.mock.test", KeyEnv: "GALAHAD_TEST_DECISION_KEY", Model: "fake-model/v1", TimeoutSeconds: 5}
	keyless := config.Provider{Name: "local", URL: "https://api.mock.test", Model: "fake-model/v1", TimeoutSeconds: 5}
	tests := []struct {
		name string
		// inputs
		args      []string // before the path
		providers []config.Provider
		config    string // the content of config.json instead of providers, when not empty
		key       string // the value of the key variable
		// expectations
		wantCode     int
		wantStdout   string // substring
		wantStderr   string // substring
		wantBackends int    // calls of the backend, which are the scans that got as far as a machine
		wantJob      bool
	}{
		{
			name: "a scan with nothing to judge is skipped", args: []string{"--decision", "mock"}, providers: []config.Provider{mock}, key: "fake-key-scan-1",
			wantCode: cli.ExitClean, wantStdout: "AI opinion (mock): skipped: no findings to send", wantBackends: 1, wantJob: true,
		},
		{
			name: "a provider with no key variable needs no key", args: []string{"--decision", "local"}, providers: []config.Provider{keyless},
			wantCode: cli.ExitClean, wantStdout: "AI opinion (local): skipped", wantBackends: 1, wantJob: true,
		},
		{
			name: "--decision with --no-network", args: []string{"--decision", "mock", "--no-network"}, providers: []config.Provider{mock}, key: "fake-key-scan-1",
			wantCode: cli.ExitUsage, wantStderr: "--decision needs the network",
		},
		{
			name: "a config that cannot be read", args: []string{"--decision", "mock"}, config: "not json", key: "fake-key-scan-1",
			wantCode: cli.ExitError, wantStderr: "galahad scan: load ",
		},
		{
			name: "an unknown provider", args: []string{"--decision", "other"}, providers: []config.Provider{mock}, key: "fake-key-scan-1",
			wantCode: cli.ExitUsage, wantStderr: "no provider other",
		},
		{
			name: "no providers at all", args: []string{"--decision", "mock"}, key: "fake-key-scan-1",
			wantCode: cli.ExitUsage, wantStderr: "no provider mock",
		},
		{
			name: "the key variable is not set", args: []string{"--decision", "mock"}, providers: []config.Provider{mock},
			wantCode: cli.ExitUsage, wantStderr: "needs the key in $GALAHAD_TEST_DECISION_KEY, which is not set",
		},
		{
			name: "the key has a control character", args: []string{"--decision", "mock"}, providers: []config.Provider{mock}, key: "fake-key\nscan",
			wantCode: cli.ExitUsage, wantStderr: "$GALAHAD_TEST_DECISION_KEY: the key has a control character",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home := t.TempDir()
			switch {
			case tt.config != "":
				if err := os.WriteFile(config.Path(home), []byte(tt.config), 0o600); err != nil {
					t.Fatal(err)
				}
			case tt.providers != nil:
				if err := config.Save(home, config.Config{Version: config.FileVersion, Providers: tt.providers}); err != nil {
					t.Fatal(err)
				}
			}
			t.Setenv("GALAHAD_TEST_DECISION_KEY", tt.key)
			backends := 0
			env := cli.Env{Home: home, Now: time.Now, Backend: func() (sandbox.Backend, error) {
				backends++
				return cleanBackend{fileSHA: hex.EncodeToString(sum[:])}, nil
			}}
			var out, errb bytes.Buffer
			args := append(append([]string{"scan"}, tt.args...), file)
			if got := cli.RunWithEnv(args, &out, &errb, env); got != tt.wantCode {
				t.Fatalf("exit = %d, want %d\nstdout: %s\nstderr: %s", got, tt.wantCode, out.String(), errb.String())
			}
			if !strings.Contains(out.String(), tt.wantStdout) {
				t.Errorf("stdout = %q, want it to contain %q", out.String(), tt.wantStdout)
			}
			if !strings.Contains(errb.String(), tt.wantStderr) {
				t.Errorf("stderr = %q, want it to contain %q", errb.String(), tt.wantStderr)
			}
			if strings.Contains(out.String()+errb.String(), "fake-key-scan") {
				t.Errorf("the key is in the output:\n%s\n%s", out.String(), errb.String())
			}
			if backends != tt.wantBackends {
				t.Errorf("backend asked %d times, want %d", backends, tt.wantBackends)
			}
			entries, _ := os.ReadDir(filepath.Join(home, "jobs"))
			if (len(entries) > 0) != tt.wantJob {
				t.Errorf("job directories = %v, want one: %v", entries, tt.wantJob)
			}
		})
	}
}
