package acceptance_test

import (
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
)

const providerTestAnswer = `{
  "object": "decisions", "model": "test/model-1", "prompt_format_version": 1,
  "answers": {
    "verdict": {"type": "choice", "probabilities": {"clean": 0.05, "suspicious": 0.15, "malicious": 0.80}, "label_mass": 0.6, "choice": "malicious"},
    "risk": {"type": "score", "probabilities": {"0": 0.05, "1": 0.1, "2": 0.35, "3": 0.5}, "label_mass": 0.4, "score": 2.3},
    "steals_secrets": {"type": "yes_no", "probabilities": {"yes": 0.9, "no": 0.1}, "label_mass": 0.5}
  },
  "usage": {"prompt_tokens": 3600, "completion_tokens": 0, "total_tokens": 3600}
}`

// TestProvider adds, lists and removes decision providers through the built binary (P9). The key
// variable holds a fake value, which must appear in no file under GALAHAD_HOME and in no output.
func TestProvider(t *testing.T) {
	const fakeKey = "fake-key-for-tests-123"
	addNetra := []string{"provider", "add", "netra"}
	tests := []struct {
		name string
		// inputs
		before [][]string // commands that run first and must exit 0
		args   []string
		// expectations
		wantCode   int
		wantStdout string // substring
		wantStderr string // substring
		wantFile   []string
		wantNoFile []string
	}{
		{
			name: "add netra writes the preset with no key",
			args: addNetra, wantCode: 0, wantStdout: "added provider netra",
			wantFile: []string{`"url": "https://api.netraruntime.com"`, `"key_env": "NETRA_API_KEY"`, `"model": "deepseek/deepseek-v4.1-flash"`, `"timeout_seconds": 60`},
		},
		{
			name:   "list shows the key is set without its value",
			before: [][]string{addNetra}, args: []string{"provider", "list"},
			wantCode: 0, wantStdout: "NETRA_API_KEY  yes      60s",
		},
		{
			name:     "add of another provider with flags after the name",
			before:   [][]string{addNetra},
			args:     []string{"provider", "add", "down", "--url", "https://down.example.com", "--model", "m1", "--timeout", "30s"},
			wantCode: 0, wantStdout: "added provider down",
			wantFile: []string{`"name": "netra"`, `"name": "down"`, `"timeout_seconds": 30`},
		},
		{
			name:   "add of a provider that exists is an error",
			before: [][]string{addNetra}, args: addNetra, wantCode: 1, wantStderr: "remove it first",
		},
		{
			name:     "add with an http URL is a usage error",
			args:     []string{"provider", "add", "down", "--url", "http://down.example.com", "--model", "m1"},
			wantCode: 2, wantStderr: "must be https", wantNoFile: []string{"down"},
		},
		{
			name:   "remove deletes the provider",
			before: [][]string{addNetra}, args: []string{"provider", "remove", "netra"},
			wantCode: 0, wantStdout: "removed provider netra", wantNoFile: []string{"netra"},
		},
		{
			name:   "list after remove has no providers",
			before: [][]string{addNetra, {"provider", "remove", "netra"}}, args: []string{"provider", "list"},
			wantCode: 0, wantStdout: "No providers. Add one with galahad provider add",
		},
		{
			name: "remove of an unknown provider is an error",
			args: []string{"provider", "remove", "netra"}, wantCode: 1, wantStderr: "no provider netra",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("GALAHAD_HOME", home)
			t.Setenv("NETRA_API_KEY", fakeKey)
			var all string
			for _, args := range tt.before {
				stdout, stderr, code := run(t, args...)
				if code != 0 {
					t.Fatalf("%v = %d\n%s%s", args, code, stdout, stderr)
				}
				all += stdout + stderr
			}
			stdout, stderr, code := run(t, tt.args...)
			all += stdout + stderr
			if code != tt.wantCode {
				t.Errorf("exit code = %d, want %d\nstdout: %s\nstderr: %s", code, tt.wantCode, stdout, stderr)
			}
			if !strings.Contains(stdout, tt.wantStdout) {
				t.Errorf("stdout lacks %q:\n%s", tt.wantStdout, stdout)
			}
			if !strings.Contains(stderr, tt.wantStderr) {
				t.Errorf("stderr lacks %q:\n%s", tt.wantStderr, stderr)
			}
			if strings.Contains(all, fakeKey) {
				t.Errorf("the key value is in the output:\n%s", all)
			}

			path := filepath.Join(home, "config.json")
			if len(tt.wantFile) > 0 {
				if runtime.GOOS != "windows" {
					fi, err := os.Stat(path)
					if err != nil {
						t.Fatal(err)
					}
					if fi.Mode().Perm() != 0o600 {
						t.Errorf("config.json mode = %v, want 0600", fi.Mode().Perm())
					}
				}
				data := readFile(t, path)
				for _, w := range tt.wantFile {
					if !strings.Contains(data, w) {
						t.Errorf("config.json lacks %q:\n%s", w, data)
					}
				}
			}
			for _, w := range tt.wantNoFile {
				if data, err := os.ReadFile(path); err == nil && strings.Contains(string(data), w) {
					t.Errorf("config.json holds %q:\n%s", w, data)
				}
			}
			err := filepath.WalkDir(home, func(p string, d fs.DirEntry, err error) error {
				if err != nil || d.IsDir() {
					return err
				}
				if data := readFile(t, p); strings.Contains(data, fakeKey) {
					t.Errorf("the key value is in %s", p)
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}

// TestProviderTest runs "provider test" through the built binary against a mock of the Decisions
// API (P9). The key variable holds a fake value, which must appear in no output and no file.
func TestProviderTest(t *testing.T) {
	const fakeKey = "fake-key-for-tests-123"
	tests := []struct {
		name string
		// inputs
		mode     string // ok, invalid, echo or down
		keyless  bool   // the provider has no key variable
		keyUnset bool   // the variable is not set
		args     []string
		// expectations
		wantCode     int
		wantStdout   []string // substrings
		wantStderr   string   // substring
		wantRequests int
	}{
		{
			name: "a working mock gives the answers, the tokens, the request ID and the latency",
			mode: "ok", args: []string{"provider", "test", "mock"}, wantCode: 0, wantRequests: 1,
			wantStdout: []string{"provider mock: ok", "clean 0.05, suspicious 0.15, malicious 0.80; choice malicious", "no harm 0.05, minor harm 0.10, serious harm 0.35, severe harm 0.50; expected level 2.30",
				"yes 0.90, no 0.10", "input tokens: 3600", "request id: req_abc", "latency: "},
		},
		{
			name: "a provider with no key variable sends no Authorization header",
			mode: "ok", keyless: true, args: []string{"provider", "test", "mock"}, wantCode: 0, wantRequests: 1, wantStdout: []string{"provider mock: ok"},
		},
		{
			name: "a closed port exits 1 with the code network",
			mode: "down", args: []string{"provider", "test", "mock"}, wantCode: 1, wantStderr: "mock failed: network: could not reach the provider (attempts 3",
		},
		{
			name: "an answer that is not JSON exits 1 with the code invalid",
			mode: "invalid", args: []string{"provider", "test", "mock"}, wantCode: 1, wantRequests: 1, wantStderr: "mock failed: invalid: response failed the checks (attempts 1",
		},
		{
			name: "a mock that echoes the key gives the fixed message",
			mode: "echo", args: []string{"provider", "test", "mock"}, wantCode: 1, wantRequests: 1, wantStderr: "mock failed: status 402: insufficient credit (attempts 1",
		},
		{
			name: "an unknown provider exits 2",
			mode: "ok", args: []string{"provider", "test", "other"}, wantCode: 2, wantStderr: "no provider other",
		},
		{
			name: "a key variable that is not set exits 2 and sends nothing",
			mode: "ok", keyUnset: true, args: []string{"provider", "test", "mock"}, wantCode: 2, wantStderr: "$NETRA_API_KEY, which is not set",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var requests atomic.Int32
			mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
				wantAuth := "Bearer " + fakeKey
				if tt.keyless {
					wantAuth = ""
				}
				if r.Method != http.MethodPost || r.URL.Path != "/v1/decisions" || r.Header.Get("Authorization") != wantAuth ||
					r.Header.Get("User-Agent") != "galahad/"+stampedVersion || !strings.Contains(string(body), `"path":"sample.txt"`) {
					t.Errorf("unexpected request: %s %s %v\n%s", r.Method, r.URL.Path, r.Header, body)
				}
				w.Header().Set("Content-Type", "application/json")
				switch tt.mode {
				case "invalid":
					_, _ = w.Write([]byte("this is not JSON"))
				case "echo":
					w.WriteHeader(http.StatusPaymentRequired)
					_, _ = w.Write([]byte("echo: " + r.Header.Get("Authorization")))
				default:
					w.Header().Set("X-Request-Id", "req_abc")
					_, _ = w.Write([]byte(providerTestAnswer))
				}
			}))
			defer mock.Close()
			url := mock.URL
			if tt.mode == "down" {
				mock.Close()
			}

			home := t.TempDir()
			t.Setenv("GALAHAD_HOME", home)
			t.Setenv("NETRA_API_KEY", fakeKey)
			add := []string{"provider", "add", "mock", "--url", url, "--model", "test/model-1", "--key-env", "NETRA_API_KEY", "--timeout", "10s"}
			if tt.keyless {
				add = []string{"provider", "add", "mock", "--url", url, "--model", "test/model-1", "--timeout", "10s"}
			}
			if stdout, stderr, code := run(t, add...); code != 0 {
				t.Fatalf("%v = %d\n%s%s", add, code, stdout, stderr)
			}
			if tt.keyUnset {
				t.Setenv("NETRA_API_KEY", "")
			}

			stdout, stderr, code := run(t, tt.args...)
			if code != tt.wantCode {
				t.Errorf("exit code = %d, want %d\nstdout: %s\nstderr: %s", code, tt.wantCode, stdout, stderr)
			}
			for _, w := range tt.wantStdout {
				if !strings.Contains(stdout, w) {
					t.Errorf("stdout lacks %q:\n%s", w, stdout)
				}
			}
			if !strings.Contains(stderr, tt.wantStderr) {
				t.Errorf("stderr lacks %q:\n%s", tt.wantStderr, stderr)
			}
			if got := int(requests.Load()); tt.mode != "down" && got != tt.wantRequests {
				t.Errorf("mock got %d requests, want %d", got, tt.wantRequests)
			}
			if strings.Contains(stdout+stderr, fakeKey) {
				t.Errorf("the key value is in the output:\n%s%s", stdout, stderr)
			}
			err := filepath.WalkDir(home, func(p string, d fs.DirEntry, err error) error {
				if err != nil || d.IsDir() {
					return err
				}
				if strings.Contains(readFile(t, p), fakeKey) {
					t.Errorf("the key value is in %s", p)
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}
