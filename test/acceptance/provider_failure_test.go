package acceptance_test

import (
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// qaKey is a fake key, built from pieces so no full literal sits in the source.
const qaKey = "fake-key-" + "qa-t32b-" + "9f3a7c21"

// answerWith returns providerTestAnswer with one piece replaced. It fails when the piece is not there.
func answerWith(t *testing.T, old, repl string) string {
	t.Helper()
	if !strings.Contains(providerTestAnswer, old) {
		t.Fatalf("providerTestAnswer lacks %q", old)
	}
	return strings.Replace(providerTestAnswer, old, repl, 1)
}

// hijackStatus writes a raw response whose status text is reason, which net/http cannot do.
func hijackStatus(t *testing.T, w http.ResponseWriter, code int, reason string) {
	t.Helper()
	conn, buf, err := w.(http.Hijacker).Hijack()
	if err != nil {
		t.Errorf("hijack: %v", err)
		return
	}
	defer func() { _ = conn.Close() }()
	_, _ = fmt.Fprintf(buf, "HTTP/1.1 %d %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", code, reason)
	_ = buf.Flush()
}

// TestProviderTestFailures runs "provider test" against mock providers that fail in each way P9
// lists. Every case checks the exit code, a clear message, the number of requests the mock got, and
// that the key is in no output and no file under a temporary HOME.
func TestProviderTestFailures(t *testing.T) {
	ok := func(w http.ResponseWriter, body string) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Request-Id", "req_qa1")
		_, _ = w.Write([]byte(body))
	}
	tests := []struct {
		name string
		// inputs
		handler func(t *testing.T, w http.ResponseWriter, r *http.Request, n int) // n counts from 1
		timeout string
		// expectations
		wantCode     int
		wantStdout   []string
		wantStderr   []string
		wantRequests int
		wantMin      time.Duration // elapsed time of the command, at least
		wantMax      time.Duration // and at most, 0 means no limit
	}{
		{
			name: "an extra unknown field at the top and inside an answer still succeeds",
			handler: func(t *testing.T, w http.ResponseWriter, r *http.Request, n int) {
				body := answerWith(t, `"object": "decisions",`, `"object": "decisions", "surprise": {"a": [1, 2]},`)
				body = strings.Replace(body, `"choice": "malicious"`, `"choice": "malicious", "note": "extra"`, 1)
				ok(w, body)
			},
			wantCode: 0, wantRequests: 1,
			wantStdout: []string{"provider mock: ok", "input tokens: 3600", "request id: req_qa1", "latency: "},
		},
		{
			name: "a mock that echoes the key in X-Request-Id on success drops the ID and succeeds",
			handler: func(t *testing.T, w http.ResponseWriter, r *http.Request, n int) {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("X-Request-Id", r.Header.Get("Authorization"))
				_, _ = w.Write([]byte(providerTestAnswer))
			},
			wantCode: 0, wantRequests: 1, wantStdout: []string{"provider mock: ok", "input tokens: 3600"},
		},
		{
			name: "a connection that nobody listens on gives network after 3 attempts",
			// handler nil: the mock is closed before the call
			wantCode: 1, wantRequests: 0, wantMin: time.Second,
			wantStderr: []string{"mock failed: network: could not reach the provider (attempts 3"},
		},
		{
			name: "401 is final",
			handler: func(t *testing.T, w http.ResponseWriter, r *http.Request, n int) {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte("bad key " + r.Header.Get("Authorization")))
			},
			wantCode: 1, wantRequests: 1, wantStderr: []string{"mock failed: status 401: invalid credentials (attempts 1"},
		},
		{
			name: "402 says insufficient credit whatever the body says",
			handler: func(t *testing.T, w http.ResponseWriter, r *http.Request, n int) {
				w.WriteHeader(http.StatusPaymentRequired)
				_, _ = w.Write([]byte(`{"error":"you are rich ` + r.Header.Get("Authorization") + `"}`))
			},
			wantCode: 1, wantRequests: 1, wantStderr: []string{"mock failed: status 402: insufficient credit (attempts 1"},
		},
		{
			name: "429 then 200 is retried and succeeds",
			handler: func(t *testing.T, w http.ResponseWriter, r *http.Request, n int) {
				if n == 1 {
					w.Header().Set("Retry-After", "1")
					w.WriteHeader(http.StatusTooManyRequests)
					return
				}
				ok(w, providerTestAnswer)
			},
			wantCode: 0, wantRequests: 2, wantMin: 900 * time.Millisecond,
			wantStdout: []string{"provider mock: ok", "(attempts 2)"},
		},
		{
			name: "a Retry-After of 60 ends the call at once",
			handler: func(t *testing.T, w http.ResponseWriter, r *http.Request, n int) {
				w.Header().Set("Retry-After", "60")
				w.WriteHeader(http.StatusTooManyRequests)
			},
			wantCode: 1, wantRequests: 1, wantMax: 5 * time.Second,
			wantStderr: []string{"mock failed: status 429: rate limited (attempts 1"},
		},
		{
			name: "503 every time gives up after 3 attempts",
			handler: func(t *testing.T, w http.ResponseWriter, r *http.Request, n int) {
				w.WriteHeader(http.StatusServiceUnavailable)
			},
			wantCode: 1, wantRequests: 3, wantMin: time.Second,
			wantStderr: []string{"mock failed: status 503: scoring unavailable (attempts 3"},
		},
		{
			name: "a request ID on a failure is kept",
			handler: func(t *testing.T, w http.ResponseWriter, r *http.Request, n int) {
				w.Header().Set("X-Request-Id", "req_fail9")
				w.WriteHeader(http.StatusForbidden)
			},
			wantCode: 1, wantRequests: 1, wantStderr: []string{"status 403: permission denied (attempts 1", "request id req_fail9"},
		},
		{
			name: "a mock that echoes the key in X-Request-Id on a failure drops the ID",
			handler: func(t *testing.T, w http.ResponseWriter, r *http.Request, n int) {
				w.Header().Set("X-Request-Id", "req_"+strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
				w.WriteHeader(http.StatusForbidden)
			},
			wantCode: 1, wantRequests: 1, wantStderr: []string{"status 403: permission denied (attempts 1"},
		},
		{
			name: "a mock that echoes the key in the status text gives the fixed message",
			handler: func(t *testing.T, w http.ResponseWriter, r *http.Request, n int) {
				hijackStatus(t, w, http.StatusPaymentRequired, strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
			},
			wantCode: 1, wantRequests: 1, wantStderr: []string{"status 402: insufficient credit (attempts 1"},
		},
		{
			name: "a mock that echoes the key in a 200 body that is not an answer gives invalid",
			handler: func(t *testing.T, w http.ResponseWriter, r *http.Request, n int) {
				ok(w, `{"echo":"`+r.Header.Get("Authorization")+`"}`)
			},
			wantCode: 1, wantRequests: 1, wantStderr: []string{"mock failed: invalid: response failed the checks (attempts 1"},
		},
		{
			name: "a mock that is slower than the time limit gives timeout",
			handler: func(t *testing.T, w http.ResponseWriter, r *http.Request, n int) {
				select {
				case <-r.Context().Done():
				case <-time.After(2500 * time.Millisecond):
				}
			},
			timeout: "1s", wantCode: 1, wantRequests: 1, wantMin: 900 * time.Millisecond, wantMax: 3 * time.Second,
			wantStderr: []string{"mock failed: timeout: provider did not answer in time"},
		},
		{
			name: "an answer over 64 KiB with a length gives too_large",
			handler: func(t *testing.T, w http.ResponseWriter, r *http.Request, n int) {
				ok(w, answerWith(t, `"object": "decisions",`, `"pad": "`+strings.Repeat("a", 70<<10)+`", "object": "decisions",`))
			},
			wantCode: 1, wantRequests: 1, wantStderr: []string{"mock failed: too_large: response is too large (attempts 1"},
		},
		{
			name: "an answer over 64 KiB sent in chunks gives too_large",
			handler: func(t *testing.T, w http.ResponseWriter, r *http.Request, n int) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(strings.Repeat(" ", 32<<10)))
				w.(http.Flusher).Flush()
				for range 4 {
					if _, err := w.Write([]byte(strings.Repeat(" ", 32<<10))); err != nil {
						return
					}
					w.(http.Flusher).Flush()
				}
				_, _ = w.Write([]byte(providerTestAnswer))
			},
			wantCode: 1, wantRequests: 1, wantStderr: []string{"mock failed: too_large: response is too large (attempts 1"},
		},
		{
			name: "a probability of 1.7 gives invalid",
			handler: func(t *testing.T, w http.ResponseWriter, r *http.Request, n int) {
				ok(w, answerWith(t, `"clean": 0.05`, `"clean": 1.7`))
			},
			wantCode: 1, wantRequests: 1, wantStderr: []string{"mock failed: invalid: response failed the checks (attempts 1"},
		},
		{
			name: "a missing answer ID gives invalid",
			handler: func(t *testing.T, w http.ResponseWriter, r *http.Request, n int) {
				ok(w, answerWith(t, `"steals_secrets": {"type": "yes_no", "probabilities": {"yes": 0.9, "no": 0.1}, "label_mass": 0.5}`, `"other": {"type": "yes_no", "probabilities": {"yes": 0.9, "no": 0.1}, "label_mass": 0.5}`))
			},
			wantCode: 1, wantRequests: 1, wantStderr: []string{"mock failed: invalid: response failed the checks (attempts 1"},
		},
		{
			name: "a wrong label gives invalid",
			handler: func(t *testing.T, w http.ResponseWriter, r *http.Request, n int) {
				ok(w, answerWith(t, `"clean": 0.05`, `"benign": 0.05`))
			},
			wantCode: 1, wantRequests: 1, wantStderr: []string{"mock failed: invalid: response failed the checks (attempts 1"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var requests atomic.Int32
			var mock *httptest.Server
			if tt.handler == nil {
				mock = httptest.NewServer(http.NotFoundHandler())
			} else {
				mock = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					n := int(requests.Add(1))
					if r.Method != http.MethodPost || r.URL.Path != "/v1/decisions" || r.Header.Get("Authorization") != "Bearer "+qaKey {
						t.Errorf("unexpected request: %s %s auth set=%v", r.Method, r.URL.Path, r.Header.Get("Authorization") != "")
					}
					tt.handler(t, w, r, n)
				}))
			}
			defer mock.Close()
			url := mock.URL
			if tt.handler == nil {
				mock.Close()
			}

			home := t.TempDir()
			t.Setenv("HOME", home)
			t.Setenv("USERPROFILE", home)
			t.Setenv("GALAHAD_HOME", "")
			t.Setenv("QA_PROVIDER_KEY", qaKey)
			timeout := tt.timeout
			if timeout == "" {
				timeout = "20s"
			}
			add := []string{"provider", "add", "mock", "--url", url, "--model", "test/model-1", "--key-env", "QA_PROVIDER_KEY", "--timeout", timeout}
			if stdout, stderr, code := run(t, add...); code != 0 {
				t.Fatalf("%v = %d\n%s%s", add, code, stdout, stderr)
			}

			begin := time.Now()
			stdout, stderr, code := run(t, "provider", "test", "mock")
			elapsed := time.Since(begin)
			if code != tt.wantCode {
				t.Errorf("exit code = %d, want %d\nstdout: %s\nstderr: %s", code, tt.wantCode, stdout, stderr)
			}
			for _, w := range tt.wantStdout {
				if !strings.Contains(stdout, w) {
					t.Errorf("stdout lacks %q:\n%s", w, stdout)
				}
			}
			for _, w := range tt.wantStderr {
				if !strings.Contains(stderr, w) {
					t.Errorf("stderr lacks %q:\n%s", w, stderr)
				}
			}
			if tt.wantCode != 0 && stdout != "" {
				t.Errorf("a failure printed on stdout:\n%s", stdout)
			}
			if tt.handler != nil {
				if got := int(requests.Load()); got != tt.wantRequests {
					t.Errorf("mock got %d requests, want %d", got, tt.wantRequests)
				}
			}
			if elapsed < tt.wantMin {
				t.Errorf("took %v, want at least %v", elapsed, tt.wantMin)
			}
			if tt.wantMax > 0 && elapsed > tt.wantMax {
				t.Errorf("took %v, want at most %v", elapsed, tt.wantMax)
			}
			if strings.Contains(stdout+stderr, qaKey) {
				t.Errorf("the key value is in the output:\n%s%s", stdout, stderr)
			}
			keyFree(t, home, qaKey)
		})
	}
}

// keyFree fails when key is in a file under dir.
func keyFree(t *testing.T, dir, key string) {
	t.Helper()
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if data, err := os.ReadFile(p); err == nil && strings.Contains(string(data), key) {
			t.Errorf("the key value is in %s", p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

var (
	releaseOnce sync.Once
	releaseBin  string
	releaseErr  error
)

// buildRelease builds galahad without the galahadtest tag, once, next to the test binary.
func buildRelease(t *testing.T) string {
	t.Helper()
	releaseOnce.Do(func() {
		root, err := moduleRoot()
		if err != nil {
			releaseErr = err
			return
		}
		dir := filepath.Dir(binPath) // removed by TestMain
		exe := ""
		if runtime.GOOS == "windows" {
			exe = ".exe"
		}
		releaseBin = filepath.Join(dir, "galahad-release"+exe)
		build := exec.Command("go", "build", "-o", releaseBin, "./cmd/galahad")
		build.Dir = root
		if out, err := build.CombinedOutput(); err != nil {
			releaseErr = fmt.Errorf("release build: %v\n%s", err, out)
		}
	})
	if releaseErr != nil {
		t.Fatal(releaseErr)
	}
	return releaseBin
}

// TestProviderLoopbackURL checks that only galahadtest builds take a plain http loopback URL (P9).
func TestProviderLoopbackURL(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		release bool
		args    []string
		// expectations
		wantCode   int
		wantStdout string
		wantStderr string
		wantConfig bool
	}{
		{
			name: "a galahadtest build takes a loopback http URL",
			args: []string{"provider", "add", "mock", "--url", "http://127.0.0.1:8080", "--model", "m1"}, wantCode: 0, wantStdout: "added provider mock", wantConfig: true,
		},
		{
			name:    "a release build refuses a loopback http URL",
			release: true, args: []string{"provider", "add", "mock", "--url", "http://127.0.0.1:8080", "--model", "m1"},
			wantCode: 2, wantStderr: "must be https",
		},
		{
			name:    "a release build refuses localhost over http",
			release: true, args: []string{"provider", "add", "mock", "--url", "http://localhost:8080", "--model", "m1"},
			wantCode: 2, wantStderr: "must be https",
		},
		{
			name:    "a release build takes an https URL",
			release: true, args: []string{"provider", "add", "mock", "--url", "https://api.example.com", "--model", "m1"},
			wantCode: 0, wantStdout: "added provider mock", wantConfig: true,
		},
	}
	release := buildRelease(t) // before HOME changes, so go build keeps the real module and build caches
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)
			t.Setenv("USERPROFILE", home)
			t.Setenv("GALAHAD_HOME", "")
			bin := binPath
			if tt.release {
				bin = release
			}
			stdout, stderr, code := runBinary(t, bin, tt.args...)
			if code != tt.wantCode {
				t.Errorf("exit code = %d, want %d\nstdout: %s\nstderr: %s", code, tt.wantCode, stdout, stderr)
			}
			if !strings.Contains(stdout, tt.wantStdout) {
				t.Errorf("stdout lacks %q:\n%s", tt.wantStdout, stdout)
			}
			if !strings.Contains(stderr, tt.wantStderr) {
				t.Errorf("stderr lacks %q:\n%s", tt.wantStderr, stderr)
			}
			_, err := os.Stat(filepath.Join(home, ".galahad", "config.json"))
			if (err == nil) != tt.wantConfig {
				t.Errorf("config.json exists = %v, want %v", err == nil, tt.wantConfig)
			}
		})
	}
}

// TestProviderLoopbackConfig checks that a release build does not call a loopback http provider that
// was written into config.json by hand (P9).
func TestProviderLoopbackConfig(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		release bool
		// expectations
		wantCode     int
		wantRequests int
	}{
		{name: "a galahadtest build calls the loopback provider", wantCode: 0, wantRequests: 1},
		{name: "a release build does not call it", release: true, wantCode: 1, wantRequests: 0},
	}
	release := buildRelease(t) // before HOME changes, so go build keeps the real module and build caches
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var requests atomic.Int32
			mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(providerTestAnswer))
			}))
			defer mock.Close()

			home := t.TempDir()
			t.Setenv("HOME", home)
			t.Setenv("USERPROFILE", home)
			t.Setenv("GALAHAD_HOME", "")
			t.Setenv("QA_PROVIDER_KEY", qaKey)
			add := []string{"provider", "add", "mock", "--url", mock.URL, "--model", "test/model-1", "--key-env", "QA_PROVIDER_KEY"}
			if stdout, stderr, code := run(t, add...); code != 0 {
				t.Fatalf("%v = %d\n%s%s", add, code, stdout, stderr)
			}
			bin := binPath
			if tt.release {
				bin = release
			}
			stdout, stderr, code := runBinary(t, bin, "provider", "test", "mock")
			if code != tt.wantCode {
				t.Errorf("exit code = %d, want %d\nstdout: %s\nstderr: %s", code, tt.wantCode, stdout, stderr)
			}
			if got := int(requests.Load()); got != tt.wantRequests {
				t.Errorf("mock got %d requests, want %d", got, tt.wantRequests)
			}
			if strings.Contains(stdout+stderr, qaKey) {
				t.Errorf("the key value is in the output:\n%s%s", stdout, stderr)
			}
			keyFree(t, home, qaKey)
		})
	}
}
