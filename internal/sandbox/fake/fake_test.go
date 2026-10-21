//go:build galahadtest

package fake_test

import (
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mrdhira/galahad/internal/sandbox/fake"
)

const helperEnv = "GALAHAD_FAKE_TEST_HELPER"

// TestMain turns the test binary into the fake agent when helperEnv is set. The tests
// start it through GALAHAD_FAKE_AGENT, so no real agent is needed.
func TestMain(m *testing.M) {
	if mode := os.Getenv(helperEnv); mode != "" {
		os.Exit(helper(mode))
	}
	os.Exit(m.Run())
}

// helper acts as galahad-agent: it checks its arguments, then does what mode says.
func helper(mode string) int {
	// Expected: guest --unsafe-host [--control tcp:ADDR] [--proxy tcp:ADDR]
	args := os.Args[1:]
	if len(args) < 2 || args[0] != "guest" || args[1] != "--unsafe-host" {
		return 3
	}
	addrs := map[string]string{}
	for i := 2; i+1 < len(args); i += 2 {
		addr, ok := strings.CutPrefix(args[i+1], "tcp:")
		if !ok {
			return 3
		}
		addrs[args[i]] = addr
	}
	switch mode {
	case "connect":
		for flag, msg := range map[string]string{"--control": "from control", "--proxy": "from proxy"} {
			addr, ok := addrs[flag]
			if !ok {
				continue
			}
			c, err := net.Dial("tcp", addr)
			if err != nil {
				return 4
			}
			if _, err := io.WriteString(c, msg); err != nil {
				return 4
			}
			_ = c.Close()
		}
		_, _ = io.WriteString(os.Stderr, "helper console line\n")
		return 0
	case "flood":
		chunk := strings.Repeat("x", 1<<10)
		for range 2 << 10 {
			_, _ = io.WriteString(os.Stderr, chunk)
		}
		return 0
	case "sleep":
		time.Sleep(time.Minute)
		return 0
	}
	return 5
}

// useHelper points the fake backend at this test binary, running in the given mode.
func useHelper(t *testing.T, mode string) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("GALAHAD_FAKE_AGENT", exe)
	t.Setenv(helperEnv, mode)
}

// readAll accepts one connection on l and returns what the peer sends.
func readAll(t *testing.T, l net.Listener) string {
	t.Helper()
	if err := l.(*net.TCPListener).SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	c, err := l.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	defer func() { _ = c.Close() }() // test connection
	b, err := io.ReadAll(c)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestStart(t *testing.T) {
	tests := []struct {
		name        string
		ports       []uint32
		agent       string // GALAHAD_FAKE_AGENT; empty means the test binary
		noJobDir    bool
		wantErr     string
		wantControl string
		wantProxy   string
		wantConsole string
	}{
		{
			name:        "listeners exist and the agent connects to both",
			ports:       []uint32{1024, 1025},
			wantControl: "from control",
			wantProxy:   "from proxy",
			wantConsole: "helper console line",
		},
		{name: "unknown port", ports: []uint32{1024, 7}, wantErr: "unknown port 7"},
		{name: "console log cannot be created", ports: []uint32{1024}, noJobDir: true, wantErr: "open console log"},
		{name: "agent does not exist", ports: []uint32{1024}, agent: filepath.Join("no", "such", "agent"), wantErr: "start agent"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			useHelper(t, "connect")
			if tt.agent != "" {
				t.Setenv("GALAHAD_FAKE_AGENT", tt.agent)
			}
			jobDir := t.TempDir()
			if tt.noJobDir {
				jobDir = filepath.Join(jobDir, "missing")
			}
			m, err := fake.Start(context.Background(), jobDir, tt.ports)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want it to contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = m.Kill() }() // cleanup
			if got := readAll(t, m.Listener(1024)); got != tt.wantControl {
				t.Errorf("control = %q, want %q", got, tt.wantControl)
			}
			if got := readAll(t, m.Listener(1025)); got != tt.wantProxy {
				t.Errorf("proxy = %q, want %q", got, tt.wantProxy)
			}
			if err := m.Wait(); err != nil {
				t.Errorf("Wait = %v", err)
			}
			if l := m.Listener(7); l != nil {
				t.Errorf("Listener(7) = %v, want nil", l)
			}
			b, err := os.ReadFile(filepath.Join(jobDir, "console.log"))
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(b), tt.wantConsole) {
				t.Errorf("console.log = %q, want it to contain %q", b, tt.wantConsole)
			}
		})
	}
}

func TestMachineKill(t *testing.T) {
	tests := []struct {
		name         string
		mode         string
		waitFirst    bool // let the agent exit before the first Kill
		kills        int
		wantWaitFail bool
	}{
		{name: "kill stops a running agent", mode: "sleep", kills: 1, wantWaitFail: true},
		{name: "kill is idempotent", mode: "sleep", kills: 3, wantWaitFail: true},
		{name: "kill after the agent exited", mode: "flood", waitFirst: true, kills: 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			useHelper(t, tt.mode)
			m, err := fake.Start(context.Background(), t.TempDir(), []uint32{1024})
			if err != nil {
				t.Fatal(err)
			}
			if tt.waitFirst {
				if err := m.Wait(); err != nil {
					t.Fatalf("Wait = %v", err)
				}
			}
			for i := range tt.kills {
				if err := m.Kill(); err != nil {
					t.Fatalf("Kill #%d = %v", i+1, err)
				}
			}
			if err := m.Wait(); (err != nil) != tt.wantWaitFail {
				t.Errorf("Wait = %v, want failure %v", err, tt.wantWaitFail)
			}
			if _, err := m.Listener(1024).Accept(); err == nil {
				t.Error("listener still accepts after Kill")
			}
		})
	}
}

func TestConsoleCap(t *testing.T) {
	tests := []struct {
		name     string
		wantSize int64
	}{
		{name: "stderr beyond 1 MiB is dropped and the agent is not blocked", wantSize: 1 << 20},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			useHelper(t, "flood")
			jobDir := t.TempDir()
			m, err := fake.Start(context.Background(), jobDir, []uint32{1024})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = m.Kill() }() // cleanup
			if err := m.Wait(); err != nil {
				t.Fatalf("Wait = %v", err)
			}
			st, err := os.Stat(filepath.Join(jobDir, "console.log"))
			if err != nil {
				t.Fatal(err)
			}
			if st.Size() != tt.wantSize {
				t.Errorf("console.log is %d bytes, want %d", st.Size(), tt.wantSize)
			}
		})
	}
}
