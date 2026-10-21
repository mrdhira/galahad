//go:build galahadtest

package sandbox_test

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/mrdhira/galahad/internal/sandbox"
)

const helperEnv = "GALAHAD_SANDBOX_TEST_HELPER"

// TestMain turns the test binary into a fake agent that exits at once when helperEnv is set.
func TestMain(m *testing.M) {
	if os.Getenv(helperEnv) != "" {
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestSelect(t *testing.T) {
	tests := []struct {
		name        string
		sandbox     string // GALAHAD_SANDBOX
		wantBackend string
		wantErr     string
	}{
		{name: "fake backend", sandbox: "fake", wantBackend: "fake"},
		{name: "unset falls through to the real backends", sandbox: "", wantErr: "sandbox not supported"},
		{name: "other value falls through to the real backends", sandbox: "firecracker", wantErr: "sandbox not supported"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("GALAHAD_SANDBOX", tt.sandbox)
			b, err := sandbox.Select()
			if tt.wantErr != "" {
				if !errors.Is(err, sandbox.ErrUnsupported) || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want ErrUnsupported containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if b.Name() != tt.wantBackend {
				t.Errorf("Name() = %q, want %q", b.Name(), tt.wantBackend)
			}
		})
	}
}

// TestFakeBackendStart checks that the adapter passes the job directory and ports through.
func TestFakeBackendStart(t *testing.T) {
	tests := []struct {
		name    string
		spec    func(dir string) sandbox.Spec
		wantErr string
	}{
		{
			name: "starts the agent with listeners for the ports",
			spec: func(dir string) sandbox.Spec { return sandbox.Spec{JobDir: dir, Ports: []uint32{1024, 1025}} },
		},
		{
			name:    "unknown port",
			spec:    func(dir string) sandbox.Spec { return sandbox.Spec{JobDir: dir, Ports: []uint32{9}} },
			wantErr: "unknown port 9",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exe, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			t.Setenv("GALAHAD_SANDBOX", "fake")
			t.Setenv("GALAHAD_FAKE_AGENT", exe)
			t.Setenv(helperEnv, "1")
			b, err := sandbox.Select()
			if err != nil {
				t.Fatal(err)
			}
			m, err := b.Start(context.Background(), tt.spec(t.TempDir()))
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want it to contain %q", err, tt.wantErr)
				}
				if m != nil {
					t.Errorf("machine = %v, want nil", m)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = m.Kill() }() // cleanup
			if m.Listener(1024) == nil || m.Listener(1025) == nil {
				t.Error("a listener is missing")
			}
			_ = m.Wait() // the helper exits at once
		})
	}
}
