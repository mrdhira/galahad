//go:build !galahadtest

package sandbox_test

import (
	"errors"
	"runtime"
	"strings"
	"testing"

	"github.com/mrdhira/galahad/internal/sandbox"
)

// Release builds have no fake backend, so GALAHAD_SANDBOX must change nothing: Linux gets
// Firecracker and every other system gets ErrUnsupported.
func TestSelect(t *testing.T) {
	tests := []struct {
		name    string
		sandbox string // GALAHAD_SANDBOX
	}{
		{name: "the real backend", sandbox: ""},
		{name: "fake is ignored without the galahadtest tag", sandbox: "fake"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("GALAHAD_SANDBOX", tt.sandbox)
			t.Setenv("GALAHAD_HOME", t.TempDir())
			b, err := sandbox.Select()
			if runtime.GOOS == "linux" {
				if err != nil {
					t.Fatal(err)
				}
				if b.Name() != "firecracker" {
					t.Errorf("Name() = %q, want firecracker", b.Name())
				}
				return
			}
			if b != nil {
				t.Errorf("backend = %v, want nil", b)
			}
			if !errors.Is(err, sandbox.ErrUnsupported) {
				t.Fatalf("err = %v, want ErrUnsupported", err)
			}
			if !strings.Contains(err.Error(), "Linux only until M5") {
				t.Errorf("err = %q, want it to contain %q", err, "Linux only until M5")
			}
		})
	}
}
