//go:build !galahadtest

package sandbox_test

import (
	"errors"
	"runtime"
	"strings"
	"testing"

	"github.com/mrdhira/galahad/internal/sandbox"
)

// Release builds have no fake backend, so GALAHAD_SANDBOX must change nothing.
func TestSelect(t *testing.T) {
	wantMsg := "the Firecracker backend is not built yet"
	if runtime.GOOS != "linux" {
		wantMsg = "Linux only until M5"
	}
	tests := []struct {
		name    string
		sandbox string // GALAHAD_SANDBOX
		wantMsg string
	}{
		{name: "no backend yet", sandbox: "", wantMsg: wantMsg},
		{name: "fake is ignored without the galahadtest tag", sandbox: "fake", wantMsg: wantMsg},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("GALAHAD_SANDBOX", tt.sandbox)
			b, err := sandbox.Select()
			if b != nil {
				t.Errorf("backend = %v, want nil", b)
			}
			if !errors.Is(err, sandbox.ErrUnsupported) {
				t.Fatalf("err = %v, want ErrUnsupported", err)
			}
			if !strings.Contains(err.Error(), tt.wantMsg) {
				t.Errorf("err = %q, want it to contain %q", err, tt.wantMsg)
			}
		})
	}
}
