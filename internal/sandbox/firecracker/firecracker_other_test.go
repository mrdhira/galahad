//go:build !linux

package firecracker_test

import (
	"errors"
	"testing"

	"github.com/mrdhira/galahad/internal/sandbox/firecracker"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name    string
		wantErr error
	}{
		{name: "unsupported off Linux", wantErr: firecracker.ErrUnsupported},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := firecracker.New()
			if b != nil {
				t.Errorf("backend = %v, want nil", b)
			}
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("err = %v, want %v", err, tt.wantErr)
			}
		})
	}
}
