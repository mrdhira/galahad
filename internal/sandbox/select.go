package sandbox

import (
	"fmt"
	"runtime"
)

// testBackend is set by select_fake.go in galahadtest builds. It returns the backend that
// the environment asks for, if any.
var testBackend func() (Backend, bool)

// Select returns the backend for this system. Until the Firecracker backend exists, and on
// every system but Linux, it returns ErrUnsupported. In galahadtest builds,
// GALAHAD_SANDBOX=fake selects the fake backend.
func Select() (Backend, error) {
	if testBackend != nil {
		if b, ok := testBackend(); ok {
			return b, nil
		}
	}
	if runtime.GOOS != "linux" {
		return nil, fmt.Errorf("%w: Linux only until M5", ErrUnsupported)
	}
	return nil, fmt.Errorf("%w: the Firecracker backend is not built yet", ErrUnsupported)
}
