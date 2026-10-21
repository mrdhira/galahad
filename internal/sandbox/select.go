package sandbox

// testBackend is set by select_fake.go in galahadtest builds. It returns the backend that
// the environment asks for, if any.
var testBackend func() (Backend, bool)

// Select returns the backend for this system: Firecracker on Linux, and ErrUnsupported
// ("Linux only until M5") on every other system. In galahadtest builds,
// GALAHAD_SANDBOX=fake selects the fake backend.
func Select() (Backend, error) {
	if testBackend != nil {
		if b, ok := testBackend(); ok {
			return b, nil
		}
	}
	return newFirecracker()
}
