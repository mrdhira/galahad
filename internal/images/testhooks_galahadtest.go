//go:build galahadtest

package images

import "os"

// GALAHAD_TEST_PINS replaces the embedded pins with the file it names, and GALAHAD_TEST_IMAGES_URL
// replaces the release URL, so an acceptance test can serve its own small assets. Neither exists
// in a release build.
func init() {
	if p := os.Getenv("GALAHAD_TEST_PINS"); p != "" {
		data, err := os.ReadFile(p)
		if err != nil {
			panic("GALAHAD_TEST_PINS: " + err.Error())
		}
		pinsJSON = data
	}
	baseURLOverride = os.Getenv("GALAHAD_TEST_IMAGES_URL")
}
