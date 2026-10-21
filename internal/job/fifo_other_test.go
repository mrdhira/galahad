//go:build !unix

package job_test

import "errors"

func mkfifo(string) error { return errors.New("not supported on this system") }
