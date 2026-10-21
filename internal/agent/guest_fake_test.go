//go:build galahadtest

package agent_test

import (
	"archive/tar"
	"bytes"
	"context"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/mrdhira/galahad/internal/protocol"
	"github.com/mrdhira/galahad/internal/sandbox/fake"
)

// tarDir returns a tar stream with the directory src under the name name.
func tarDir(t *testing.T, src, name string) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		hdr := tar.Header{Name: path(name, rel), Mode: 0o644}
		if d.IsDir() {
			hdr.Typeflag = tar.TypeDir
			hdr.Name += "/"
			return tw.WriteHeader(&hdr)
		}
		body, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		hdr.Typeflag, hdr.Size = tar.TypeReg, int64(len(body))
		if err := tw.WriteHeader(&hdr); err != nil {
			return err
		}
		_, err = tw.Write(body)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// path joins the target name and a slash-separated relative path.
func path(name, rel string) string {
	if rel == "." {
		return name
	}
	return name + "/" + filepath.ToSlash(rel)
}

// TestGuestThroughFakeBackend builds the agent, starts it through the fake sandbox backend
// and acts as the host: the Result for a corpus fixture shows that the backend and the guest fit.
func TestGuestThroughFakeBackend(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		fixture string
		// want*
		wantTool string
	}{
		{name: "benign Go CLI", fixture: "benign-go-cli", wantTool: "galahad-agent"},
	}
	exe := ""
	if runtime.GOOS == "windows" {
		exe = ".exe"
	}
	bin := filepath.Join(t.TempDir(), "galahad-agent"+exe)
	build := exec.Command("go", "build", "-tags", "galahadtest", "-o", bin, "../../cmd/galahad-agent")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build agent: %v\n%s", err, out)
	}
	t.Setenv("GALAHAD_FAKE_AGENT", bin)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			jobDir := t.TempDir()
			m, err := fake.Start(ctx, jobDir, []uint32{1024, 1025})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = m.Kill() }()

			c, err := m.Listener(1024).Accept()
			if err != nil {
				t.Fatalf("the agent did not dial the control port: %v", err)
			}
			defer func() { _ = c.Close() }()

			data := tarDir(t, filepath.Join("..", "..", "testdata", "corpus", tt.fixture), tt.fixture)
			if err := writeJSON(c, protocol.FrameJob, testJob(tt.fixture, 300)); err != nil {
				t.Fatal(err)
			}
			if err := sendInput(c, data, endOf(data)); err != nil {
				t.Fatal(err)
			}
			got := readGuest(t, c)
			if got.result == nil || got.result.Tool.Name != tt.wantTool || got.result.Target.Name != tt.fixture {
				t.Fatalf("result = %+v, error = %+v", got.result, got.errMsg)
			}
			if err := m.Wait(); err != nil {
				console, _ := os.ReadFile(filepath.Join(jobDir, "console.log")) // capped by the backend
				t.Errorf("agent exit: %v; console %q", err, console)
			}
		})
	}
}
