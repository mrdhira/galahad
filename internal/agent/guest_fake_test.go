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
	"slices"
	"strings"
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

// buildStubs builds a clamscan and a yara that report a hit in main.go of the scanned directory,
// and returns the directory that holds them.
func buildStubs(t *testing.T, exe string) string {
	t.Helper()
	dir := t.TempDir()
	src := filepath.Join(t.TempDir(), "main.go")
	const code = `package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	hit := filepath.Join(os.Args[len(os.Args)-1], "main.go")
	if strings.HasPrefix(filepath.Base(os.Args[0]), "clamscan") {
		fmt.Printf("%s: Test.Sig-1 FOUND\n", hit)
		os.Exit(1)
	}
	fmt.Printf("Test_Rule %s\n", hit)
}
`
	if err := os.WriteFile(src, []byte(code), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"clamscan", "yara"} {
		build := exec.Command("go", "build", "-o", filepath.Join(dir, name+exe), src)
		if out, err := build.CombinedOutput(); err != nil {
			t.Fatalf("build %s stub: %v\n%s", name, err, out)
		}
	}
	return dir
}

// TestGuestThroughFakeBackend builds the agent, starts it through the fake sandbox backend
// and acts as the host: the Result for a corpus fixture shows that the backend and the guest fit.
func TestGuestThroughFakeBackend(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		fixture string
		stubs   bool // clamscan and yara stubs on PATH that report a hit in main.go, with signatures for them
		// want*
		wantTool      string
		wantAnalyzers []string // tools that must be in the coverage
		wantMissing   []string // tools that must not be, and tools.log says so
		wantFindings  []string // "rule path" of the findings of the tools
	}{
		{
			name: "no signatures leaves the tools out", fixture: "benign-go-cli", wantTool: "galahad-agent",
			wantMissing: []string{"clamav", "yara"},
		},
		{
			name: "stub scanners report their hits", fixture: "benign-go-cli", stubs: true, wantTool: "galahad-agent",
			wantAnalyzers: []string{"clamav", "yara"}, wantFindings: []string{"GAL-AV-001 main.go", "GAL-YARA-001 main.go"},
		},
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

	stubDir := buildStubs(t, exe)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sigs := t.TempDir()
			t.Setenv("GALAHAD_TEST_SIG_DIR", sigs)
			if tt.stubs {
				t.Setenv("PATH", stubDir+string(os.PathListSeparator)+os.Getenv("PATH"))
				for dir, name := range map[string]string{"clamav": "main.cvd", "yara": "core.yarc"} {
					if err := os.MkdirAll(filepath.Join(sigs, dir), 0o750); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(sigs, dir, name), nil, 0o600); err != nil {
						t.Fatal(err)
					}
				}
			}
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
			for _, name := range tt.wantAnalyzers {
				if !slices.Contains(got.result.Coverage.Analyzers, name) {
					t.Errorf("analyzers = %v, want %s", got.result.Coverage.Analyzers, name)
				}
			}
			for _, name := range tt.wantMissing {
				if slices.Contains(got.result.Coverage.Analyzers, name) || !strings.Contains(got.toolsLog, name+": left out: ") {
					t.Errorf("analyzers = %v, tools.log = %q, want %s left out and explained", got.result.Coverage.Analyzers, got.toolsLog, name)
				}
			}
			var findings []string
			for _, f := range got.result.Findings {
				if f.Analyzer == "clamav" || f.Analyzer == "yara" {
					findings = append(findings, f.RuleID+" "+f.Evidence[0].Path)
				}
			}
			slices.Sort(findings)
			if !slices.Equal(findings, tt.wantFindings) {
				t.Errorf("tool findings = %v, want %v", findings, tt.wantFindings)
			}
			if err := m.Wait(); err != nil {
				console, _ := os.ReadFile(filepath.Join(jobDir, "console.log")) // capped by the backend
				t.Errorf("agent exit: %v; console %q", err, console)
			}
		})
	}
}
