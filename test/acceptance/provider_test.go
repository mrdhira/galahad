package acceptance_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestProvider adds, lists and removes decision providers through the built binary (P9). The key
// variable holds a fake value, which must appear in no file under GALAHAD_HOME and in no output.
func TestProvider(t *testing.T) {
	const fakeKey = "fake-key-for-tests-123"
	addNetra := []string{"provider", "add", "netra"}
	tests := []struct {
		name string
		// inputs
		before [][]string // commands that run first and must exit 0
		args   []string
		// expectations
		wantCode   int
		wantStdout string // substring
		wantStderr string // substring
		wantFile   []string
		wantNoFile []string
	}{
		{
			name: "add netra writes the preset with no key",
			args: addNetra, wantCode: 0, wantStdout: "added provider netra",
			wantFile: []string{`"url": "https://api.netraruntime.com"`, `"key_env": "NETRA_API_KEY"`, `"model": "deepseek/deepseek-v4.1-flash"`, `"timeout_seconds": 60`},
		},
		{
			name:   "list shows the key is set without its value",
			before: [][]string{addNetra}, args: []string{"provider", "list"},
			wantCode: 0, wantStdout: "NETRA_API_KEY  yes      60s",
		},
		{
			name:     "add of another provider with flags after the name",
			before:   [][]string{addNetra},
			args:     []string{"provider", "add", "down", "--url", "https://down.example.com", "--model", "m1", "--timeout", "30s"},
			wantCode: 0, wantStdout: "added provider down",
			wantFile: []string{`"name": "netra"`, `"name": "down"`, `"timeout_seconds": 30`},
		},
		{
			name:   "add of a provider that exists is an error",
			before: [][]string{addNetra}, args: addNetra, wantCode: 1, wantStderr: "remove it first",
		},
		{
			name:     "add with an http URL is a usage error",
			args:     []string{"provider", "add", "down", "--url", "http://down.example.com", "--model", "m1"},
			wantCode: 2, wantStderr: "must be https", wantNoFile: []string{"down"},
		},
		{
			name:   "remove deletes the provider",
			before: [][]string{addNetra}, args: []string{"provider", "remove", "netra"},
			wantCode: 0, wantStdout: "removed provider netra", wantNoFile: []string{"netra"},
		},
		{
			name:   "list after remove has no providers",
			before: [][]string{addNetra, {"provider", "remove", "netra"}}, args: []string{"provider", "list"},
			wantCode: 0, wantStdout: "No providers. Add one with galahad provider add",
		},
		{
			name: "remove of an unknown provider is an error",
			args: []string{"provider", "remove", "netra"}, wantCode: 1, wantStderr: "no provider netra",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("GALAHAD_HOME", home)
			t.Setenv("NETRA_API_KEY", fakeKey)
			var all string
			for _, args := range tt.before {
				stdout, stderr, code := run(t, args...)
				if code != 0 {
					t.Fatalf("%v = %d\n%s%s", args, code, stdout, stderr)
				}
				all += stdout + stderr
			}
			stdout, stderr, code := run(t, tt.args...)
			all += stdout + stderr
			if code != tt.wantCode {
				t.Errorf("exit code = %d, want %d\nstdout: %s\nstderr: %s", code, tt.wantCode, stdout, stderr)
			}
			if !strings.Contains(stdout, tt.wantStdout) {
				t.Errorf("stdout lacks %q:\n%s", tt.wantStdout, stdout)
			}
			if !strings.Contains(stderr, tt.wantStderr) {
				t.Errorf("stderr lacks %q:\n%s", tt.wantStderr, stderr)
			}
			if strings.Contains(all, fakeKey) {
				t.Errorf("the key value is in the output:\n%s", all)
			}

			path := filepath.Join(home, "config.json")
			if len(tt.wantFile) > 0 {
				if runtime.GOOS != "windows" {
					fi, err := os.Stat(path)
					if err != nil {
						t.Fatal(err)
					}
					if fi.Mode().Perm() != 0o600 {
						t.Errorf("config.json mode = %v, want 0600", fi.Mode().Perm())
					}
				}
				data := readFile(t, path)
				for _, w := range tt.wantFile {
					if !strings.Contains(data, w) {
						t.Errorf("config.json lacks %q:\n%s", w, data)
					}
				}
			}
			for _, w := range tt.wantNoFile {
				if data, err := os.ReadFile(path); err == nil && strings.Contains(string(data), w) {
					t.Errorf("config.json holds %q:\n%s", w, data)
				}
			}
			err := filepath.WalkDir(home, func(p string, d fs.DirEntry, err error) error {
				if err != nil || d.IsDir() {
					return err
				}
				if data := readFile(t, p); strings.Contains(data, fakeKey) {
					t.Errorf("the key value is in %s", p)
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
		})
	}
}
