package cli_test

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/mrdhira/galahad/internal/cli"
)

const fakeKey = "fake-key-for-tests-123"

func TestProvider(t *testing.T) {
	var sixteen []string
	for i := range 16 {
		sixteen = append(sixteen, fmt.Sprintf(`{"name": "p%d", "url": "https://example.com", "key_env": "", "model": "m", "timeout_seconds": 5}`, i))
	}
	full := `{"version": 1, "providers": [` + strings.Join(sixteen, ",") + `]}`
	addNetra := []string{"provider", "add", "netra"}
	addDown := []string{"provider", "add", "down", "--url", "https://down.example.com/api", "--model", "m1", "--timeout", "5s"}
	tests := []struct {
		name string
		// inputs
		before [][]string        // commands that run first and must exit 0
		file   string            // raw config.json written first
		env    map[string]string // environment variables
		args   []string
		// expectations
		wantCode   int
		wantStdout []string // substrings
		wantStderr string   // substring
		wantFile   []string // substrings of config.json afterwards
		wantNoFile []string // substrings that config.json must not hold
		wantNot    string   // in neither stdout nor stderr
	}{
		{
			name: "add netra with no flags writes the preset",
			args: addNetra, wantCode: 0, wantStdout: []string{"added provider netra"},
			wantFile: []string{`"url": "https://api.netraruntime.com"`, `"key_env": "NETRA_API_KEY"`, `"model": "deepseek/deepseek-v4.1-flash"`, `"timeout_seconds": 60`},
		},
		{
			name: "flags override single fields of the preset, after the name",
			args: []string{"provider", "add", "netra", "--model", "other/model", "--timeout", "90s", "--key-env", ""}, wantCode: 0,
			wantFile: []string{`"url": "https://api.netraruntime.com"`, `"key_env": ""`, `"model": "other/model"`, `"timeout_seconds": 90`},
		},
		{
			name: "flags before the name work too",
			args: []string{"provider", "add", "--url", "https://x.example.com", "--model", "m", "--key-env", "X_KEY", "x"}, wantCode: 0,
			wantFile: []string{`"name": "x"`, `"key_env": "X_KEY"`, `"timeout_seconds": 60`},
		},
		{
			name: "another name with --url and --model and no key variable",
			args: addDown, wantCode: 0,
			wantFile: []string{`"name": "down"`, `"url": "https://down.example.com/api"`, `"key_env": ""`, `"timeout_seconds": 5`},
		},
		{
			name:   "list shows the providers and that the key is set, never its value",
			before: [][]string{addNetra, addDown}, env: map[string]string{"NETRA_API_KEY": fakeKey},
			args: []string{"provider", "list"}, wantCode: 0,
			wantStdout: []string{"NAME", "KEY_SET", "TIMEOUT", "netra", "https://api.netraruntime.com", "NETRA_API_KEY", "yes", "60s", "down", "5s"},
			wantNot:    fakeKey,
		},
		{
			name:   "list says no when the variable is not set",
			before: [][]string{addNetra}, args: []string{"provider", "list"}, wantCode: 0,
			wantStdout: []string{"netra", "NETRA_API_KEY", "no"},
		},
		{
			name: "list with no providers",
			args: []string{"provider", "list"}, wantCode: 0, wantStdout: []string{"No providers. Add one with galahad provider add"},
		},
		{
			name:   "remove deletes the provider and keeps the others",
			before: [][]string{addNetra, addDown}, env: map[string]string{"NETRA_API_KEY": fakeKey},
			args: []string{"provider", "remove", "netra"}, wantCode: 0, wantStdout: []string{"removed provider netra"},
			wantFile: []string{`"name": "down"`}, wantNoFile: []string{"netra", fakeKey},
		},
		{
			name: "no subcommand is a usage error",
			args: []string{"provider"}, wantCode: 2, wantStderr: "want add, list, remove or test",
		},
		{
			name: "an unknown subcommand is a usage error",
			args: []string{"provider", "bogus", "netra"}, wantCode: 2, wantStderr: "want add, list, remove or test",
		},
		{
			name: "add with a bad flag is a usage error",
			args: []string{"provider", "add", "netra", "--bogus"}, wantCode: 2, wantStderr: "provider add",
		},
		{
			name: "add without a name is a usage error",
			args: []string{"provider", "add", "--url", "https://x.example.com", "--model", "m"}, wantCode: 2, wantStderr: "want one provider name",
		},
		{
			name: "add with two names is a usage error",
			args: []string{"provider", "add", "a", "b"}, wantCode: 2, wantStderr: "want one provider name",
		},
		{
			name: "a name other than netra needs --url",
			args: []string{"provider", "add", "down", "--model", "m"}, wantCode: 2, wantStderr: "--url and --model are required",
		},
		{
			name: "a name other than netra needs --model",
			args: []string{"provider", "add", "down", "--url", "https://x.example.com"}, wantCode: 2, wantStderr: "--url and --model are required",
		},
		{
			name: "a timeout that is not whole seconds is a usage error",
			args: slices.Concat(addNetra, []string{"--timeout", "1500ms"}), wantCode: 2, wantStderr: "whole number of seconds",
		},
		{
			name: "a timeout of 0 is a usage error",
			args: slices.Concat(addNetra, []string{"--timeout", "0s"}), wantCode: 2, wantStderr: "timeout must be 1 to 150 seconds",
		},
		{
			name: "a timeout over 150 s is a usage error",
			args: slices.Concat(addNetra, []string{"--timeout", "151s"}), wantCode: 2, wantStderr: "timeout must be 1 to 150 seconds",
		},
		{
			name: "a bad name is a usage error",
			args: []string{"provider", "add", "Bad_Name", "--url", "https://x.example.com", "--model", "m"}, wantCode: 2, wantStderr: "provider name must match",
		},
		{
			name: "an http URL is a usage error",
			args: slices.Concat(addNetra, []string{"--url", "http://api.example.com"}), wantCode: 2, wantStderr: "must be https",
		},
		{
			name: "a URL with user info is a usage error",
			args: slices.Concat(addNetra, []string{"--url", "https://user:pw@api.example.com"}), wantCode: 2, wantStderr: "user info",
		},
		{
			name: "a URL with a query is a usage error",
			args: slices.Concat(addNetra, []string{"--url", "https://api.example.com/?a=b"}), wantCode: 2, wantStderr: "query or a fragment",
		},
		{
			name: "a bad model is a usage error",
			args: slices.Concat(addNetra, []string{"--model", "a b"}), wantCode: 2, wantStderr: "model must match",
		},
		{
			name: "a bad key variable is a usage error",
			args: slices.Concat(addNetra, []string{"--key-env", "lower"}), wantCode: 2, wantStderr: "key_env must match",
		},
		{
			name:   "a provider that exists is an error",
			before: [][]string{addNetra}, args: addNetra, wantCode: 1, wantStderr: "remove it first",
		},
		{
			name: "add refuses a config it cannot load",
			file: `{"version": 1, "providers": [], "api_key": "` + fakeKey + `"}`,
			args: addNetra, wantCode: 1, wantStderr: "use key_env", wantNot: fakeKey,
		},
		{
			name: "add cannot save a 17th provider",
			file: full, args: addNetra, wantCode: 1, wantStderr: "at most 16 providers",
		},
		{
			name: "list refuses a config it cannot load and prints none of it",
			file: `{"version": 2, "providers": [{"name": "` + fakeKey + `"}]}`,
			args: []string{"provider", "list"}, wantCode: 1, wantStderr: "version must be 1", wantNot: fakeKey,
		},
		{
			name: "list with an argument is a usage error",
			args: []string{"provider", "list", "netra"}, wantCode: 2, wantStderr: "unexpected argument",
		},
		{
			name: "remove without a name is a usage error",
			args: []string{"provider", "remove"}, wantCode: 2, wantStderr: "want one provider name",
		},
		{
			name: "remove refuses a config it cannot load",
			file: `not json ` + fakeKey,
			args: []string{"provider", "remove", "netra"}, wantCode: 1, wantStderr: "not valid JSON", wantNot: fakeKey,
		},
		{
			name: "test without a name is a usage error",
			args: []string{"provider", "test"}, wantCode: 2, wantStderr: "want one provider name",
		},
		{
			name: "test of an unknown provider is a usage error",
			args: []string{"provider", "test", "other"}, wantCode: 2, wantStderr: "no provider other",
		},
		{
			name:   "test with the key variable unset is a usage error",
			before: [][]string{addNetra}, args: []string{"provider", "test", "netra"}, wantCode: 2, wantStderr: "$NETRA_API_KEY, which is not set",
		},
		{
			name: "test refuses a config it cannot load",
			file: `not json ` + fakeKey,
			args: []string{"provider", "test", "netra"}, wantCode: 1, wantStderr: "not valid JSON", wantNot: fakeKey,
		},
		{
			name:   "remove of an unknown provider is an error",
			before: [][]string{addNetra}, args: []string{"provider", "remove", "other"}, wantCode: 1, wantStderr: "no provider other",
			wantFile: []string{`"name": "netra"`},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home := t.TempDir()
			for k, v := range tt.env {
				t.Setenv(k, v)
			}
			if tt.env["NETRA_API_KEY"] == "" {
				t.Setenv("NETRA_API_KEY", "")
			}
			if tt.file != "" {
				if err := os.WriteFile(filepath.Join(home, "config.json"), []byte(tt.file), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			for _, args := range tt.before {
				if _, stderr, code := runProvider(home, args...); code != 0 {
					t.Fatalf("%v = %d: %s", args, code, stderr)
				}
			}
			stdout, stderr, code := runProvider(home, tt.args...)
			if code != tt.wantCode {
				t.Errorf("exit code = %d, want %d\nstdout: %s\nstderr: %s", code, tt.wantCode, stdout, stderr)
			}
			for _, w := range tt.wantStdout {
				if !strings.Contains(stdout, w) {
					t.Errorf("stdout lacks %q:\n%s", w, stdout)
				}
			}
			if !strings.Contains(stderr, tt.wantStderr) {
				t.Errorf("stderr lacks %q:\n%s", tt.wantStderr, stderr)
			}
			if tt.wantNot != "" && strings.Contains(stdout+stderr, tt.wantNot) {
				t.Errorf("output holds %q:\n%s%s", tt.wantNot, stdout, stderr)
			}
			if len(tt.wantFile)+len(tt.wantNoFile) == 0 {
				return
			}
			data, err := os.ReadFile(filepath.Join(home, "config.json"))
			if err != nil {
				t.Fatal(err)
			}
			for _, w := range tt.wantFile {
				if !strings.Contains(string(data), w) {
					t.Errorf("config.json lacks %q:\n%s", w, data)
				}
			}
			for _, w := range tt.wantNoFile {
				if strings.Contains(string(data), w) {
					t.Errorf("config.json holds %q:\n%s", w, data)
				}
			}
		})
	}
}

func runProvider(home string, args ...string) (stdout, stderr string, code int) {
	var out, errb bytes.Buffer
	code = cli.RunWithEnv(args, &out, &errb, cli.Env{Home: home})
	return out.String(), errb.String(), code
}
