package config_test

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/mrdhira/galahad/internal/config"
)

// marker stands for content of the file that an error must never repeat.
const marker = "MARKER-VALUE-123"

const netraJSON = `{"name": "netra", "url": "https://api.netraruntime.com", "key_env": "NETRA_API_KEY", "model": "deepseek/deepseek-v4.1-flash", "timeout_seconds": 60}`

// providerJSON returns a valid provider entry with the given name.
func providerJSON(name string) string {
	return fmt.Sprintf(`{"name": %q, "url": "https://example.com", "key_env": "", "model": "m", "timeout_seconds": 5}`, name)
}

func writeConfig(content string) func(t *testing.T, path string) {
	return func(t *testing.T, path string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestLoad(t *testing.T) {
	var many []string
	for i := range config.MaxProviders + 1 {
		many = append(many, providerJSON(fmt.Sprintf("p%d", i)))
	}
	valid := `{"version": 1, "providers": [` + netraJSON + `]}`
	tests := []struct {
		name string
		// inputs
		setup func(t *testing.T, path string) // makes config.json
		// expectations
		wantNames []string
		wantErr   string // substring; the error never holds the marker
	}{
		{name: "a valid file", setup: writeConfig(valid), wantNames: []string{"netra"}},
		{name: "a missing file is an empty config", setup: func(*testing.T, string) {}},
		{
			name: "a symlink is refused",
			setup: func(t *testing.T, path string) {
				target := filepath.Join(filepath.Dir(path), "real.json")
				writeConfig(valid)(t, target)
				if err := os.Symlink(target, path); err != nil {
					t.Skipf("no symlinks here: %v", err)
				}
			},
			wantErr: "it is a symlink",
		},
		{
			name: "a FIFO is refused",
			setup: func(t *testing.T, path string) {
				if err := mkfifo(path); err != nil {
					t.Skipf("no FIFOs here: %v", err)
				}
			},
			wantErr: "it is not a regular file",
		},
		{
			name:    "a file over 64 KiB is refused",
			setup:   writeConfig(valid + strings.Repeat(" ", 64<<10) + marker),
			wantErr: "larger than 65536 bytes",
		},
		{
			name:      "a file of exactly 64 KiB is read",
			setup:     writeConfig(valid + strings.Repeat(" ", 64<<10-len(valid))),
			wantNames: []string{"netra"},
		},
		{
			name:    "a key-like field says to use key_env",
			setup:   writeConfig(`{"version": 1, "providers": [{"name": "netra", "api_key": "` + marker + `"}]}`),
			wantErr: "keys are read from environment variables only; use key_env",
		},
		{
			name:    "another unknown field is refused without its name",
			setup:   writeConfig(`{"version": 1, "providers": [], "` + marker + `": 1}`),
			wantErr: "unknown field",
		},
		{
			name:    "bad JSON is refused",
			setup:   writeConfig(`{"version": 1, "providers": ` + marker),
			wantErr: "not valid JSON for the config",
		},
		{
			name:    "a wrong type is refused",
			setup:   writeConfig(`{"version": "` + marker + `", "providers": []}`),
			wantErr: "not valid JSON for the config",
		},
		{
			name:    "data after the JSON value is refused",
			setup:   writeConfig(valid + ` ` + marker),
			wantErr: "trailing data",
		},
		{
			name:    "a version other than 1 is refused",
			setup:   writeConfig(`{"version": 2, "providers": []}`),
			wantErr: "version must be 1",
		},
		{
			name:    "more than 16 providers are refused",
			setup:   writeConfig(`{"version": 1, "providers": [` + strings.Join(many, ",") + `]}`),
			wantErr: "at most 16 providers",
		},
		{
			name:    "an invalid provider is refused without its value",
			setup:   writeConfig(`{"version": 1, "providers": [{"name": "a", "url": "http://` + marker + `", "model": "m", "timeout_seconds": 5}]}`),
			wantErr: "provider a: url must be https",
		},
		{
			name:    "duplicate names are refused",
			setup:   writeConfig(`{"version": 1, "providers": [` + providerJSON("a") + `,` + providerJSON("a") + `]}`),
			wantErr: "provider a appears twice",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home := t.TempDir()
			tt.setup(t, config.Path(home))
			got, err := config.Load(home)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("Load error = %v, want it to contain %q", err, tt.wantErr)
				}
				if strings.Contains(err.Error(), marker) {
					t.Errorf("Load error repeats the content of the file: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			var names []string
			for _, p := range got.Providers {
				names = append(names, p.Name)
			}
			if !slices.Equal(names, tt.wantNames) {
				t.Errorf("provider names = %v, want %v", names, tt.wantNames)
			}
			if got.Version != config.FileVersion {
				t.Errorf("Version = %d, want %d", got.Version, config.FileVersion)
			}
		})
	}
}

func TestSave(t *testing.T) {
	netra, _ := config.Preset("netra")
	good := config.Config{Version: config.FileVersion, Providers: []config.Provider{netra}}
	tests := []struct {
		name string
		// inputs
		old   *config.Config // saved first
		cfg   config.Config
		block bool // config.json is a non-empty directory, so the rename fails
		// expectations
		wantErr string // substring
		wantOld bool   // the old file is unchanged
	}{
		{name: "a valid config round-trips", cfg: good},
		{name: "an empty config is written with an empty list", cfg: config.Config{Version: config.FileVersion}},
		{name: "the new config replaces the old one", old: &config.Config{Version: config.FileVersion}, cfg: good},
		{
			name: "an invalid config leaves the old file as it was",
			old:  &good, cfg: config.Config{Version: 2},
			wantErr: "version must be 1", wantOld: true,
		},
		{
			name:  "a failed rename leaves no temporary file",
			cfg:   good,
			block: true, wantErr: "save config",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			home := t.TempDir()
			var before []byte
			if tt.old != nil {
				if err := config.Save(home, *tt.old); err != nil {
					t.Fatal(err)
				}
				before = readFile(t, config.Path(home))
			}
			if tt.block {
				if err := os.MkdirAll(filepath.Join(config.Path(home), "x"), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			err := config.Save(home, tt.cfg)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("Save error = %v, want it to contain %q", err, tt.wantErr)
				}
				entries, err := os.ReadDir(home)
				if err != nil {
					t.Fatal(err)
				}
				if len(entries) != 1 {
					t.Errorf("home holds %d entries after a failed save, want only config.json", len(entries))
				}
				if tt.wantOld && string(readFile(t, config.Path(home))) != string(before) {
					t.Error("a failed save changed the old file")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if runtime.GOOS != "windows" {
				fi, err := os.Stat(config.Path(home))
				if err != nil {
					t.Fatal(err)
				}
				if fi.Mode().Perm() != 0o600 {
					t.Errorf("mode = %v, want 0600", fi.Mode().Perm())
				}
			}
			if strings.Contains(string(readFile(t, config.Path(home))), "null") {
				t.Errorf("config.json holds null: %s", readFile(t, config.Path(home)))
			}
			got, err := config.Load(home)
			if err != nil {
				t.Fatal(err)
			}
			if len(got.Providers) != len(tt.cfg.Providers) || (len(got.Providers) > 0 && got.Providers[0] != tt.cfg.Providers[0]) {
				t.Errorf("Load after Save = %+v, want %+v", got, tt.cfg)
			}
		})
	}
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestProviderValidate(t *testing.T) {
	netra, _ := config.Preset("netra")
	with := func(f func(p *config.Provider)) config.Provider {
		p := netra
		f(&p)
		return p
	}
	tests := []struct {
		name string
		// inputs
		p config.Provider
		// expectations
		wantErr string // substring; empty means valid
	}{
		{name: "the netra preset", p: netra},
		{name: "an empty key_env", p: with(func(p *config.Provider) { p.KeyEnv = "" })},
		{name: "a URL with a path and a port", p: with(func(p *config.Provider) { p.URL = "https://example.com:8443/api" })},
		{name: "a name with a capital", p: with(func(p *config.Provider) { p.Name = "Netra" }), wantErr: "provider name must match"},
		{name: "a name that starts with a digit", p: with(func(p *config.Provider) { p.Name = "1a" }), wantErr: "provider name must match"},
		{name: "a name of 33 bytes", p: with(func(p *config.Provider) { p.Name = "a" + strings.Repeat("b", 32) }), wantErr: "provider name must match"},
		{name: "a URL over 256 bytes", p: with(func(p *config.Provider) { p.URL = "https://example.com/" + strings.Repeat("a", 240) }), wantErr: "longer than 256 bytes"},
		{name: "a URL with a space", p: with(func(p *config.Provider) { p.URL = "https://exa mple.com" }), wantErr: "printable ASCII"},
		{name: "a URL with a bidi character", p: with(func(p *config.Provider) { p.URL = "https://example.com/\u202e" }), wantErr: "printable ASCII"},
		{name: "a URL that does not parse", p: with(func(p *config.Provider) { p.URL = "https://[::1" }), wantErr: "url is not valid"},
		{name: "an http URL", p: with(func(p *config.Provider) { p.URL = "http://example.com" }), wantErr: "must be https"},
		{name: "a URL without a host", p: with(func(p *config.Provider) { p.URL = "https:///path" }), wantErr: "must be https"},
		{name: "a URL with user info", p: with(func(p *config.Provider) { p.URL = "https://user:pw@example.com" }), wantErr: "user info"},
		{name: "a URL with a query", p: with(func(p *config.Provider) { p.URL = "https://example.com/?a=b" }), wantErr: "query or a fragment"},
		{name: "a URL with an empty query", p: with(func(p *config.Provider) { p.URL = "https://example.com/?" }), wantErr: "query or a fragment"},
		{name: "a URL with a fragment", p: with(func(p *config.Provider) { p.URL = "https://example.com/#a" }), wantErr: "query or a fragment"},
		{name: "a lower-case key_env", p: with(func(p *config.Provider) { p.KeyEnv = "netra_key" }), wantErr: "key_env must match"},
		{name: "a key_env of 65 bytes", p: with(func(p *config.Provider) { p.KeyEnv = strings.Repeat("A", 65) }), wantErr: "key_env must match"},
		{name: "an empty model", p: with(func(p *config.Provider) { p.Model = "" }), wantErr: "model must match"},
		{name: "a model with a space", p: with(func(p *config.Provider) { p.Model = "a b" }), wantErr: "model must match"},
		{name: "a model of 129 bytes", p: with(func(p *config.Provider) { p.Model = strings.Repeat("a", 129) }), wantErr: "model must match"},
		{name: "a timeout of 1 s", p: with(func(p *config.Provider) { p.TimeoutSeconds = 1 })},
		{name: "a timeout of 150 s", p: with(func(p *config.Provider) { p.TimeoutSeconds = 150 })},
		{name: "a timeout of 0", p: with(func(p *config.Provider) { p.TimeoutSeconds = 0 }), wantErr: "timeout must be 1 to 150 seconds"},
		{name: "a timeout of 151 s", p: with(func(p *config.Provider) { p.TimeoutSeconds = 151 }), wantErr: "timeout must be 1 to 150 seconds"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.p.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Validate error = %v, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestPreset(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		preset string
		// expectations
		wantOK  bool
		wantURL string
	}{
		{name: "netra", preset: "netra", wantOK: true, wantURL: "https://api.netraruntime.com"},
		{name: "any other name has no preset", preset: "other"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, ok := config.Preset(tt.preset)
			if ok != tt.wantOK || p.URL != tt.wantURL {
				t.Errorf("Preset(%q) = %+v, %v, want url %q, %v", tt.preset, p, ok, tt.wantURL, tt.wantOK)
			}
			if ok {
				if err := p.Validate(); err != nil {
					t.Errorf("the preset is not valid: %v", err)
				}
				if p.KeyEnv != "NETRA_API_KEY" || p.Model != "deepseek/deepseek-v4.1-flash" || p.TimeoutSeconds != 60 {
					t.Errorf("preset = %+v", p)
				}
			}
		})
	}
}
