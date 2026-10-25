package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	// FileVersion is the only version of config.json.
	FileVersion = 1
	// MaxProviders is the most providers config.json may hold.
	MaxProviders = 16
	// MaxTimeoutSeconds is the longest time limit of a provider.
	MaxTimeoutSeconds = 150
	// DefaultTimeoutSeconds is the time limit of a provider that does not set one.
	DefaultTimeoutSeconds = 60

	fileName    = "config.json"
	maxFileSize = 64 << 10
	maxURLBytes = 256
)

var (
	nameRe   = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
	keyEnvRe = regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,63}$`)
	modelRe  = regexp.MustCompile(`^[A-Za-z0-9._/:-]{1,128}$`)
)

// Provider is a decision provider. It holds the name of the environment variable that carries the
// key, never the key.
type Provider struct {
	Name           string `json:"name"`
	URL            string `json:"url"`
	KeyEnv         string `json:"key_env"`
	Model          string `json:"model"`
	TimeoutSeconds int    `json:"timeout_seconds"`
}

// Config is the content of config.json.
type Config struct {
	Version   int        `json:"version"`
	Providers []Provider `json:"providers"`
}

// Preset returns the built-in provider with the given name.
func Preset(name string) (Provider, bool) {
	if name != "netra" {
		return Provider{}, false
	}
	return Provider{
		Name:           "netra",
		URL:            "https://api.netraruntime.com",
		KeyEnv:         "NETRA_API_KEY",
		Model:          "deepseek/deepseek-v4.1-flash",
		TimeoutSeconds: DefaultTimeoutSeconds,
	}, true
}

// Validate checks every field of p. The errors never repeat a value, so they are safe to show
// for a config file that is not trusted.
func (p Provider) Validate() error {
	if !nameRe.MatchString(p.Name) {
		return errors.New("provider name must match ^[a-z][a-z0-9-]{0,31}$")
	}
	if err := validateURL(p.URL); err != nil {
		return fmt.Errorf("provider %s: %w", p.Name, err)
	}
	if p.KeyEnv != "" && !keyEnvRe.MatchString(p.KeyEnv) {
		return fmt.Errorf("provider %s: key_env must match ^[A-Z_][A-Z0-9_]{0,63}$ or be empty", p.Name)
	}
	if !modelRe.MatchString(p.Model) {
		return fmt.Errorf("provider %s: model must match ^[A-Za-z0-9._/:-]{1,128}$", p.Name)
	}
	if p.TimeoutSeconds < 1 || p.TimeoutSeconds > MaxTimeoutSeconds {
		return fmt.Errorf("provider %s: timeout must be 1 to %d seconds", p.Name, MaxTimeoutSeconds)
	}
	return nil
}

func validateURL(s string) error {
	if len(s) > maxURLBytes {
		return fmt.Errorf("url is longer than %d bytes", maxURLBytes)
	}
	for i := 0; i < len(s); i++ {
		if s[i] <= ' ' || s[i] > '~' {
			return errors.New("url must be printable ASCII without spaces")
		}
	}
	u, err := url.Parse(s)
	switch {
	case err != nil:
		return errors.New("url is not valid")
	case u.Scheme != "https" || u.Hostname() == "":
		return errors.New("url must be https with a host")
	case u.User != nil:
		return errors.New("url must not have user info")
	case strings.ContainsAny(s, "?#"):
		return errors.New("url must not have a query or a fragment")
	}
	return nil
}

// Validate checks the version, the number of providers, every provider and the uniqueness of the names.
func (c Config) Validate() error {
	if c.Version != FileVersion {
		return fmt.Errorf("version must be %d", FileVersion)
	}
	if len(c.Providers) > MaxProviders {
		return fmt.Errorf("at most %d providers", MaxProviders)
	}
	seen := make(map[string]bool, len(c.Providers))
	for _, p := range c.Providers {
		if err := p.Validate(); err != nil {
			return err
		}
		if seen[p.Name] {
			return fmt.Errorf("provider %s appears twice", p.Name)
		}
		seen[p.Name] = true
	}
	return nil
}

// Find returns the provider with the given name.
func (c Config) Find(name string) (Provider, bool) {
	for _, p := range c.Providers {
		if p.Name == name {
			return p, true
		}
	}
	return Provider{}, false
}

// Path returns the config file in the galahad home directory.
func Path(home string) string { return filepath.Join(home, fileName) }

// Load reads and strictly decodes config.json in home. A missing file is an empty config. It
// refuses anything but a regular file of at most 64 KiB, and an error never repeats the content
// of the file.
func Load(home string) (Config, error) {
	path := Path(home)
	fi, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return Config{Version: FileVersion}, nil
	}
	if err != nil {
		return Config{}, fmt.Errorf("load %s: %w", path, err)
	}
	if fi.Mode()&fs.ModeSymlink != 0 {
		return Config{}, fmt.Errorf("load %s: it is a symlink", path)
	}
	if !fi.Mode().IsRegular() {
		return Config{}, fmt.Errorf("load %s: it is not a regular file", path)
	}
	f, err := os.OpenFile(path, readFlags, 0) // #nosec G304 -- the path is in galahad's own state directory
	if err != nil {
		return Config{}, fmt.Errorf("load %s: %w", path, err)
	}
	defer func() { _ = f.Close() }() // read-only file
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		return Config{}, fmt.Errorf("load %s: it is not a regular file", path)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxFileSize+1))
	if err != nil {
		return Config{}, fmt.Errorf("load %s: %w", path, err)
	}
	if len(data) > maxFileSize {
		return Config{}, fmt.Errorf("load %s: it is larger than %d bytes", path, maxFileSize)
	}

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var c Config
	if err := dec.Decode(&c); err != nil {
		return Config{}, fmt.Errorf("load %s: %w", path, decodeError(err))
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return Config{}, fmt.Errorf("load %s: trailing data after the JSON value", path)
	}
	if err := c.Validate(); err != nil {
		return Config{}, fmt.Errorf("load %s: %w", path, err)
	}
	return c, nil
}

// decodeError describes a decode error without the content of the file. Only an unknown field
// that looks like it holds a key gets a message of its own.
func decodeError(err error) error {
	if name, ok := strings.CutPrefix(err.Error(), `json: unknown field "`); ok {
		lower := strings.ToLower(name)
		for _, w := range []string{"key", "secret", "token", "password"} {
			if strings.Contains(lower, w) {
				return errors.New("keys are read from environment variables only; use key_env")
			}
		}
		return errors.New("unknown field")
	}
	return errors.New("not valid JSON for the config")
}

// Save validates c and writes it to config.json in home with mode 0600. It writes a temporary
// file in the same directory and renames it, so a failed save leaves the old file as it was.
func Save(home string, c Config) error {
	if err := c.Validate(); err != nil {
		return fmt.Errorf("save config: %w", err)
	}
	if c.Providers == nil {
		c.Providers = []Provider{} // "providers": [], not null
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("save config: %w", err)
	}
	if err := os.MkdirAll(home, 0o700); err != nil {
		return fmt.Errorf("save config: %w", err)
	}
	tmp, err := os.CreateTemp(home, fileName+".*.tmp")
	if err != nil {
		return fmt.Errorf("save config: %w", err)
	}
	_, err = tmp.Write(append(data, '\n'))
	if err == nil {
		err = tmp.Chmod(0o600)
	}
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp.Name(), Path(home))
	}
	if err != nil {
		_ = os.Remove(tmp.Name()) // best effort; err is the one to report
		return fmt.Errorf("save config: %w", err)
	}
	return nil
}
