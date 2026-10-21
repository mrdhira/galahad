// Package images holds the pinned guest images and the pinned Firecracker release. The pins are
// committed with the source; .github/workflows/image.yml fails when a rebuild does not match them.
package images

import (
	"bytes"
	_ "embed" // pins.json
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

//go:embed pins.json
var pinsJSON []byte

// Asset is one downloadable image: a gzip file and the file it unpacks to.
type Asset struct {
	Name      string `json:"name"`       // release asset, for example core.ext4.gz
	File      string `json:"file"`       // unpacked file name, for example core.ext4
	SHA256    string `json:"sha256"`     // of the gzip file
	Size      int64  `json:"size"`       // of the gzip file in bytes
	RawSHA256 string `json:"raw_sha256"` // of the unpacked file
	RawSize   int64  `json:"raw_size"`   // of the unpacked file in bytes
}

// Firecracker is the pinned Firecracker release archive.
type Firecracker struct {
	Version string `json:"version"`
	URL     string `json:"url"`
	SHA256  string `json:"sha256"`
}

// Pins is the content of pins.json.
type Pins struct {
	Version     string      `json:"version"` // images/linux/VERSION
	Tag         string      `json:"tag"`     // the release that holds the assets: images-<Version>
	Assets      []Asset     `json:"assets"`
	Firecracker Firecracker `json:"firecracker"`
}

// Load decodes and validates the embedded pins.
func Load() (Pins, error) {
	return Parse(pinsJSON)
}

// Parse decodes data strictly (unknown fields and trailing data are errors) and validates it.
func Parse(data []byte) (Pins, error) {
	var p Pins
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return Pins{}, fmt.Errorf("decode pins: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return Pins{}, errors.New("decode pins: trailing data")
	}
	if err := p.validate(); err != nil {
		return Pins{}, err
	}
	return p, nil
}

func (p Pins) validate() error {
	if p.Version == "" {
		return errors.New("pins: empty version")
	}
	if p.Tag != "images-"+p.Version {
		return fmt.Errorf("pins: tag %q must be images-%s", p.Tag, p.Version)
	}
	if len(p.Assets) == 0 {
		return errors.New("pins: no assets")
	}
	for _, a := range p.Assets {
		if err := validName(a.Name); err != nil {
			return fmt.Errorf("pins: asset name: %w", err)
		}
		if err := validName(a.File); err != nil {
			return fmt.Errorf("pins: asset %s file: %w", a.Name, err)
		}
		if err := validHash(a.SHA256); err != nil {
			return fmt.Errorf("pins: asset %s sha256: %w", a.Name, err)
		}
		if err := validHash(a.RawSHA256); err != nil {
			return fmt.Errorf("pins: asset %s raw_sha256: %w", a.Name, err)
		}
		if a.Size < 0 || a.RawSize < 0 {
			return fmt.Errorf("pins: asset %s has a negative size", a.Name)
		}
	}
	f := p.Firecracker
	if f.Version == "" {
		return errors.New("pins: empty firecracker version")
	}
	if !strings.HasPrefix(f.URL, "https://") {
		return fmt.Errorf("pins: firecracker url %q must be https", f.URL)
	}
	if err := validHash(f.SHA256); err != nil {
		return fmt.Errorf("pins: firecracker sha256: %w", err)
	}
	return nil
}

// validName accepts a plain file name: it is joined to a directory or a URL later.
func validName(s string) error {
	if s == "" || s == "." || s == ".." || strings.ContainsAny(s, `/\`) {
		return fmt.Errorf("%q is not a plain file name", s)
	}
	return nil
}

// validHash accepts 64 lower-case hex digits, the form sha256sum prints.
func validHash(s string) error {
	if _, err := hex.DecodeString(s); err != nil || len(s) != 64 || strings.ToLower(s) != s {
		return fmt.Errorf("%q is not 64 lower-case hex digits", s)
	}
	// All zeros is the placeholder for a hash that is not known yet, so it must never be committed.
	if s == strings.Repeat("0", 64) {
		return errors.New("is the all-zero placeholder")
	}
	return nil
}
