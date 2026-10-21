package images_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/mrdhira/galahad/internal/images"
)

const hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func valid() images.Pins {
	return images.Pins{
		Version: "1.2.3",
		Tag:     "images-1.2.3",
		Assets: []images.Asset{
			{Name: "core.ext4.gz", File: "core.ext4", SHA256: hash, Size: 10, RawSHA256: hash, RawSize: 100},
		},
		Firecracker: images.Firecracker{Version: "v1.17.0", URL: "https://example.test/fc.tgz", SHA256: hash},
	}
}

func TestParse(t *testing.T) {
	tests := []struct {
		name    string
		raw     string // used instead of the encoded pins when set
		mutate  func(*images.Pins)
		wantErr string // substring; empty means success
	}{
		{name: "valid pins", mutate: func(*images.Pins) {}},
		{name: "unknown field", raw: `{"version":"1","extra":true}`, wantErr: "unknown field"},
		{name: "trailing data", raw: `{"version":"1"} {}`, wantErr: "trailing data"},
		{name: "empty version", mutate: func(p *images.Pins) { p.Version = "" }, wantErr: "empty version"},
		{name: "tag does not follow the version", mutate: func(p *images.Pins) { p.Tag = "images-9.9.9" }, wantErr: "must be images-1.2.3"},
		{name: "no assets", mutate: func(p *images.Pins) { p.Assets = nil }, wantErr: "no assets"},
		{name: "empty asset name", mutate: func(p *images.Pins) { p.Assets[0].Name = "" }, wantErr: "asset name"},
		{name: "asset name with a path", mutate: func(p *images.Pins) { p.Assets[0].Name = "../core.ext4.gz" }, wantErr: "plain file name"},
		{name: "empty unpacked file name", mutate: func(p *images.Pins) { p.Assets[0].File = "" }, wantErr: "file"},
		{name: "short asset hash", mutate: func(p *images.Pins) { p.Assets[0].SHA256 = "abcd" }, wantErr: "asset core.ext4.gz sha256"},
		{name: "upper-case asset hash", mutate: func(p *images.Pins) { p.Assets[0].SHA256 = strings.ToUpper(hash) }, wantErr: "asset core.ext4.gz sha256"},
		{name: "non-hex raw hash", mutate: func(p *images.Pins) { p.Assets[0].RawSHA256 = strings.Repeat("g", 64) }, wantErr: "raw_sha256"},
		{name: "placeholder asset hash", mutate: func(p *images.Pins) { p.Assets[0].SHA256 = strings.Repeat("0", 64) }, wantErr: "placeholder"},
		{name: "negative size", mutate: func(p *images.Pins) { p.Assets[0].RawSize = -1 }, wantErr: "negative size"},
		{name: "empty firecracker version", mutate: func(p *images.Pins) { p.Firecracker.Version = "" }, wantErr: "firecracker version"},
		{name: "firecracker url not https", mutate: func(p *images.Pins) { p.Firecracker.URL = "http://example.test/fc.tgz" }, wantErr: "must be https"},
		{name: "bad firecracker hash", mutate: func(p *images.Pins) { p.Firecracker.SHA256 = "" }, wantErr: "firecracker sha256"},
		{name: "placeholder firecracker hash", mutate: func(p *images.Pins) { p.Firecracker.SHA256 = strings.Repeat("0", 64) }, wantErr: "placeholder"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := []byte(tt.raw)
			if tt.raw == "" {
				p := valid()
				tt.mutate(&p)
				var err error
				if raw, err = json.Marshal(p); err != nil {
					t.Fatal(err)
				}
			}
			got, err := images.Parse(raw)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("Parse error = %v, want it to contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if got.Version != "1.2.3" || len(got.Assets) != 1 || got.Assets[0].RawSize != 100 {
				t.Errorf("Parse = %+v", got)
			}
		})
	}
}

func TestLoad(t *testing.T) {
	tests := []struct {
		name       string
		wantAssets []string
	}{
		{name: "the embedded pins are valid", wantAssets: []string{"vmlinux.gz", "core.ext4.gz", "re.ext4.gz"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := images.Load()
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if len(p.Assets) != len(tt.wantAssets) {
				t.Fatalf("assets = %+v, want %v", p.Assets, tt.wantAssets)
			}
			for i, want := range tt.wantAssets {
				if p.Assets[i].Name != want {
					t.Errorf("asset %d = %s, want %s", i, p.Assets[i].Name, want)
				}
			}
			if !strings.HasPrefix(p.Firecracker.Version, "v") {
				t.Errorf("firecracker version = %q", p.Firecracker.Version)
			}
		})
	}
}
