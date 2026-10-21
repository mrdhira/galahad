package config_test

import (
	"path/filepath"
	"testing"

	"github.com/mrdhira/galahad/internal/config"
)

func TestHome(t *testing.T) {
	userHome := t.TempDir()
	tests := []struct {
		name string
		env  string // GALAHAD_HOME
		want string
	}{
		{name: "default is ~/.galahad", env: "", want: filepath.Join(userHome, ".galahad")},
		{name: "GALAHAD_HOME wins", env: "/custom/gh", want: "/custom/gh"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("GALAHAD_HOME", tt.env)
			t.Setenv("HOME", userHome)        // unix
			t.Setenv("USERPROFILE", userHome) // windows
			got, err := config.Home()
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Errorf("Home() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDirs(t *testing.T) {
	home := filepath.Join("x", "gh")
	tests := []struct {
		name string
		got  string
		want string
	}{
		{name: "jobs", got: config.JobsDir(home), want: filepath.Join(home, "jobs")},
		{name: "images", got: config.ImagesDir(home), want: filepath.Join(home, "images")},
		{name: "bin", got: config.BinDir(home), want: filepath.Join(home, "bin")},
		{name: "signatures image", got: config.SignaturesPath(home), want: filepath.Join(home, "signatures.img")},
		{name: "signatures stamp", got: config.SignaturesStamp(home), want: filepath.Join(home, "signatures.stamp")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Errorf("got %q, want %q", tt.got, tt.want)
			}
		})
	}
}
