package deps_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/mrdhira/galahad/internal/analyze/static/deps"
)

func TestPinnedByName(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		file string
		// expectations
		want bool
	}{
		{name: "a lockfile", file: "web/package-lock.json", want: true},
		{name: "a requirements file", file: "Requirements-dev.txt", want: true},
		{name: "a txt file below a requirements directory", file: "requirements/prod.txt", want: true},
		{name: "a txt file with another name", file: "notes.txt"},
		{name: "a package.json", file: "package.json"},
		{name: "a requirements name without the txt extension", file: "requirements.in"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := deps.PinnedByName(tt.file); got != tt.want {
				t.Errorf("PinnedByName(%q) = %v, want %v", tt.file, got, tt.want)
			}
		})
	}
}

func TestPinned(t *testing.T) {
	npm := func(name, version string) deps.Package {
		return deps.Package{Ecosystem: deps.EcosystemNPM, Name: name, Version: version}
	}
	pypi := func(name, version string) deps.Package {
		return deps.Package{Ecosystem: deps.EcosystemPyPI, Name: name, Version: version}
	}
	tests := []struct {
		name string
		// inputs
		file string
		data string
		// expectations
		want []deps.Package
	}{
		{
			name: "lockfile v3 lists every package under node_modules, scoped and nested ones too",
			file: "package-lock.json",
			data: `{"name":"demo","version":"1.0.0","lockfileVersion":3,"requires":true,"packages":{
"":{"name":"demo","version":"1.0.0","dependencies":{"left-pad":"^1.3.0"}},
"node_modules/left-pad":{"version":"1.3.0","resolved":"https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz","integrity":"sha512-x"},
"node_modules/@babel/core":{"version":"7.24.0"},
"node_modules/a/node_modules/b":{"version":"2.0.0-beta.1+build5"}}}`,
			want: []deps.Package{npm("left-pad", "1.3.0"), npm("@babel/core", "7.24.0"), npm("b", "2.0.0-beta.1+build5")},
		},
		{
			name: "lockfile v2 reads packages and ignores the legacy dependencies section",
			file: "sub/package-lock.json",
			data: `{"lockfileVersion":2,"packages":{"node_modules/x":{"version":"1.0.0"}},"dependencies":{"x":{"version":"1.0.0"},"y":{"version":"9.9.9"}}}`,
			want: []deps.Package{npm("x", "1.0.0")},
		},
		{
			name: "an alias is listed under the name of the real package",
			file: "package-lock.json",
			data: `{"lockfileVersion":3,"packages":{"node_modules/alias":{"name":"real-pkg","version":"3.1.4"}}}`,
			want: []deps.Package{npm("real-pkg", "3.1.4")},
		},
		{
			name: "the project, a workspace package and a link are not pinned dependencies",
			file: "package-lock.json",
			data: `{"lockfileVersion":3,"packages":{"":{"name":"root","version":"1.0.0"},"packages/ws":{"name":"ws","version":"0.0.1"},"node_modules/ws":{"resolved":"packages/ws","link":true}}}`,
		},
		{
			name: "the same package at the same version is listed once",
			file: "package-lock.json",
			data: `{"lockfileVersion":3,"packages":{"node_modules/x":{"version":"1.0.0"},"node_modules/a/node_modules/x":{"version":"1.0.0"},"node_modules/b/node_modules/x":{"version":"2.0.0"}}}`,
			want: []deps.Package{npm("x", "1.0.0"), npm("x", "2.0.0")},
		},
		{
			name: "a lockfile of version 1 has no packages section",
			file: "package-lock.json",
			data: `{"lockfileVersion":1,"dependencies":{"x":{"version":"1.0.0"}}}`,
		},
		{
			name: "a version or name that is not well formed is dropped",
			file: "package-lock.json",
			data: `{"lockfileVersion":3,"packages":{"node_modules/a":{"version":"git+ssh://host/a.git"},"node_modules/b":{"version":"^1.0.0"},"node_modules/c d":{"version":"1.0.0"},"node_modules/e":{"version":"1.0.0"}}}`,
			want: []deps.Package{npm("e", "1.0.0")},
		},
		{
			name: "a lockfile that is cut off keeps what was read",
			file: "package-lock.json",
			data: `{"lockfileVersion":3,"packages":{"node_modules/x":{"version":"1.0.0"},"node_modules/y":{"version":"2.0`,
			want: []deps.Package{npm("x", "1.0.0")},
		},
		{
			name: "a lockfile that is not JSON has no pins",
			file: "package-lock.json",
			data: "not json",
		},
		{
			name: "requirements pins with == are listed with a normalized name",
			file: "requirements.txt",
			data: "# deps\nFlask_Login==0.6.3\nrequests[security]==2.31.0 ; python_version >= '3.8'\nurllib3 == 2.0.7 # pinned\nold===1.0\nwith-hash==1.2.3 --hash=sha256:abcd \\\n    --hash=sha256:ef01\n",
			want: []deps.Package{pypi("flask-login", "0.6.3"), pypi("requests", "2.31.0"), pypi("urllib3", "2.0.7"), pypi("old", "1.0"), pypi("with-hash", "1.2.3")},
		},
		{
			name: "requirements ranges, wildcards, options and URLs are not pins",
			file: "requirements-dev.txt",
			data: "-r base.txt\n--index-url https://pypi.org/simple\nrequests>=2\nnumpy~=1.26\nscipy==1.*\npandas\ngit+https://example.com/x.git#egg=x\npkg @ https://example.com/pkg.zip\n",
		},
		{
			name: "a txt file under a requirements directory is read",
			file: "requirements/prod.txt",
			data: "flask==2.0.0\nflask==2.0.0\n",
			want: []deps.Package{pypi("flask", "2.0.0")},
		},
		{
			name: "a txt file that reads as requirements is read",
			file: "deps.txt",
			data: "-r other.txt\nflask==2.0.0\n",
			want: []deps.Package{pypi("flask", "2.0.0")},
		},
		{
			name: "a txt file that is prose is not read",
			file: "notes.txt",
			data: "Remember to run flask==2.0.0 before the demo.\n",
		},
		{
			name: "a version that is too long is dropped",
			file: "requirements.txt",
			data: "a==1." + strings.Repeat("0", 200) + "\nb==1.0\n",
			want: []deps.Package{pypi("b", "1.0")},
		},
		{
			name: "other files have no pins",
			file: "package.json",
			data: `{"dependencies":{"left-pad":"1.3.0"}}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := deps.Pinned(tt.file, []byte(tt.data))

			if !slices.Equal(got, tt.want) {
				t.Errorf("Pinned(%q) = %v, want %v", tt.file, got, tt.want)
			}
		})
	}
}
