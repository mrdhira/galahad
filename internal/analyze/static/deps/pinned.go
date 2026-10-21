package deps

import (
	"path"
	"regexp"
	"strings"

	"github.com/mrdhira/galahad/internal/analyze"
)

// Package ecosystems, as OSV names them.
const (
	EcosystemNPM  = "npm"
	EcosystemPyPI = "PyPI"
)

// Package is a dependency pinned to one version.
type Package struct {
	Ecosystem string
	Name      string
	Version   string
}

var (
	npmPackage = regexp.MustCompile(`(?i)^(?:@[a-z0-9._~-]+/)?[a-z0-9._~-]+$`)
	pinVersion = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+!_-]*$`)
	// pyPin is one requirement cut down to "name[extras]==version": the options, markers and
	// comments are already gone.
	pyPin = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[A-Za-z0-9._, -]*\])?\s*===?\s*(\S+)$`)
)

const (
	maxPackageName    = 214 // bytes, the npm limit
	maxPackageVersion = 128
)

// Pinned returns the dependencies of one file that are pinned to an exact version, in file order and
// without repeats. name is the path of the file below the target, with slashes. It reads
// package-lock.json (lockfile versions 2 and 3, which list every package under "packages") and
// requirements files with "==" pins, and returns nothing for any other file, for a lockfile of
// version 1 and for a file that does not parse. Packages that come from a path, a workspace or a
// range are not pinned and not listed. The lengths of names and versions are bounded.
func Pinned(name string, data []byte) []Package {
	lock, requirements := pinFile(name)
	var c collector
	switch {
	case lock:
		pinnedLock(&c, data)
	case requirements, strings.HasSuffix(strings.ToLower(name), ".txt") && looksLikeRequirements(data):
		pinnedRequirements(&c, data)
	}
	return c.pkgs
}

// PinnedByName reports whether Pinned reads a file because of its name: a package-lock.json, a
// requirements*.txt, or a .txt file below a directory named requirements. Pinned also reads any other
// .txt file whose content looks like a requirements file, which a name cannot tell.
func PinnedByName(name string) bool {
	lock, requirements := pinFile(name)
	return lock || requirements
}

// pinFile classifies a file by its name.
func pinFile(name string) (lock, requirements bool) {
	base := strings.ToLower(path.Base(name))
	switch {
	case base == "package-lock.json":
		return true, false
	case !strings.HasSuffix(base, ".txt"):
		return false, false
	}
	return false, strings.HasPrefix(base, "requirements") || inRequirementsDir(name)
}

// collector keeps the well formed packages it is given, each once.
type collector struct {
	pkgs []Package
	seen map[Package]bool
}

func (c *collector) add(ecosystem, name, version string) {
	if len(name) > maxPackageName || len(version) > maxPackageVersion || !pinVersion.MatchString(version) {
		return
	}
	if ecosystem == EcosystemNPM && !npmPackage.MatchString(name) {
		return
	}
	p := Package{Ecosystem: ecosystem, Name: name, Version: version}
	if c.seen[p] {
		return
	}
	if c.seen == nil {
		c.seen = map[Package]bool{}
	}
	c.seen[p] = true
	c.pkgs = append(c.pkgs, p)
}

// pinnedLock reads the "packages" section of a lockfile. The key of an entry is its path, such as
// "node_modules/a/node_modules/b"; an entry without a node_modules directory is a workspace package.
// An entry may name the real package in "name", when the key is an alias.
func pinnedLock(c *collector, data []byte) {
	members, _ := walkJSON(data) // what was read before an error still counts
	type entry struct{ name, version string }
	var order []string
	entries := map[string]*entry{}
	for _, m := range members {
		if len(m.path) != 3 || m.path[0] != "packages" || (m.path[2] != "version" && m.path[2] != "name") {
			continue
		}
		e := entries[m.path[1]]
		if e == nil {
			e = &entry{}
			entries[m.path[1]] = e
			order = append(order, m.path[1])
		}
		if m.path[2] == "version" {
			e.version = m.val
		} else {
			e.name = m.val
		}
	}
	for _, key := range order {
		i := strings.LastIndex(key, "node_modules/")
		if i < 0 {
			continue // the project itself or a workspace package
		}
		e := entries[key]
		name := e.name
		if name == "" {
			name = key[i+len("node_modules/"):]
		}
		c.add(EcosystemNPM, name, e.version)
	}
}

// pinnedRequirements reads the "name==version" lines of a requirements file.
func pinnedRequirements(c *collector, data []byte) {
	for line := range strings.SplitSeq(string(data), "\n") {
		s := strings.TrimSpace(line[:min(len(line), analyze.MaxLineScan)])
		if i := strings.Index(s, " #"); i >= 0 {
			s = s[:i]
		}
		s, _, _ = strings.Cut(s, ";") // an environment marker
		if i := strings.Index(s, " --"); i >= 0 {
			s = s[:i] // per-requirement options such as --hash
		}
		s = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(s), "\\"))
		if s == "" || s[0] == '#' || s[0] == '-' {
			continue
		}
		if m := pyPin.FindStringSubmatch(s); m != nil {
			c.add(EcosystemPyPI, pypiName(m[1]), m[2])
		}
	}
}
