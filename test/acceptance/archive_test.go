package acceptance_test

import (
	"archive/tar"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

// zipOfBenignCLI zips testdata/corpus/benign-go-cli into dest.
func zipOfBenignCLI(t *testing.T, dest string) {
	t.Helper()
	root, err := moduleRoot()
	if err != nil {
		t.Fatal(err)
	}
	zipDir(t, filepath.Join(root, "testdata", "corpus", "benign-go-cli"), dest)
}

func TestArchive(t *testing.T) {
	tests := []struct {
		name string
		// build writes the archive to dest
		build func(t *testing.T, dest string)
		file  string // archive file name
		// expectations
		wantCode     int
		wantRule     string   // rule that must be present at wantAt; empty means no findings at all
		wantAt       string   // "path:line"
		wantFiles    []string // paths that must be listed in files
		wantSkips    int      // number of coverage skips
		wantMaxSecs  float64  // 0 means no time limit
		wantAllClean bool     // every file seen was analyzed
	}{
		{
			name: "benign-archive lists the members of a zip of the benign CLI",
			file: "benign.zip",
			build: func(t *testing.T, dest string) {
				zipOfBenignCLI(t, dest)
			},
			wantCode:     0,
			wantFiles:    []string{"benign.zip", "benign.zip!/main.go", "benign.zip!/go.mod", "benign.zip!/Makefile"},
			wantAllClean: true,
		},
		{
			name: "archive-zipslip skips the member and reports it",
			file: "evil.zip",
			build: func(t *testing.T, dest string) {
				zipEntries(t, dest, []zipEntry{{name: "../../evil.sh", data: []byte("echo hi\n")}, {name: "ok.txt", data: []byte("fine\n")}})
			},
			wantCode:  10,
			wantRule:  "GAL-ARCHIVE-001",
			wantAt:    "evil.zip!/../../evil.sh:0",
			wantFiles: []string{"evil.zip!/ok.txt"},
		},
		{
			name: "zip with only nested safe names has no finding",
			file: "safe.zip",
			build: func(t *testing.T, dest string) {
				zipEntries(t, dest, []zipEntry{{name: "a/b/ok.txt", data: []byte("fine\n")}, {name: "a..b.txt", data: []byte("fine\n")}})
			},
			wantCode:     0,
			wantFiles:    []string{"safe.zip!/a/b/ok.txt", "safe.zip!/a..b.txt"},
			wantAllClean: true,
		},
		{
			name: "archive-bomb stops at the ratio limit and finishes quickly",
			file: "bomb.zip",
			build: func(t *testing.T, dest string) {
				zipZeros(t, dest, "zeros.bin", 200<<20)
			},
			wantCode:    10,
			wantRule:    "GAL-ARCHIVE-003",
			wantAt:      "bomb.zip:0",
			wantSkips:   1,
			wantMaxSecs: 30,
		},
		{
			name: "small run of zeros is not a bomb",
			file: "small.zip",
			build: func(t *testing.T, dest string) {
				zipZeros(t, dest, "zeros.bin", 512<<10)
			},
			wantCode:     0,
			wantFiles:    []string{"small.zip!/zeros.bin"},
			wantAllClean: true,
		},
		{
			name: "archive-symlink reports the link and never resolves it",
			file: "links.tgz",
			build: func(t *testing.T, dest string) {
				tarGz(t, dest, []tarEntry{{name: "link", typeflag: tar.TypeSymlink, link: "/etc/passwd"}, {name: "ok.txt", data: []byte("fine\n")}})
			},
			wantCode:  10,
			wantRule:  "GAL-ARCHIVE-002",
			wantAt:    "links.tgz!/link:0",
			wantFiles: []string{"links.tgz!/ok.txt"},
		},
		{
			name: "tgz with regular files only has no finding",
			file: "plain.tgz",
			build: func(t *testing.T, dest string) {
				tarGz(t, dest, []tarEntry{{name: "dir/ok.txt", data: []byte("fine\n")}})
			},
			wantCode:     0,
			wantFiles:    []string{"plain.tgz!/dir/ok.txt"},
			wantAllClean: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given an archive built at test time inside a scratch tree
			root := t.TempDir()
			in := filepath.Join(root, "in")
			if err := os.Mkdir(in, 0o700); err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(in, tt.file)
			tt.build(t, target)
			out := filepath.Join(root, "out")
			// When the agent analyzes it
			start := time.Now()
			stdout, stderr, code := runAgent(t, "analyze", "--unsafe-host", "-o", out, target)
			elapsed := time.Since(start).Seconds()
			// Then the exit code, findings and coverage match
			if code != tt.wantCode {
				t.Fatalf("exit = %d, want %d\nstdout: %s\nstderr: %s", code, tt.wantCode, stdout, stderr)
			}
			b, err := os.ReadFile(filepath.Join(out, "report.json"))
			if err != nil {
				t.Fatal(err)
			}
			var rep report
			if err := json.Unmarshal(b, &rep); err != nil {
				t.Fatal(err)
			}
			if tt.wantRule == "" {
				if len(rep.Findings) != 0 {
					t.Errorf("findings = %+v, want none", rep.Findings)
				}
			} else if !hasFinding(rep, tt.wantRule, tt.wantAt) {
				t.Errorf("no %s at %s in %+v", tt.wantRule, tt.wantAt, rep.Findings)
			}
			var paths []string
			for _, f := range rep.Files {
				paths = append(paths, f.Path)
			}
			for _, want := range tt.wantFiles {
				if !slices.Contains(paths, want) {
					t.Errorf("files %v lack %s", paths, want)
				}
			}
			if len(rep.Coverage.Skipped) != tt.wantSkips {
				t.Errorf("skips = %+v, want %d", rep.Coverage.Skipped, tt.wantSkips)
			}
			if tt.wantAllClean && rep.Coverage.FilesAnalyzed != rep.Coverage.FilesSeen {
				t.Errorf("analyzed/seen = %d/%d, want all analyzed", rep.Coverage.FilesAnalyzed, rep.Coverage.FilesSeen)
			}
			if tt.wantMaxSecs > 0 && elapsed > tt.wantMaxSecs {
				t.Errorf("took %.1fs, want under %.0fs", elapsed, tt.wantMaxSecs)
			}
			// And nothing was written outside the output directory: no member was extracted anywhere
			var stray []string
			err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
				if err != nil {
					return err
				}
				rel, _ := filepath.Rel(root, p)
				if rel != "." && rel != "in" && rel != "out" && !isUnder(rel, "in") && !isUnder(rel, "out") {
					stray = append(stray, rel)
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if len(stray) != 0 {
				t.Errorf("files written outside in/ and out/: %v", stray)
			}
			if entries, err := os.ReadDir(in); err != nil || len(entries) != 1 {
				t.Errorf("in/ = %v (err %v), want only the archive", entries, err)
			}
		})
	}
}

func isUnder(rel, dir string) bool {
	return len(rel) > len(dir) && rel[:len(dir)] == dir && os.IsPathSeparator(rel[len(dir)])
}
