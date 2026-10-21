package analyze_test

import (
	"context"
	"errors"
	"io/fs"
	"strings"
	"testing"

	"github.com/mrdhira/galahad/internal/analyze"
)

// openProbe is an analyzer that records what File.Open gives the file "main"
// for each path it is asked to read. Reading is repeated reads times.
func openProbe(paths []string, reads int, got map[string]string) analyze.Analyzer {
	return fake{name: "probe", fn: func(_ context.Context, f analyze.File) (analyze.Output, error) {
		if f.Name != "main" {
			return analyze.Output{}, nil
		}
		if f.Open == nil {
			got["<open>"] = "nil"
			return analyze.Output{}, nil
		}
		for range reads {
			for _, p := range paths {
				data, err := f.Open(p)
				switch {
				case errors.Is(err, fs.ErrNotExist):
					got[p] = "notexist"
				case err != nil:
					got[p] = "error"
				default:
					got[p] = "data:" + string(data)
				}
			}
		}
		return analyze.Output{}, nil
	}}
}

func TestRunOpen(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		files  map[string]string // path to content, "main" is the file analyzed
		paths  []string          // paths the analyzer reads
		reads  int               // times each path is read, 1 when zero
		target string            // path of the target, the directory when empty
		// expectations
		wantGot map[string]string
	}{
		{
			name:    "a file next to the analyzed one is read",
			files:   map[string]string{"main": "m", "sub/x.txt": "hello"},
			paths:   []string{"sub/x.txt"},
			wantGot: map[string]string{"sub/x.txt": "data:hello"},
		},
		{
			name:    "a missing file wraps not exist",
			files:   map[string]string{"main": "m"},
			paths:   []string{"nope.txt"},
			wantGot: map[string]string{"nope.txt": "notexist"},
		},
		{
			name:    "paths that climb out of the target or name the root are refused",
			files:   map[string]string{"main": "m"},
			paths:   []string{"../main", "a/../main", "/etc/passwd", ".", ""},
			wantGot: map[string]string{"../main": "error", "a/../main": "error", "/etc/passwd": "error", ".": "error", "": "error"},
		},
		{
			name:    "a directory is refused",
			files:   map[string]string{"main": "m", "sub/x.txt": "x"},
			paths:   []string{"sub"},
			wantGot: map[string]string{"sub": "error"},
		},
		{
			name:    "a file over the config size limit is refused",
			files:   map[string]string{"main": "m", "big": strings.Repeat("x", analyze.MaxConfigSize+1)},
			paths:   []string{"big"},
			wantGot: map[string]string{"big": "error"},
		},
		{
			name:    "reads stop at the per-job limit",
			files:   map[string]string{"main": "m", "x": "x"},
			paths:   []string{"x"},
			reads:   analyze.MaxNeighborReads + 1,
			wantGot: map[string]string{"x": "error"},
		},
		{
			name:    "a single file target has no neighbors",
			files:   map[string]string{"main": "m"},
			target:  "main",
			paths:   []string{"x"},
			wantGot: map[string]string{"<open>": "nil"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			for name, data := range tt.files {
				write(t, dir, name, []byte(data))
			}
			target := dir
			if tt.target != "" {
				target = dir + "/" + tt.target
			}
			got := map[string]string{}

			_, err := analyze.Run(context.Background(), target, []analyze.Analyzer{openProbe(tt.paths, max(tt.reads, 1), got)})

			if err != nil {
				t.Fatal(err)
			}
			if len(got) != len(tt.wantGot) {
				t.Errorf("got %v, want %v", got, tt.wantGot)
			}
			for p, want := range tt.wantGot {
				if got[p] != want {
					t.Errorf("Open(%q) = %q, want %q", p, got[p], want)
				}
			}
		})
	}
}

func TestRunOpenMember(t *testing.T) {
	tests := []struct {
		name string
		// expectations
		wantMemberOpenNil bool
	}{
		{name: "a container member has no neighbors", wantMemberOpenNil: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			write(t, dir, "a.zip", []byte("x"))
			var memberSeen, memberNil bool
			spy := fake{name: "spy", fn: func(_ context.Context, f analyze.File) (analyze.Output, error) {
				if f.Name == "a.zip" {
					return analyze.Output{Children: []analyze.File{{Name: "m", Data: []byte("x")}}}, nil
				}
				if f.Member != "" {
					memberSeen, memberNil = true, f.Open == nil
				}
				return analyze.Output{}, nil
			}}

			if _, err := analyze.Run(context.Background(), dir, []analyze.Analyzer{spy}); err != nil {
				t.Fatal(err)
			}

			if !memberSeen || memberNil != tt.wantMemberOpenNil {
				t.Errorf("member seen = %v, Open nil = %v, want nil = %v", memberSeen, memberNil, tt.wantMemberOpenNil)
			}
		})
	}
}
