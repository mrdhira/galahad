package analyze_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mrdhira/galahad/internal/analyze"
	"github.com/mrdhira/galahad/internal/protocol"
)

type fake struct {
	name string
	fn   func(ctx context.Context, f analyze.File) (analyze.Output, error)
}

func (a fake) Name() string { return a.name }

func (a fake) Analyze(ctx context.Context, f analyze.File) (analyze.Output, error) {
	return a.fn(ctx, f)
}

func write(t *testing.T, dir, rel string, data []byte) string {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func finding(id string, sev protocol.Severity, path string, line int, snippet string) protocol.Finding {
	r := protocol.Rule{ID: id, Severity: sev, Title: "t"}
	return r.Finding(protocol.Evidence{Path: path, Line: line, Snippet: snippet})
}

// nothing is an analyzer that finds nothing.
var nothing = fake{name: "nothing", fn: func(context.Context, analyze.File) (analyze.Output, error) {
	return analyze.Output{}, nil
}}

func TestRun(t *testing.T) {
	stamp := []analyze.Analyzer{
		fake{name: "zeta", fn: func(_ context.Context, f analyze.File) (analyze.Output, error) {
			out := analyze.Output{
				Findings: []protocol.Finding{
					finding("GAL-T-001", protocol.SeverityLow, f.Path, 0, ""),
					{RuleID: "GAL-T-009", Severity: protocol.SeverityCritical}, // no evidence: dropped
				},
				IOCs: []protocol.IOC{{Type: "url", Value: "http://x.test/", Path: f.Path}},
			}
			if f.Path == "b.txt" {
				out.Skips = []protocol.Skip{{Path: "b.txt!/enc", Reason: protocol.SkipEncrypted}}
			}
			return out, nil
		}},
		fake{name: "alpha", fn: func(_ context.Context, f analyze.File) (analyze.Output, error) {
			if f.Path != "b.txt" {
				return analyze.Output{}, nil
			}
			return analyze.Output{Findings: []protocol.Finding{finding("GAL-T-002", protocol.SeverityHigh, f.Path, 1, "hi")}}, nil
		}},
	}
	failOn := func(name string, fn func() (analyze.Output, error)) analyze.Analyzer {
		return fake{name: "fail", fn: func(_ context.Context, f analyze.File) (analyze.Output, error) {
			if f.Name == name {
				return fn()
			}
			return analyze.Output{}, nil
		}}
	}
	// children returns an analyzer that emits the given members for the file named parent.
	children := func(parent string, kids ...analyze.File) analyze.Analyzer {
		return fake{name: "kids", fn: func(_ context.Context, f analyze.File) (analyze.Output, error) {
			if f.Name == parent {
				return analyze.Output{Children: kids}, nil
			}
			return analyze.Output{}, nil
		}}
	}
	// sharedMembers returns members that together exceed MaxTotalBytes, all backed by one slice.
	sharedMembers := func() []analyze.File {
		shared := make([]byte, analyze.MaxFileSize+1) // too large to analyze, so only hashed
		var kids []analyze.File
		for i := range analyze.MaxTotalBytes / analyze.MaxFileSize {
			kids = append(kids, analyze.File{Name: fmt.Sprintf("m%d", i), Data: shared})
		}
		return kids
	}
	// 20 members of MaxFileSize each, then as many grandchildren as fit in what the budget has left.
	nestedShared := make([]byte, analyze.MaxFileSize)
	const nestedFit = (analyze.MaxTotalBytes - 1 - 20*analyze.MaxFileSize) / analyze.MaxFileSize
	nest := fake{name: "nest", fn: func(context.Context, analyze.File) (analyze.Output, error) {
		return analyze.Output{Children: []analyze.File{{Name: "c", Data: []byte("x")}}}, nil
	}}
	many := fake{name: "many", fn: func(_ context.Context, f analyze.File) (analyze.Output, error) {
		var out analyze.Output
		for range 25 {
			out.Findings = append(out.Findings, finding("GAL-T-003", protocol.SeverityLow, f.Path, 1, ""))
		}
		return out, nil
	}}
	tooMany := func(n int) analyze.Analyzer {
		return fake{name: "many", fn: func(_ context.Context, f analyze.File) (analyze.Output, error) {
			var out analyze.Output
			for i := range n {
				out.Findings = append(out.Findings, finding("GAL-T-004", protocol.SeverityLow, fmt.Sprintf("%s#%d", f.Path, i/protocol.MaxFindingsPerRulePerFile), 1, ""))
			}
			return out, nil
		}}
	}

	tests := []struct {
		name string
		// inputs
		setup     func(t *testing.T, dir string) string // returns the target path
		analyzers []analyze.Analyzer
		timeout   time.Duration // job timeout; 0 means none
		cancelled bool          // job context is cancelled before the run
		// expectations
		wantErr          bool
		wantTargetKind   string
		wantTargetSHA    string
		wantFileCount    int
		wantFiles        []string
		wantSeen         int
		wantAnalyzed     int
		wantSkips        []protocol.Skip
		wantFindings     []string // "rule@path:line analyzer snippet", in order; nil means do not check
		wantFindingCount int      // checked when > 0
		wantIOCs         int
		wantAnalyzerList []string
		wantTruncated    bool
	}{
		{
			name: "directory is walked in order, findings stamped and sorted, iocs deduplicated",
			setup: func(t *testing.T, dir string) string {
				write(t, dir, "b.txt", []byte("hello\n"))
				write(t, dir, "a/x.txt", []byte("x"))
				return dir
			},
			analyzers:      stamp,
			wantTargetKind: protocol.TargetDir,
			wantFileCount:  2,
			wantFiles:      []string{"a/x.txt", "b.txt"},
			wantSeen:       3, wantAnalyzed: 2, // the encrypted member counts as seen
			wantSkips: []protocol.Skip{{Path: "b.txt!/enc", Reason: protocol.SkipEncrypted}},
			wantFindings: []string{
				"GAL-T-002@b.txt:1 alpha hi",
				"GAL-T-001@a/x.txt:0 zeta ",
				"GAL-T-001@b.txt:0 zeta ",
			},
			wantIOCs:         1,
			wantAnalyzerList: []string{"alpha", "zeta"},
		},
		{
			name:      "nonexistent target",
			setup:     func(_ *testing.T, dir string) string { return filepath.Join(dir, "missing") },
			analyzers: []analyze.Analyzer{nothing},
			wantErr:   true,
		},
		{
			name: "file target records its sha256",
			setup: func(t *testing.T, dir string) string {
				return write(t, dir, "b.txt", []byte("hello\n"))
			},
			analyzers:      []analyze.Analyzer{nothing},
			wantTargetKind: protocol.TargetFile,
			wantTargetSHA:  "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03",
			wantFileCount:  1,
			wantFiles:      []string{"b.txt"},
			wantSeen:       1, wantAnalyzed: 1,
		},
		{
			name: "directories nested deeper than MaxDirDepth are skipped",
			setup: func(t *testing.T, dir string) string {
				deep := strings.Repeat("d/", analyze.MaxDirDepth+1)
				write(t, dir, deep+"f.txt", []byte("x"))
				return dir
			},
			analyzers:      []analyze.Analyzer{nothing},
			wantTargetKind: protocol.TargetDir,
			wantSkips:      []protocol.Skip{{Path: strings.TrimSuffix(strings.Repeat("d/", analyze.MaxDirDepth+1), "/"), Reason: protocol.SkipDepth}},
		},
		{
			name: "cancelled job ends the walk and truncates",
			setup: func(t *testing.T, dir string) string {
				write(t, dir, "a.txt", []byte("x"))
				return dir
			},
			analyzers:      []analyze.Analyzer{nothing},
			cancelled:      true,
			wantTargetKind: protocol.TargetDir,
			wantTruncated:  true,
		},
		{
			name: "symlinks are not followed",
			setup: func(t *testing.T, dir string) string {
				target := filepath.Join(dir, "target")
				write(t, target, "real.txt", []byte("x"))
				outside := write(t, dir, "outside.txt", []byte("secret"))
				if err := os.Symlink(outside, filepath.Join(target, "link.txt")); err != nil {
					t.Skipf("symlinks not available: %v", err)
				}
				if err := os.Symlink(dir, filepath.Join(target, "dirlink")); err != nil {
					t.Skipf("symlinks not available: %v", err)
				}
				return target
			},
			analyzers:      []analyze.Analyzer{nothing},
			wantTargetKind: protocol.TargetDir,
			wantFileCount:  1,
			wantFiles:      []string{"real.txt"},
			wantSeen:       3, wantAnalyzed: 1,
			wantSkips: []protocol.Skip{
				{Path: "dirlink", Reason: protocol.SkipUnsupported},
				{Path: "link.txt", Reason: protocol.SkipUnsupported},
			},
		},
		{
			name: "file over MaxFileSize is hashed and skipped as too_large",
			setup: func(t *testing.T, dir string) string {
				p := write(t, dir, "big.bin", nil)
				if err := os.Truncate(p, analyze.MaxFileSize+1); err != nil {
					t.Fatal(err)
				}
				return dir
			},
			analyzers:      []analyze.Analyzer{failOn("big.bin", func() (analyze.Output, error) { panic("must not be called") })},
			wantTargetKind: protocol.TargetDir,
			wantFileCount:  1,
			wantFiles:      []string{"big.bin"},
			wantSeen:       1,
			wantSkips:      []protocol.Skip{{Path: "big.bin", Reason: protocol.SkipTooLarge}},
		},
		{
			name: "analyzer panic becomes a skip and the file is not analyzed",
			setup: func(t *testing.T, dir string) string {
				write(t, dir, "boom.txt", []byte("x"))
				write(t, dir, "ok.txt", []byte("x"))
				return dir
			},
			analyzers:      []analyze.Analyzer{failOn("boom.txt", func() (analyze.Output, error) { panic("boom") })},
			wantTargetKind: protocol.TargetDir,
			wantFileCount:  2,
			wantFiles:      []string{"boom.txt", "ok.txt"},
			wantSeen:       2, wantAnalyzed: 1,
			wantSkips: []protocol.Skip{{Path: "boom.txt", Reason: protocol.SkipPanic}},
		},
		{
			name: "analyzer error becomes a skip once per file",
			setup: func(t *testing.T, dir string) string {
				write(t, dir, "bad.txt", []byte("x"))
				return dir
			},
			analyzers: []analyze.Analyzer{
				failOn("bad.txt", func() (analyze.Output, error) { return analyze.Output{}, errors.New("broken") }),
				fake{name: "fail2", fn: func(context.Context, analyze.File) (analyze.Output, error) { panic("again") }},
			},
			wantTargetKind: protocol.TargetDir,
			wantFileCount:  1,
			wantFiles:      []string{"bad.txt"},
			wantSeen:       1,
			wantSkips:      []protocol.Skip{{Path: "bad.txt", Reason: protocol.SkipParseError}},
		},
		{
			name: "analyzer that outlives the timeout becomes a timeout skip",
			setup: func(t *testing.T, dir string) string {
				write(t, dir, "slow.txt", []byte("x"))
				return dir
			},
			analyzers: []analyze.Analyzer{fake{name: "slow", fn: func(ctx context.Context, _ analyze.File) (analyze.Output, error) {
				<-ctx.Done()
				return analyze.Output{}, ctx.Err()
			}}},
			timeout:        50 * time.Millisecond,
			wantTargetKind: protocol.TargetDir,
			wantFileCount:  1,
			wantFiles:      []string{"slow.txt"},
			wantSeen:       1,
			wantSkips:      []protocol.Skip{{Path: "slow.txt", Reason: protocol.SkipTimeout}},
		},
		{
			name: "children are dispatched with !/ paths in FIFO order",
			setup: func(t *testing.T, dir string) string {
				write(t, dir, "a.zip", []byte("x"))
				return dir
			},
			analyzers: []analyze.Analyzer{
				children("a.zip",
					analyze.File{Name: "dir/m1.txt", Data: []byte("one")},
					analyze.File{Name: "e\x1bvil.txt", Data: []byte("two")}),
				children("m1.txt", analyze.File{Name: "g.txt", Data: []byte("three")}),
				fake{name: "names", fn: func(_ context.Context, f analyze.File) (analyze.Output, error) {
					return analyze.Output{Findings: []protocol.Finding{finding("GAL-T-001", protocol.SeverityLow, f.Path, 0, protocol.Snippet(fmt.Sprintf("%s depth=%d", f.Name, f.Depth)))}}, nil
				}},
			},
			wantTargetKind: protocol.TargetDir,
			wantFileCount:  1,
			wantFiles:      []string{"a.zip", "a.zip!/dir/m1.txt", `a.zip!/e\u001bvil.txt`, "a.zip!/dir/m1.txt!/g.txt"},
			wantSeen:       4, wantAnalyzed: 4,
			wantFindings: []string{
				"GAL-T-001@a.zip:0 names a.zip depth=0",
				"GAL-T-001@a.zip!/dir/m1.txt:0 names m1.txt depth=1",
				"GAL-T-001@a.zip!/dir/m1.txt!/g.txt:0 names g.txt depth=2",
				`GAL-T-001@a.zip!/e\u001bvil.txt:0 names e\u001bvil.txt depth=1`,
			},
		},
		{
			name: "analyzer skips that hide nothing are recorded but not counted as files",
			setup: func(t *testing.T, dir string) string {
				write(t, dir, "a.txt", []byte("x"))
				return dir
			},
			analyzers: []analyze.Analyzer{fake{name: "skips", fn: func(context.Context, analyze.File) (analyze.Output, error) {
				return analyze.Output{Skips: []protocol.Skip{{Path: "a.txt!/m", Reason: protocol.SkipUnsupported}}}, nil
			}}},
			wantTargetKind: protocol.TargetDir,
			wantFileCount:  1,
			wantFiles:      []string{"a.txt"},
			wantSeen:       1, wantAnalyzed: 1,
			wantSkips: []protocol.Skip{{Path: "a.txt!/m", Reason: protocol.SkipUnsupported}},
		},
		{
			name: "backslashes in member names separate path segments",
			setup: func(t *testing.T, dir string) string {
				write(t, dir, "a.zip", []byte("x"))
				return dir
			},
			analyzers: []analyze.Analyzer{
				children("a.zip", analyze.File{Name: `d\.vscode\tasks.json`, Data: []byte("one")}),
				fake{name: "names", fn: func(_ context.Context, f analyze.File) (analyze.Output, error) {
					return analyze.Output{Findings: []protocol.Finding{finding("GAL-T-001", protocol.SeverityLow, f.Path, 0, f.Name)}}, nil
				}},
			},
			wantTargetKind: protocol.TargetDir,
			wantFileCount:  1,
			wantFiles:      []string{"a.zip", "a.zip!/d/.vscode/tasks.json"},
			wantSeen:       2, wantAnalyzed: 2,
			wantFindings: []string{
				"GAL-T-001@a.zip:0 names a.zip",
				"GAL-T-001@a.zip!/d/.vscode/tasks.json:0 names tasks.json",
			},
		},
		{
			name: "member path over MaxPath is cut so the result still validates",
			setup: func(t *testing.T, dir string) string {
				write(t, dir, "a.zip", []byte("x"))
				return dir
			},
			analyzers:      []analyze.Analyzer{children("a.zip", analyze.File{Name: strings.Repeat("n", 1100), Data: []byte("x")})},
			wantTargetKind: protocol.TargetDir,
			wantFileCount:  1,
			wantFiles:      []string{"a.zip", ("a.zip!/" + strings.Repeat("n", 1100))[:protocol.MaxPath]},
			wantSeen:       2, wantAnalyzed: 2,
		},
		{
			name: "job timeout during dispatch drops the queued members and truncates",
			setup: func(t *testing.T, dir string) string {
				write(t, dir, "a.zip", []byte("x"))
				return dir
			},
			analyzers: []analyze.Analyzer{fake{name: "wait", fn: func(ctx context.Context, _ analyze.File) (analyze.Output, error) {
				<-ctx.Done()
				return analyze.Output{Children: []analyze.File{{Name: "m", Data: []byte("x")}}}, nil
			}}},
			timeout:        50 * time.Millisecond,
			wantTargetKind: protocol.TargetDir,
			wantFileCount:  1,
			wantFiles:      []string{"a.zip"},
			wantSeen:       1, wantAnalyzed: 1,
			wantTruncated: true,
		},
		{
			name: "member over MaxFileSize is hashed and skipped as too_large",
			setup: func(t *testing.T, dir string) string {
				write(t, dir, "a.zip", []byte("x"))
				return dir
			},
			analyzers:      []analyze.Analyzer{children("a.zip", analyze.File{Name: "big", Data: make([]byte, analyze.MaxFileSize+1)})},
			wantTargetKind: protocol.TargetDir,
			wantFileCount:  1,
			wantFiles:      []string{"a.zip", "a.zip!/big"},
			wantSeen:       2, wantAnalyzed: 1,
			wantSkips: []protocol.Skip{{Path: "a.zip!/big", Reason: protocol.SkipTooLarge}},
		},
		{
			name: "nesting deeper than MaxNesting becomes a depth skip",
			setup: func(t *testing.T, dir string) string {
				write(t, dir, "a", []byte("x"))
				return dir
			},
			analyzers:      []analyze.Analyzer{nest},
			wantTargetKind: protocol.TargetDir,
			wantFileCount:  1,
			wantFiles:      []string{"a", "a!/c", "a!/c!/c", "a!/c!/c!/c", "a!/c!/c!/c!/c"},
			wantSeen:       analyze.MaxNesting + 2, wantAnalyzed: analyze.MaxNesting + 1,
			wantSkips: []protocol.Skip{{Path: "a" + strings.Repeat("!/c", analyze.MaxNesting+1), Reason: protocol.SkipDepth}},
		},
		{
			name: "member bytes over MaxTotalBytes become a budget skip and truncate",
			setup: func(t *testing.T, dir string) string {
				write(t, dir, "a.zip", []byte("x"))
				return dir
			},
			analyzers:      []analyze.Analyzer{children("a.zip", sharedMembers()...)},
			wantTargetKind: protocol.TargetDir,
			wantFileCount:  1,
			wantSeen:       analyze.MaxTotalBytes/analyze.MaxFileSize + 1, wantAnalyzed: 1,
			wantSkips:     budgetSkips(),
			wantTruncated: true,
		},
		{
			name: "queued members are charged to the budget when queued, so nested members cannot exceed it",
			setup: func(t *testing.T, dir string) string {
				write(t, dir, "a", []byte("x"))
				return dir
			},
			analyzers: []analyze.Analyzer{fake{name: "fan", fn: func(_ context.Context, f analyze.File) (analyze.Output, error) {
				if f.Depth >= 2 {
					return analyze.Output{}, nil
				}
				var kids []analyze.File
				for i := range 20 {
					kids = append(kids, analyze.File{Name: fmt.Sprintf("k%d", i), Data: nestedShared})
				}
				return analyze.Output{Children: kids}, nil
			}}},
			wantTargetKind: protocol.TargetDir,
			wantFileCount:  1,
			wantSeen:       1 + 20 + 400,
			wantAnalyzed:   1 + 20 + nestedFit,
			wantSkips:      nestedBudgetSkips(nestedFit),
			wantTruncated:  true,
		},
		{
			name: "findings per rule and file are capped",
			setup: func(t *testing.T, dir string) string {
				write(t, dir, "a", []byte("x"))
				return dir
			},
			analyzers:        []analyze.Analyzer{many},
			wantTargetKind:   protocol.TargetDir,
			wantFileCount:    1,
			wantFiles:        []string{"a"},
			wantSeen:         1,
			wantAnalyzed:     1,
			wantFindingCount: protocol.MaxFindingsPerRulePerFile,
		},
		{
			name: "findings over MaxFindings truncate the coverage",
			setup: func(t *testing.T, dir string) string {
				write(t, dir, "a", []byte("x"))
				return dir
			},
			analyzers:        []analyze.Analyzer{tooMany(protocol.MaxFindings + 1)},
			wantTargetKind:   protocol.TargetDir,
			wantFileCount:    1,
			wantFiles:        []string{"a"},
			wantSeen:         1,
			wantAnalyzed:     1,
			wantFindingCount: protocol.MaxFindings,
			wantTruncated:    true,
		},
		{
			name: "files over MaxFiles are counted but not analyzed",
			setup: func(t *testing.T, dir string) string {
				for i := range analyze.MaxFiles + 1 {
					write(t, dir, fmt.Sprintf("f%05d", i), nil)
				}
				return dir
			},
			analyzers:      []analyze.Analyzer{nothing},
			wantTargetKind: protocol.TargetDir,
			wantFileCount:  analyze.MaxFiles,
			wantSeen:       analyze.MaxFiles + 1, wantAnalyzed: analyze.MaxFiles,
			wantTruncated: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target := tt.setup(t, t.TempDir())
			ctx := context.Background()
			if tt.timeout > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, tt.timeout)
				defer cancel()
			}
			if tt.cancelled {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}

			res, err := analyze.Run(ctx, target, tt.analyzers)

			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if err := res.Validate(); err != nil {
				t.Errorf("result does not validate: %v", err)
			}
			if res.Target.Kind != tt.wantTargetKind || res.Target.SHA256 != tt.wantTargetSHA || res.Target.FileCount != tt.wantFileCount {
				t.Errorf("target = %+v, want kind %q sha %q file_count %d", res.Target, tt.wantTargetKind, tt.wantTargetSHA, tt.wantFileCount)
			}
			var files []string
			for _, f := range res.Files {
				files = append(files, f.Path)
				if len(f.Path) > protocol.MaxPath {
					t.Errorf("path of %d bytes, max %d", len(f.Path), protocol.MaxPath)
				}
			}
			if tt.wantFiles != nil && !slices.Equal(files, tt.wantFiles) {
				t.Errorf("files = %q, want %q", files, tt.wantFiles)
			}
			c := res.Coverage
			if c.FilesSeen != tt.wantSeen || c.FilesAnalyzed != tt.wantAnalyzed || c.Truncated != tt.wantTruncated {
				t.Errorf("coverage seen/analyzed/truncated = %d/%d/%v, want %d/%d/%v", c.FilesSeen, c.FilesAnalyzed, c.Truncated, tt.wantSeen, tt.wantAnalyzed, tt.wantTruncated)
			}
			skips := c.Skipped
			if len(skips) == 0 {
				skips = nil
			}
			if !slices.Equal(skips, tt.wantSkips) {
				t.Errorf("skipped = %v, want %v", skips, tt.wantSkips)
			}
			if tt.wantFindings != nil {
				var got []string
				for _, f := range res.Findings {
					e := f.Evidence[0]
					got = append(got, fmt.Sprintf("%s@%s:%d %s %s", f.RuleID, e.Path, e.Line, f.Analyzer, e.Snippet))
				}
				if !slices.Equal(got, tt.wantFindings) {
					t.Errorf("findings =\n%q\nwant\n%q", got, tt.wantFindings)
				}
			}
			if tt.wantFindingCount > 0 && len(res.Findings) != tt.wantFindingCount {
				t.Errorf("%d findings, want %d", len(res.Findings), tt.wantFindingCount)
			}
			if len(res.IOCs) != tt.wantIOCs {
				t.Errorf("%d iocs, want %d", len(res.IOCs), tt.wantIOCs)
			}
			if tt.wantAnalyzerList != nil && !slices.Equal(c.Analyzers, tt.wantAnalyzerList) {
				t.Errorf("analyzers = %q, want %q", c.Analyzers, tt.wantAnalyzerList)
			}
		})
	}
}

// budgetSkips lists what the shared-members case skips: the member that does
// not fit in the budget is dropped when it is queued, and every member that
// fits is too large to analyze.
func budgetSkips() []protocol.Skip {
	const fit = analyze.MaxTotalBytes / (analyze.MaxFileSize + 1)
	skips := []protocol.Skip{{Path: fmt.Sprintf("a.zip!/m%d", fit), Reason: protocol.SkipBudget}}
	for i := range fit {
		skips = append(skips, protocol.Skip{Path: fmt.Sprintf("a.zip!/m%d", i), Reason: protocol.SkipTooLarge})
	}
	return skips
}

// nestedBudgetSkips lists the grandchildren the nested-members case drops: each of
// the 20 members offers 20 grandchildren, and only the first fitFirst fit in the budget.
func nestedBudgetSkips(fitFirst int) []protocol.Skip {
	var skips []protocol.Skip
	left := fitFirst
	for i := range 20 {
		for j := range 20 {
			if left > 0 {
				left--
				continue
			}
			skips = append(skips, protocol.Skip{Path: fmt.Sprintf("a!/k%d!/k%d", i, j), Reason: protocol.SkipBudget})
		}
	}
	return skips
}
