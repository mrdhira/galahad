package tools_test

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mrdhira/galahad/internal/analyze/tools"
	"github.com/mrdhira/galahad/internal/protocol"
	"github.com/mrdhira/galahad/internal/scoring"
)

// The tests run the test binary as the scanners: TestMain copies it to a directory as clamscan
// and yara, and it prints what the environment says when GALAHAD_TOOLS_TEST_MODE is set.
const (
	envMode = "GALAHAD_TOOLS_TEST_MODE" // print, hang or flood
	envOut  = "GALAHAD_TOOLS_TEST_OUT"  // file with the output to print; "%ROOT%" stands for the scanned path
	envExit = "GALAHAD_TOOLS_TEST_EXIT"
	envErr  = "GALAHAD_TOOLS_TEST_ERR"  // what the fake writes to stderr
	envArgs = "GALAHAD_TOOLS_TEST_ARGS" // file that gets the arguments of the fake
)

var binDir string // holds the fake clamscan and yara

func TestMain(m *testing.M) {
	if mode := os.Getenv(envMode); mode != "" {
		os.Exit(fake(mode))
	}
	os.Exit(testMain(m))
}

func testMain(m *testing.M) int {
	dir, err := os.MkdirTemp("", "galahad-tools-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer func() { _ = os.RemoveAll(dir) }() // temp dir of this run
	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	ext := ""
	if runtime.GOOS == "windows" {
		ext = ".exe"
	}
	for _, name := range []string{"clamscan", "yara"} {
		if err := copyFile(exe, filepath.Join(dir, name+ext)); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
	}
	binDir = dir
	return m.Run()
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }() // read-only handle
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o700)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close() // the copy already failed
		return err
	}
	return out.Close()
}

// fake acts as clamscan or yara. The last argument is the scanned path.
func fake(mode string) int {
	if p := os.Getenv(envArgs); p != "" {
		if err := os.WriteFile(p, []byte(strings.Join(os.Args[1:], "\n")), 0o600); err != nil {
			return 90
		}
	}
	_, _ = io.WriteString(os.Stderr, os.Getenv(envErr))
	switch mode {
	case "print":
		data, err := os.ReadFile(os.Getenv(envOut))
		if err != nil {
			return 91
		}
		root := os.Args[len(os.Args)-1]
		text := strings.ReplaceAll(string(data), "%ROOT%/", root+string(filepath.Separator))
		_, _ = io.WriteString(os.Stdout, strings.ReplaceAll(text, "%ROOT%", root))
		code, _ := strconv.Atoi(os.Getenv(envExit))
		return code
	case "hang":
		time.Sleep(time.Minute) // the tool is killed first
		return 94
	case "flood":
		chunk := strings.Repeat("x", 64<<10)
		for range 80 { // 5 MiB, over the cap
			if _, err := io.WriteString(os.Stdout, chunk); err != nil {
				return 92
			}
		}
		return 1
	}
	return 93
}

// fakeRun says what the fake scanners do in one test.
type fakeRun struct {
	mode string // print when empty
	out  string
	exit int
	err  string
}

// useFake puts the fake scanners alone on PATH and returns the file that gets their arguments.
func useFake(t *testing.T, f fakeRun) (argsFile string) {
	t.Helper()
	dir := t.TempDir()
	outFile := filepath.Join(dir, "out")
	if err := os.WriteFile(outFile, []byte(f.out), 0o600); err != nil {
		t.Fatal(err)
	}
	argsFile = filepath.Join(dir, "args")
	t.Setenv("PATH", binDir)
	t.Setenv(envMode, cmp.Or(f.mode, "print"))
	t.Setenv(envOut, outFile)
	t.Setenv(envExit, strconv.Itoa(f.exit))
	t.Setenv(envErr, f.err)
	t.Setenv(envArgs, argsFile)
	return argsFile
}

// format renders findings as "rule path snippet".
func format(fs []protocol.Finding) []string {
	var out []string
	for _, f := range fs {
		out = append(out, fmt.Sprintf("%s %s %s", f.RuleID, f.Evidence[0].Path, f.Evidence[0].Snippet))
	}
	return out
}

// stubTool is a tool with a fixed outcome.
type stubTool struct {
	name string
	fs   []protocol.Finding
	note string
	err  error
}

func (s stubTool) Name() string  { return s.name }
func (s stubTool) Stage() string { return s.name + "-stage" }
func (s stubTool) Run(context.Context, string) (tools.Result, error) {
	return tools.Result{Findings: s.fs, Note: s.note}, s.err
}

func TestApply(t *testing.T) {
	hit := protocol.Finding{RuleID: "GAL-AV-001", Severity: protocol.SeverityHigh, Title: "t", Evidence: []protocol.Evidence{{Path: "a", Snippet: "s"}}}
	tests := []struct {
		name string
		// inputs
		tools      []tools.Tool
		have       []string // analyzers of the engine
		progressAt int      // the progress call that fails, 1-based; 0 means none
		// expectations
		wantAnalyzers []string
		wantFindings  int
		wantStages    []string
		wantLog       string
		wantErr       string
		wantTruncated bool   // a tool was left out
		wantVerdict   string // of a result with one file, all analyzed, and the findings of the tools; not checked when empty
		wantConf      int
	}{
		{
			name:          "a tool that ran is covered and its findings are marked",
			tools:         []tools.Tool{stubTool{name: "clamav", fs: []protocol.Finding{hit}}},
			have:          []string{"filetype", "script"},
			wantAnalyzers: []string{"clamav", "filetype", "script"},
			wantFindings:  1,
			wantStages:    []string{"clamav-stage"},
			wantLog:       "clamav: ok, 1 findings\n",
		},
		{
			name:          "a tool that found nothing is still covered",
			tools:         []tools.Tool{stubTool{name: "yara"}},
			wantAnalyzers: []string{"yara"},
			wantStages:    []string{"yara-stage"},
			wantLog:       "yara: ok, 0 findings\n",
			wantVerdict:   "clean",
			wantConf:      100,
		},
		{
			name:          "a note of a tool goes to the log",
			tools:         []tools.Tool{stubTool{name: "clamav", fs: []protocol.Finding{hit}, note: "output has a line\x1b that is not a hit"}},
			wantAnalyzers: []string{"clamav"},
			wantFindings:  1,
			wantStages:    []string{"clamav-stage"},
			wantLog:       "clamav: ok, 1 findings\nclamav: note: output has a line\\u001b that is not a hit\n",
		},
		{
			name:          "a progress error ends the step",
			tools:         []tools.Tool{stubTool{name: "clamav"}, stubTool{name: "yara"}},
			progressAt:    2,
			wantAnalyzers: []string{"clamav"},
			wantStages:    []string{"clamav-stage", "yara-stage"},
			wantLog:       "clamav: ok, 0 findings\n",
			wantErr:       "progress failed",
		},
		{
			name:          "a tool that failed is left out and the others still run",
			tools:         []tools.Tool{stubTool{name: "clamav", err: errors.New("timed out after 3m0s")}, stubTool{name: "yara", fs: []protocol.Finding{hit}}},
			have:          []string{"filetype"},
			wantStages:    []string{"clamav-stage", "yara-stage"},
			wantLog:       "clamav: left out: timed out after 3m0s\nyara: ok, 1 findings\n",
			wantAnalyzers: []string{"filetype", "yara"},
			wantFindings:  1,
			wantTruncated: true,
		},
		{
			name:          "the reason of a tool is cleaned in the log",
			tools:         []tools.Tool{stubTool{name: "yara", err: errors.New("bad\x1b[2J line")}},
			wantAnalyzers: []string{},
			wantStages:    []string{"yara-stage"},
			wantLog:       "yara: left out: bad\\u001b[2J line\n",
			wantTruncated: true,
			wantVerdict:   "clean",
			wantConf:      50,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := protocol.Result{Coverage: protocol.Coverage{Analyzers: slices.Clone(tt.have), FilesSeen: 1, FilesAnalyzed: 1}}
			var stages []string
			calls := 0
			progress := func(stage string) error {
				calls++
				stages = append(stages, stage)
				if calls == tt.progressAt {
					return errors.New("progress failed")
				}
				return nil
			}

			log, err := tools.Apply(context.Background(), tt.tools, t.TempDir(), &res, progress)

			if (err != nil) != (tt.wantErr != "") || (err != nil && !strings.Contains(err.Error(), tt.wantErr)) {
				t.Fatalf("error = %v, want %q", err, tt.wantErr)
			}
			if string(log) != tt.wantLog {
				t.Errorf("log = %q, want %q", log, tt.wantLog)
			}
			if !slices.Equal(stages, tt.wantStages) {
				t.Errorf("stages = %v, want %v", stages, tt.wantStages)
			}
			if got := res.Coverage.Analyzers; !slices.Equal(got, tt.wantAnalyzers) {
				t.Errorf("analyzers = %v, want %v", got, tt.wantAnalyzers)
			}
			if len(res.Findings) != tt.wantFindings {
				t.Errorf("findings = %d, want %d", len(res.Findings), tt.wantFindings)
			}
			if len(res.Coverage.Skipped) != 0 || res.Coverage.Truncated != tt.wantTruncated {
				t.Errorf("skipped = %v, truncated = %v, want no skips and truncated = %v", res.Coverage.Skipped, res.Coverage.Truncated, tt.wantTruncated)
			}
			if tt.wantVerdict != "" {
				scoring.Apply(&res)
				if string(res.Verdict) != tt.wantVerdict || res.Confidence != tt.wantConf {
					t.Errorf("verdict = %s, confidence = %d, want %s, %d", res.Verdict, res.Confidence, tt.wantVerdict, tt.wantConf)
				}
			}
			for _, f := range res.Findings {
				if f.Analyzer != "clamav" && f.Analyzer != "yara" {
					t.Errorf("finding analyzer = %q, want the name of its tool", f.Analyzer)
				}
			}
		})
	}
}

func TestAll(t *testing.T) {
	tests := []struct {
		name string
		// expectations
		wantNames  []string
		wantStages []string
	}{
		{name: "ClamAV and YARA, sorted by name", wantNames: []string{"clamav", "yara"}, wantStages: []string{protocol.StageClamAV, protocol.StageYARA}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var names, stages []string

			for _, tool := range tools.All() {
				names = append(names, tool.Name())
				stages = append(stages, tool.Stage())
			}

			if !slices.Equal(names, tt.wantNames) || !slices.Equal(stages, tt.wantStages) {
				t.Errorf("tools = %v, stages = %v, want %v, %v", names, stages, tt.wantNames, tt.wantStages)
			}
		})
	}
}
