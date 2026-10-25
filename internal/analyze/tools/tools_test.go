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

// The tests run the test binary as the scanners: TestMain copies it to a directory as clamscan,
// yara and capa, and it prints what the environment says when GALAHAD_TOOLS_TEST_MODE is set.
const (
	envMode = "GALAHAD_TOOLS_TEST_MODE" // print, hang or flood
	envOut  = "GALAHAD_TOOLS_TEST_OUT"  // file with the output to print; "%ROOT%" stands for the scanned path
	envExit = "GALAHAD_TOOLS_TEST_EXIT"
	envErr  = "GALAHAD_TOOLS_TEST_ERR"  // what the fake writes to stderr
	envArgs = "GALAHAD_TOOLS_TEST_ARGS" // file that gets the arguments of the fake
	envLeak = "GALAHAD_TOOLS_TEST_LEAK" // when set, the fake writes a file into its TMPDIR, as capa unpacks itself
)

var binDir string // holds the fake clamscan, yara and capa

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
	for _, name := range []string{"clamscan", "yara", "capa"} {
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

// fake acts as clamscan, yara or capa. The last argument is the scanned path.
func fake(mode string) int {
	if p := os.Getenv(envArgs); p != "" {
		if err := os.WriteFile(p, []byte(strings.Join(os.Args[1:], "\n")), 0o600); err != nil {
			return 90
		}
	}
	_, _ = io.WriteString(os.Stderr, os.Getenv(envErr))
	if os.Getenv(envLeak) != "" {
		if err := os.WriteFile(filepath.Join(os.Getenv("TMPDIR"), "_MEIleak"), []byte("unpacked"), 0o600); err != nil {
			return 95
		}
	}
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
	leak bool // write a file into TMPDIR first
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
	t.Setenv("GORACE", "atexit_sleep_ms=0") // a race build of the fake would wait a second before it exits
	t.Setenv(envMode, cmp.Or(f.mode, "print"))
	t.Setenv(envOut, outFile)
	t.Setenv(envExit, strconv.Itoa(f.exit))
	t.Setenv(envErr, f.err)
	t.Setenv(envArgs, argsFile)
	if f.leak {
		t.Setenv(envLeak, "1")
	} else {
		t.Setenv(envLeak, "")
	}
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
	name    string
	fs      []protocol.Finding
	note    string
	partial bool
	err     error
}

func (s stubTool) Name() string  { return s.name }
func (s stubTool) Stage() string { return s.name + "-stage" }
func (s stubTool) Run(context.Context, string) (tools.Result, error) {
	return tools.Result{Findings: s.fs, Note: s.note, Partial: s.partial}, s.err
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
			name:          "a partial tool is covered and marks the coverage truncated",
			tools:         []tools.Tool{stubTool{name: "capa", partial: true, note: "not every executable was examined"}},
			wantAnalyzers: []string{"capa"},
			wantStages:    []string{"capa-stage"},
			wantLog:       "capa: ok, 0 findings\ncapa: note: not every executable was examined\n",
			wantTruncated: true,
			wantVerdict:   "clean",
			wantConf:      50,
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

// TestApplyLeftOut checks that a tool that is left out is named in the coverage with its cause, and that
// the reason of a clean verdict says so.
func TestApplyLeftOut(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		tool   func() tools.Tool
		files  map[string][]byte
		fake   fakeRun
		budget time.Duration
		// expectations
		wantLeftOut []protocol.LeftOut
		wantReasons []string
	}{
		{
			name:        "a tool that ran is not named",
			tool:        func() tools.Tool { return stubTool{name: "yara"} },
			wantLeftOut: nil,
			wantReasons: []string{"no findings"},
		},
		{
			name:        "OSV without a network is left out for no network",
			tool:        func() tools.Tool { return tools.NewOSV("", "http://api.osv.dev:443") },
			files:       map[string][]byte{"requirements.txt": []byte("flask==2.0.0\n")},
			wantLeftOut: []protocol.LeftOut{{Tool: "osv", Cause: protocol.LeftOutNoNetwork}},
			wantReasons: []string{"no findings", "osv was left out: no network"},
		},
		{
			name:        "capa that runs out of time is left out for a timeout",
			tool:        func() tools.Tool { return tools.NewCapa("") },
			files:       map[string][]byte{"a.exe": peFile},
			fake:        fakeRun{mode: "hang"},
			budget:      300 * time.Millisecond,
			wantLeftOut: []protocol.LeftOut{{Tool: "capa", Cause: protocol.LeftOutTimeout}},
			wantReasons: []string{"no findings", "capa was left out: timed out"},
		},
		{
			name:        "any other failure is left out as failed",
			tool:        func() tools.Tool { return stubTool{name: "clamav", err: errors.New("exited with code 2")} },
			wantLeftOut: []protocol.LeftOut{{Tool: "clamav", Cause: protocol.LeftOutFailed}},
			wantReasons: []string{"no findings", "clamav was left out: it failed, see artifacts/tools.log"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			useFake(t, tt.fake)
			dir := t.TempDir()
			writeTree(t, dir, tt.files)
			ctx, cancel := context.WithTimeout(context.Background(), cmp.Or(tt.budget, time.Minute))
			defer cancel()
			res := protocol.Result{Coverage: protocol.Coverage{FilesSeen: 1, FilesAnalyzed: 1}}

			_, err := tools.Apply(ctx, []tools.Tool{tt.tool()}, dir, &res, func(string) error { return nil })
			scoring.Apply(&res)

			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(res.Coverage.LeftOut, tt.wantLeftOut) {
				t.Errorf("left out = %v, want %v", res.Coverage.LeftOut, tt.wantLeftOut)
			}
			if !slices.Equal(res.Reasons, tt.wantReasons) {
				t.Errorf("reasons = %q, want %q", res.Reasons, tt.wantReasons)
			}
		})
	}
}

func TestAll(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		env tools.Env
		// expectations
		wantNames  []string
		wantStages []string
	}{
		{
			name: "the core image has ClamAV, OSV and YARA, sorted by name", env: tools.Env{Image: protocol.ImageCore},
			wantNames: []string{"clamav", "osv", "yara"}, wantStages: []string{protocol.StageClamAV, protocol.StageOSV, protocol.StageYARA},
		},
		{
			name: "a job without an image is a core job", env: tools.Env{},
			wantNames: []string{"clamav", "osv", "yara"}, wantStages: []string{protocol.StageClamAV, protocol.StageOSV, protocol.StageYARA},
		},
		{
			name: "the re image adds capa, last", env: tools.Env{Image: protocol.ImageRE},
			wantNames: []string{"clamav", "osv", "yara", "capa"}, wantStages: []string{protocol.StageClamAV, protocol.StageOSV, protocol.StageYARA, protocol.StageCapa},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var names, stages []string

			for _, tool := range tools.All(tt.env) {
				names = append(names, tool.Name())
				stages = append(stages, tool.Stage())
			}

			if !slices.Equal(names, tt.wantNames) || !slices.Equal(stages, tt.wantStages) {
				t.Errorf("tools = %v, stages = %v, want %v, %v", names, stages, tt.wantNames, tt.wantStages)
			}
		})
	}
}

func TestExec(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		fake    fakeRun
		program string // clamscan when empty
		limit   time.Duration
		args    []string
		// expectations
		wantOut  string
		wantErr  string
		wantCode int
		wantLog  string // stderr of the program
	}{
		{
			name: "a program that ran gives its output and arguments", fake: fakeRun{out: "done\n", err: "warn\n"}, args: []string{"--a", "b"},
			wantOut: "done\n", wantLog: "warn\n",
		},
		{name: "a non-zero exit is a code and not an error", fake: fakeRun{out: "x\n", exit: 3}, wantOut: "x\n", wantCode: 3},
		{name: "a program that is not installed", fake: fakeRun{}, program: "freshclam", wantErr: "freshclam is not installed"},
		{name: "output over the cap kills the program", fake: fakeRun{mode: "flood"}, wantErr: "output is over"},
		{name: "a hang ends at the limit", fake: fakeRun{mode: "hang"}, limit: 300 * time.Millisecond, wantErr: "timed out"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			argsFile := useFake(t, tt.fake)

			out, stderr, code, err := tools.Exec(context.Background(), cmp.Or(tt.limit, time.Minute), cmp.Or(tt.program, "clamscan"), tt.args...)

			if (err != nil) != (tt.wantErr != "") || (err != nil && !strings.Contains(err.Error(), tt.wantErr)) {
				t.Fatalf("error = %v, want %q", err, tt.wantErr)
			}
			if string(out) != tt.wantOut || code != tt.wantCode || stderr != tt.wantLog {
				t.Errorf("stdout = %q, stderr = %q, code = %d, want %q, %q, %d", out, stderr, code, tt.wantOut, tt.wantLog, tt.wantCode)
			}
			if tt.args != nil {
				if got, _ := os.ReadFile(argsFile); string(got) != strings.Join(tt.args, "\n") {
					t.Errorf("arguments = %q, want %q", got, tt.args)
				}
			}
		})
	}
}
