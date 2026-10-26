package acceptance_test

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// TestDemo runs the M1 demo from docs/milestones/M1.md section 5, step by step, with the
// same arguments. "{out}" stands for the output directory and "{corpus}" for testdata/corpus.
// The analyze steps pass --unsafe-host because the demo runs on the host until M2 moves it into a VM.
func TestDemo(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		args []string
		// expectations
		wantCode     int
		wantStdout   []string // each must be in stdout
		wantEvidence []string // "RULE path:line" that must be in report.json
		wantFiles    []string // files that must exist in the output directory
		wantSummary  []string // each must be in summary.md, which the demo has the reader open
		wantVerdict  string   // empty means the step writes no report
	}{
		{
			name:       "galahad-agent version prints the build",
			args:       []string{"version"},
			wantCode:   0,
			wantStdout: []string{"galahad-agent " + stampedVersion},
		},
		{
			name:         "fake-interview-repo is malicious with tasks.json:7 and setup.js:3 as evidence",
			args:         []string{"analyze", "--unsafe-host", "-o", "{out}", "{corpus}/fake-interview-repo"},
			wantCode:     20,
			wantStdout:   []string{"Verdict: MALICIOUS", "Do not open, install or run this.", "Runs automatically (", "report.html"},
			wantEvidence: []string{"GAL-AUTOEXEC-010 .vscode/tasks.json:7", "GAL-EXFIL-001 scripts/setup.js:3"},
			wantSummary:  []string{".vscode/tasks.json:7", "scripts/setup.js:3", "- Kind: folder, ", "Do not open, install or run this.", "## Why", "## Runs automatically ("},
			wantFiles:    []string{"summary.md", "report.html", "report.json"},
			wantVerdict:  "malicious",
		},
		{
			name:        "benign-express-app is clean",
			args:        []string{"analyze", "--unsafe-host", "-o", "{out}", "{corpus}/benign-express-app"},
			wantCode:    0,
			wantStdout:  []string{"Verdict: CLEAN", "No known-bad patterns found. This is not a guarantee."},
			wantSummary: []string{"No known-bad patterns found. This is not a guarantee.", "## Network indicators (not a sign of compromise)"},
			wantFiles:   []string{"summary.md", "report.html", "report.json"},
			wantVerdict: "clean",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given the built agent and the demo fixtures
			out := filepath.Join(t.TempDir(), "demo")
			args := make([]string, len(tt.args))
			for i, a := range tt.args {
				a = strings.ReplaceAll(a, "{out}", out)
				args[i] = strings.ReplaceAll(a, "{corpus}", corpus(t, "."))
			}
			// When the demo step runs
			stdout, stderr, code := runAgent(t, args...)
			// Then the exit code, terminal summary and report files match
			if code != tt.wantCode {
				t.Fatalf("exit = %d, want %d\nstdout: %s\nstderr: %s", code, tt.wantCode, stdout, stderr)
			}
			for _, want := range tt.wantStdout {
				if !strings.Contains(stdout, want) {
					t.Errorf("stdout lacks %q:\n%s", want, stdout)
				}
			}
			for _, name := range tt.wantFiles {
				if st, err := os.Stat(filepath.Join(out, name)); err != nil || st.Size() == 0 {
					t.Errorf("%s missing or empty: %v", name, err)
				}
			}
			if tt.wantVerdict == "" {
				return
			}
			rep, err := readReport(filepath.Join(out, "report.json"))
			if err != nil {
				t.Fatal(err)
			}
			if rep.Verdict != tt.wantVerdict {
				t.Errorf("verdict = %q, want %q", rep.Verdict, tt.wantVerdict)
			}
			for _, want := range tt.wantEvidence {
				rule, at, _ := strings.Cut(want, " ")
				if !hasFinding(rep, rule, at) {
					t.Errorf("no %s at %s in %+v", rule, at, rep.Findings)
				}
			}
			for _, want := range tt.wantSummary {
				if md := readFile(t, filepath.Join(out, "summary.md")); !strings.Contains(md, want) {
					t.Errorf("summary.md lacks %q:\n%s", want, md)
				}
			}
			// And the summary the reader opens has no live link: every URL is defanged
			for _, name := range []string{"summary.md", "report.html"} {
				if m := liveLink.FindString(readFile(t, filepath.Join(out, name))); m != "" {
					t.Errorf("%s has a live link %q", name, m)
				}
			}
			checkHTMLPage(t, readFile(t, filepath.Join(out, "report.html")), rep.Verdict)
		})
	}
}

// demoBackend is a sandbox that TestDemoM2 runs on.
type demoBackend struct {
	name string
	// home points the galahad binary at the sandbox and returns its state directory.
	home func(t *testing.T) string
}

// demoBackends lists the sandboxes of the M2 demo: the fake one everywhere, and Firecracker in the vm build
// (vm_corpus_test.go).
var demoBackends = []demoBackend{{name: "fake", home: func(t *testing.T) string {
	home := t.TempDir()
	t.Setenv("GALAHAD_HOME", home)
	t.Setenv("GALAHAD_SANDBOX", "fake")
	return home
}}}

// demoScanLimit is how long a scan of the demo may run: the default time limit of a core scan, plus slack.
const demoScanLimit = 11 * time.Minute

// runStep runs one galahad command of the demo. A scan may need a VM, so it gets the time of a whole scan.
func runStep(t *testing.T, args []string) (stdout, stderr string, code int) {
	t.Helper()
	if args[0] != "scan" {
		return run(t, args...)
	}
	got := runP8(t, demoScanLimit, args[1:]...)
	return got.stdout, got.stderr, got.code
}

// newJob returns the job directory in home that is not one of the seen job IDs.
func newJob(t *testing.T, home string, seen []string) string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(home, "jobs"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if !slices.Contains(seen, e.Name()) {
			return filepath.Join(home, "jobs", e.Name())
		}
	}
	t.Fatalf("no new job in %s after %v", home, seen)
	return ""
}

// TestDemoM2 runs the M2 demo from docs/milestones/M2.md section 5 in order, on each sandbox. The repositories
// and the PDF link are the sinkhole of startSinkhole instead of GitHub, and "{invoice}" is a local copy of the
// P4 PDF. "{id}" is the ID of the first scan. The setup step is left out: the fake sandbox needs no images,
// setup_test.go covers setup with its test hooks, and vm.yml installs the real images with the same checks.
func TestDemoM2(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		args    []string
		backend string // when set, only this sandbox runs the step
		// expectations
		wantCode     int
		wantStdout   []string // each must be in stdout
		wantEvidence []string // "RULE path:line" that must be in report.json of the job the step made
		wantSnippet  string   // must be in the evidence of GAL-NET-001
	}{
		{
			name:    "doctor passes on a host that is set up",
			args:    []string{"doctor"},
			backend: "firecracker", wantCode: 0, wantStdout: []string{"PASS  signatures:"},
		},
		{
			name:     "the Git repository fake-interview-repo exits 20 with tasks.json:7 and setup.js:3 as evidence",
			args:     []string{"scan", "http://git.test/interview.git"},
			wantCode: 20, wantStdout: []string{"MALICIOUS"},
			wantEvidence: []string{"GAL-AUTOEXEC-010 .vscode/tasks.json:7", "GAL-EXFIL-001 scripts/setup.js:3"},
		},
		{
			name:     "the PDF invoice.pdf exits 10",
			args:     []string{"scan", "{invoice}"},
			wantCode: 10, wantStdout: []string{"SUSPICIOUS"},
			wantEvidence: []string{"GAL-PDF-002 invoice.pdf:3"},
		},
		{
			name:     "a submodule at the metadata address is denied and reported as GAL-NET-001",
			args:     []string{"scan", "--submodules", "http://git.test/metadata.git"},
			wantCode: 10, wantStdout: []string{"GAL-NET-001"},
			wantSnippet: "CONNECT 169.254.169.254:443 denied",
		},
		{
			name:     "jobs lists the three scans",
			args:     []string{"jobs"},
			wantCode: 0, wantStdout: []string{"{id}", "invoice.pdf", "git.test/metadata.git"},
		},
		{
			name:     "report shows the first scan again",
			args:     []string{"report", "{id}"},
			wantCode: 20, wantStdout: []string{"MALICIOUS", "GAL-AUTOEXEC-001"},
		},
	}
	for _, backend := range demoBackends {
		t.Run(backend.name, func(t *testing.T) {
			// Given the sinkhole, a sandbox, and a PDF at the path the demo gives
			startSinkhole(t)
			home := backend.home(t)
			invoice := filepath.Join(t.TempDir(), "invoice.pdf")
			writeBytes(t, invoice, []byte(readFile(t, filepath.Join(corpus(t, "p4-pdf-openaction-uri"), "statement.pdf"))))
			var seen []string // the job directories of the scans so far
			for _, tt := range tests {
				if tt.backend != "" && tt.backend != backend.name {
					continue
				}
				t.Run(tt.name, func(t *testing.T) {
					// When the step runs
					id := ""
					if len(seen) > 0 {
						id = seen[0]
					}
					args := make([]string, len(tt.args))
					for i, a := range tt.args {
						a = strings.ReplaceAll(a, "{invoice}", invoice)
						args[i] = strings.ReplaceAll(a, "{id}", id)
					}
					stdout, stderr, code := runStep(t, args)

					// Then the exit code and the output match
					if code != tt.wantCode {
						t.Fatalf("exit = %d, want %d\nstdout: %s\nstderr: %s", code, tt.wantCode, stdout, stderr)
					}
					for _, w := range tt.wantStdout {
						if w = strings.ReplaceAll(w, "{id}", id); !strings.Contains(stdout, w) {
							t.Errorf("stdout lacks %q:\n%s", w, stdout)
						}
					}
					if args[0] != "scan" {
						return
					}
					// And the job of a scan is done, and its report has the evidence
					dir := newJob(t, home, seen)
					seen = append(seen, filepath.Base(dir))
					if j := readJob(t, dir); j.State != "done" || j.ExitCode != tt.wantCode {
						t.Errorf("job.json = %+v, want state done and exit code %d", j, tt.wantCode)
					}
					rep, err := readReport(filepath.Join(dir, "report.json"))
					if err != nil {
						t.Fatal(err)
					}
					for _, want := range tt.wantEvidence {
						rule, at, _ := strings.Cut(want, " ")
						if !hasFinding(rep, rule, at) {
							t.Errorf("no %s at %s in %+v", rule, at, rep.Findings)
						}
					}
					if tt.wantSnippet != "" && !hasRuleSnippet(rep, "GAL-NET-001", tt.wantSnippet) {
						t.Errorf("no GAL-NET-001 evidence with %q in %+v", tt.wantSnippet, rep.Findings)
					}
				})
			}
		})
	}
}

// hasRuleSnippet reports whether the report has a finding of rule with evidence whose snippet contains want.
func hasRuleSnippet(rep report, rule, want string) bool {
	for _, f := range rep.Findings {
		for _, e := range f.Evidence {
			if f.RuleID == rule && strings.Contains(e.Snippet, want) {
				return true
			}
		}
	}
	return false
}

// TestDemoM3 runs the M3 demo from docs/milestones/M3.md section 5 in order, on the fake sandbox. The provider is
// a loopback mock (the galahadtest build accepts http on loopback) that is named "mock" instead of "netra", and the
// repositories are the fixtures in testdata/corpus. "{mock}" stands for the URL of the mock, "{corpus}" for
// testdata/corpus and "{id}" for the ID of the first scan.
func TestDemoM3(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		args []string
		// expectations
		wantCode     int
		wantStdout   []string // each must be in stdout
		wantEvidence []string // "RULE path:line" that must be in report.json of the job the step made
		wantHTML     []string // each must be in report.html of the job the step made
	}{
		{
			name:     "provider add registers the mock with the key variable",
			args:     []string{"provider", "add", "mock", "--url", "{mock}", "--model", "test/model-1", "--key-env", "NETRA_API_KEY"},
			wantCode: 0, wantStdout: []string{"added provider mock"},
		},
		{
			name:     "provider list shows the provider and that its key is set",
			args:     []string{"provider", "list"},
			wantCode: 0, wantStdout: []string{"mock", "NETRA_API_KEY  yes"},
		},
		{
			name:     "provider test gets the three answers",
			args:     []string{"provider", "test", "mock"},
			wantCode: 0, wantStdout: []string{"provider mock: ok", "verdict", "risk", "steals_secrets", "input tokens: ", "request id: req_t34b"},
		},
		{
			name:     "fake-interview-repo exits 20 and shows the AI opinion",
			args:     []string{"scan", "--decision", "mock", "{corpus}/fake-interview-repo"},
			wantCode: 20, wantStdout: []string{"MALICIOUS", "AI opinion (mock): malicious 90%, no change"},
			wantEvidence: []string{"GAL-AUTOEXEC-010 .vscode/tasks.json:7", "GAL-EXFIL-001 scripts/setup.js:3"},
			wantHTML:     []string{"AI opinions", "What was sent"},
		},
		{
			name:     "p9-prompt-injection-repo exits 20 with GAL-INJECT-001 and the keys redacted",
			args:     []string{"scan", "--decision", "mock", "{corpus}/p9-prompt-injection-repo"},
			wantCode: 20, wantStdout: []string{"MALICIOUS", "AI opinion (mock): "},
			wantEvidence: []string{"GAL-INJECT-001 README.md:5"},
			wantHTML:     []string{"tries to steer an AI reviewer", "[REDACTED:aws-access-key]", "[REDACTED:aws-secret]"},
		},
		{
			name:     "report prints the AI line of the first scan again",
			args:     []string{"report", "{id}"},
			wantCode: 20, wantStdout: []string{"MALICIOUS", "AI opinion (mock): malicious 90%, no change"},
		},
	}
	// Given a fake key, a mock that answers the test and every scan with a malicious opinion, and an empty state
	mock := newMockProvider(t, func(w http.ResponseWriter, r *http.Request, n int) {
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), "GAL-TEST-001") {
			answers(providerTestAnswer)(w, r, n)
			return
		}
		answers(decisionAnswer(0.05, 0.05, 0.9))(w, r, n)
	})
	home := t.TempDir()
	t.Setenv("GALAHAD_HOME", home)
	t.Setenv("GALAHAD_SANDBOX", "fake")
	t.Setenv("NETRA_API_KEY", decisionKey)
	var seen []string // the job directories of the scans so far
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// When the step runs
			id := ""
			if len(seen) > 0 {
				id = seen[0]
			}
			args := make([]string, len(tt.args))
			for i, a := range tt.args {
				a = strings.ReplaceAll(a, "{mock}", mock.srv.URL)
				a = strings.ReplaceAll(a, "{corpus}", corpus(t, "."))
				args[i] = strings.ReplaceAll(a, "{id}", id)
			}
			stdout, stderr, code := run(t, args...)

			// Then the exit code and the output match, and the key is not in the output
			if code != tt.wantCode {
				t.Fatalf("exit = %d, want %d\nstdout: %s\nstderr: %s", code, tt.wantCode, stdout, stderr)
			}
			for _, w := range tt.wantStdout {
				if !strings.Contains(stdout, w) {
					t.Errorf("stdout lacks %q:\n%s", w, stdout)
				}
			}
			if strings.Contains(stdout+stderr, decisionKey) {
				t.Errorf("the key is in the output:\n%s%s", stdout, stderr)
			}
			if args[0] != "scan" {
				return
			}
			// And the job of a scan is done, and its report has the evidence and the opinion
			dir := newJob(t, home, seen)
			seen = append(seen, filepath.Base(dir))
			if j := readJob(t, dir); j.State != "done" || j.ExitCode != tt.wantCode {
				t.Errorf("job.json = %+v, want state done and exit code %d", j, tt.wantCode)
			}
			rep, err := readReport(filepath.Join(dir, "report.json"))
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range tt.wantEvidence {
				rule, at, _ := strings.Cut(want, " ")
				if !hasFinding(rep, rule, at) {
					t.Errorf("no %s at %s in %+v", rule, at, rep.Findings)
				}
			}
			page := readFile(t, filepath.Join(dir, "report.html"))
			for _, want := range tt.wantHTML {
				if !strings.Contains(page, want) {
					t.Errorf("report.html lacks %q", want)
				}
			}
		})
	}
	keyFree(t, home, decisionKey)
}
