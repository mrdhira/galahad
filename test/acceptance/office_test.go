package acceptance_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestOffice(t *testing.T) {
	tests := []struct {
		name string
		// build writes the document to dest
		build func(t *testing.T, dest string)
		file  string // document file name
		// expectations
		wantCode int
		wantRule string // rule that must be present at wantAt; empty means no findings at all
		wantAt   string // "path:line"
		wantIOCs []string
	}{
		{
			name: "p5-remote-template: offer.docx built from docx-src reports the template URL",
			file: "offer.docx",
			build: func(t *testing.T, dest string) {
				root, err := moduleRoot()
				if err != nil {
					t.Fatal(err)
				}
				zipDir(t, filepath.Join(root, "testdata", "corpus", "p5-remote-template", "docx-src"), dest)
			},
			wantCode: 10,
			wantRule: "GAL-OFFICE-001",
			wantAt:   "offer.docx!/word/_rels/settings.xml.rels:5",
			wantIOCs: []string{"http://templates.sinkhole.test/t.dotm"},
		},
		{
			name:     "benign-docx: internal and external hyperlinks are not suspicious",
			file:     "guide.docx",
			build:    benignDocx,
			wantCode: 0,
			wantIOCs: []string{"https://docs.sinkhole.test/guide"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given a document built at test time
			dir := t.TempDir()
			target := filepath.Join(dir, tt.file)
			tt.build(t, target)
			// When the agent analyzes it
			out := filepath.Join(t.TempDir(), "out")
			stdout, stderr, code := runAgent(t, "analyze", "--unsafe-host", "-o", out, target)
			// Then the exit code, finding and indicators match
			if code != tt.wantCode {
				t.Fatalf("exit = %d, want %d\nstdout: %s\nstderr: %s", code, tt.wantCode, stdout, stderr)
			}
			b, err := os.ReadFile(filepath.Join(out, "report.json"))
			if err != nil {
				t.Fatal(err)
			}
			var rep struct {
				report
				IOCs []struct {
					Type  string `json:"type"`
					Value string `json:"value"`
				} `json:"iocs"`
			}
			if err := json.Unmarshal(b, &rep); err != nil {
				t.Fatalf("report.json: %v", err)
			}
			if tt.wantRule == "" {
				if len(rep.Findings) != 0 {
					t.Errorf("findings = %+v, want none", rep.Findings)
				}
			} else if !hasFinding(rep.report, tt.wantRule, tt.wantAt) {
				t.Errorf("no %s at %s in %+v", tt.wantRule, tt.wantAt, rep.Findings)
			}
			var iocs []string
			for _, i := range rep.IOCs {
				if i.Type == "url" {
					iocs = append(iocs, i.Value)
				}
			}
			slices.Sort(iocs)
			if !slices.Equal(iocs, tt.wantIOCs) {
				t.Errorf("url iocs = %q, want %q", iocs, tt.wantIOCs)
			}
			if rep.Coverage.FilesAnalyzed != rep.Coverage.FilesSeen || len(rep.Coverage.Skipped) != 0 {
				t.Errorf("coverage analyzed/seen/skipped = %d/%d/%v, want all analyzed", rep.Coverage.FilesAnalyzed, rep.Coverage.FilesSeen, rep.Coverage.Skipped)
			}
		})
	}
}
