package pdf_test

import (
	"bytes"
	"compress/zlib"
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/mrdhira/galahad/internal/analyze"
	"github.com/mrdhira/galahad/internal/analyze/ident"
	"github.com/mrdhira/galahad/internal/analyze/static/pdf"
)

func deflate(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	if _, err := w.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func doc(parts ...string) []byte {
	return []byte("%PDF-1.7\n" + strings.Join(parts, "") + "trailer\n<< /Root 1 0 R >>\n%%EOF\n")
}

func obj(n int, body string) string { return fmt.Sprintf("%d 0 obj\n%s\nendobj\n", n, body) }

func stream(n int, dict string, data []byte) string {
	return fmt.Sprintf("%d 0 obj\n<< %s /Length %d >>\nstream\n%s\nendstream\nendobj\n", n, dict, len(data), data)
}

func utf16BE(s string) string {
	out := "\xfe\xff"
	for _, r := range s {
		out += string([]byte{byte(r >> 8), byte(r)})
	}
	return out
}

func TestAnalyze(t *testing.T) {
	zeros := func(n int) []byte { return make([]byte, n) }
	longURI := "http://a.test/" + strings.Repeat("a", pdf.MaxURILen)
	objstm := func() string {
		members := "<< /OpenAction 11 0 R >> << /S /JavaScript /JS (app.alert\\(1\\)) >>"
		first := len("10 0 11 22 ")
		body := []byte("10 0 11 22 " + members)
		return stream(5, fmt.Sprintf("/Type /ObjStm /N 2 /First %d /Filter /FlateDecode", first), deflate(t, body))
	}
	manyObjs := strings.Repeat("1 0 obj\nendobj\n", pdf.MaxObjects+1)
	fiveBombs := ""
	for i := range 5 {
		fiveBombs += stream(i+1, "/Filter /FlateDecode", deflate(t, zeros(pdf.MaxStreamBytes)))
	}

	tests := []struct {
		name string
		// inputs
		kind ident.Kind
		data []byte
		ctx  context.Context
		// expectations
		wantRules   []string
		wantLines   map[string]int // rule -> line of the first evidence
		wantSnippet map[string]string
		wantIOCs    []string // type=value
		wantSkip    string
		wantErr     bool
	}{
		{
			name:        "Flate object stream hides an OpenAction to JavaScript",
			kind:        ident.PDF,
			data:        doc(obj(1, "<< /Type /Catalog >>"), objstm()),
			wantRules:   []string{"GAL-PDF-001", "GAL-PDF-002"},
			wantLines:   map[string]int{"GAL-PDF-001": 5, "GAL-PDF-002": 5},
			wantSnippet: map[string]string{"GAL-PDF-001": "app.alert(1)"},
		},
		{
			name: "not a PDF kind",
			kind: ident.Text,
			data: doc(obj(1, "<< /S /Launch >>")),
		},
		{
			name: "a plain page has no findings",
			kind: ident.PDF,
			data: doc(obj(1, "<< /Type /Catalog /Pages 2 0 R >>"), obj(2, "<< /Type /Pages /Kids [] /Count 0 >>")),
		},
		{
			name:        "JavaScript string with escapes and UTF-16",
			kind:        ident.PDF,
			data:        doc(obj(1, "<< /S /JavaScript /JS (this.\\psa\\)\\n\\101\\\nB) >>"), obj(2, "<< /JS ("+utf16BE("hi")+") >>")),
			wantRules:   []string{"GAL-PDF-001"},
			wantLines:   map[string]int{"GAL-PDF-001": 2},
			wantSnippet: map[string]string{"GAL-PDF-001": "this.psa) AB"},
		},
		{
			name:        "JavaScript in a Flate stream",
			kind:        ident.PDF,
			data:        doc(obj(1, "<< /S /JavaScript /JS 2 0 R >>"), stream(2, "/Filter /FlateDecode", deflate(t, []byte("var x = 1;\nrun(x);")))),
			wantRules:   []string{"GAL-PDF-001"},
			wantSnippet: map[string]string{"GAL-PDF-001": "var x = 1; run(x);"},
		},
		{
			name:        "JavaScript in an object that holds a string",
			kind:        ident.PDF,
			data:        doc(obj(1, "<< /JS 2 0 R >>"), obj(2, "(go\\(\\))")),
			wantRules:   []string{"GAL-PDF-001"},
			wantSnippet: map[string]string{"GAL-PDF-001": "go()"},
		},
		{
			name:      "Launch action",
			kind:      ident.PDF,
			data:      doc(obj(1, "<< /Type /Catalog >>"), obj(2, "<< /S /Launch /F (calc.exe) >>")),
			wantRules: []string{"GAL-PDF-003"},
			wantLines: map[string]int{"GAL-PDF-003": 5},
		},
		{
			name:      "OpenAction with an inline action dictionary",
			kind:      ident.PDF,
			data:      doc(obj(1, "<< /OpenAction << /S /GoToR /F (other.pdf) >> >>")),
			wantRules: []string{"GAL-PDF-002"},
		},
		{
			name: "OpenAction with a destination array does not count",
			kind: ident.PDF,
			data: doc(obj(1, "<< /OpenAction [3 0 R /FitH] >>"), obj(3, "<< /Type /Page >>")),
		},
		{
			name: "OpenAction that references a destination array object does not count",
			kind: ident.PDF,
			data: doc(obj(1, "<< /OpenAction 2 0 R >>"), obj(2, "[3 0 R /XYZ 0 0 0]")),
		},
		{
			name: "OpenAction with an inline dictionary that is not an action does not count",
			kind: ident.PDF,
			data: doc(obj(1, "<< /OpenAction << /D [3 0 R /Fit] >> >>")),
		},
		{
			name: "OpenAction with an action type outside the list does not count",
			kind: ident.PDF,
			data: doc(obj(1, "<< /OpenAction 2 0 R >>"), obj(2, "<< /S /GoTo /D [3 0 R /Fit] >>")),
		},
		{
			name:      "OpenAction through a reference to an action",
			kind:      ident.PDF,
			data:      doc(obj(1, "<< /OpenAction 2 0 R >>"), obj(2, "<< /S /SubmitForm /F (http://x.test/) >>")),
			wantRules: []string{"GAL-PDF-002"},
		},
		{
			name:      "additional actions through a referenced dictionary",
			kind:      ident.PDF,
			data:      doc(obj(1, "<< /AA 2 0 R >>"), obj(2, "<< /O 3 0 R >>"), obj(3, "<< /S /ImportData >>")),
			wantRules: []string{"GAL-PDF-002"},
		},
		{
			name: "reference to the parent is not followed",
			kind: ident.PDF,
			data: doc(obj(1, "<< /AA << /Parent 2 0 R >> >>"), obj(2, "<< /S /Launch >>")),
			// the Launch object still counts for rule 003, but not as automatic
			wantRules: []string{"GAL-PDF-003"},
		},
		{
			name: "reference cycle ends",
			kind: ident.PDF,
			data: doc(obj(1, "<< /OpenAction 2 0 R >>"), obj(2, "<< /Next 3 0 R >>"), obj(3, "<< /Next 2 0 R >>")),
		},
		{
			name: "OpenAction at the end of the data",
			kind: ident.PDF,
			data: []byte("%PDF-1.4\n1 0 obj\n<< /OpenAction"),
		},
		{
			name:      "comments, hex strings, braces, stray parentheses and string escapes are skipped",
			kind:      ident.PDF,
			data:      doc(obj(1, "<< /A <6a6b> /B {1} ) /C (a(b)\\r\\t\\b\\f\\\r\nc) % /S /JavaScript\n /S /Launch >>")),
			wantRules: []string{"GAL-PDF-003"},
		},
		{
			name:      "unterminated hex string",
			kind:      ident.PDF,
			data:      doc(obj(1, "<< /S /Launch /X <6a")),
			wantRules: []string{"GAL-PDF-003"},
		},
		{
			name:        "unterminated string ending in a backslash",
			kind:        ident.PDF,
			data:        []byte("%PDF-1.4\nxobj 1 0 objx\n1 0 obj << /JS (abc\\"),
			wantRules:   []string{"GAL-PDF-001"},
			wantSnippet: map[string]string{"GAL-PDF-001": "abc"},
		},
		{
			name:      "hex escape of a capital letter in a name",
			kind:      ident.PDF,
			data:      doc(obj(1, "<< /S /#4caunch >>")),
			wantRules: []string{"GAL-PDF-003", "GAL-PDF-006"},
		},
		{
			name:      "embedded file",
			kind:      ident.PDF,
			data:      doc(obj(1, "<< /Names << /EmbeddedFiles 2 0 R >> >>"), stream(3, "/Type /EmbeddedFile", []byte("MZ"))),
			wantRules: []string{"GAL-PDF-004"},
			wantLines: map[string]int{"GAL-PDF-004": 2},
		},
		{
			name:      "hex escapes hide a name",
			kind:      ident.PDF,
			data:      doc(obj(1, "<< /S /J#61vaScript /JS (x) >>")),
			wantRules: []string{"GAL-PDF-001", "GAL-PDF-006"},
		},
		{
			name: "escaped space in a font name is normal",
			kind: ident.PDF,
			data: doc(obj(1, "<< /BaseFont /Times#20New#20Roman /Other /A#2FB >>")),
		},
		{
			name:        "URI strings become IOCs",
			kind:        ident.PDF,
			data:        doc(obj(1, "<< /S /URI /URI (http://a.test/\\(x\\)\\057p) >>"), obj(2, "<< /URI (http://a.test/\\(x\\)\\057p) >>"), obj(3, "<< /URI (mailto:u@a.test?subject=x) >>")),
			wantRules:   []string{"GAL-PDF-005"},
			wantLines:   map[string]int{"GAL-PDF-005": 2},
			wantIOCs:    []string{"url=http://a.test/(x)/p", "email=u@a.test"},
			wantSnippet: map[string]string{},
		},
		{
			name: "URIs that are empty, too long, relative, with controls or only a mailto scheme are dropped",
			kind: ident.PDF,
			data: doc(obj(1, "<< /URI () /A (x) >>"), obj(2, "<< /URI ("+longURI+") >>"), obj(3, "<< /URI (/relative) >>"),
				obj(4, "<< /URI (http://a.test/\\001) >>"), obj(5, "<< /URI (mailto:) >>"), obj(6, "<< /URI (1x:y) >>"), obj(7, "<< /URI <6162> >>")),
		},
		{
			name:      "unsupported filter",
			kind:      ident.PDF,
			data:      doc(obj(1, "<< >>"), stream(2, "/Filter [/ASCII85Decode /FlateDecode]", []byte("abc"))),
			wantRules: []string{"GAL-PDF-007"},
			wantLines: map[string]int{"GAL-PDF-007": 5},
		},
		{
			name: "image filter is normal",
			kind: ident.PDF,
			data: doc(obj(1, "<< >>"), stream(2, "/Subtype /Image /Filter /DCTDecode", []byte("\xff\xd8"))),
		},
		{
			name:      "corrupt Flate stream",
			kind:      ident.PDF,
			data:      doc(stream(1, "/Filter /FlateDecode", []byte("not zlib")), stream(2, "/Filter /FlateDecode", deflate(t, []byte("abcdef"))[:8])),
			wantRules: []string{"GAL-PDF-007"},
		},
		{
			name:      "encrypted document",
			kind:      ident.PDF,
			data:      doc(obj(1, "<< /Encrypt 9 0 R >>"), stream(2, "/Filter /FlateDecode", []byte("cipher"))),
			wantRules: []string{"GAL-PDF-007"},
		},
		{
			name:      "stream over the per-stream limit",
			kind:      ident.PDF,
			data:      doc(stream(1, "/Filter /FlateDecode", deflate(t, zeros(pdf.MaxStreamBytes+1)))),
			wantRules: []string{"GAL-PDF-007"},
		},
		{
			name:      "streams over the per-file limit",
			kind:      ident.PDF,
			data:      doc(fiveBombs),
			wantRules: []string{"GAL-PDF-007"},
			wantLines: map[string]int{"GAL-PDF-007": 26},
		},
		{
			name:     "too many objects",
			kind:     ident.PDF,
			data:     doc(manyObjs),
			wantSkip: "budget",
		},
		{
			name:    "cancelled context",
			kind:    ident.PDF,
			data:    doc(obj(1, "<< >>")),
			ctx:     func() context.Context { c, cancel := context.WithCancel(context.Background()); cancel(); return c }(),
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := tt.ctx
			if ctx == nil {
				ctx = context.Background()
			}
			f := analyze.File{Path: "d/a.pdf", Name: "a.pdf", Kind: tt.kind, Data: tt.data}

			out, err := pdf.New().Analyze(ctx, f)

			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			var got []string
			for _, fd := range out.Findings {
				got = append(got, fd.RuleID)
				if len(fd.Evidence) == 0 || fd.Evidence[0].Path != "d/a.pdf" {
					t.Errorf("%s evidence = %+v", fd.RuleID, fd.Evidence)
				}
				if line, ok := tt.wantLines[fd.RuleID]; ok && fd.Evidence[0].Line != line {
					t.Errorf("%s line = %d, want %d", fd.RuleID, fd.Evidence[0].Line, line)
				}
				if sn, ok := tt.wantSnippet[fd.RuleID]; ok && fd.Evidence[0].Snippet != sn {
					t.Errorf("%s snippet = %q, want %q", fd.RuleID, fd.Evidence[0].Snippet, sn)
				}
			}
			if !reflect.DeepEqual(got, tt.wantRules) {
				t.Errorf("rules = %v, want %v", got, tt.wantRules)
			}
			var iocs []string
			for _, ioc := range out.IOCs {
				iocs = append(iocs, ioc.Type+"="+ioc.Value)
			}
			if !reflect.DeepEqual(iocs, tt.wantIOCs) {
				t.Errorf("iocs = %v, want %v", iocs, tt.wantIOCs)
			}
			gotSkip := ""
			if len(out.Skips) > 0 {
				gotSkip = out.Skips[0].Reason
			}
			if gotSkip != tt.wantSkip {
				t.Errorf("skip = %q, want %q", gotSkip, tt.wantSkip)
			}
		})
	}
}

func TestNew(t *testing.T) {
	tests := []struct {
		name     string
		wantName string
	}{
		{name: "analyzer name", wantName: "pdf"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := pdf.New().Name(); got != tt.wantName {
				t.Errorf("Name() = %q, want %q", got, tt.wantName)
			}
		})
	}
}
