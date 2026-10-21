package eml_test

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/mrdhira/galahad/internal/analyze"
	"github.com/mrdhira/galahad/internal/analyze/ident"
	"github.com/mrdhira/galahad/internal/analyze/static/eml"
	"github.com/mrdhira/galahad/internal/protocol"
)

const lure = "From: \"Talent\" <recruiter@recruit-sinkhole.test>\n" +
	"Reply-To: hr@careers-reply.test\n" +
	"Return-Path: <bounce@bounce-sinkhole.test>\n" +
	"MIME-Version: 1.0\n" +
	"Content-Type: multipart/mixed; boundary=\"B\"\n" +
	"\n" +
	"--B\n" +
	"Content-Type: text/html\n" +
	"\n" +
	"<p><a href=\"http://login.sinkhole.test/\">careers.example.com</a></p>\n" +
	"--B\n" +
	"Content-Type: application/javascript\n" +
	"Content-Disposition: attachment; filename=\"setup.js\"\n" +
	"\n" +
	"one\ntwo\n" +
	"--B--\n"

func simple(extra, body string) string {
	return "From: a@a.test\nMIME-Version: 1.0\n" + extra + "\n" + body
}

func multi(parts ...string) string {
	s := "From: a@a.test\nMIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=\"B\"\n\n"
	for _, p := range parts {
		s += "--B\n" + p + "\n"
	}
	return s + "--B--\n"
}

func TestAnalyze(t *testing.T) {
	deep := "x"
	for i := 0; i < eml.MaxDepth+1; i++ {
		deep = fmt.Sprintf("Content-Type: multipart/mixed; boundary=\"D%d\"\n\n--D%d\n%s\n--D%d--", i, i, deep, i)
	}
	deep = "From: a@a.test\nMIME-Version: 1.0\n" + deep + "\n"
	many := make([]string, eml.MaxParts+1)
	for i := range many {
		many[i] = "Content-Type: text/plain\n\nhi"
	}
	manyLinks := ""
	for i := 0; i < 300; i++ {
		manyLinks += fmt.Sprintf(`<a href="http://t.test/">s%d.example</a>`, i)
	}
	rtlo := "setup\u202egnp.js"
	tests := []struct {
		name string
		// inputs
		file string
		data string
		// expectations
		wantFindings []string // "RULE path:line snippet-substring"
		wantChildren []string
		wantIOCs     []string // "type value line"
		wantSkips    []string // reasons
	}{
		{
			name: "multipart lure: sender, reply-to, link mismatch, attachment child",
			file: "lure.eml", data: lure,
			wantFindings: []string{
				"GAL-EML-001 lure.eml:1 From: recruiter@recruit-sinkhole.test (domain: recruit-sinkhole.test); Reply-To domain: careers-reply.test; Return-Path domain: bounce-sinkhole.test",
				"GAL-EML-002 lure.eml:2 careers-reply.test",
				"GAL-EML-003 lure.eml:10 careers.example.com goes to login.sinkhole.test",
			},
			wantChildren: []string{"setup.js"},
			wantIOCs:     []string{"url http://login.sinkhole.test/ 10", "domain login.sinkhole.test 10"},
		},
		{name: "other files are ignored", file: "notes.txt", data: "From: x\nbody\n"},
		{
			name: "text with From and MIME-Version is sniffed without the extension",
			file: "message", data: simple("Content-Type: text/plain\n", "see http://a.sinkhole.test/x\n"),
			wantFindings: []string{"GAL-EML-001 message:1 From: a@a.test"},
		},
		{name: "headers over the limit are a parse error", file: "big.eml", data: "From: a@a.test\nX: " + strings.Repeat("a", eml.MaxHeaderSize) + "\n\nbody", wantSkips: []string{"parse_error"}},
		{name: "no header block is a parse error", file: "bad.eml", data: "not a message\n\nbody", wantSkips: []string{"parse_error"}},
		{name: "no sender gives no sender finding", file: "a.eml", data: "Subject: x\n\nhello\n"},
		{
			name: "reply-to on the sender domain is not flagged",
			file: "a.eml", data: "From: a@A.test\nReply-To: b@a.TEST\n\nhello\n",
			wantFindings: []string{"GAL-EML-001 a.eml:1 From: a@A.test (domain: a.test); Reply-To domain: a.test"},
		},
		{name: "unparsable sender with no address is ignored", file: "a.eml", data: "From: <<>\n\nhello\n"},
		{
			name: "sender list: first address; any differing reply-to is flagged",
			file: "a.eml", data: "From: a@a.test, b@b.test\nReply-To: c@a.test, d@d.test\n\nhello\n",
			wantFindings: []string{"GAL-EML-001 a.eml:1 From: a@a.test (domain: a.test); Reply-To domain: a.test", "GAL-EML-002 a.eml:2 d@d.test"},
		},
		{
			name: "unknown charset in the display name still gives the addresses",
			file: "a.eml", data: "From: =?koi8-r?B?8NLJ18XU?= <a@a.test>\nReply-To: =?koi8-r?B?8NLJ18XU?= <r@r.test>\n\nhello\n",
			wantFindings: []string{"GAL-EML-001 a.eml:1 From: a@a.test", "GAL-EML-002 a.eml:2 r@r.test"},
		},
		{
			name: "malformed sender falls back to the addresses in the text",
			file: "a.eml", data: "From: (oops <a@a.test>\nReply-To: (oops r@r.test\n\nhello\n",
			wantFindings: []string{"GAL-EML-001 a.eml:1 From: a@a.test", "GAL-EML-002 a.eml:2 r@r.test"},
		},
		{
			name: "a blank line with CRLF after LF ends the headers like net/mail",
			file: "a.eml", data: "From: a@a.test\nMIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=\"B\"\n\r\n--B\nContent-Disposition: attachment; filename=x.bin\n\nbody\n--B--\n",
			wantFindings: []string{"GAL-EML-001 a.eml:1 "},
			wantChildren: []string{"x.bin"},
		},
		{
			name:         "duplicate parameters: still an attachment, without a name",
			file:         "a.eml",
			data:         multi("Content-Type: application/zip; name=a; name=b\nContent-Disposition: attachment; x=1; x=2\n\nPK"),
			wantFindings: []string{"GAL-EML-001 a.eml:1 "},
			wantChildren: []string{"attachment-2"},
		},
		{
			name:         "multipart with a duplicate boundary parameter is kept whole as a child",
			file:         "a.eml",
			data:         "From: a@a.test\nContent-Type: multipart/mixed; boundary=B; boundary=C\n\n--B\nContent-Type: text/plain\n\nhi\n--B--\n",
			wantFindings: []string{"GAL-EML-001 a.eml:1 "},
			wantChildren: []string{"attachment-1"},
		},
		{name: "multipart nested too deep", file: "a.eml", data: deep, wantFindings: []string{"GAL-EML-001 a.eml:1 "}, wantSkips: []string{"depth"}},
		{name: "too many parts", file: "a.eml", data: multi(many...), wantFindings: []string{"GAL-EML-001 a.eml:1 "}, wantSkips: []string{"budget"}},
		{
			name: "base64 attachment keeps the raw decoded name with RTLO",
			file: "a.eml",
			data: multi("Content-Type: application/octet-stream\nContent-Transfer-Encoding: base64\nContent-Disposition: attachment; filename=\"=?UTF-8?B?" +
				"c2V0dXDigK5nbnAuanM=" + "?=\"\n\naGVsbG8g\nd29ybGQ="),
			wantFindings: []string{"GAL-EML-001 a.eml:1 "},
			wantChildren: []string{rtlo},
		},
		{
			name: "quoted-printable body, name from the content type, path cut from the name",
			file: "a.eml",
			data: multi("Content-Type: text/plain\nContent-Transfer-Encoding: quoted-printable\n\nsee http://q.sinkhole.test/=\nx=20ok",
				"Content-Type: text/plain; name=\"..\\dir/run.sh\"\n\necho"),
			wantFindings: []string{"GAL-EML-001 a.eml:1 "},
			wantChildren: []string{"body-2.txt", "run.sh"},
		},
		{
			name: "nested message and unnamed parts get names; duplicates are made unique",
			file: "a.eml",
			data: multi("Content-Type: message/rfc822\n\nSubject: inner\n\nhi",
				"Content-Type: image/png\n\nA",
				"Content-Disposition: attachment; filename=x.bin\n\nB",
				"Content-Disposition: attachment; filename=x.bin\n\nC"),
			wantFindings: []string{"GAL-EML-001 a.eml:1 "},
			wantChildren: []string{"message-2.eml", "attachment-3", "x.bin", "5-x.bin"},
		},
		{
			name: "links to the same site, subdomains and file names are fine; broken and non-http links are skipped",
			file: "a.eml",
			data: simple("Content-Type: text/html\n", `<a href="https://www.a.test/">a.test</a><a href="https://x.a.test/">a.test</a>`+
				`<a href="https://a.test/r.pdf">report.pdf</a><a href="mailto:x@a.test">b.test</a><a href="http://[::1">c.test</a><a href="/rel">d.test</a>`),
			wantFindings: []string{"GAL-EML-001 a.eml:1 "},
			wantIOCs:     []string{"url https://www.a.test/ 5", "domain www.a.test 5", "url https://x.a.test/ 5", "domain x.a.test 5", "url https://a.test/r.pdf 5", "domain a.test 5"},
		},
		{
			name: "link findings are capped per file",
			file: "a.eml", data: simple("Content-Type: text/html\n", manyLinks),
			wantFindings: append([]string{"GAL-EML-001 a.eml:1 "}, slices.Repeat([]string{"GAL-EML-003 a.eml:5 "}, protocol.MaxFindingsPerRulePerFile)...),
			wantIOCs:     []string{"url http://t.test/ 5", "domain t.test 5"},
		},
		{
			name: "html in base64 maps links to the start of the part; nested anchors; unclosed anchor; first domain only",
			file: "a.eml",
			data: simple("Content-Type: text/html\nContent-Transfer-Encoding: base64\n",
				"PGEgaHJlZj0iaHR0cDovL3gudGVzdC8iPm9uZS5leGFtcGxlIHR3by5leGFtcGxlPGEgaHJlZj0iaHR0cDovL3kudGVzdC8iPnRocmVlLmV4YW1wbGU="),
			wantChildren: []string{"body-1.html"},
			wantFindings: []string{"GAL-EML-001 a.eml:1 ", "GAL-EML-003 a.eml:6 one.example goes to x.test", "GAL-EML-003 a.eml:6 three.example goes to y.test"},
			wantIOCs:     []string{"url http://x.test/ 6", "domain x.test 6", "url http://y.test/ 6", "domain y.test 6"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given a file with the case's name and content
			f := analyze.File{Path: tt.file, Name: tt.file, Kind: ident.Text, Data: []byte(tt.data)}
			// When the analyzer runs
			out, err := eml.New().Analyze(context.Background(), f)
			if err != nil {
				t.Fatal(err)
			}
			// Then findings, children, indicators and skips match
			var findings []string
			for _, fd := range out.Findings {
				ev := fd.Evidence[0]
				findings = append(findings, fmt.Sprintf("%s %s:%d %s", fd.RuleID, ev.Path, ev.Line, ev.Snippet))
			}
			if len(findings) != len(tt.wantFindings) {
				t.Fatalf("findings = %q, want %d like %q", findings, len(tt.wantFindings), tt.wantFindings)
			}
			for i, want := range tt.wantFindings {
				if !strings.HasPrefix(findings[i], strings.SplitN(want, " ", 3)[0]+" "+strings.SplitN(want, " ", 3)[1]) ||
					!strings.Contains(findings[i], strings.SplitN(want, " ", 3)[2]) {
					t.Errorf("finding %d = %q, want %q", i, findings[i], want)
				}
			}
			var children, iocs, skips []string
			for _, c := range out.Children {
				children = append(children, c.Name)
			}
			for _, i := range out.IOCs {
				iocs = append(iocs, fmt.Sprintf("%s %s %d", i.Type, i.Value, i.Line))
			}
			for _, s := range out.Skips {
				skips = append(skips, s.Reason)
			}
			for _, c := range []struct {
				what      string
				got, want []string
			}{{"children", children, tt.wantChildren}, {"iocs", iocs, tt.wantIOCs}, {"skips", skips, tt.wantSkips}} {
				if !slices.Equal(c.got, c.want) {
					t.Errorf("%s = %q, want %q", c.what, c.got, c.want)
				}
			}
		})
	}
}

func TestAnalyzeChildData(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		data string
		// expectations
		wantData string
	}{
		{name: "7bit attachment is kept as it is", data: lure, wantData: "one\ntwo"},
		{name: "base64 attachment is decoded, missing padding and noise allowed", data: multi("Content-Disposition: attachment; filename=a\nContent-Transfer-Encoding: base64\n\naGVs bG8g d29y bGQ"), wantData: "hello world"},
		{name: "a lone trailing base64 character is dropped", data: multi("Content-Disposition: attachment; filename=a\nContent-Transfer-Encoding: base64\n\naGVsbG8gd29ybGQhZ"), wantData: "hello world!"},
		{name: "quoted-printable attachment is decoded", data: multi("Content-Disposition: attachment; filename=a\nContent-Transfer-Encoding: quoted-printable\n\na=3Db"), wantData: "a=b"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := analyze.File{Path: "a.eml", Name: "a.eml", Kind: ident.Text, Data: []byte(tt.data)}
			out, err := eml.New().Analyze(context.Background(), f)
			if err != nil {
				t.Fatal(err)
			}
			if len(out.Children) == 0 || string(out.Children[len(out.Children)-1].Data) != tt.wantData {
				t.Errorf("children = %+v, want last data %q", out.Children, tt.wantData)
			}
		})
	}
}

func TestAnalyzeBudget(t *testing.T) {
	data := multi("Content-Disposition: attachment; filename=a\n\n" + strings.Repeat("a", 100))
	tests := []struct {
		name string
		// inputs
		budget int64 // negative means the context carries none
		// expectations
		wantChildren int
		wantSkips    []string // reasons
	}{
		{name: "a part within the job budget becomes a child", budget: 1000, wantChildren: 1},
		{name: "no budget leaves the message limit alone", budget: -1, wantChildren: 1},
		{name: "a part over the job budget is a budget skip", budget: 50, wantSkips: []string{protocol.SkipBudget}},
		{name: "a spent job budget keeps every non-empty part out", budget: 0, wantSkips: []string{protocol.SkipBudget}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			if tt.budget >= 0 {
				ctx = analyze.WithBudget(ctx, tt.budget)
			}
			f := analyze.File{Path: "a.eml", Name: "a.eml", Kind: ident.Text, Data: []byte(data)}

			out, err := eml.New().Analyze(ctx, f)

			if err != nil {
				t.Fatal(err)
			}
			var skips []string
			for _, s := range out.Skips {
				skips = append(skips, s.Reason)
			}
			if len(out.Children) != tt.wantChildren || !slices.Equal(skips, tt.wantSkips) {
				t.Errorf("children = %d, skips = %v, want %d and %v", len(out.Children), skips, tt.wantChildren, tt.wantSkips)
			}
		})
	}
}

func TestAnalyzeCancelled(t *testing.T) {
	tests := []struct {
		name string
		// expectations
		wantErr error
	}{
		{name: "a cancelled context stops the analyzer", wantErr: context.Canceled},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			f := analyze.File{Path: "a.eml", Name: "a.eml", Kind: ident.Text, Data: []byte(lure)}
			if _, err := eml.New().Analyze(ctx, f); err != tt.wantErr {
				t.Errorf("err = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestName(t *testing.T) {
	tests := []struct {
		name     string
		wantName string
	}{{name: "name", wantName: "eml"}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := eml.New().Name(); got != tt.wantName {
				t.Errorf("Name() = %q, want %q", got, tt.wantName)
			}
		})
	}
}
