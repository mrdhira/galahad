package ioc_test

import (
	"context"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mrdhira/galahad/internal/analyze"
	"github.com/mrdhira/galahad/internal/analyze/ident"
	"github.com/mrdhira/galahad/internal/analyze/static/ioc"
	"github.com/mrdhira/galahad/internal/protocol"
)

func TestExtract(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		text string
		// expectations: "type value line"
		want []string
	}{
		{name: "url with domain, email with domain, public ip", text: "see https://a.example.test/x?y=1, mail bob@Mail.test\nhost 8.8.4.4 up\n",
			want: []string{"url https://a.example.test/x?y=1 1", "domain a.example.test 1", "email bob@Mail.test 1", "domain mail.test 1", "ip 8.8.4.4 2"}},
		{name: "ip host url", text: "http://8.8.8.8:8080/a.sh", want: []string{"url http://8.8.8.8:8080/a.sh 1", "ip 8.8.8.8 1"}},
		{name: "ipv6 host url", text: "http://[2606:4700::1111]/", want: []string{"url http://[2606:4700::1111]/ 1", "ip 2606:4700::1111 1"}},
		{name: "trailing punctuation and markdown", text: "[x](https://d.test/p).", want: []string{"url https://d.test/p 1", "domain d.test 1"}},
		{name: "private and documentation ips are not listed", text: "10.0.0.1 172.16.5.5 192.168.1.1 127.0.0.1 192.0.2.7 198.51.100.7 203.0.113.7 169.254.1.1", want: nil},
		{name: "private ip url is listed without ip", text: "http://192.168.1.5/a", want: []string{"url http://192.168.1.5/a 1"}},
		{name: "version numbers are not ips", text: "v1.2.3.4 and 1.2.3.4.5 and 999.1.1.1 and 08.8.8.8", want: nil},
		{name: "email inside a url is not an email", text: "ftp://user@h.test/f", want: []string{"url ftp://user@h.test/f 1", "domain h.test 1"}},
		{name: "bare domains and localhost are ignored", text: "evil.test and http://localhost:3000/", want: []string{"url http://localhost:3000/ 1"}},
		{name: "bidi character cuts the value", text: "http://a.test/p\u202eb", want: []string{"url http://a.test/p 1", "domain a.test 1"}},
		{name: "invalid utf-8 cuts the value", text: "http://a.test/p\xff", want: []string{"url http://a.test/p 1", "domain a.test 1"}},
		{name: "unsafe character before the host leaves nothing to list", text: "http://\x01a.test/", want: []string{"url http:// 1"}},
		{name: "no indicators", text: "plain text", want: nil},
		{name: "empty", text: "", want: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got []string
			for _, m := range ioc.Extract([]byte(tt.text)) {
				got = append(got, fmt.Sprintf("%s %s %d", m.Type, m.Value, m.Line))
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("Extract(%q) = %q, want %q", tt.text, got, tt.want)
			}
		})
	}
}

func TestExtractLimits(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		text string
		// expectations
		wantMaxLen int
	}{
		{name: "long url is cut at the path limit", text: "http://a.test/" + strings.Repeat("x", 100000), wantMaxLen: protocol.MaxPath},
		{name: "one mixed 1 MiB line keeps every value bounded", text: mixedLine(1 << 20), wantMaxLen: protocol.MaxPath},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ms := ioc.Extract([]byte(tt.text))
			if len(ms) == 0 {
				t.Fatal("no matches")
			}
			for _, m := range ms {
				if len(m.Value) > tt.wantMaxLen {
					t.Fatalf("value of %d bytes, want at most %d", len(m.Value), tt.wantMaxLen)
				}
			}
		})
	}
}

// TestExtractScalesLinearly guards against quadratic matching on long lines.
// It compares run times instead of using a fixed limit, so a slow or busy
// machine (or the race detector) does not make it flaky: a 4x larger line must
// take well under 16x as long, the ratio a quadratic scan would show.
func TestExtractScalesLinearly(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		small, large int
		// expectations
		wantMaxRatio float64
	}{
		{name: "4x larger mixed line costs well under 16x", small: 64 << 10, large: 256 << 10, wantMaxRatio: 10},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			small := []byte(mixedLine(tt.small))
			large := []byte(mixedLine(tt.large))
			ratio := float64(fastest(large)) / float64(fastest(small))
			if ratio > tt.wantMaxRatio {
				t.Errorf("time ratio %.1f, want at most %.1f", ratio, tt.wantMaxRatio)
			}
		})
	}
}

func mixedLine(n int) string {
	const unit = "http://a.test/x u@h.test 8.8.8.8 "
	return strings.Repeat(unit, n/len(unit))
}

// fastest returns the best of three Extract runs to damp scheduling noise.
func fastest(text []byte) time.Duration {
	best := time.Duration(math.MaxInt64)
	for range 3 {
		start := time.Now()
		ioc.Extract(text)
		best = min(best, time.Since(start))
	}
	return best
}

func TestExtractOffset(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		text string
		// expectations
		wantOffsets []int
	}{
		{name: "offset of the url start", text: "ab https://a.test/x", wantOffsets: []int{3, 3}},
		{name: "offset on a later line", text: "x\nmail a@b.test", wantOffsets: []int{7, 7}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got []int
			for _, m := range ioc.Extract([]byte(tt.text)) {
				got = append(got, m.Offset)
			}
			if !slices.Equal(got, tt.wantOffsets) {
				t.Errorf("offsets = %v, want %v", got, tt.wantOffsets)
			}
		})
	}
}

func TestAnalyze(t *testing.T) {
	long := strings.Repeat("x", analyze.MaxLineScan) + " http://beyond.test/"
	var many strings.Builder
	for i := range protocol.MaxIOCs + 5 {
		fmt.Fprintf(&many, "http://h%d.test/\n", i)
	}
	tests := []struct {
		name string
		// inputs
		kind ident.Kind
		data string
		// expectations: findings as "rule line", iocs as "type value line"
		wantFindings []string
		wantIOCs     []string
		wantIOCCount int
	}{
		{name: "discord webhook on line 2", kind: ident.Text, data: "hello\ncurl https://discord.com/api/webhooks/1/abc\n",
			wantFindings: []string{"GAL-IOC-002 2"}, wantIOCs: []string{"url https://discord.com/api/webhooks/1/abc 2", "domain discord.com 2"}},
		{name: "non-text file is skipped", kind: ident.PDF, data: "https://pastebin.com/x"},
		{name: "raw public ip url", kind: ident.Text, data: "wget http://8.8.8.8/x.sh",
			wantFindings: []string{"GAL-IOC-001 1"}, wantIOCs: []string{"url http://8.8.8.8/x.sh 1", "ip 8.8.8.8 1"}},
		{name: "service hosts and subdomains", kind: ident.Text, data: "https://x.ngrok-free.app/a\nhttps://pastebin.com/raw/1\nhttps://api.telegram.org/bot1:A/send\nhttps://webhook.site/u\nhttps://transfer.sh/f\nhttps://paste.ee/p\nhttps://discordapp.com/api/webhooks/1/a\nhttps://abc.ngrok.io/\n",
			wantFindings: []string{"GAL-IOC-002 1", "GAL-IOC-002 2", "GAL-IOC-002 3", "GAL-IOC-002 4", "GAL-IOC-002 5", "GAL-IOC-002 6", "GAL-IOC-002 7", "GAL-IOC-002 8"}, wantIOCCount: 16},
		{name: "service host with another path is benign", kind: ident.Text, data: "https://discord.com/channels/1\nhttps://api.telegram.org/docs\nhttps://notpastebin.com/x\n",
			wantIOCCount: 6},
		{name: "spoofed hosts and paths do not match", kind: ident.Text, data: "https://discord.com.evil.test/api/webhooks/1\nhttps://evil.test/discord.com/api/webhooks/1\nhttps://discord.com@evil.test/api/webhooks/1\nhttps://evil.test/?u=pastebin.com\n",
			wantIOCCount: 6},
		{name: "raw ip host with trailing dot", kind: ident.Text, data: "http://8.8.8.8./x\n", wantFindings: []string{"GAL-IOC-001 1"}, wantIOCs: []string{"url http://8.8.8.8./x 1", "ip 8.8.8.8 1"}},
		{name: "control character cuts the url but rules still fire", kind: ident.Text, data: "https://discord.com/api/webhooks/1/a?\x01x\n",
			wantFindings: []string{"GAL-IOC-002 1"}, wantIOCs: []string{"url https://discord.com/api/webhooks/1/a 1", "domain discord.com 1"}},
		{name: "invalid byte cuts the url", kind: ident.Text, data: "https://webhook.site/a\xffb\n",
			wantFindings: []string{"GAL-IOC-002 1"}, wantIOCs: []string{"url https://webhook.site/a 1", "domain webhook.site 1"}},
		{name: "private and documentation ip urls", kind: ident.Text, data: "http://10.0.0.1/a\nhttp://192.0.2.5/b\nhttp://[::1]/c\n",
			wantIOCs: []string{"url http://10.0.0.1/a 1", "url http://192.0.2.5/b 2", "url http://[::1]/c 3"}},
		{name: "normal links, deduplicated", kind: ident.Text, data: "https://example.test/a\nagain https://example.test/a\n",
			wantIOCs: []string{"url https://example.test/a 1", "domain example.test 1"}},
		{name: "repeated risky url yields one finding", kind: ident.Text, data: "https://webhook.site/u\nhttps://webhook.site/u\n",
			wantFindings: []string{"GAL-IOC-002 1"}, wantIOCCount: 2},
		{name: "unparsable url is listed without findings", kind: ident.Text, data: "http://[bad/x\n", wantIOCs: []string{"url http://[bad/x 1"}},
		{name: "windows line endings", kind: ident.Text, data: "a\r\nhttps://pastebin.com/x\r\n", wantFindings: []string{"GAL-IOC-002 2"}, wantIOCCount: 2},
		{name: "text past the line scan limit is not scanned", kind: ident.Text, data: long, wantIOCCount: 0},
		{name: "ioc list is capped", kind: ident.Text, data: many.String(), wantIOCCount: protocol.MaxIOCs},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := analyze.File{Path: "dir/notes.txt", Name: "notes.txt", Kind: tt.kind, Data: []byte(tt.data)}

			out, err := ioc.New().Analyze(context.Background(), f)

			if err != nil {
				t.Fatal(err)
			}
			var findings []string
			for _, fd := range out.Findings {
				if fd.Evidence[0].Path != f.Path {
					t.Errorf("evidence path = %q, want %q", fd.Evidence[0].Path, f.Path)
				}
				findings = append(findings, fmt.Sprintf("%s %d", fd.RuleID, fd.Evidence[0].Line))
			}
			if !slices.Equal(findings, tt.wantFindings) {
				t.Errorf("findings = %q, want %q", findings, tt.wantFindings)
			}
			var iocs []string
			for _, i := range out.IOCs {
				if i.Path != f.Path {
					t.Errorf("ioc path = %q, want %q", i.Path, f.Path)
				}
				iocs = append(iocs, fmt.Sprintf("%s %s %d", i.Type, i.Value, i.Line))
			}
			if tt.wantIOCs != nil && !slices.Equal(iocs, tt.wantIOCs) {
				t.Errorf("iocs = %q, want %q", iocs, tt.wantIOCs)
			}
			if tt.wantIOCCount != 0 && len(iocs) != tt.wantIOCCount {
				t.Errorf("%d iocs, want %d", len(iocs), tt.wantIOCCount)
			}
		})
	}
}

func TestAnalyzeFindingDetails(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		data string
		// expectations
		wantRule    string
		wantSev     protocol.Severity
		wantAttack  string
		wantSnippet string
	}{
		{name: "service rule", data: "x\nhttps://webhook.site/u\n", wantRule: "GAL-IOC-002", wantSev: protocol.SeverityMedium, wantAttack: "T1567", wantSnippet: "https://webhook.site/u"},
		{name: "raw ip rule", data: "http://8.8.8.8/\n", wantRule: "GAL-IOC-001", wantSev: protocol.SeverityLow, wantAttack: "T1071.001", wantSnippet: "http://8.8.8.8/"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := analyze.File{Path: "n.txt", Name: "n.txt", Kind: ident.Text, Data: []byte(tt.data)}

			out, err := ioc.New().Analyze(context.Background(), f)

			if err != nil || len(out.Findings) != 1 {
				t.Fatalf("err = %v, findings = %+v", err, out.Findings)
			}
			got := out.Findings[0]
			if got.RuleID != tt.wantRule || got.Severity != tt.wantSev || got.Attack != tt.wantAttack || got.Evidence[0].Snippet != tt.wantSnippet {
				t.Errorf("finding = %+v", got)
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
		{name: "cancelled context stops the scan", wantErr: context.Canceled},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			f := analyze.File{Path: "n.txt", Name: "n.txt", Kind: ident.Text, Data: []byte("https://a.test/")}

			_, err := ioc.New().Analyze(ctx, f)

			if !errors.Is(err, tt.wantErr) {
				t.Errorf("err = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

// lateCancel reports no error on its first Err call, the check before a line, and Canceled after that.
type lateCancel struct {
	context.Context
	calls int
}

func (c *lateCancel) Err() error {
	if c.calls++; c.calls > 1 {
		return context.Canceled
	}
	return nil
}

func TestAnalyzeCancelledInLine(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		data string
		// expectations
		wantErr error
	}{
		{name: "cancelled context stops a line with many matches", data: strings.Repeat("http://a.test/x ", 1000), wantErr: context.Canceled},
		{name: "cancelled context stops a line with many emails", data: strings.Repeat("u@h.test ", 1000), wantErr: context.Canceled},
		{name: "cancelled context stops a line with many ips", data: strings.Repeat("8.8.8.8 ", 1000), wantErr: context.Canceled},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := analyze.File{Path: "n.txt", Name: "n.txt", Kind: ident.Text, Data: []byte(tt.data)}

			_, err := ioc.New().Analyze(&lateCancel{Context: context.Background()}, f)

			if !errors.Is(err, tt.wantErr) {
				t.Errorf("err = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestName(t *testing.T) {
	tests := []struct {
		name string
		// expectations
		want string
	}{
		{name: "analyzer name", want: "ioc"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ioc.New().Name(); got != tt.want {
				t.Errorf("Name() = %q, want %q", got, tt.want)
			}
		})
	}
}
