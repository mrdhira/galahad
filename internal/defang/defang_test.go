package defang_test

import (
	"fmt"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/mrdhira/galahad/internal/defang"
)

func TestDefang(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		in string
		// expectations
		want string
	}{
		{name: "https url", in: "https://a.b.test/x", want: "hxxps://a[.]b[.]test/x"},
		{name: "http url keeps case of the rest", in: "HTTP://A.test/Path.exe", want: "hxxp://A[.]test/Path[.]exe"},
		{name: "host starting with http is not a scheme", in: "httpbin.org", want: "httpbin[.]org"},
		{name: "http without slashes", in: "https.test", want: "https[.]test"},
		{name: "ftp url", in: "ftp://files.test", want: "fxp://files[.]test"},
		{name: "ftps url", in: "FTPS://files.test", want: "fxps://files[.]test"},
		{name: "file url", in: "file:///C:/Users/a/evil.exe", want: "fxle:///C:/Users/a/evil[.]exe"},
		{name: "scheme without slashes", in: "file.test", want: "file[.]test"},
		{name: "email", in: "user@host.test", want: "user[@]host[.]test"},
		{name: "ip address", in: "http://203.0.113.9:8080/a", want: "hxxp://203[.]0[.]113[.]9:8080/a"},
		{name: "host", in: "evil.test", want: "evil[.]test"},
		{name: "already defanged", in: "hxxps://a[.]b[.]test", want: "hxxps://a[.]b[.]test"},
		{name: "empty", in: "", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := defang.Defang(tt.in); got != tt.want {
				t.Errorf("Defang(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestDefangText(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		in string
		// expectations
		want string
	}{
		{name: "urls and emails in prose", in: "See https://a.test/x, or mail bob@c.test. Done.", want: "See hxxps://a[.]test/x, or mail bob[@]c[.]test. Done."},
		{name: "ftp url in prose", in: "get ftp://f.test/a.bin now", want: "get fxp://f[.]test/a[.]bin now"},
		{name: "ftps url in prose", in: "get ftps://f.test/a.bin now", want: "get fxps://f[.]test/a[.]bin now"},
		{name: "file url in prose", in: "open file:///etc/p.txt, then", want: "open fxle:///etc/p[.]txt, then"},
		{name: "markdown link", in: "[docs](http://d.test/p)", want: "[docs](hxxp://d[.]test/p)"},
		{name: "at sign inside a url", in: "http://u@h.test/", want: "hxxp://u[@]h[.]test/"},
		{name: "url glued to a word", in: "xhttps://evil.test/a", want: "xhxxps://evil[.]test/a"},
		{name: "url after a parenthesis", in: "(https://evil.test/a)", want: "(hxxps://evil[.]test/a)"},
		{name: "url after a quote", in: `"https://evil.test/a"`, want: `"hxxps://evil[.]test/a"`},
		{name: "already defanged text is unchanged", in: "see hxxps://evil[.]test/a and bob[@]c[.]test", want: "see hxxps://evil[.]test/a and bob[@]c[.]test"},
		{name: "text without indicators", in: "version 1.2.3 is out.", want: "version 1.2.3 is out."},
		{name: "empty", in: "", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := defang.DefangText(tt.in); got != tt.want {
				t.Errorf("DefangText(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestDefangHosts(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		in    string
		hosts map[string]bool
		// expectations
		want string
	}{
		{name: "bare domain in a snippet", in: "hostname: 'collect.sinkhole.test'", hosts: map[string]bool{"collect.sinkhole.test": true}, want: "hostname: 'collect[.]sinkhole[.]test'"},
		{name: "case is ignored and kept", in: "ping Collect.Sinkhole.TEST now", hosts: map[string]bool{"collect.sinkhole.test": true}, want: "ping Collect[.]Sinkhole[.]TEST now"},
		{name: "several occurrences and hosts", in: "a.test b.test a.test", hosts: map[string]bool{"a.test": true, "b.test": true}, want: "a[.]test b[.]test a[.]test"},
		{name: "ip address", in: "connect 203.0.113.9:80", hosts: map[string]bool{"203.0.113.9": true}, want: "connect 203[.]0[.]113[.]9:80"},
		{name: "sentence end", in: "see evil.test.", hosts: map[string]bool{"evil.test": true}, want: "see evil[.]test."},
		{name: "file names are untouched", in: "run setup.js and evil.test", hosts: map[string]bool{"evil.test": true}, want: "run setup.js and evil[.]test"},
		{name: "longer name is not a match", in: "xevil.test evil.testing sub.evil.test evil.test.example", hosts: map[string]bool{"evil.test": true}, want: "xevil.test evil.testing sub.evil.test evil.test.example"},
		{name: "already defanged text is unchanged", in: "evil[.]test", hosts: map[string]bool{"evil.test": true}, want: "evil[.]test"},
		{name: "ip inside a version is not a match", in: "1.2.3.45 and 11.2.3.4", hosts: map[string]bool{"1.2.3.4": true}, want: "1.2.3.45 and 11.2.3.4"},
		{name: "no hosts", in: "evil.test", hosts: nil, want: "evil.test"},
		{name: "empty host is ignored", in: "evil.test", hosts: map[string]bool{"": true}, want: "evil.test"},
		{name: "leading dots are not part of the name", in: "..evil.test and ...evil.test.", hosts: map[string]bool{"evil.test": true}, want: "..evil[.]test and ...evil[.]test."},
		{name: "dot before a non-name character ends the run", in: "evil.test/x evil.test, (evil.test)", hosts: map[string]bool{"evil.test": true}, want: "evil[.]test/x evil[.]test, (evil[.]test)"},
		{name: "non-ascii text keeps offsets", in: "İ evil.test", hosts: map[string]bool{"evil.test": true}, want: "İ evil[.]test"},
		{name: "empty", in: "", hosts: map[string]bool{"evil.test": true}, want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := defang.DefangHosts(tt.in, tt.hosts); got != tt.want {
				t.Errorf("DefangHosts(%q, %v) = %q, want %q", tt.in, tt.hosts, got, tt.want)
			}
		})
	}
}

// TestDefangHostsScalesLinearly guards against work that grows with hosts times text: a hostile
// repository controls the number of IOC hosts, so many hosts must cost about the same as few.
func TestDefangHostsScalesLinearly(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		texts, fewHosts, manyHosts int
		// expectations
		wantMaxRatio float64
	}{
		{name: "1000 hosts over 2000 snippets cost about the same as 1 host", texts: 2000, fewHosts: 1, manyHosts: 1000, wantMaxRatio: 8},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			text := strings.Repeat("hostname: 'h5.sinkhole.test' call(setup.js) ", 5)[:200]
			run := func(hosts int) time.Duration {
				set := map[string]bool{"h5.sinkhole.test": true}
				for i := 1; i < hosts; i++ {
					set[fmt.Sprintf("h%d.sinkhole.test", i+1000)] = true
				}
				best := time.Duration(math.MaxInt64)
				for range 3 {
					start := time.Now()
					for range tt.texts {
						_ = defang.DefangHosts(text, set)
					}
					best = min(best, time.Since(start))
				}
				return best
			}
			few, many := run(tt.fewHosts), run(tt.manyHosts)
			if ratio := float64(many) / float64(few); ratio > tt.wantMaxRatio {
				t.Errorf("time ratio %.1f for %d hosts against %d, want at most %.1f", ratio, tt.manyHosts, tt.fewHosts, tt.wantMaxRatio)
			}
		})
	}
}
