package defang_test

import (
	"testing"

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
		{name: "ftp url", in: "ftp://files.test", want: "ftp://files[.]test"},
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
		{name: "markdown link", in: "[docs](http://d.test/p)", want: "[docs](hxxp://d[.]test/p)"},
		{name: "at sign inside a url", in: "http://u@h.test/", want: "hxxp://u[@]h[.]test/"},
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
