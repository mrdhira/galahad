package report

import (
	"fmt"
	"strings"

	"github.com/mrdhira/galahad/internal/protocol"
)

const (
	mdMaxFindings = 10
	mdMaxIOCs     = 20
	mdMaxSkips    = 20
)

// mdSpecial are the characters that can start Markdown constructs inside a line. <, > and & become
// HTML entities instead, so raw markup never appears in the file.
const mdSpecial = "\\`*_{}[]()|~!"

// mdEscape defangs s and escapes Markdown-active characters so untrusted text cannot become a
// link, image, code span, table cell break or raw HTML. The defang markers [.] and [@] stay as
// they are after a letter or digit; elsewhere the bracket is escaped (see mdEscapeClean).
func mdEscape(s string) string {
	return mdEscapeClean(strings.ReplaceAll(clean(s), "www.", "www[.]"))
}

// mdText is mdEscape for free text (snippets, titles, reasons): it also defangs the IOC hosts.
func mdText(hosts map[string]bool, s string) string {
	return mdEscapeClean(strings.ReplaceAll(text(hosts, s), "www.", "www[.]"))
}

// mdValue is mdEscape for a value that is a URL, domain, IP or email as a whole.
func mdValue(s string) string {
	return mdEscapeClean(cleanValue(s))
}

func mdEscapeClean(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		// A defang marker stays as it is only right after a letter or digit, as in "evil[.]test".
		// Anywhere else (line start, after a list marker or space) "[.]: url" could define a link
		// reference that turns every marker in the file into a link.
		if (strings.HasPrefix(s[i:], "[.]") || strings.HasPrefix(s[i:], "[@]")) && i > 0 && isAlnum(s[i-1]) {
			b.WriteString(s[i : i+3])
			i += 2
			continue
		}
		switch s[i] {
		case '<':
			b.WriteString("&lt;")
			continue
		case '>':
			b.WriteString("&gt;")
			continue
		case '&':
			b.WriteString("&amp;")
			continue
		}
		if strings.IndexByte(mdSpecial, s[i]) >= 0 {
			b.WriteByte('\\')
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func renderMarkdown(res *protocol.Result) string {
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }
	hosts := iocHosts(res)

	all := groups(res, nil)
	w("# Galahad report\n\n")
	w("**Verdict: %s**\n\n%s\n\n%s\n", mdEscape(strings.ToUpper(string(res.Verdict))), actionLine(res.Verdict), metaLine(res))
	if top := why(res.Verdict, all); len(top) > 0 {
		w("\n## Why\n\n")
		for _, g := range top {
			mdLine(&b, hosts, g.Entries[0].Severity, g.Entries[0].Title, g.Location)
		}
	}

	if auto := groups(res, isAutoexec); len(auto) > 0 {
		w("\n## Runs automatically (%d)\n\n", len(auto))
		for i, g := range auto {
			if i == mdMaxFindings {
				w("\nShowing %d of %d. See report.json for the rest.\n", mdMaxFindings, len(auto))
				break
			}
			mdLine(&b, hosts, g.severity(), g.titles(), g.Location)
		}
	}

	w("\n## Findings (%d)\n\n", len(all))
	mdFindings(&b, hosts, all, mdMaxFindings)

	w("\n## %s\n\n", iocHeading(res))
	if len(res.IOCs) == 0 {
		w("None.\n")
	} else {
		w("| Type | Value | Location |\n|---|---|---|\n")
		for i, ioc := range res.IOCs {
			if i == mdMaxIOCs {
				w("\nShowing %d of %d. See report.json for the rest.\n", mdMaxIOCs, len(res.IOCs))
				break
			}
			w("| %s | %s | %s |\n", mdEscape(ioc.Type), mdValue(ioc.Value), mdEscape(location(ioc.Path, ioc.Line)))
		}
	}

	w("\n## Coverage\n\n")
	c := res.Coverage
	w("- %s\n", coverageLine(c))
	if warn := coverageWarning(c); warn != "" {
		w("- **Warning:** %s\n", warn)
	}
	if c.Truncated {
		w("- Truncated: the file or finding limit was reached\n")
	}
	if len(c.Skipped) == 0 {
		w("- Skipped: none\n")
	}
	for i, s := range c.Skipped {
		if i == mdMaxSkips {
			w("- ... %d more skipped, see report.json\n", len(c.Skipped)-mdMaxSkips)
			break
		}
		w("- Skipped %s: %s\n", mdEscape(s.Path), mdEscape(s.Reason))
	}

	w("\n## Target\n\n")
	t := describeTarget(res.Target)
	w("- Name: %s\n- Kind: %s\n", mdEscape(res.Target.Name), t.Kind)
	if t.SHA256 != "" {
		w("- SHA-256: %s\n", mdEscape(t.SHA256))
	}
	w("- Size: %s\n", t.Size)

	w("\n## Scoring details\n\n")
	if len(res.Reasons) == 0 {
		w("No scoring reasons.\n")
	}
	for _, r := range res.Reasons {
		w("- %s\n", mdText(hosts, r))
	}
	return b.String()
}

// mdLine writes one list item of the Why and Runs automatically lists.
func mdLine(b *strings.Builder, hosts map[string]bool, sev protocol.Severity, title, loc string) {
	fmt.Fprintf(b, "- %s: %s", mdEscape(string(sev)), mdText(hosts, title))
	if loc != "" {
		fmt.Fprintf(b, " in %s", mdEscape(loc))
	}
	b.WriteString("\n")
}

func mdFindings(b *strings.Builder, hosts map[string]bool, rs []group, limit int) {
	if len(rs) == 0 {
		b.WriteString("None.\n")
		return
	}
	b.WriteString("| Severity | Rule | Title | ATT&CK | Location | Snippet |\n|---|---|---|---|---|---|\n")
	for i, r := range rs {
		if i == limit {
			fmt.Fprintf(b, "\nShowing %d of %d. See report.json for the rest.\n", limit, len(rs))
			break
		}
		fmt.Fprintf(b, "| %s | %s | %s | %s | %s | %s |\n", mdEscape(string(r.severity())), mdEscape(r.rules()), mdText(hosts, r.titles()), mdEscape(r.attacks()), mdEscape(r.Location), mdText(hosts, r.Snippet))
	}
}

func isAlnum(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}
