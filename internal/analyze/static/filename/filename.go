// Package filename flags deceptive file names (decoy double extensions, bidi
// controls) and Windows shortcut or script-host files, and looks inside LNK
// files for interpreters and URLs.
package filename

import (
	"context"
	"path"
	"regexp"
	"slices"
	"strings"
	"unicode"

	"github.com/mrdhira/galahad/internal/analyze"
	"github.com/mrdhira/galahad/internal/analyze/ident"
	"github.com/mrdhira/galahad/internal/protocol"
)

var (
	ruleDouble = protocol.Rule{ID: "GAL-NAME-001", Severity: protocol.SeverityCritical, Title: "Decoy double extension ending in an executable type", Attack: "T1036.007"}
	// ruleDoubleSource has the ID of ruleDouble with a lower severity, for a plain JavaScript file in a test
	// or example folder of a source tree. The scorer counts an ID once, at its highest severity.
	ruleDoubleSource = protocol.Rule{ID: "GAL-NAME-001", Severity: protocol.SeverityMedium, Title: "Decoy double extension ending in a script, in a test or example folder", Attack: "T1036.007"}
	ruleBidi         = protocol.Rule{ID: "GAL-NAME-002", Severity: protocol.SeverityCritical, Title: "Bidi control character in the filename", Attack: "T1036.002"}
	ruleShort        = protocol.Rule{ID: "GAL-NAME-003", Severity: protocol.SeverityMedium, Title: "Windows shortcut or script-host file", Attack: "T1204.002"}
	ruleLNK          = protocol.Rule{ID: "GAL-LNK-001", Severity: protocol.SeverityHigh, Title: "Shortcut launches a script interpreter or URL", Attack: "T1059"}
)

// maxLNKScan bounds how much of a shortcut is searched for strings.
const maxLNKScan = 64 << 10

// minString is the shortest run of characters treated as a string.
const minString = 4

var (
	// decoyExts are the document, image, media, data and archive types that people open by double-click.
	// dataExts are the data and markup types among them: source trees are full of names such as
	// express.json.js, so they are decoys for every executable type except js.
	decoyExts = setOf("txt", "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "rtf", "csv", "odt", "ods",
		"jpg", "jpeg", "png", "gif", "bmp", "ico", "mp3", "mp4", "mov", "wav", "zip", "rar", "json", "xml", "html", "htm")
	dataExts     = setOf("csv", "json", "xml", "html", "htm")
	execExts     = setOf("exe", "scr", "com", "pif", "bat", "cmd", "lnk", "js", "jse", "vbs", "vbe", "wsf", "hta", "ps1", "msi", "jar")
	sourceDirs   = setOf("test", "tests", "__tests__", "fixtures", "playground", "examples", "e2e")
	shortcutExts = setOf("lnk", "url", "scf", "hta", "wsf", "vbe", "jse")

	interpreter = regexp.MustCompile(`(?i)\b(powershell|cmd|mshta|wscript|cscript|rundll32|regsvr32)(\.exe)?\b`)
	urlPattern  = regexp.MustCompile(`(?i)\b(https?|ftp)://[^\s"'<>]+`)
)

func setOf(items ...string) map[string]bool {
	m := make(map[string]bool, len(items))
	for _, s := range items {
		m[s] = true
	}
	return m
}

type analyzer struct{}

// New returns the filename analyzer.
func New() analyze.Analyzer { return analyzer{} }

func (analyzer) Name() string { return "filename" }

func (analyzer) Analyze(_ context.Context, f analyze.File) (analyze.Output, error) {
	var out analyze.Output
	add := func(r protocol.Rule, snippet string) {
		out.Findings = append(out.Findings, r.Finding(protocol.Evidence{Path: f.Path, Snippet: protocol.Snippet(snippet)}))
	}
	if isDoubleExt(f.Name) {
		r := ruleDouble
		if isSourceFixture(f) {
			r = ruleDoubleSource
		}
		add(r, f.Name)
	}
	if hasBidi(f.Name) {
		add(ruleBidi, f.Name)
	}
	isLNK := f.Kind == ident.LNK || lastExt(f.Name) == "lnk"
	if isLNK || shortcutExts[lastExt(f.Name)] {
		add(ruleShort, f.Name)
	}
	if isLNK {
		if s := launchString(f.Data[:min(len(f.Data), maxLNKScan)]); s != "" {
			add(ruleLNK, s)
		}
	}
	return out, nil
}

// isPadding reports characters Windows or a viewer ignores at the end of a
// name or around a dot: trailing dots and spaces, and invisible fillers.
func isPadding(r rune) bool {
	return unicode.IsSpace(r) || unicode.Is(unicode.Cf, r) ||
		r == 0x115F || r == 0x1160 || r == 0x2800 || r == 0x3164 || r == 0xFFA0
}

func isTrailing(r rune) bool { return r == '.' || isPadding(r) }

// lastExt returns the lowercase extension of name without the dot, ignoring
// trailing dots and padding.
func lastExt(name string) string {
	return strings.ToLower(strings.TrimPrefix(path.Ext(strings.TrimRightFunc(name, isTrailing)), "."))
}

// isDoubleExt reports a decoy extension directly followed by an executable one,
// allowing whitespace padding before the last dot.
func isDoubleExt(name string) bool {
	name = strings.TrimRightFunc(name, isTrailing)
	i := strings.LastIndexByte(name, '.')
	exec := strings.ToLower(name[i+1:])
	if i < 0 || !execExts[exec] {
		return false
	}
	decoy := lastExt(strings.TrimRightFunc(name[:i], isPadding))
	return decoyExts[decoy] && (exec != "js" || !dataExts[decoy])
}

// isSourceFixture reports a plain JavaScript file on disk below a test or example
// folder, such as test/e2e/image/test.png.js in a source tree. A file named like
// that in an archive or an email is an attack, and so is a file at the top of
// the target or one that is not text: only a script that sits in a folder meant
// for tests is graded lower.
func isSourceFixture(f analyze.File) bool {
	if f.Member != "" || f.Kind != ident.Text || lastExt(f.Name) != "js" {
		return false
	}
	dirs := strings.Split(strings.ToLower(f.Path), "/")
	return slices.ContainsFunc(dirs[:len(dirs)-1], func(d string) bool { return sourceDirs[d] })
}

func hasBidi(name string) bool {
	return strings.ContainsFunc(name, func(r rune) bool {
		return r == 0x061C || r == 0x200E || r == 0x200F || (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069)
	})
}

// launchString returns the first ASCII or UTF-16LE string in data that names a
// script interpreter or a URL, or "".
func launchString(data []byte) string {
	for _, s := range append(asciiStrings(data), utf16Strings(data)...) {
		if interpreter.MatchString(s) || urlPattern.MatchString(s) {
			return s
		}
	}
	return ""
}

func printable(b byte) bool { return b >= 0x20 && b < 0x7f }

func asciiStrings(data []byte) []string {
	var res []string
	for i := 0; i < len(data); {
		j := i
		for j < len(data) && printable(data[j]) {
			j++
		}
		if j-i >= minString {
			res = append(res, string(data[i:j]))
		}
		i = j + 1
	}
	return res
}

// utf16Strings finds runs of printable ASCII code units encoded as UTF-16LE at
// any byte alignment.
func utf16Strings(data []byte) []string {
	var res []string
	for i := 0; i+1 < len(data); {
		if !printable(data[i]) || data[i+1] != 0 {
			i++
			continue
		}
		var sb strings.Builder
		j := i
		for ; j+1 < len(data) && printable(data[j]) && data[j+1] == 0; j += 2 {
			sb.WriteByte(data[j])
		}
		if sb.Len() >= minString {
			res = append(res, sb.String())
		}
		i = j
	}
	return res
}
