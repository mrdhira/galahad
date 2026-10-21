// Package eml parses .eml messages. It reports the sender, hands attachments
// and nested messages to the engine as children and checks links in the bodies.
package eml

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"net/url"
	"path"
	"regexp"
	"strings"

	"golang.org/x/net/html"

	"github.com/mrdhira/galahad/internal/analyze"
	"github.com/mrdhira/galahad/internal/analyze/static/ioc"
	"github.com/mrdhira/galahad/internal/protocol"
)

var (
	ruleSender  = protocol.Rule{ID: "GAL-EML-001", Severity: protocol.SeverityInfo, Title: "Email sender"}
	ruleReplyTo = protocol.Rule{ID: "GAL-EML-002", Severity: protocol.SeverityLow, Title: "Reply-To domain differs from the sender", Attack: "T1566"}
	ruleLink    = protocol.Rule{ID: "GAL-EML-003", Severity: protocol.SeverityMedium, Title: "Link text shows a different domain than its target", Attack: "T1566.002"}
)

// Limits.
const (
	MaxHeaderSize = 64 << 10 // bytes of message headers
	MaxParts      = 200      // MIME parts per message
	MaxDepth      = 10       // multipart nesting
	maxLinkText   = 1 << 10  // bytes of anchor text compared
	checkEvery    = 1024     // tokens between context checks
	sniffWindow   = 4096
)

var (
	fromRe = regexp.MustCompile(`(?im)^from:`)
	mimeRe = regexp.MustCompile(`(?im)^mime-version:`)
	// textDomainRe finds a host name written in link text, such as "careers.example.com".
	textDomainRe = regexp.MustCompile(`(?i)(?:https?://)?((?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,})\b`)
	// fileExts are not top-level domains: "report.pdf" is a file name, not a host.
	fileExts = map[string]bool{
		"pdf": true, "doc": true, "docx": true, "xls": true, "xlsx": true, "ppt": true, "pptx": true,
		"txt": true, "csv": true, "zip": true, "rar": true, "exe": true, "png": true, "jpg": true,
		"jpeg": true, "gif": true, "js": true, "html": true, "htm": true, "php": true, "md": true,
	}
)

type analyzer struct{}

// New returns the email analyzer.
func New() analyze.Analyzer { return analyzer{} }

func (analyzer) Name() string { return "eml" }

func (analyzer) Analyze(ctx context.Context, f analyze.File) (analyze.Output, error) {
	if !matches(f) {
		return analyze.Output{}, nil
	}
	parseError := analyze.Output{Skips: []protocol.Skip{{Path: f.Path, Reason: protocol.SkipParseError}}}
	end := headerEnd(f.Data)
	if end < 0 {
		return parseError, nil
	}
	msg, err := mail.ReadMessage(bytes.NewReader(f.Data[:end]))
	if err != nil {
		return parseError, nil
	}
	budget := int64(analyze.MaxFileSize)
	if b, ok := analyze.Budget(ctx); ok {
		budget = min(budget, b)
	}
	w := &walker{ctx: ctx, f: f, hdr: end, budget: int(budget), names: map[string]bool{}, iocs: map[string]bool{}}
	w.headers(msg.Header)
	w.entity(msg.Header.Get, bytes.NewReader(f.Data[end:]), end, 0)
	if err := ctx.Err(); err != nil {
		return analyze.Output{}, err
	}
	return w.out, nil
}

// matches says whether f is an email: a .eml name, or text that starts with From: and MIME-Version: headers.
func matches(f analyze.File) bool {
	if strings.EqualFold(path.Ext(f.Name), ".eml") {
		return true
	}
	head := f.Data[:min(len(f.Data), sniffWindow)]
	return fromRe.Match(head) && mimeRe.Match(head)
}

// headerEnd returns the offset of the first body byte: the byte after the
// first empty line, as net/mail sees it. It is -1 if that line is not reached
// within MaxHeaderSize.
func headerEnd(data []byte) int {
	for pos := 0; pos < len(data) && pos <= MaxHeaderSize; {
		line, next := data[pos:], len(data)
		if nl := bytes.IndexByte(line, '\n'); nl >= 0 {
			line, next = line[:nl], pos+nl+1
		}
		if len(bytes.TrimSuffix(line, []byte{'\r'})) == 0 {
			return next
		}
		pos = next
	}
	return -1
}

type walker struct {
	ctx    context.Context
	f      analyze.File
	out    analyze.Output
	hdr    int // offset of the first body byte
	parts  int
	budget int // decoded bytes still allowed
	cursor int // file offset where the search for the next part body starts
	names  map[string]bool
	iocs   map[string]bool
	stop   bool
	links  int // GAL-EML-003 findings so far
}

func (w *walker) skip(reason string) {
	w.out.Skips = append(w.out.Skips, protocol.Skip{Path: w.f.Path, Reason: reason})
}

// headerOffset returns the file offset of the named message header line, or 0.
func (w *walker) headerOffset(name string) int {
	re := regexp.MustCompile(`(?im)^` + regexp.QuoteMeta(name) + `:`)
	if loc := re.FindIndex(w.f.Data[:w.hdr]); loc != nil {
		return loc[0]
	}
	return 0
}

func (w *walker) evidence(off int, snippet string) protocol.Evidence {
	ev := analyze.EvidenceAt(w.f, off)
	ev.Snippet = protocol.Snippet(snippet)
	return ev
}

// headers reports the sender, and a Reply-To domain that differs from it.
func (w *walker) headers(h mail.Header) {
	froms := addresses(h, "From")
	if len(froms) == 0 {
		return
	}
	from := froms[0]
	fromDom := domainOf(from)
	snippet := fmt.Sprintf("From: %s (domain: %s)", from, fromDom)
	replyTos := addresses(h, "Reply-To")
	if len(replyTos) > 0 {
		snippet += fmt.Sprintf("; Reply-To domain: %s", domainOf(replyTos[0]))
	}
	if ret := addresses(h, "Return-Path"); len(ret) > 0 {
		snippet += fmt.Sprintf("; Return-Path domain: %s", domainOf(ret[0]))
	}
	w.out.Findings = append(w.out.Findings, ruleSender.Finding(w.evidence(w.headerOffset("From"), snippet)))
	for _, r := range replyTos {
		if domainOf(r) != fromDom {
			w.out.Findings = append(w.out.Findings, ruleReplyTo.Finding(
				w.evidence(w.headerOffset("Reply-To"), fmt.Sprintf("Reply-To: %s (domain: %s)", r, domainOf(r)))))
			break
		}
	}
}

// addrParser accepts every charset without converting: only the addresses matter.
var addrParser = &mail.AddressParser{WordDecoder: &mime.WordDecoder{
	CharsetReader: func(_ string, r io.Reader) (io.Reader, error) { return r, nil },
}}

// addresses returns the addresses of a header. If the value does not parse, it
// returns the email addresses found in the raw text.
func addresses(h mail.Header, name string) []string {
	raw := h.Get(name)
	if raw == "" {
		return nil
	}
	var out []string
	if list, err := addrParser.ParseList(raw); err == nil {
		for _, a := range list {
			out = append(out, a.Address)
		}
		return out
	}
	for _, m := range ioc.Extract([]byte(raw)) {
		if m.Type == ioc.TypeEmail {
			out = append(out, m.Value)
		}
	}
	return out
}

func domainOf(addr string) string {
	return strings.ToLower(addr[strings.LastIndexByte(addr, '@')+1:])
}

// entity handles one message or part: a multipart body is split into parts,
// anything else is a body, an attachment or a nested message. off is the file
// offset of the first byte of body, or -1 if unknown.
func (w *walker) entity(get func(string) string, body io.Reader, off, depth int) {
	if w.stop || w.ctx.Err() != nil {
		return
	}
	w.parts++
	if w.parts > MaxParts {
		w.skip(protocol.SkipBudget)
		w.stop = true
		return
	}
	ctype, params := mediaType(get("Content-Type"))
	if ctype == "" {
		ctype = "text/plain"
	}
	if strings.HasPrefix(ctype, "multipart/") && params["boundary"] != "" {
		if depth >= MaxDepth {
			w.skip(protocol.SkipDepth)
			return
		}
		mr := multipart.NewReader(body, params["boundary"])
		for !w.stop && w.ctx.Err() == nil {
			p, err := mr.NextRawPart()
			if errors.Is(err, io.EOF) {
				return
			}
			if err != nil {
				// The parts after a broken one were not read, and a lenient reader might.
				w.skip(protocol.SkipUnreadable)
				return
			}
			w.entity(p.Header.Get, p, -1, depth+1)
		}
		return
	}
	raw, err := io.ReadAll(io.LimitReader(body, analyze.MaxFileSize))
	if err != nil && len(raw) == 0 {
		return
	}
	if off < 0 {
		off = w.locate(raw)
	}
	w.cursor = off + len(raw)
	enc := strings.ToLower(strings.TrimSpace(get("Content-Transfer-Encoding")))
	data := decode(enc, raw)
	if len(data) > w.budget {
		w.skip(protocol.SkipBudget)
		return
	}
	w.budget -= len(data)

	identity := enc != "base64" && enc != "quoted-printable"
	name := attachmentName(get, params)
	disp, _ := mediaType(get("Content-Disposition"))
	switch {
	case ctype == "message/rfc822":
		w.child(name, "message", ".eml", data)
	case disp == "attachment" || name != "" || !strings.HasPrefix(ctype, "text/"):
		w.child(name, "attachment", "", data)
	case !identity:
		// The engine scans decoded bodies as children, so every analyzer sees them.
		ext := ".txt"
		if ctype == "text/html" {
			ext = ".html"
			w.html(data, off, false)
		}
		w.child("", "body", ext, data)
	case ctype == "text/html":
		w.html(data, off, true)
	}
}

// mediaType parses a Content-Type or Content-Disposition value. If the
// parameters are invalid, it still returns the type, with no parameters.
func mediaType(v string) (string, map[string]string) {
	t, p, err := mime.ParseMediaType(v)
	if t == "" && err != nil {
		t, _, _ = strings.Cut(v, ";")
		t = strings.ToLower(strings.TrimSpace(t))
	}
	return t, p
}

// locate finds the file offset of a part body that was read from the file.
func (w *walker) locate(raw []byte) int {
	cur := min(w.cursor, len(w.f.Data))
	probe := raw[:min(len(raw), 128)]
	if i := bytes.Index(w.f.Data[cur:], probe); i >= 0 {
		return cur + i
	}
	return cur
}

// child queues data as a child of the email, under a unique name without a slash.
func (w *walker) child(name, fallback, ext string, data []byte) {
	if name == "" {
		name = fmt.Sprintf("%s-%d%s", fallback, w.parts, ext)
	}
	for w.names[name] {
		name = fmt.Sprintf("%d-%s", w.parts, name)
	}
	w.names[name] = true
	w.out.Children = append(w.out.Children, analyze.File{Name: name, Data: data})
}

// attachmentName returns the raw RFC 2047 decoded file name of a part, cut to its last path element.
func attachmentName(get func(string) string, ctypeParams map[string]string) string {
	_, dp := mediaType(get("Content-Disposition"))
	name := dp["filename"]
	if name == "" {
		name = ctypeParams["name"]
	}
	if d, err := new(mime.WordDecoder).DecodeHeader(name); err == nil {
		name = d
	}
	return name[strings.LastIndexAny(name, `/\`)+1:]
}

// decode undoes the content transfer encoding. Damaged input yields what could be decoded.
func decode(enc string, raw []byte) []byte {
	switch enc {
	case "base64":
		clean := make([]byte, 0, len(raw))
		for _, c := range raw {
			if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '+' || c == '/' {
				clean = append(clean, c)
			}
		}
		if len(clean)%4 == 1 {
			clean = clean[:len(clean)-1]
		}
		out := make([]byte, base64.RawStdEncoding.DecodedLen(len(clean)))
		n, _ := base64.RawStdEncoding.Decode(out, clean)
		return out[:n]
	case "quoted-printable":
		out, _ := io.ReadAll(io.LimitReader(quotedprintable.NewReader(bytes.NewReader(raw)), analyze.MaxFileSize))
		return out
	}
	return raw
}

// offsetOf returns the file offset for byte idx of a decoded body. Only bodies
// stored as they are map exactly; others map to the start of the body.
func offsetOf(base, idx int, identity bool) int {
	if identity {
		return base + idx
	}
	return base
}

func (w *walker) addIOC(typ, value string, off int) {
	key := typ + "\x00" + value
	if w.iocs[key] || len(w.out.IOCs) >= protocol.MaxIOCs {
		return
	}
	w.iocs[key] = true
	w.out.IOCs = append(w.out.IOCs, protocol.IOC{Type: typ, Value: value, Path: w.f.Path, Line: analyze.EvidenceAt(w.f, off).Line})
}

// html reads the anchors of an HTML body and flags links whose text names another domain.
func (w *walker) html(data []byte, base int, identity bool) {
	z := html.NewTokenizer(bytes.NewReader(data))
	var href string
	var text strings.Builder
	pos, anchorAt, n := 0, 0, 0
	inAnchor := false
	flush := func() {
		if inAnchor {
			w.link(href, strings.TrimSpace(text.String()), offsetOf(base, anchorAt, identity))
		}
		inAnchor = false
	}
	for {
		if n++; n%checkEvery == 0 && w.ctx.Err() != nil {
			return
		}
		if w.links >= protocol.MaxFindingsPerRulePerFile && len(w.out.IOCs) >= protocol.MaxIOCs {
			return
		}
		tt := z.Next()
		start := pos
		pos += len(z.Raw())
		switch tt {
		case html.ErrorToken:
			flush()
			return
		case html.StartTagToken, html.SelfClosingTagToken:
			name, more := z.TagName()
			if string(name) != "a" {
				break
			}
			flush()
			href = ""
			for more {
				var k, v []byte
				k, v, more = z.TagAttr()
				if string(k) == "href" {
					href = strings.TrimSpace(string(v))
				}
			}
			inAnchor, anchorAt = true, start
			text.Reset()
		case html.TextToken:
			if inAnchor && text.Len() < maxLinkText {
				text.Write(z.Text())
			}
		case html.EndTagToken:
			if name, _ := z.TagName(); string(name) == "a" {
				flush()
			}
		}
	}
}

// link records one anchor: its target as an indicator, and a finding if the text names another domain.
func (w *walker) link(href, text string, off int) {
	u, err := url.Parse(href)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return
	}
	if len(w.out.IOCs) < protocol.MaxIOCs {
		for _, m := range ioc.Extract([]byte(href)) {
			w.addIOC(m.Type, m.Value, off)
		}
	}
	if w.links >= protocol.MaxFindingsPerRulePerFile {
		return
	}
	target := strings.ToLower(u.Hostname())
	for _, m := range textDomainRe.FindAllStringSubmatch(text, -1) {
		shown := strings.ToLower(m[1])
		if fileExts[shown[strings.LastIndexByte(shown, '.')+1:]] || sameSite(shown, target) {
			continue
		}
		w.links++
		w.out.Findings = append(w.out.Findings, ruleLink.Finding(
			w.evidence(off, fmt.Sprintf("link text %s goes to %s", shown, target))))
		return
	}
}

// sameSite says whether two host names are equal or one is a subdomain of the other, ignoring a leading www.
func sameSite(a, b string) bool {
	a, b = strings.TrimPrefix(a, "www."), strings.TrimPrefix(b, "www.")
	return a == b || strings.HasSuffix(a, "."+b) || strings.HasSuffix(b, "."+a)
}
