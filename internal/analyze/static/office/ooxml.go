package office

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"errors"
	"io"
	"path"
	"regexp"
	"strings"

	"github.com/mrdhira/galahad/internal/analyze"
	"github.com/mrdhira/galahad/internal/protocol"
)

// Limits of one OOXML package.
const (
	maxEntries = 5000
	maxRels    = 1 << 20  // bytes of one relationships part
	maxXML     = 16 << 20 // bytes of document.xml or sharedStrings.xml
	maxBudget  = 64 << 20 // decompressed bytes read from one package
	ddeContext = 100      // bytes of a DDE field shown after its keyword
)

// External relationship types that load content from another place. A
// hyperlink is only an indicator.
var externalTypes = map[string]bool{
	"attachedTemplate": true, "oleObject": true, "frame": true,
	"subDocument": true, "externalLinkPath": true,
}

var (
	targetRE  = regexp.MustCompile(`\sTarget\s*=`)
	ddeSimple = regexp.MustCompile(`(?i)\binstr\s*=\s*["']\s*DDE(?:AUTO)?\b`)
	ddeField  = regexp.MustCompile(`(?i)^\s*DDE(?:AUTO)?\b`)
	instrRE   = regexp.MustCompile(`<w:instrText[^>]*>([^<]*)</w:instrText>`)
	ddeCellRE = regexp.MustCompile(`(?i)\bDDE(?:AUTO)?\b`)
)

func (s *scan) ooxml(f analyze.File) error {
	zr, err := zip.NewReader(bytes.NewReader(f.Data), int64(len(f.Data)))
	if err != nil && !errors.Is(err, zip.ErrInsecurePath) {
		return err
	}
	budget := int64(maxBudget)
	for i, zf := range zr.File {
		if err := s.ctx.Err(); err != nil {
			return err
		}
		if i >= maxEntries {
			s.skip(f.Path, protocol.SkipBudget)
			break
		}
		name := strings.ToLower(zf.Name)
		limit := entryLimit(name)
		if limit == 0 {
			continue
		}
		mf := analyze.File{Path: protocol.CleanPath(f.Path + "!/" + zf.Name)}
		data, stop := s.read(zf, mf.Path, limit, &budget)
		if stop {
			break
		}
		if data == nil {
			continue
		}
		mf.Data = data
		switch {
		case path.Base(name) == "vbaproject.bin":
			if err := s.project(mf.Path, data, true); err != nil {
				return err
			}
		case name == "word/document.xml":
			s.ddeWord(mf)
		case name == "xl/sharedstrings.xml":
			s.dde(mf, ddeCellRE)
		default:
			s.rels(mf)
		}
	}
	return nil
}

// entryLimit is how many bytes to read of a package part, or 0 for parts that are not inspected.
func entryLimit(name string) int64 {
	switch {
	case strings.HasSuffix(name, ".rels"):
		return maxRels
	case name == "word/document.xml", name == "xl/sharedstrings.xml":
		return maxXML
	case path.Base(name) == "vbaproject.bin":
		return maxStream
	}
	return 0
}

// read returns the content of a part, or nil when it is skipped. stop says the
// package budget is spent.
func (s *scan) read(zf *zip.File, member string, limit int64, budget *int64) (data []byte, stop bool) {
	if zf.Flags&1 != 0 {
		s.skip(member, protocol.SkipEncrypted)
		return nil, false
	}
	if zf.UncompressedSize64 > uint64(limit) {
		s.skip(member, protocol.SkipTooLarge)
		return nil, false
	}
	rc, err := zf.Open()
	if err != nil {
		s.skip(member, protocol.SkipParseError)
		return nil, false
	}
	defer func() { _ = rc.Close() }() // in-memory reader
	data, err = io.ReadAll(io.LimitReader(rc, limit+1))
	switch {
	case err != nil:
		s.skip(member, protocol.SkipParseError)
		return nil, false
	case int64(len(data)) > limit:
		s.skip(member, protocol.SkipTooLarge)
		return nil, false
	}
	*budget -= int64(len(data))
	if *budget < 0 {
		s.skip(member, protocol.SkipBudget)
		return nil, true
	}
	return data, false
}

// rels reports external relationships of one .rels part, with the line of the Target attribute.
func (s *scan) rels(mf analyze.File) {
	dec := xml.NewDecoder(bytes.NewReader(mf.Data))
	for {
		start := int(dec.InputOffset())
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return
		}
		if err != nil {
			s.skip(mf.Path, protocol.SkipParseError)
			return
		}
		el, ok := tok.(xml.StartElement)
		if !ok || el.Name.Local != "Relationship" {
			continue
		}
		var typ, target, mode string
		for _, a := range el.Attr {
			switch a.Name.Local {
			case "Type":
				typ = a.Value
			case "Target":
				target = a.Value
			case "TargetMode":
				mode = a.Value
			}
		}
		target = strings.TrimSpace(target)
		kind := typ[strings.LastIndexByte(typ, '/')+1:]
		if !strings.EqualFold(mode, "External") || (!externalTypes[kind] && kind != "hyperlink") {
			continue
		}
		at := start
		if loc := targetRE.FindIndex(mf.Data[start:int(dec.InputOffset())]); loc != nil {
			at += loc[0] + 1
		}
		ev := analyze.EvidenceAt(mf, at)
		ev.Snippet = protocol.Snippet(kind + " -> " + target)
		if externalTypes[kind] {
			s.out.Findings = append(s.out.Findings, ruleTemplate.Finding(ev))
		}
		s.ioc(target, ev)
	}
}

// dde reports the first DDE or DDEAUTO field in an XML part.
func (s *scan) dde(mf analyze.File, re *regexp.Regexp) {
	loc := re.FindIndex(mf.Data)
	if loc == nil {
		return
	}
	ev := analyze.EvidenceAt(mf, loc[0])
	ev.Snippet = protocol.Snippet(string(mf.Data[loc[0]:min(loc[1]+ddeContext, len(mf.Data))]))
	s.out.Findings = append(s.out.Findings, ruleDDE.Finding(ev))
}

// ddeWord reports the first DDE or DDEAUTO field in document.xml. A field
// instruction split over consecutive runs is joined before it is matched.
func (s *scan) ddeWord(mf analyze.File) {
	if loc := ddeSimple.FindIndex(mf.Data); loc != nil {
		s.addDDE(mf, loc[0], string(mf.Data[loc[0]:min(loc[1]+ddeContext, len(mf.Data))]))
		return
	}
	first, prevEnd := -1, 0
	var joined strings.Builder
	flush := func() bool {
		if first >= 0 && ddeField.MatchString(joined.String()) {
			s.addDDE(mf, first, strings.TrimSpace(joined.String()))
			return true
		}
		return false
	}
	for _, m := range instrRE.FindAllSubmatchIndex(mf.Data, -1) {
		gap := mf.Data[prevEnd:m[0]]
		if bytes.Contains(gap, []byte("fldChar")) || bytes.Contains(gap, []byte("<w:t>")) || bytes.Contains(gap, []byte("<w:t ")) {
			if flush() {
				return
			}
			first = -1
			joined.Reset()
		}
		if first < 0 {
			first = m[0]
		}
		joined.Write(mf.Data[m[2]:m[3]])
		prevEnd = m[1]
	}
	flush()
}

func (s *scan) addDDE(mf analyze.File, at int, text string) {
	ev := analyze.EvidenceAt(mf, at)
	ev.Snippet = protocol.Snippet(text)
	s.out.Findings = append(s.out.Findings, ruleDDE.Finding(ev))
}
