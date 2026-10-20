// Package office inspects OOXML documents and legacy OLE documents for remote
// templates and external objects, DDE fields and VBA macros. It reads a minimal
// subset of the OLE compound file format and of MS-OVBA, all in memory and
// within fixed limits.
package office

import (
	"context"
	"net/url"
	"regexp"

	"github.com/mrdhira/galahad/internal/analyze"
	"github.com/mrdhira/galahad/internal/analyze/ident"
	"github.com/mrdhira/galahad/internal/protocol"
)

var (
	ruleTemplate = protocol.Rule{ID: "GAL-OFFICE-001", Severity: protocol.SeverityHigh, Title: "Remote template or external object", Attack: "T1221"}
	ruleVBA      = protocol.Rule{ID: "GAL-OFFICE-002", Severity: protocol.SeverityMedium, Title: "Document contains VBA macros", Attack: "T1059.005"}
	ruleAutoExec = protocol.Rule{ID: "GAL-OFFICE-003", Severity: protocol.SeverityHigh, Title: "Macro runs automatically when the document opens", Attack: "T1059.005"}
	ruleShell    = protocol.Rule{ID: "GAL-OFFICE-004", Severity: protocol.SeverityHigh, Title: "Macro calls a shell or downloader", Attack: "T1105"}
	ruleDDE      = protocol.Rule{ID: "GAL-OFFICE-005", Severity: protocol.SeverityHigh, Title: "DDE field", Attack: "T1559.002"}
)

var (
	autoExecRE = regexp.MustCompile(`(?im)^[ \t]*(?:(?:public|private|friend)[ \t]+)?(?:sub|function)[ \t]+(?:autoopen|document_open|workbook_open|auto_open|autoexec)\b`)
	shellRE    = regexp.MustCompile(`(?i)\b(?:shell|wscript\.shell|createobject|urldownloadtofile|powershell|msxml2\.xmlhttp)\b`)
)

type analyzer struct{}

// New returns the Office analyzer.
func New() analyze.Analyzer { return analyzer{} }

func (analyzer) Name() string { return "office" }

func (analyzer) Analyze(ctx context.Context, f analyze.File) (analyze.Output, error) {
	s := &scan{ctx: ctx}
	var err error
	switch f.Kind {
	case ident.OOXML:
		err = s.ooxml(f)
	case ident.OLE:
		s.project(f.Path, f.Data, false)
	}
	return s.out, err
}

type scan struct {
	ctx context.Context
	out analyze.Output
}

func (s *scan) skip(path, reason string) {
	s.out.Skips = append(s.out.Skips, protocol.Skip{Path: path, Reason: reason})
}

// ioc records an external target as a url indicator when it is a clean absolute URL.
func (s *scan) ioc(target string, ev protocol.Evidence) {
	u, err := url.Parse(target)
	if err != nil || u.Scheme == "" || u.Host == "" || protocol.CleanPath(target) != target {
		return
	}
	s.out.IOCs = append(s.out.IOCs, protocol.IOC{Type: "url", Value: target, Path: ev.Path, Line: ev.Line})
}

// project scans the VBA project in a compound file. A vbaProject.bin member
// (always) is reported as a macro container even if its content cannot be read.
func (s *scan) project(path string, data []byte, always bool) {
	var mods []module
	found := false
	c, err := openCFB(data)
	if err == nil {
		mods, found, err = vbaModules(c)
	}
	if err != nil {
		s.skip(path, protocol.SkipParseError)
	}
	if found || always {
		s.out.Findings = append(s.out.Findings, ruleVBA.Finding(protocol.Evidence{Path: path, Snippet: "VBA project"}))
	}
	for _, m := range mods {
		mf := analyze.File{Path: protocol.CleanPath(path + "!/" + m.path), Data: m.source}
		if loc := autoExecRE.FindIndex(mf.Data); loc != nil {
			s.out.Findings = append(s.out.Findings, ruleAutoExec.Finding(analyze.EvidenceAt(mf, loc[0])))
		}
		if loc := shellRE.FindIndex(mf.Data); loc != nil {
			s.out.Findings = append(s.out.Findings, ruleShell.Finding(analyze.EvidenceAt(mf, loc[0])))
		}
	}
}
