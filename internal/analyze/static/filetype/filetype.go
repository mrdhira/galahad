// Package filetype finds the EICAR test signature and executable content
// hidden behind a document or media extension.
package filetype

import (
	"bytes"
	"context"
	"path"
	"strings"

	"github.com/mrdhira/galahad/internal/analyze"
	"github.com/mrdhira/galahad/internal/analyze/ident"
	"github.com/mrdhira/galahad/internal/protocol"
)

var (
	ruleEICAR = protocol.Rule{ID: "GAL-SIG-001", Severity: protocol.SeverityCritical, Title: "EICAR test signature"}
	ruleMasq  = protocol.Rule{ID: "GAL-IDENT-001", Severity: protocol.SeverityHigh, Title: "Executable content behind a non-executable extension", Attack: "T1036.008"}
)

// The signature is assembled from parts so this source file is not itself a test file for scanners.
var eicar = []byte(`X5O!P%@AP[4\PZX54(P^)7CC)7}$` + `EICAR-STANDARD-ANTIVIRUS-TEST-FILE!` + `$H+H*`)

// executable kinds, and the extensions that make such content look harmless.
var (
	executableKinds = map[ident.Kind]bool{ident.PE: true, ident.ELF: true, ident.MachO: true, ident.LNK: true}
	decoyExts       = map[string]bool{
		".txt": true, ".pdf": true, ".doc": true, ".docx": true, ".xls": true, ".xlsx": true,
		".ppt": true, ".pptx": true, ".rtf": true, ".csv": true, ".md": true, ".log": true,
		".jpg": true, ".jpeg": true, ".png": true, ".gif": true, ".bmp": true, ".ico": true,
		".mp3": true, ".mp4": true, ".wav": true, ".zip": true, ".json": true, ".xml": true,
		".html": true, ".htm": true,
	}
)

type analyzer struct{}

// New returns the file type analyzer.
func New() analyze.Analyzer { return analyzer{} }

func (analyzer) Name() string { return "filetype" }

func (analyzer) Analyze(_ context.Context, f analyze.File) (analyze.Output, error) {
	var out analyze.Output
	if i := bytes.Index(f.Data, eicar); i >= 0 {
		out.Findings = append(out.Findings, ruleEICAR.Finding(analyze.EvidenceAt(f, i)))
	}
	ext := strings.ToLower(path.Ext(f.Name))
	if executableKinds[f.Kind] && decoyExts[ext] {
		out.Findings = append(out.Findings, ruleMasq.Finding(protocol.Evidence{
			Path:    f.Path,
			Snippet: protocol.Snippet(string(f.Kind) + " content behind a " + ext + " extension"),
		}))
	}
	return out, nil
}
