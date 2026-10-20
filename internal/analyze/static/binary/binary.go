// Package binary reports sections, imports and packing signals for PE, ELF and
// Mach-O files. It parses with the standard library and never executes anything.
package binary

import (
	"context"
	"fmt"
	"strings"

	"github.com/mrdhira/galahad/internal/analyze"
	"github.com/mrdhira/galahad/internal/analyze/ident"
	"github.com/mrdhira/galahad/internal/protocol"
)

// Parse limits.
const (
	maxSections     = 256
	maxImports      = 100000
	maxSectionBytes = 16 << 20 // section data read for entropy
	entropyLimit    = 7.2
)

var (
	ruleEntropy = protocol.Rule{ID: "GAL-BIN-001", Severity: protocol.SeverityMedium, Title: "High-entropy executable section", Attack: "T1027.002"}
	rulePacker  = protocol.Rule{ID: "GAL-BIN-002", Severity: protocol.SeverityMedium, Title: "Packer section name", Attack: "T1027.002"}
	ruleInject  = protocol.Rule{ID: "GAL-BIN-003", Severity: protocol.SeverityHigh, Title: "Process injection imports", Attack: "T1055"}
	ruleKeylog  = protocol.Rule{ID: "GAL-BIN-004", Severity: protocol.SeverityMedium, Title: "Keylogging or credential API imports", Attack: "T1056.001"}

	packerNames = map[string]bool{"upx0": true, "upx1": true, ".aspack": true, ".mpress1": true, ".mpress2": true}
	injectSets  = [][]string{{"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"}, {"NtUnmapViewOfSection"}, {"ZwUnmapViewOfSection"}}
	keylogSets  = [][]string{{"SetWindowsHookEx", "GetAsyncKeyState"}, {"CryptUnprotectData"}}
	binaryKinds = map[ident.Kind]bool{ident.PE: true, ident.ELF: true, ident.MachO: true}
)

// Section is one parsed section.
type Section struct {
	Name       string
	Size       uint64
	Executable bool
	Entropy    float64 // over at most 16 MiB of section data
}

// Features is what the rules look at.
type Features struct {
	Path     string // evidence path
	Format   string // pe, elf or macho
	Sections []Section
	Imports  []string // function names, without library
}

// Assess applies the binary rules to parsed features. Evidence has no line.
func Assess(ft Features) []protocol.Finding {
	var out []protocol.Finding
	ev := func(snippet string) protocol.Evidence {
		return protocol.Evidence{Path: ft.Path, Snippet: protocol.Snippet(snippet)}
	}
	for _, s := range ft.Sections {
		if s.Executable && s.Entropy > entropyLimit {
			out = append(out, ruleEntropy.Finding(ev(fmt.Sprintf("section %s entropy %.2f", s.Name, s.Entropy))))
		}
	}
	for _, s := range ft.Sections {
		if packerNames[strings.ToLower(s.Name)] {
			out = append(out, rulePacker.Finding(ev("packer section "+s.Name)))
		}
	}
	have := map[string]bool{}
	for _, name := range ft.Imports {
		have[name] = true
	}
	if set := matchSet(have, injectSets); set != "" {
		out = append(out, ruleInject.Finding(ev("imports "+set)))
	}
	if set := matchSet(have, keylogSets); set != "" {
		out = append(out, ruleKeylog.Finding(ev("imports "+set)))
	}
	return out
}

// matchSet returns the first set whose members are all imported, joined with
// " + ", or "" if none. An ANSI or wide suffix (A, W) on an import is accepted.
func matchSet(have map[string]bool, sets [][]string) string {
	for _, set := range sets {
		ok := true
		for _, n := range set {
			if !have[n] && !have[n+"A"] && !have[n+"W"] {
				ok = false
				break
			}
		}
		if ok {
			return strings.Join(set, " + ")
		}
	}
	return ""
}

type analyzer struct{}

// New returns the binary analyzer.
func New() analyze.Analyzer { return analyzer{} }

func (analyzer) Name() string { return "binary" }

func (analyzer) Analyze(ctx context.Context, f analyze.File) (analyze.Output, error) {
	var out analyze.Output
	if !binaryKinds[f.Kind] {
		return out, nil
	}
	ft, err := Parse(ctx, f.Data)
	if err != nil {
		return out, err
	}
	ft.Path = f.Path
	out.Findings = Assess(ft)
	return out, nil
}
