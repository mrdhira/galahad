// Package binary reports sections, imports and packing signals for PE, ELF and
// Mach-O files. It parses with the standard library and never executes anything.
package binary

import (
	"bytes"
	"context"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"fmt"
	"io"
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
	injectSets  = [][]string{{"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"}, {"NtUnmapViewOfSection"}}
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

// Parse reads the sections and imports of a PE, ELF or Mach-O file. Malformed
// input returns an error, including when the standard library panics.
func Parse(data []byte) (ft Features, err error) {
	defer func() {
		if r := recover(); r != nil {
			ft, err = Features{}, fmt.Errorf("binary parse panic: %v", r)
		}
	}()
	r := bytes.NewReader(data)
	switch ident.Identify("", data) {
	case ident.PE:
		return parsePE(r)
	case ident.ELF:
		return parseELF(r)
	case ident.MachO:
		return parseMachO(r)
	}
	return Features{}, fmt.Errorf("not a PE, ELF or Mach-O file")
}

func sectionEntropy(r io.Reader) float64 {
	b, err := io.ReadAll(io.LimitReader(r, maxSectionBytes))
	if err != nil {
		return 0
	}
	return ident.Entropy(b)
}

func parsePE(r *bytes.Reader) (Features, error) {
	f, err := pe.NewFile(r)
	if err != nil {
		return Features{}, err
	}
	ft := Features{Format: "pe"}
	for _, s := range f.Sections[:min(len(f.Sections), maxSections)] {
		ft.Sections = append(ft.Sections, Section{
			Name:       s.Name,
			Size:       uint64(s.Size),
			Executable: s.Characteristics&(pe.IMAGE_SCN_MEM_EXECUTE|pe.IMAGE_SCN_CNT_CODE) != 0,
			Entropy:    sectionEntropy(s.Open()),
		})
	}
	syms, _ := f.ImportedSymbols() // "Func:dll"; an unreadable import table is just empty
	for _, s := range syms[:min(len(syms), maxImports)] {
		name, _, _ := strings.Cut(s, ":")
		ft.Imports = append(ft.Imports, name)
	}
	return ft, nil
}

func parseELF(r *bytes.Reader) (Features, error) {
	f, err := elf.NewFile(r)
	if err != nil {
		return Features{}, err
	}
	ft := Features{Format: "elf"}
	for _, s := range f.Sections[:min(len(f.Sections), maxSections)] {
		sec := Section{Name: s.Name, Size: s.Size, Executable: s.Flags&elf.SHF_EXECINSTR != 0}
		if s.Type != elf.SHT_NOBITS {
			sec.Entropy = sectionEntropy(s.Open())
		}
		ft.Sections = append(ft.Sections, sec)
	}
	syms, _ := f.ImportedSymbols()
	for _, s := range syms[:min(len(syms), maxImports)] {
		ft.Imports = append(ft.Imports, s.Name)
	}
	return ft, nil
}

func parseMachO(r *bytes.Reader) (Features, error) {
	f, err := macho.NewFile(r)
	if err != nil {
		fat, ferr := macho.NewFatFile(r)
		if ferr != nil || len(fat.Arches) == 0 {
			return Features{}, err
		}
		f = fat.Arches[0].File
	}
	ft := Features{Format: "macho"}
	for _, s := range f.Sections[:min(len(f.Sections), maxSections)] {
		ft.Sections = append(ft.Sections, Section{
			Name:       s.Name,
			Size:       s.Size,
			Executable: s.Seg == "__TEXT",
			Entropy:    sectionEntropy(s.Open()),
		})
	}
	syms, _ := f.ImportedSymbols()
	for _, s := range syms[:min(len(syms), maxImports)] {
		ft.Imports = append(ft.Imports, strings.TrimPrefix(s, "_"))
	}
	return ft, nil
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

func (analyzer) Analyze(_ context.Context, f analyze.File) (analyze.Output, error) {
	var out analyze.Output
	if !binaryKinds[f.Kind] {
		return out, nil
	}
	ft, err := Parse(f.Data)
	if err != nil {
		return out, err
	}
	ft.Path = f.Path
	out.Findings = Assess(ft)
	return out, nil
}
