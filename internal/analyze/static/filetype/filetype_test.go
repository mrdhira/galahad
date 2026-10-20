package filetype_test

import (
	"context"
	"encoding/binary"
	"testing"

	"github.com/mrdhira/galahad/internal/analyze"
	"github.com/mrdhira/galahad/internal/analyze/ident"
	"github.com/mrdhira/galahad/internal/analyze/static/filetype"
)

// eicar is built from parts so no file in the repo contains the signature.
func eicar() string {
	return `X5O!P%@AP[4\PZX54(P^)7CC)7}$` + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!" + "$H+H*"
}

func peBytes() []byte {
	b := make([]byte, 0x80)
	copy(b, "MZ")
	binary.LittleEndian.PutUint32(b[0x3c:], 0x40)
	copy(b[0x40:], "PE\x00\x00")
	return b
}

func TestAnalyze(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		file string
		data []byte
		// expectations
		wantRule    string
		wantSev     string
		wantAttack  string
		wantLine    int
		wantSnippet string
	}{
		{name: "eicar on the first line", file: "eicar.txt", data: []byte(eicar()), wantRule: "GAL-SIG-001", wantSev: "critical", wantLine: 1, wantSnippet: eicar()},
		{name: "eicar later in a file", file: "notes.txt", data: []byte("hello\n" + eicar() + "\n"), wantRule: "GAL-SIG-001", wantSev: "critical", wantLine: 2, wantSnippet: eicar()},
		{name: "pe behind a pdf extension", file: "invoice.PDF", data: peBytes(), wantRule: "GAL-IDENT-001", wantSev: "high", wantAttack: "T1036.008", wantSnippet: "pe content behind a .pdf extension"},
		{name: "elf behind a txt extension", file: "readme.txt", data: []byte("\x7fELF\x02\x01"), wantRule: "GAL-IDENT-001", wantSev: "high", wantAttack: "T1036.008", wantSnippet: "elf content behind a .txt extension"},
		{name: "plain text", file: "a.txt", data: []byte("hello\n")},
		{name: "pe with an executable extension", file: "setup.exe", data: peBytes()},
		{name: "elf without an extension", file: "tool", data: []byte("\x7fELF\x02\x01")},
		{name: "pdf with a pdf extension", file: "a.pdf", data: []byte("%PDF-1.7\n")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := filetype.New()
			f := analyze.File{Path: "dir/" + tt.file, Name: tt.file, Kind: ident.Identify(tt.file, tt.data), Data: tt.data}

			out, err := a.Analyze(context.Background(), f)

			if err != nil {
				t.Fatal(err)
			}
			if tt.wantRule == "" {
				if len(out.Findings) != 0 {
					t.Errorf("findings = %+v, want none", out.Findings)
				}
				return
			}
			if len(out.Findings) != 1 {
				t.Fatalf("%d findings, want 1: %+v", len(out.Findings), out.Findings)
			}
			got := out.Findings[0]
			ev := got.Evidence[0]
			if got.RuleID != tt.wantRule || string(got.Severity) != tt.wantSev || got.Attack != tt.wantAttack {
				t.Errorf("finding = %s %s %q, want %s %s %q", got.RuleID, got.Severity, got.Attack, tt.wantRule, tt.wantSev, tt.wantAttack)
			}
			if ev.Path != f.Path || ev.Line != tt.wantLine || ev.Snippet != tt.wantSnippet {
				t.Errorf("evidence = %+v, want path %q line %d snippet %q", ev, f.Path, tt.wantLine, tt.wantSnippet)
			}
		})
	}
}

func TestName(t *testing.T) {
	tests := []struct {
		name     string
		wantName string
	}{
		{name: "analyzer name", wantName: "filetype"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := filetype.New().Name(); got != tt.wantName {
				t.Errorf("Name = %q, want %q", got, tt.wantName)
			}
		})
	}
}
