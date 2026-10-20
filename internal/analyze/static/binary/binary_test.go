package binary_test

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/mrdhira/galahad/internal/analyze"
	"github.com/mrdhira/galahad/internal/analyze/ident"
	"github.com/mrdhira/galahad/internal/analyze/static/binary"
)

func TestAssess(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		ft binary.Features
		// expectations
		wantRules   []string
		wantSev     string // severity of the first finding
		wantAttack  string // attack of the first finding
		wantSnippet string // substring of the first finding's snippet
	}{
		{
			name:        "high entropy executable section",
			ft:          binary.Features{Sections: []binary.Section{{Name: ".text", Executable: true, Entropy: 7.8}}},
			wantRules:   []string{"GAL-BIN-001"},
			wantSev:     "medium",
			wantAttack:  "T1027.002",
			wantSnippet: "section .text entropy 7.80",
		},
		{name: "high entropy data section", ft: binary.Features{Sections: []binary.Section{{Name: ".rdata", Entropy: 7.9}}}},
		{name: "entropy at the limit", ft: binary.Features{Sections: []binary.Section{{Name: ".text", Executable: true, Entropy: 7.2}}}},
		{
			name:        "packer section name, any case",
			ft:          binary.Features{Sections: []binary.Section{{Name: "UPX1"}}},
			wantRules:   []string{"GAL-BIN-002"},
			wantSev:     "medium",
			wantAttack:  "T1027.002",
			wantSnippet: "UPX1",
		},
		{name: "aspack section", ft: binary.Features{Sections: []binary.Section{{Name: ".aspack"}}}, wantRules: []string{"GAL-BIN-002"}},
		{name: "mpress section", ft: binary.Features{Sections: []binary.Section{{Name: ".MPRESS1"}}}, wantRules: []string{"GAL-BIN-002"}},
		{name: "ordinary sections", ft: binary.Features{Sections: []binary.Section{{Name: ".text"}, {Name: ".data"}}}},
		{
			name:        "remote thread injection set",
			ft:          binary.Features{Imports: []string{"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"}},
			wantRules:   []string{"GAL-BIN-003"},
			wantSev:     "high",
			wantAttack:  "T1055",
			wantSnippet: "VirtualAllocEx + WriteProcessMemory + CreateRemoteThread",
		},
		{name: "injection set with a wide suffix", ft: binary.Features{Imports: []string{"VirtualAllocExW", "WriteProcessMemory", "CreateRemoteThread"}}, wantRules: []string{"GAL-BIN-003"}},
		{name: "process hollowing import", ft: binary.Features{Imports: []string{"NtUnmapViewOfSection"}}, wantRules: []string{"GAL-BIN-003"}},
		{name: "partial injection set", ft: binary.Features{Imports: []string{"VirtualAllocEx", "WriteProcessMemory"}}},
		{
			name:        "keylogger hook set",
			ft:          binary.Features{Imports: []string{"SetWindowsHookExW", "GetAsyncKeyState"}},
			wantRules:   []string{"GAL-BIN-004"},
			wantSev:     "medium",
			wantAttack:  "T1056.001",
			wantSnippet: "SetWindowsHookEx + GetAsyncKeyState",
		},
		{name: "credential decrypt import", ft: binary.Features{Imports: []string{"CryptUnprotectData"}}, wantRules: []string{"GAL-BIN-004"}},
		{name: "hook import alone", ft: binary.Features{Imports: []string{"SetWindowsHookExA"}}},
		{
			name: "all rules at once, in code order",
			ft: binary.Features{
				Sections: []binary.Section{{Name: "UPX0", Executable: true, Entropy: 7.5}},
				Imports:  []string{"NtUnmapViewOfSection", "CryptUnprotectData"},
			},
			wantRules: []string{"GAL-BIN-001", "GAL-BIN-002", "GAL-BIN-003", "GAL-BIN-004"},
		},
		{name: "no features"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.ft.Path = "dir/sample.bin"

			got := binary.Assess(tt.ft)

			if len(got) != len(tt.wantRules) {
				t.Fatalf("findings = %+v, want rules %v", got, tt.wantRules)
			}
			for i, f := range got {
				if f.RuleID != tt.wantRules[i] {
					t.Errorf("finding %d rule = %s, want %s", i, f.RuleID, tt.wantRules[i])
				}
				if len(f.Evidence) != 1 || f.Evidence[0].Line != 0 || f.Evidence[0].Path != "dir/sample.bin" {
					t.Errorf("evidence = %+v, want one entry at dir/sample.bin line 0", f.Evidence)
				}
			}
			if len(got) == 0 {
				return
			}
			if tt.wantSev != "" && string(got[0].Severity) != tt.wantSev {
				t.Errorf("severity = %s, want %s", got[0].Severity, tt.wantSev)
			}
			if tt.wantAttack != "" && got[0].Attack != tt.wantAttack {
				t.Errorf("attack = %s, want %s", got[0].Attack, tt.wantAttack)
			}
			if !strings.Contains(got[0].Evidence[0].Snippet, tt.wantSnippet) {
				t.Errorf("snippet = %q, want it to contain %q", got[0].Evidence[0].Snippet, tt.wantSnippet)
			}
		})
	}
}

func selfBytes(t *testing.T) []byte {
	t.Helper()
	p, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParse(t *testing.T) {
	self := selfBytes(t)
	tests := []struct {
		name string
		// inputs
		data []byte
		// expectations
		wantErr      bool
		wantSections bool
	}{
		{name: "the test binary itself", data: self, wantSections: true},
		{name: "plain text", data: []byte("hello world, not a binary"), wantErr: true},
		{name: "empty", data: nil, wantErr: true},
		{name: "truncated header", data: self[:20], wantErr: true},
		{name: "mz without a pe header", data: append([]byte("MZ"), make([]byte, 100)...), wantErr: true},
		{name: "garbage after elf magic", data: append([]byte("\x7fELF"), []byte(strings.Repeat("\xff", 200))...), wantErr: true},
		{name: "garbage after macho magic", data: append([]byte{0xcf, 0xfa, 0xed, 0xfe}, []byte(strings.Repeat("\xff", 200))...), wantErr: true},
		{name: "truncated in the middle", data: self[:len(self)/2]}, // may parse or fail; it must not panic
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ft, err := binary.Parse(tt.data)

			if tt.name != "truncated in the middle" && (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantSections {
				if len(ft.Sections) == 0 {
					t.Errorf("features = %+v, want sections", ft)
				}
				if got := binary.Assess(ft); len(got) != 0 {
					t.Errorf("findings on a normal Go binary = %+v, want none", got)
				}
			}
		})
	}
}

func TestAnalyze(t *testing.T) {
	self := selfBytes(t)
	tests := []struct {
		name string
		// inputs
		kind ident.Kind
		data []byte
		// expectations
		wantErr bool
	}{
		{name: "executable parses without findings", kind: ident.Identify("", self), data: self},
		{name: "other kinds are ignored", kind: ident.Text, data: []byte("hello")},
		{name: "corrupt binary is an error", kind: ident.ELF, data: []byte("\x7fELF"), wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := binary.New()

			out, err := a.Analyze(context.Background(), analyze.File{Path: "x", Name: "x", Kind: tt.kind, Data: tt.data})

			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if len(out.Findings) != 0 {
				t.Errorf("findings = %+v, want none", out.Findings)
			}
		})
	}
}
