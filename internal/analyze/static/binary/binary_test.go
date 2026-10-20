package binary_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"slices"
	"strconv"
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
		{name: "process hollowing import, Zw form", ft: binary.Features{Imports: []string{"ZwUnmapViewOfSection"}}, wantRules: []string{"GAL-BIN-003"}},
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

func elfExtendedCount() []byte {
	b, shoff := buildELF([]elfSection{{name: ".text", typ: 1, flags: 6, data: []byte{1}}}, 0, nil)
	le.PutUint16(b[60:], 0)
	le.PutUint64(b[shoff+32:], 1<<20)
	return b
}

func elfWith(secs []elfSection, shstrFlags uint64, shstr []byte) []byte {
	b, _ := buildELF(secs, shstrFlags, shstr)
	return b
}

func TestParse(t *testing.T) {
	self := selfBytes(t)
	text := elfSection{name: ".text", typ: 1, flags: 6, data: noise(8192)}
	machoText := buildMachO("__TEXT", 5, []machoSection{{name: "__text", seg: "__TEXT", data: noise(8192)}})
	tests := []struct {
		name string
		// inputs
		data []byte
		// expectations
		wantErr     bool
		wantAnyErr  bool // an error or success are both fine; it must not panic or hang
		wantRules   []string
		wantImports int // 0 skips the check
	}{
		{name: "the test binary itself", data: self},
		{name: "pe with packed sections", data: buildPE([]peSection{{name: "UPX0", chars: peData}, {name: ".text", chars: peExec, data: noise(8192)}}, -1), wantRules: []string{"GAL-BIN-001", "GAL-BIN-002"}},
		{name: "pe with an ordinary data section", data: buildPE([]peSection{{name: ".data", chars: peData, data: noise(8192)}}, -1)},
		{name: "pe importing the injection set", data: buildPEImports([]string{"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"}, 2), wantImports: 3, wantRules: []string{"GAL-BIN-003"}},
		{name: "pe with many descriptors sharing one thunk array", data: buildPEImports(manyNames(2000), 20000), wantImports: 2000},
		{name: "elf with a packed executable section", data: elfWith([]elfSection{text, {name: "UPX1", typ: 1, flags: 2, data: []byte{1}}}, 0, nil), wantRules: []string{"GAL-BIN-001", "GAL-BIN-002"}},
		{name: "mach-o text segment", data: machoText, wantRules: []string{"GAL-BIN-001"}},
		{name: "mach-o custom executable segment", data: buildMachO("EVIL", 5, []machoSection{{name: "x", seg: "EVIL", data: noise(8192)}}), wantRules: []string{"GAL-BIN-001"}},
		{name: "mach-o executable section flags", data: buildMachO("DATA", 3, []machoSection{{name: "x", seg: "DATA", data: noise(8192), flags: 0x80000400}}), wantRules: []string{"GAL-BIN-001"}},
		{name: "mach-o data segment", data: buildMachO("__DATA", 3, []machoSection{{name: "__data", seg: "__DATA", data: noise(8192)}})},
		{name: "fat mach-o reads the first architecture", data: buildFat(machoText, 19), wantRules: []string{"GAL-BIN-001"}},
		{name: "plain text", data: []byte("hello world, not a binary"), wantErr: true},
		{name: "empty", wantErr: true},
		{name: "truncated header", data: self[:20], wantErr: true},
		{name: "truncated in the middle", data: self[:len(self)/2], wantAnyErr: true},
		{name: "mz without a pe header", data: append([]byte("MZ"), make([]byte, 100)...), wantErr: true},
		{name: "garbage after elf magic", data: append([]byte("\x7fELF"), bytes.Repeat([]byte{0xff}, 200)...), wantErr: true},
		{name: "garbage after mach-o magic", data: append([]byte{0xcf, 0xfa, 0xed, 0xfe}, bytes.Repeat([]byte{0xff}, 200)...), wantErr: true},
		{name: "pe with thousands of sections", data: buildPE(make([]peSection, 6000), -1), wantErr: true},
		{name: "pe section count beyond the table", data: buildPE([]peSection{{name: ".text", chars: peExec}}, 257), wantErr: true},
		{name: "pe relocation tables larger than the file", data: buildPE([]peSection{{name: "a", nreloc: 65535}, {name: "b", nreloc: 65535}}, -1), wantErr: true},
		{name: "elf compressed section declaring 1 GiB", data: elfWith([]elfSection{{name: ".dynsym", typ: 11, flags: 0x800, data: chdr(1 << 30)}}, 0, nil), wantErr: true},
		{name: "elf compressed section string table", data: elfWith(nil, 0x800, chdr(1<<30)), wantErr: true},
		{name: "elf extended section count beyond the file", data: elfExtendedCount(), wantErr: true},
		{name: "mach-o with hundreds of sections", data: buildMachO("__TEXT", 5, make([]machoSection, 300)), wantErr: true},
		{name: "mach-o relocation tables larger than the file", data: buildMachO("__TEXT", 5, []machoSection{{nreloc: 1 << 20}, {nreloc: 1 << 20}}), wantErr: true},
		{name: "fat mach-o pointing outside the file", data: buildFat(machoText, 1)[:30], wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ft, err := binary.Parse(context.Background(), tt.data)

			if !tt.wantAnyErr && (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil || tt.wantAnyErr {
				return
			}
			var got []string
			for _, f := range binary.Assess(ft) {
				got = append(got, f.RuleID)
			}
			if tt.wantImports != 0 && len(ft.Imports) != tt.wantImports {
				t.Errorf("imports = %d, want %d", len(ft.Imports), tt.wantImports)
			}
			if !slices.Equal(got, tt.wantRules) {
				t.Errorf("rules = %v, want %v (features %+v)", got, tt.wantRules, ft)
			}
		})
	}
}

func TestParseCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := binary.Parse(ctx, buildPE([]peSection{{name: ".text", chars: peExec, data: noise(100)}}, -1))

	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
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

func manyNames(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = "Func" + strconv.Itoa(i)
	}
	return out
}
