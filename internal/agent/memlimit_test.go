package agent_test

import (
	"testing"

	"github.com/mrdhira/galahad/internal/agent"
)

func TestMemoryLimit(t *testing.T) {
	const gib = 1 << 30
	tests := []struct {
		name string
		// inputs
		ram        uint64
		gomemlimit bool
		guest      bool
		flag       int64
		// expectations
		wantLimit int64
		wantSet   bool
	}{
		{name: "75% of the memory", ram: 4 * gib, wantLimit: 3 * gib, wantSet: true},
		{name: "50% of the memory in guest mode", ram: 4 * gib, guest: true, wantLimit: 2 * gib, wantSet: true},
		{name: "the flag overrides the default", ram: 4 * gib, flag: 100 << 20, wantLimit: 100 << 20, wantSet: true},
		{name: "the flag overrides GOMEMLIMIT", ram: 4 * gib, gomemlimit: true, flag: 100 << 20, wantLimit: 100 << 20, wantSet: true},
		{name: "the flag may exceed the 4 GiB ceiling", ram: 64 * gib, flag: 8 * gib, wantLimit: 8 * gib, wantSet: true},
		{name: "GOMEMLIMIT is left alone", ram: 4 * gib, gomemlimit: true, wantSet: false},
		{name: "GOMEMLIMIT is left alone when the memory is unknown", gomemlimit: true, wantSet: false},
		{name: "unknown memory falls back to 2 GiB", wantLimit: 2 * gib, wantSet: true},
		{name: "the default is capped at 4 GiB", ram: 64 * gib, wantLimit: 4 * gib, wantSet: true},
		{name: "5 GiB stays under the cap", ram: 5 * gib, wantLimit: 15 * gib / 4, wantSet: true},
		{name: "6 GiB would pass the cap", ram: 6 * gib, wantLimit: 4 * gib, wantSet: true},
		{name: "guest mode is capped at 4 GiB", ram: 10 * gib, guest: true, wantLimit: 4 * gib, wantSet: true},
		{name: "a huge memory does not overflow", ram: 1<<64 - 1, wantLimit: 4 * gib, wantSet: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			limit, set := agent.MemoryLimit(tt.ram, tt.gomemlimit, tt.guest, tt.flag)

			if limit != tt.wantLimit || set != tt.wantSet {
				t.Errorf("MemoryLimit(%d, %v, %v, %d) = %d, %v, want %d, %v", tt.ram, tt.gomemlimit, tt.guest, tt.flag, limit, set, tt.wantLimit, tt.wantSet)
			}
		})
	}
}

func TestParseSize(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		in string
		// expectations
		want    int64
		wantErr bool
	}{
		{name: "plain bytes", in: "1048576", want: 1048576},
		{name: "KiB", in: "64KiB", want: 64 << 10},
		{name: "MiB", in: "512MiB", want: 512 << 20},
		{name: "GiB", in: "2GiB", want: 2 << 30},
		{name: "suffix in any case", in: "3gib", want: 3 << 30},
		{name: "space before the suffix", in: "4 MiB", want: 4 << 20},
		{name: "not a number", in: "lots", wantErr: true},
		{name: "empty", in: "", wantErr: true},
		{name: "suffix only", in: "MiB", wantErr: true},
		{name: "unknown suffix", in: "5TiB", wantErr: true},
		{name: "zero", in: "0", wantErr: true},
		{name: "negative", in: "-1MiB", wantErr: true},
		{name: "overflow", in: "9223372036854775807GiB", wantErr: true},
		{name: "largest plain count", in: "9223372036854775807", want: 1<<63 - 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := agent.ParseSize(tt.in)

			if (err != nil) != tt.wantErr || got != tt.want {
				t.Errorf("ParseSize(%q) = %d, %v, want %d, error %v", tt.in, got, err, tt.want, tt.wantErr)
			}
		})
	}
}

func TestParseMemInfo(t *testing.T) {
	tests := []struct {
		name string
		// inputs
		in string
		// expectations
		want   uint64
		wantOK bool
	}{
		{name: "MemTotal line", in: "MemTotal:       16465852 kB\nMemFree:         1234 kB\n", want: 16465852 << 10, wantOK: true},
		{name: "MemTotal after other lines", in: "MemFree: 5 kB\nMemTotal: 2048 kB\n", want: 2048 << 10, wantOK: true},
		{name: "no MemTotal", in: "MemFree: 5 kB\n", wantOK: false},
		{name: "empty", in: "", wantOK: false},
		{name: "unit is not kB", in: "MemTotal: 5 MB\n", wantOK: false},
		{name: "no unit", in: "MemTotal: 5\n", wantOK: false},
		{name: "not a number", in: "MemTotal: lots kB\n", wantOK: false},
		{name: "zero", in: "MemTotal: 0 kB\n", wantOK: false},
		{name: "overflow", in: "MemTotal: 18446744073709551615 kB\n", wantOK: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := agent.ParseMemInfo(tt.in)

			if got != tt.want || ok != tt.wantOK {
				t.Errorf("ParseMemInfo(%q) = %d, %v, want %d, %v", tt.in, got, ok, tt.want, tt.wantOK)
			}
		})
	}
}
