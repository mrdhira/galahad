package job_test

import (
	"sort"
	"testing"
	"time"

	"github.com/mrdhira/galahad/internal/job"
)

func TestNewID(t *testing.T) {
	base := time.Date(2026, 10, 21, 15, 30, 12, 0, time.UTC)
	tests := []struct {
		name    string
		now     time.Time
		count   int
		step    time.Duration // time between calls
		wantFmt string        // format of the first ID, minus the random suffix
	}{
		{name: "format uses UTC time", now: base.In(time.FixedZone("x", 7*3600)), count: 1, wantFmt: "20261021-153012-"},
		{name: "10000 calls at one instant are unique", now: base, count: 10000},
		{name: "IDs sort by time", now: base, count: 1000, step: time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ids := make([]string, 0, tt.count)
			seen := map[string]bool{}
			for i := range tt.count {
				id, err := job.NewID(tt.now.Add(time.Duration(i) * tt.step))
				if err != nil {
					t.Fatal(err)
				}
				if !job.ValidID(id) {
					t.Fatalf("ID %q does not match the format", id)
				}
				if seen[id] {
					t.Fatalf("duplicate ID %q", id)
				}
				seen[id] = true
				ids = append(ids, id)
			}
			if tt.wantFmt != "" && ids[0][:len(tt.wantFmt)] != tt.wantFmt {
				t.Errorf("ID %q does not start with %q", ids[0], tt.wantFmt)
			}
			if tt.step > 0 && !sort.StringsAreSorted(ids) {
				t.Error("IDs are not in time order")
			}
		})
	}
}

func TestValidID(t *testing.T) {
	tests := []struct {
		name string
		id   string
		want bool
	}{
		{name: "valid", id: "20261021-153012-a1b2c3", want: true},
		{name: "empty", id: "", want: false},
		{name: "parent directory", id: "..", want: false},
		{name: "path traversal", id: "../20261021-153012-a1b2c3", want: false},
		{name: "separator", id: "20261021-153012-a1b2c3/x", want: false},
		{name: "uppercase hex", id: "20261021-153012-A1B2C3", want: false},
		{name: "short suffix", id: "20261021-153012-a1b2c", want: false},
		{name: "trailing newline", id: "20261021-153012-a1b2c3\n", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := job.ValidID(tt.id); got != tt.want {
				t.Errorf("ValidID(%q) = %v, want %v", tt.id, got, tt.want)
			}
		})
	}
}
