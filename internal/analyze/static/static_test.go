package static_test

import (
	"slices"
	"testing"

	"github.com/mrdhira/galahad/internal/analyze/static"
)

func TestAll(t *testing.T) {
	tests := []struct {
		name string
		// expectations
		wantNames []string // analyzers that must be registered
	}{
		{name: "registered analyzers are sorted by name", wantNames: []string{"filetype"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			all := static.All()
			var names []string
			for _, a := range all {
				names = append(names, a.Name())
			}
			if !slices.IsSorted(names) {
				t.Errorf("names %q not sorted", names)
			}
			for _, want := range tt.wantNames {
				if !slices.Contains(names, want) {
					t.Errorf("analyzer %q not registered in %q", want, names)
				}
			}
			all[0] = nil // changing the copy must not change the registry
			if static.All()[0] == nil {
				t.Error("All returned the registry slice, not a copy")
			}
		})
	}
}
