// Package static is the registry of static analyzers. Each analyzer adds
// itself from an init function in its own file in this package.
package static

import (
	"slices"
	"strings"

	"github.com/mrdhira/galahad/internal/analyze"
)

var analyzers []analyze.Analyzer

// All returns a copy of the registered analyzers sorted by name.
func All() []analyze.Analyzer {
	all := slices.Clone(analyzers)
	slices.SortFunc(all, func(a, b analyze.Analyzer) int { return strings.Compare(a.Name(), b.Name()) })
	return all
}
