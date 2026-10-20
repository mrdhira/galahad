package static

import "github.com/mrdhira/galahad/internal/analyze/static/office"

func init() { analyzers = append(analyzers, office.New()) }
