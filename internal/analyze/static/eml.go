package static

import "github.com/mrdhira/galahad/internal/analyze/static/eml"

func init() { analyzers = append(analyzers, eml.New()) }
