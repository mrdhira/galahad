package static

import "github.com/mrdhira/galahad/internal/analyze/static/inject"

func init() { analyzers = append(analyzers, inject.New()) }
