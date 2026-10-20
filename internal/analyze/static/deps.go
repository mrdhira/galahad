package static

import "github.com/mrdhira/galahad/internal/analyze/static/deps"

func init() { analyzers = append(analyzers, deps.New()) }
