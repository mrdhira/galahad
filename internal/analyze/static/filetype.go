package static

import "github.com/mrdhira/galahad/internal/analyze/static/filetype"

func init() { analyzers = append(analyzers, filetype.New()) }
