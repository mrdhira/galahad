package static

import "github.com/mrdhira/galahad/internal/analyze/static/archive"

func init() { analyzers = append(analyzers, archive.New()) }
