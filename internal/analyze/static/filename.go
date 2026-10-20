package static

import "github.com/mrdhira/galahad/internal/analyze/static/filename"

func init() { analyzers = append(analyzers, filename.New()) }
