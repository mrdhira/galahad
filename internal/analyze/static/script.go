package static

import "github.com/mrdhira/galahad/internal/analyze/static/script"

func init() { analyzers = append(analyzers, script.New()) }
