package static

import "github.com/mrdhira/galahad/internal/analyze/static/autoexec"

func init() { analyzers = append(analyzers, autoexec.New()) }
