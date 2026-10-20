package static

import "github.com/mrdhira/galahad/internal/analyze/static/ioc"

func init() { analyzers = append(analyzers, ioc.New()) }
