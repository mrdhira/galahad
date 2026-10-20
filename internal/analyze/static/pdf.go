package static

import "github.com/mrdhira/galahad/internal/analyze/static/pdf"

func init() { analyzers = append(analyzers, pdf.New()) }
