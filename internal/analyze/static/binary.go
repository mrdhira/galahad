package static

import "github.com/mrdhira/galahad/internal/analyze/static/binary"

func init() { analyzers = append(analyzers, binary.New()) }
