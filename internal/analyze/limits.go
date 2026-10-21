package analyze

import "time"

// Limits on input. Every reader of untrusted data stays within them.
const (
	MaxFileSize   = 32 << 20 // bytes given to analyzers
	MaxTotalBytes = 1 << 30  // read plus unpacked bytes per job
	MaxFiles      = 20000    // files analyzed per job, members included
	MaxNesting    = 6        // container depth
	MaxDirDepth   = 64
	MaxLineScan   = 1 << 20 // bytes per line scanned by line heuristics
	MaxConfigSize = 1 << 20 // JSON, JSONC and YAML-ish config files
)

// Time limits.
const (
	PerFileTimeout    = 10 * time.Second
	DefaultJobTimeout = 5 * time.Minute
)

// maxFilesSeen is where counting stops: files beyond MaxFiles are counted but not analyzed.
const maxFilesSeen = MaxFiles * 10

// identifyWindow is how many leading bytes identify a file too large to keep.
const identifyWindow = 4096
