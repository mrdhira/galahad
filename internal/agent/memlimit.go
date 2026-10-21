package agent

import (
	"errors"
	"strconv"
	"strings"
)

// Soft memory limits of the agent, in bytes.
const (
	maxMemoryLimit      = 4 << 30 // ceiling of the default limit
	fallbackMemoryLimit = 2 << 30 // default when the physical memory is unknown
)

// MemoryLimit returns the soft memory limit the agent sets and whether it sets
// one. ram is the physical memory in bytes, 0 when it could not be read.
// gomemlimit says the GOMEMLIMIT environment variable is set, which the agent
// leaves alone. flag is the value of --memory-limit, 0 when absent, and it
// overrides both. Otherwise the limit is 50% of ram, which leaves room for clamscan, at most
// 4 GiB, or 2 GiB when ram is unknown.
func MemoryLimit(ram uint64, gomemlimit bool, flag int64) (limit int64, set bool) {
	switch {
	case flag > 0:
		return flag, true
	case gomemlimit:
		return 0, false
	case ram == 0:
		return fallbackMemoryLimit, true
	}
	return int64(min(ram/2, maxMemoryLimit)), true
}

// ParseSize parses a byte count with an optional KiB, MiB or GiB suffix, such as
// "512MiB". The count must be positive and fit in an int64.
func ParseSize(s string) (int64, error) {
	num, mult := s, int64(1)
	for _, u := range []struct {
		suffix string
		mult   int64
	}{{"KiB", 1 << 10}, {"MiB", 1 << 20}, {"GiB", 1 << 30}} {
		if cut, ok := strings.CutSuffix(strings.ToLower(s), strings.ToLower(u.suffix)); ok {
			num, mult = cut, u.mult
			break
		}
	}
	n, err := strconv.ParseInt(strings.TrimSpace(num), 10, 64)
	switch {
	case err != nil:
		return 0, errors.New("want a number of bytes with an optional KiB, MiB or GiB suffix")
	case n <= 0:
		return 0, errors.New("must be positive")
	case n > (1<<63-1)/mult:
		return 0, errors.New("too large")
	}
	return n * mult, nil
}

// ParseMemInfo returns the MemTotal line of /proc/meminfo in bytes.
func ParseMemInfo(meminfo string) (uint64, bool) {
	for line := range strings.SplitSeq(meminfo, "\n") {
		rest, ok := strings.CutPrefix(line, "MemTotal:")
		if !ok {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) != 2 || fields[1] != "kB" {
			return 0, false
		}
		kb, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil || kb > (1<<64-1)>>10 {
			return 0, false
		}
		return kb << 10, kb > 0
	}
	return 0, false
}
