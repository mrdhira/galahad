package protocol

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
)

// truncationPath is the path of the budget skip that EncodeResult adds.
const truncationPath = "(result)"

// shrinkSteps cut a Result down, cheapest loss first. Findings and reasons are never
// cut: they decide the verdict. Each step reports whether it changed anything.
var shrinkSteps = []func(r *Result) bool{
	func(r *Result) bool { // the file list; the count fields stay
		changed := len(r.Files) > 0
		r.Files = []FileInfo{}
		return changed
	},
	func(r *Result) bool { // the skip list; markTruncated adds the budget skip that says so
		changed := len(r.Coverage.Skipped) > 0
		r.Coverage.Skipped = []Skip{}
		return changed
	},
	func(r *Result) bool { // all evidence but the first, which is the primary one
		changed := false
		fs := slices.Clone(r.Findings)
		for i := range fs {
			if len(fs[i].Evidence) > 1 {
				fs[i].Evidence = fs[i].Evidence[:1:1]
				changed = true
			}
		}
		r.Findings = fs
		return changed
	},
	func(r *Result) bool { // the IOCs
		changed := len(r.IOCs) > 0
		r.IOCs = []IOC{}
		return changed
	},
}

// EncodeResult encodes res for the Result frame. Guests must use it, and nothing
// else, to encode a Result. The output is compact JSON without HTML escaping, so
// the worst case is two bytes per raw byte (a quote, a backslash or U+2028 in
// text counted in runes: six bytes per rune).
//
// If the JSON is over the frame limit, EncodeResult cuts the Result step by step
// and encodes again after each step: the files, the skipped list, the evidence
// past the first entry of each finding, then the IOCs. Any cut sets
// Coverage.Truncated and leaves a final budget skip, so a clean verdict becomes
// suspicious. It returns an error if the Result is still too large; with the
// caps that Validate enforces it never is. res is not modified.
func EncodeResult(res *Result) ([]byte, error) {
	data, err := encodeJSON(res)
	if err != nil {
		return nil, err
	}
	limit := frameLimits[FrameResult]
	r := *res
	for _, step := range shrinkSteps {
		if len(data) <= limit {
			break
		}
		if !step(&r) {
			continue
		}
		markTruncated(&r)
		if data, err = encodeJSON(&r); err != nil {
			return nil, err
		}
	}
	if len(data) > limit {
		return nil, fmt.Errorf("result is %d bytes after shrinking, max %d", len(data), limit)
	}
	return data, nil
}

// markTruncated sets Truncated and makes the last skip a budget skip, replacing the
// last entry if the list is full. It does not write to the caller's slice.
func markTruncated(r *Result) {
	r.Coverage.Truncated = true
	sk := r.Coverage.Skipped
	if n := len(sk); n > 0 && sk[n-1].Reason == SkipBudget {
		return
	}
	if len(sk) >= MaxSkipped {
		sk = sk[:MaxSkipped-1]
	}
	r.Coverage.Skipped = append(sk[:len(sk):len(sk)], Skip{Path: truncationPath, Reason: SkipBudget})
}

func encodeJSON(r *Result) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(r); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}
