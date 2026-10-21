package analyze

import "github.com/mrdhira/galahad/internal/protocol"

// AddFindings adds findings that did not come from the walk, such as those of the guest
// tools, to res. It applies the caps of the walk: at most protocol.MaxFindingsPerRulePerFile
// of a rule per file, and at most protocol.MaxFindings in all, where a more severe finding
// replaces a less severe repeated one. Findings without evidence are dropped. The findings
// are marked with analyzer, and the list stays sorted.
func AddFindings(res *protocol.Result, analyzer string, fs []protocol.Finding) {
	perRule := map[string]int{}
	for _, f := range res.Findings {
		perRule[f.RuleID+"\x00"+f.Evidence[0].Path]++
	}
	for _, fd := range fs {
		if len(fd.Evidence) == 0 {
			continue
		}
		key := fd.RuleID + "\x00" + fd.Evidence[0].Path
		if perRule[key] >= protocol.MaxFindingsPerRulePerFile {
			continue
		}
		fd.Analyzer = analyzer
		fd.Evidence = fd.Evidence[:min(len(fd.Evidence), protocol.MaxEvidence)]
		if len(res.Findings) >= protocol.MaxFindings {
			res.Coverage.Truncated = true
			if !evictFor(res.Findings, fd) {
				continue
			}
		} else {
			res.Findings = append(res.Findings, fd)
		}
		perRule[key]++
	}
	sortFindings(res.Findings)
}
