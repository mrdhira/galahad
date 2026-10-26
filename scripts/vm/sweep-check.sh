#!/usr/bin/env bash
# Collects the lines that sweep.sh wrote into one JSON summary, and fails when the sweep of
# docs/milestones/M2.md section 4 is not met:
#   - each of the 12 repos that must stay clean (group clean) is CLEAN;
#   - none of the 10 repos that were SUSPICIOUS in v0.1.0 (group suspicious) is MALICIOUS;
#   - none of the 12 clean repos gets GAL-INJECT-001, and neither of the 2 repos with no baseline (group new,
#     promptfoo/promptfoo and NVIDIA/garak, docs/milestones/M3.md section 4) is MALICIOUS or SUSPICIOUS because of
#     GAL-INJECT-001: the score reaches 70 or 15 with the rule and not without it. sweep.sh records rest_score, the
#     score of the other rules by the model of internal/scoring. Both repos ship attack samples and are MALICIOUS from
#     older rules; the owner accepted that on 2026-10-26, so only the new rule is held against them. A SUSPICIOUS
#     verdict from coverage (a score under 15) is not blamed on the rule;
#   - the built galahad binary (group binary) is CLEAN.
# A target that has no result, or whose scan ended in an error, does not meet its rule either. ClamAV, YARA and
# OSV must be among the analyzers of each repo (a repo with no baseline may have ClamAV left out by its time limit,
# as it is on the large promptfoo tree), and ClamAV and YARA among those of the binary, because the
# sweep means nothing when a tool was left out. For the binary, capa may be left out only by its time limit: it does
# not finish on large Go binaries (a known gap in docs/milestones/M2.md section 4). Any other reason fails.
# Each failure prints one ::error:: line (at most 9, as GitHub shows 10 per step).
#   scripts/vm/sweep-check.sh RESULTS_JSONL SUMMARY_JSON
set -euo pipefail

results=${1:?usage: sweep-check.sh RESULTS_JSONL SUMMARY_JSON}
summary=${2:?usage: sweep-check.sh RESULTS_JSONL SUMMARY_JSON}
want_clean=12
want_suspicious=10
want_new=2
want_binary=1

if [ ! -s "$results" ]; then
	echo "::error::the sweep has no results"
	echo '{"commit":"","results":[],"failures":["the sweep has no results"]}' >"$summary"
	exit 1
fi

# One failure text for each target that breaks its rule. The names are ours or from the GitHub list in the workflow,
# and the verdicts are enums that sweep.sh made printable.
failures=$(jq -rs --argjson wc "$want_clean" --argjson ws "$want_suspicious" --argjson wn "$want_new" --argjson wb "$want_binary" '
	def missing($have; $need): [$need[] | select(. as $n | $have | index($n) | not)];
	def count($g): [.[] | select(.group == $g)] | length;
	[ .[]
	  | if .group == "clean" and .verdict != "clean" then "\(.target): want CLEAN, got \(.verdict) (exit \(.exit_code)) \(.error)"
	    elif .group == "suspicious" and .verdict == "malicious" then "\(.target): MALICIOUS, want at most SUSPICIOUS (score \(.score), \(.findings | join(",")))"
	    elif .group == "suspicious" and .verdict == "error" then "\(.target): the scan ended in an error (exit \(.exit_code)) \(.error)"
	    elif .group == "new" and .verdict == "malicious" and (.findings | index("GAL-INJECT-001")) and .rest_score < 70 then "\(.target): MALICIOUS only because of GAL-INJECT-001 (score \(.score), \(.rest_score) without it): a false alarm"
	    elif .group == "new" and .verdict == "error" then "\(.target): the scan ended in an error (exit \(.exit_code)) \(.error)"
	    elif .group == "new" and .verdict == "suspicious" and (.findings | index("GAL-INJECT-001")) and .score >= 15 and .rest_score < 15 then "\(.target): SUSPICIOUS only because of GAL-INJECT-001 (score \(.score), \(.rest_score) without it): a false alarm"
	    elif .group == "binary" and .verdict != "clean" then "\(.target): want CLEAN, got \(.verdict) (exit \(.exit_code)) \(.error)"
	    else empty end ] +
	[ .[]
	  | select(.group == "clean" and (.findings | index("GAL-INJECT-001")))
	  | "\(.target): GAL-INJECT-001 on a repo that must stay clean" ] +
	[ .[]
	  | select(.verdict != "error")
	  | . as $r
	  | (if .group == "binary" then ["clamav", "yara"]
	     elif .group == "new" and ((.tools // "") | test("clamav: left out: [^;]*timed out")) then ["yara", "osv"]
	     else ["clamav", "yara", "osv"] end) as $need
	  | missing($r.analyzers; $need)
	  | select(length > 0)
	  | "\($r.target): not active: \(join(", ")) \($r.tools // "")" ] +
	[ .[]
	  | select(.group == "binary" and .verdict != "error" and (.analyzers | index("capa") | not))
	  | select((.capa // "") | test("^capa: left out: [^;]*timed out") | not)
	  | "\(.target): capa left out for a reason other than the known timeout: \(if (.capa // "") == "" then "no capa line in tools.log" else .capa end)" ] +
	[ (if count("clean") != $wc then "the sweep has \(count("clean")) results for the clean repos, want \($wc)" else empty end),
	  (if count("suspicious") != $ws then "the sweep has \(count("suspicious")) results for the suspicious repos, want \($ws)" else empty end),
	  (if count("new") != $wn then "the sweep has \(count("new")) results for the repos with no baseline, want \($wn)" else empty end),
	  (if count("binary") != $wb then "the sweep has \(count("binary")) results for the galahad binary, want \($wb)" else empty end) ]
	| .[]' "$results")

jq -s --arg commit "${GITHUB_SHA:-}" --argjson failures "$(jq -Rn '[inputs | select(length > 0)]' <<<"$failures")" \
	'{commit: $commit, results: ., failures: $failures}' "$results" >"$summary"

if [ -z "$failures" ]; then
	echo "the sweep is met: $(jq -s 'length' "$results") results"
	exit 0
fi
n=0
while IFS= read -r line; do
	printf '::error::%s\n' "$(printf '%s' "$line" | tr -cd '[:print:]' | cut -c1-300)"
	n=$((n + 1))
	[ "$n" -lt 9 ] || break
done <<<"$failures"
echo "::error::the sweep is not met: $(printf '%s\n' "$failures" | wc -l) problems"
exit 1
