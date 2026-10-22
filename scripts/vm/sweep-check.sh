#!/usr/bin/env bash
# Collects the lines that sweep.sh wrote into one JSON summary, and fails when the sweep of
# docs/milestones/M2.md section 4 is not met:
#   - each of the 12 repos that must stay clean (group clean) is CLEAN;
#   - none of the 10 repos that were SUSPICIOUS in v0.1.0 (group suspicious) is MALICIOUS;
#   - the built galahad binary (group binary) is CLEAN.
# A target that has no result, or whose scan ended in an error, does not meet its rule either. ClamAV, YARA and
# OSV must be among the analyzers of each repo, and ClamAV, YARA and capa among those of the binary, because the
# sweep means nothing when a tool was left out.
# Each failure prints one ::error:: line (at most 9, as GitHub shows 10 per step).
#   scripts/vm/sweep-check.sh RESULTS_JSONL SUMMARY_JSON
set -euo pipefail

results=${1:?usage: sweep-check.sh RESULTS_JSONL SUMMARY_JSON}
summary=${2:?usage: sweep-check.sh RESULTS_JSONL SUMMARY_JSON}
want_clean=12
want_suspicious=10
want_binary=1

if [ ! -s "$results" ]; then
	echo "::error::the sweep has no results"
	echo '{"commit":"","results":[],"failures":["the sweep has no results"]}' >"$summary"
	exit 1
fi

# One failure text for each target that breaks its rule. The names are ours or from the GitHub list in the workflow,
# and the verdicts are enums that sweep.sh made printable.
failures=$(jq -rs --argjson wc "$want_clean" --argjson ws "$want_suspicious" --argjson wb "$want_binary" '
	def missing($have; $need): [$need[] | select(. as $n | $have | index($n) | not)];
	def count($g): [.[] | select(.group == $g)] | length;
	[ .[]
	  | if .group == "clean" and .verdict != "clean" then "\(.target): want CLEAN, got \(.verdict) (exit \(.exit_code)) \(.error)"
	    elif .group == "suspicious" and .verdict == "malicious" then "\(.target): MALICIOUS, want at most SUSPICIOUS (score \(.score), \(.findings | join(",")))"
	    elif .group == "suspicious" and .verdict == "error" then "\(.target): the scan ended in an error (exit \(.exit_code)) \(.error)"
	    elif .group == "binary" and .verdict != "clean" then "\(.target): want CLEAN, got \(.verdict) (exit \(.exit_code)) \(.error)"
	    else empty end ] +
	[ .[]
	  | select(.verdict != "error")
	  | . as $r
	  | (if .group == "binary" then ["clamav", "yara", "capa"] else ["clamav", "yara", "osv"] end) as $need
	  | missing($r.analyzers; $need)
	  | select(length > 0)
	  | "\($r.target): not active: \(join(", "))" ] +
	[ (if count("clean") != $wc then "the sweep has \(count("clean")) results for the clean repos, want \($wc)" else empty end),
	  (if count("suspicious") != $ws then "the sweep has \(count("suspicious")) results for the suspicious repos, want \($ws)" else empty end),
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
