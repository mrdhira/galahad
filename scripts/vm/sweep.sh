#!/usr/bin/env bash
# Scans one target for the release sweep (docs/milestones/M2.md section 4) in a real VM, with the signatures and
# OSV active. It appends one JSON line to $SWEEP_DIR/results.jsonl and prints one ::notice:: annotation: the
# target, the exit code, the verdict, the score, the finding IDs and the duration. A scan that fails is recorded
# as the verdict "error" and does not fail this script; sweep-check.sh decides afterwards.
# GitHub shows at most 10 notices per step, so the workflow scans at most 10 targets in a step.
# The text of a report comes from a VM, so it never goes into a workflow command as it is: an annotation is one
# printable line that starts with this script's own text.
#   GALAHAD_HOME=DIR SWEEP_DIR=DIR [GALAHAD=bin/galahad] scripts/vm/sweep.sh GROUP TARGET [scan flags]
# GROUP is clean, suspicious or binary. TARGET is a link or a path, and the flags (for example --image re) follow it.
set -euo pipefail

: "${GALAHAD_HOME:?GALAHAD_HOME is not set}"
: "${SWEEP_DIR:?SWEEP_DIR is not set}"
group=${1:?usage: sweep.sh GROUP TARGET [scan flags]}
target=${2:?usage: sweep.sh GROUP TARGET [scan flags]}
shift 2
galahad=${GALAHAD:-bin/galahad}
jobs=$GALAHAD_HOME/jobs
mkdir -p "$SWEEP_DIR"
err=$(mktemp)
trap 'rm -f "$err"' EXIT

# printable TEXT: the text as one printable line of at most 200 characters.
printable() {
	printf '%s' "$1" | tr -cd '[:print:]' | cut -c1-200
}

rm -rf "$jobs"
code=0
start=$SECONDS
"$galahad" scan "$@" "$target" >/dev/null 2>"$err" || code=$?
duration=$((SECONDS - start))
pkill -KILL -x firecracker || true

job=$(find "$jobs" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | head -n 1 || true)
verdict=error
score=null
findings='[]'
analyzers='[]'
reasons='[]'
error=
if [ -n "$job" ] && [ -s "$job/report.json" ]; then
	verdict=$(jq -r '.verdict | gsub("[^ -~]"; "")' "$job/report.json")
	score=$(jq -r '.score' "$job/report.json")
	findings=$(jq -c '[.findings[]?.rule_id | gsub("[^ -~]"; "")] | unique' "$job/report.json")
	analyzers=$(jq -c '[.coverage.analyzers[]? | gsub("[^ -~]"; "")]' "$job/report.json")
	reasons=$(jq -c '[.reasons[:3][]? | gsub("[^ -~]"; "")]' "$job/report.json")
else
	# No report: say why, from the job and from stderr.
	if [ -n "$job" ] && [ -f "$job/job.json" ]; then
		error=$(jq -r '"state \(.state), error \(.error // "none")"' "$job/job.json" 2>&1 || true)
	fi
	error=$(printable "$error $(tail -n 1 "$err")")
fi

name=${target#https://github.com/}
jq -cn --arg group "$group" --arg target "$name" --argjson code "$code" --arg verdict "$verdict" --argjson score "$score" \
	--argjson findings "$findings" --argjson analyzers "$analyzers" --argjson reasons "$reasons" \
	--argjson duration "$duration" --arg error "$error" \
	'{group: $group, target: $target, exit_code: $code, verdict: $verdict, score: $score, findings: $findings,
	  analyzers: $analyzers, reasons: $reasons, duration_seconds: $duration, error: $error}' >>"$SWEEP_DIR/results.jsonl"

ids=$(jq -r 'join(",")' <<<"$findings")
printf '::notice::%s exit=%s verdict=%s score=%s duration=%ss findings=%s%s\n' \
	"$name" "$code" "$verdict" "$score" "$duration" "$(printable "${ids:-none}")" "${error:+ error=$error}"
