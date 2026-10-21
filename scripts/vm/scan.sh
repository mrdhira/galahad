#!/usr/bin/env bash
# Runs "galahad scan" on a fixture in a real VM and checks the exit code, that no firecracker process
# is left, and that the job directory holds no transient files. Used by .github/workflows/vm.yml.
# Failures print ::error:: lines, which GitHub shows as annotations (at most 10 per step).
#   GALAHAD_HOME=DIR scripts/vm/scan.sh FIXTURE WANT_EXIT_CODE
set -euo pipefail

: "${GALAHAD_HOME:?GALAHAD_HOME is not set}"
fixture=${1:?usage: scan.sh FIXTURE WANT_EXIT_CODE}
want=${2:?usage: scan.sh FIXTURE WANT_EXIT_CODE}
galahad=${GALAHAD:-bin/galahad}
jobs=$GALAHAD_HOME/jobs
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT

# One printable, one-line annotation. The guest console is raw bytes from the VM, so it never goes
# into a workflow command as it is.
annotate() {
	printf '::error::%s%s\n' "$1" "$(printf '%s' "$2" | tr -cd '[:print:]' | cut -c1-200)"
}

# fail MESSAGE: the message, then what the job says, then the ends of stderr and the console.
fail() {
	annotate "" "$*"
	job=$(find "$jobs" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | head -n 1 || true)
	if [ -n "$job" ] && [ -f "$job/job.json" ]; then
		annotate "job: " "$(jq -r '"state \(.state), error \(.error // "none")"' "$job/job.json" 2>&1)"
	fi
	if [ -s "$out/stderr" ]; then
		tail -n 3 "$out/stderr" | while IFS= read -r line; do annotate "stderr: " "$line"; done
	fi
	if [ -n "$job" ] && [ -s "$job/console.log" ]; then
		tail -n 4 "$job/console.log" | while IFS= read -r line; do annotate "console: " "$line"; done
	fi
	pkill -KILL -x firecracker || true
	exit 1
}

rm -rf "$jobs"
code=0
"$galahad" scan "$fixture" >"$out/stdout" 2>"$out/stderr" || code=$?
echo "scan $fixture: exit $code"

[ "$code" = "$want" ] || fail "scan $fixture exited $code, want $want"

if pgrep -x firecracker >/dev/null; then
	fail "a firecracker process is left after scan $fixture"
fi

[ "$(find "$jobs" -mindepth 1 -maxdepth 1 -type d | wc -l)" = 1 ] || fail "scan $fixture left other than one job directory"
job=$(find "$jobs" -mindepth 1 -maxdepth 1 -type d)
left=$(find "$job" \( -name 'fc.sock*' -o -name 'v.sock*' -o -name scratch.img -o -name agent.img \) | head -n 3 | tr '\n' ' ')
[ -z "$left" ] || fail "transient files are left in the job directory: $left"

[ "$(jq -r '.state' "$job/job.json")" = "done" ] || fail "job.json does not say state done"
[ -s "$job/report.json" ] || fail "the job has no report.json"
echo "scan $fixture: verdict $(jq -r '.verdict' "$job/job.json"), no firecracker process, no transient files"
