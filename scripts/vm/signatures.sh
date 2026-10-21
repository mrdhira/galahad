#!/usr/bin/env bash
# Runs "galahad setup", which fills signatures.img through the update VM, and checks that the new image and
# the stamp are there and that nothing was left behind. Used by .github/workflows/vm.yml.
# Failures print ::error:: lines, which GitHub shows as annotations (at most 10 per step).
#   GALAHAD_HOME=DIR scripts/vm/signatures.sh
set -euo pipefail

: "${GALAHAD_HOME:?GALAHAD_HOME is not set}"
galahad=${GALAHAD:-bin/galahad}
jobs=$GALAHAD_HOME/jobs
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT

# One printable, one-line annotation. The guest console and the logs are raw bytes from the VM, so they
# never go into a workflow command as they are.
annotate() {
	printf '::error::%s%s\n' "$1" "$(printf '%s' "$2" | tr -cd '[:print:]' | cut -c1-200)"
}

# fail MESSAGE: the message, then what the update job says, then the ends of stderr, tools.log and the console.
fail() {
	annotate "" "$*"
	job=$(find "$jobs" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort | tail -n 1 || true)
	if [ -n "$job" ] && [ -f "$job/job.json" ]; then
		annotate "job: " "$(jq -r '"state \(.state), error \(.error // "none")"' "$job/job.json" 2>&1)"
	fi
	if [ -s "$out/stderr" ]; then
		tail -n 3 "$out/stderr" | while IFS= read -r line; do annotate "stderr: " "$line"; done
	fi
	if [ -n "$job" ] && [ -s "$job/artifacts/tools.log" ]; then
		tail -n 4 "$job/artifacts/tools.log" | while IFS= read -r line; do annotate "tools.log: " "$line"; done
	fi
	if [ -n "$job" ] && [ -s "$job/console.log" ]; then
		tail -n 6 "$job/console.log" | while IFS= read -r line; do annotate "console: " "$line"; done
	fi
	pkill -KILL -x firecracker || true
	exit 1
}

code=0
"$galahad" setup >"$out/stdout" 2>"$out/stderr" || code=$?
cat "$out/stdout"
[ "$code" = 0 ] || fail "galahad setup exited $code"

[ -s "$GALAHAD_HOME/signatures.img" ] || fail "setup left no signatures.img"
[ -s "$GALAHAD_HOME/signatures.stamp" ] || fail "setup wrote no signatures.stamp"
[ ! -e "$GALAHAD_HOME/signatures.img.new" ] || fail "signatures.img.new is left after the update"
if pgrep -x firecracker >/dev/null; then
	fail "a firecracker process is left after the update"
fi
echo "signatures: image $(stat -c %s "$GALAHAD_HOME/signatures.img") bytes, stamp $(tr -d '\n' <"$GALAHAD_HOME/signatures.stamp")"
