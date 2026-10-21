#!/usr/bin/env bash
# Runs "galahad doctor" and checks that it exits 0 and that the signatures line is PASS: the stamp is fresh and
# the image is there. Used by .github/workflows/vm.yml.
# Failures print ::error:: lines, which GitHub shows as annotations (at most 10 per step).
#   GALAHAD_HOME=DIR scripts/vm/doctor.sh
set -euo pipefail

galahad=${GALAHAD:-bin/galahad}
code=0
report=$("$galahad" doctor) || code=$?
printf '%s\n' "$report"

annotate() {
	printf '::error::%s\n' "$(printf '%s' "$1" | tr -cd '[:print:]' | cut -c1-200)"
}

if ! grep -q '^PASS  signatures:' <<<"$report"; then
	annotate "doctor does not show signatures PASS: $(grep '^[A-Z]*  signatures:' <<<"$report" || echo 'no signatures line')"
	exit 1
fi
if [ "$code" != 0 ]; then
	grep '^FAIL' <<<"$report" | while IFS= read -r line; do annotate "$line"; done
	annotate "doctor exited $code"
	exit 1
fi
