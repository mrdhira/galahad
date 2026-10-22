#!/usr/bin/env bash
# Runs the P8 isolation probes through real Firecracker VMs (test/acceptance/p8_test.go). Each probe pushes at a
# limit of the guest (processes, memory, disk, the root drive, the network, vsock, the Result frame) and the test
# checks what the host saw. Used by .github/workflows/vm.yml.
# Every failing probe prints an ::error:: line, which GitHub shows as an annotation (at most 10 per step).
#   GALAHAD_HOME=DIR scripts/vm/p8.sh
set -euo pipefail

: "${GALAHAD_HOME:?GALAHAD_HOME is not set}"
out=$(mktemp)
trap 'rm -f "$out"' EXIT

# One printable, one-line annotation. The probe output is bytes from a VM, so it never goes into a
# workflow command as it is.
annotate() {
	printf '::error::%s\n' "$(printf '%s' "$1" | tr -cd '[:print:]' | cut -c1-200)"
}

# The probes run one after the other. The sleep probe waits for its whole time limit (2 minutes), and the disk
# fill writes 4 GiB, so the run takes several minutes; -timeout covers the whole test binary.
code=0
go test -tags 'vm galahadtest' -count=1 -timeout 40m -v -run P8 ./test/acceptance >"$out" 2>&1 || code=$?
grep -E '^ *--- (PASS|FAIL|SKIP):' "$out" || true

if [ "$code" = 0 ]; then
	echo "P8: every probe passed"
	exit 0
fi

# A failing probe is a "--- FAIL" line of the subtest, then its messages, which start with the file and line.
failed=0
while IFS= read -r line; do
	annotate "P8 probe failed: $line"
	failed=$((failed + 1))
	[ "$failed" -lt 9 ] || break
done < <(awk '
	/^ *--- FAIL: TestP8[A-Za-z]*\// { name = $3; sub(/^TestP8[A-Za-z]*\//, "", name); next }
	/^ *--- / { name = "" }
	name != "" && /_test\.go:[0-9]+:/ { sub(/^ */, ""); print name ": " $0 }
' "$out")
if [ "$failed" = 0 ]; then
	# The binary failed without a failing subtest: a build error, a panic or the timeout.
	tail -n 5 "$out" | while IFS= read -r line; do annotate "go test: $line"; done
fi
annotate "the P8 probes failed (go test exited $code)"
exit 1
