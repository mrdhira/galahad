#!/usr/bin/env bash
# Runs the P8 isolation probes through real Firecracker VMs (test/acceptance/p8_test.go). Each probe pushes at a
# limit of the guest (processes, memory, disk, the root drive, the network, vsock, the Result frame) and the test
# checks what the host saw. Used by .github/workflows/vm.yml.
# Every failing probe prints one ::error:: line with its first messages, which GitHub shows as an annotation
# (at most 10 per step). The whole output follows in the step log, sanitized and capped.
#   GALAHAD_HOME=DIR scripts/vm/p8.sh
set -euo pipefail

: "${GALAHAD_HOME:?GALAHAD_HOME is not set}"
out=$(mktemp)
trap 'rm -f "$out"' EXIT

# One printable, one-line annotation. The probe output is bytes from a VM, so it never goes into a
# workflow command as it is.
annotate() {
	printf '::error::%s\n' "$(printf '%s' "$1" | tr -cd '[:print:]' | cut -c1-300)"
}

# failures prints one line for each failing subtest of the go test -v output in file $1: its name, then the
# first lines of its messages. With -v a subtest's messages come after its "=== RUN" (or "=== NAME") line and
# before the "--- FAIL" lines, which the tests print last, so the messages are collected by the current name.
failures() {
	awk '
		/^=== (RUN|NAME) / { cur = $3; sub(/^TestP8[A-Za-z]*\//, "", cur); inmsg = 0; next }
		/^ *--- FAIL: TestP8[A-Za-z]*\// {
			n = $3; sub(/^TestP8[A-Za-z]*\//, "", n)
			if (!(n in seen)) { seen[n] = 1; order[++count] = n }
			cur = ""; next
		}
		/^ *--- / || /^=== / || /^(FAIL|ok|PASS)/ { cur = ""; next }
		cur != "" && /_test\.go:[0-9]+:/ { inmsg = 1; sub(/^ */, ""); add(cur, $0); next }
		cur != "" && inmsg && NF { sub(/^ */, ""); add(cur, $0) }
		function add(name, line) {
			if (lines[name]++ < 4) msg[name] = msg[name] " | " line
		}
		END { for (i = 1; i <= count; i++) print order[i] msg[order[i]] }
	' "$1"
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

failed=0
while IFS= read -r line; do
	annotate "P8 probe failed: $line"
	failed=$((failed + 1))
	[ "$failed" -lt 9 ] || break
done < <(failures "$out")
if [ "$failed" = 0 ]; then
	# The binary failed without a failing subtest: a build error, a panic or the timeout.
	tail -n 5 "$out" | while IFS= read -r line; do annotate "go test: $line"; done
fi
annotate "the P8 probes failed (go test exited $code)"
echo "::group::go test output (sanitized, last 400 lines)"
# The '| ' prefix keeps a guest line that starts with :: from being read as a workflow command.
tr -cd '[:print:]\n' <"$out" | cut -c1-400 | tail -n 400 | sed 's/^/| /'
echo "::endgroup::"
exit 1
