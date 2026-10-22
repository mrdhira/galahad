#!/usr/bin/env bash
# Runs the vm-tagged acceptance tests that match a pattern through real Firecracker VMs (test/acceptance), and turns
# each failing case into one ::error:: annotation. Used by .github/workflows/vm.yml directly and through p8.sh.
# GitHub shows at most 10 error annotations per step, so at most 9 cases are named, and the last annotation says
# that the run failed. The whole go test output follows in the step log, sanitized and capped.
# The output of a case is bytes from a VM, so it never goes into a workflow command as it is: an annotation is one
# printable line that starts with this script's own text, and every line of the log dump starts with '| '.
#   GALAHAD_HOME=DIR scripts/vm/vmtest.sh LABEL RUN_PATTERN TIMEOUT
# LABEL names the run in the annotations, RUN_PATTERN is the go test -run pattern, and TIMEOUT (for example 40m)
# covers the whole test binary.
set -euo pipefail

: "${GALAHAD_HOME:?GALAHAD_HOME is not set}"
label=${1:?usage: vmtest.sh LABEL RUN_PATTERN TIMEOUT}
pattern=${2:?usage: vmtest.sh LABEL RUN_PATTERN TIMEOUT}
timeout=${3:?usage: vmtest.sh LABEL RUN_PATTERN TIMEOUT}
out=$(mktemp)
trap 'rm -f "$out"' EXIT

# One printable, one-line annotation.
annotate() {
	printf '::error::%s\n' "$(printf '%s' "$1" | tr -cd '[:print:]' | cut -c1-300)"
}

# failures prints one line for each failing case of the go test -v output in file $1: its name, then the first
# lines of its messages. With -v a case's messages come after its "=== RUN" (or "=== NAME") line and before the
# "--- FAIL" lines, which the tests print last, so the messages are collected by the current name. A parent of a
# failing case also fails; it is left out when a case below it is named.
failures() {
	awk '
		/^=== (RUN|NAME) / { cur = $3; sub(/^Test[A-Za-z0-9]*\//, "", cur); inmsg = 0; next }
		/^ *--- FAIL: Test[A-Za-z0-9]*\// {
			n = $3; sub(/^Test[A-Za-z0-9]*\//, "", n)
			if (!(n in seen)) { seen[n] = 1; order[++count] = n }
			cur = ""; next
		}
		/^ *--- / || /^=== / || /^(FAIL|ok|PASS)/ { cur = ""; next }
		cur != "" && /_test\.go:[0-9]+:/ { inmsg = 1; sub(/^ */, ""); add(cur, $0); next }
		cur != "" && inmsg && NF { sub(/^ */, ""); add(cur, $0) }
		function add(name, line) {
			if (lines[name]++ < 4) msg[name] = msg[name] " | " line
		}
		END {
			for (i = 1; i <= count; i++) {
				parent = 0
				for (j = 1; j <= count; j++) if (index(order[j], order[i] "/") == 1) parent = 1
				if (!parent) print order[i] msg[order[i]]
			}
		}
	' "$1"
}

code=0
go test -tags 'vm galahadtest' -count=1 -timeout "$timeout" -v -run "$pattern" ./test/acceptance >"$out" 2>&1 || code=$?
grep -E '^ *--- (PASS|FAIL|SKIP):' "$out" | cut -c1-200 || true

if [ "$code" = 0 ]; then
	echo "$label: every case passed"
	exit 0
fi

failed=0
while IFS= read -r line; do
	annotate "$label failed: $line"
	failed=$((failed + 1))
	[ "$failed" -lt 9 ] || break
done < <(failures "$out")
if [ "$failed" = 0 ]; then
	# The binary failed without a failing case: a build error, a panic or the timeout.
	tail -n 5 "$out" | while IFS= read -r line; do annotate "go test: $line"; done
fi
annotate "$label failed (go test exited $code)"
echo "::group::go test output (sanitized, last 400 lines)"
# The '| ' prefix keeps a guest line that starts with :: from being read as a workflow command.
tr -cd '[:print:]\n' <"$out" | cut -c1-400 | tail -n 400 | sed 's/^/| /'
echo "::endgroup::"
exit 1
