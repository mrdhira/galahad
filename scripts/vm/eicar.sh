#!/usr/bin/env bash
# Scans an EICAR test file in a real VM. The file is built here, from two parts, so the test string is
# never written out in the repository. The scan must exit 20 with GAL-SIG-001 (the Go engine) and
# GAL-AV-001 (ClamAV), and the report must list clamav and yara as covered. Used by .github/workflows/vm.yml.
#   GALAHAD_HOME=DIR scripts/vm/eicar.sh
set -euo pipefail

dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT
# shellcheck disable=SC2016 # the dollar signs belong to the test string
printf '%s%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-' 'TEST-FILE!$H+H*' >"$dir/eicar.txt"

WANT_ANALYZERS="clamav yara" WANT_RULES="GAL-SIG-001 GAL-AV-001" "$(dirname "$0")/scan.sh" "$dir" 20
