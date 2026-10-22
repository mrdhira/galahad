#!/usr/bin/env bash
# Runs the P8 isolation probes through real Firecracker VMs (test/acceptance/p8_test.go). Each probe pushes at a
# limit of the guest (processes, memory, disk, the root drive, the network, vsock, the Result frame) and the test
# checks what the host saw. Used by .github/workflows/vm.yml.
# The probes run one after the other. The sleep probe waits for its whole time limit (2 minutes), and the disk
# fill writes 4 GiB, so the run takes several minutes; the 40 minutes cover the whole test binary.
# Failures are annotated by vmtest.sh.
#   GALAHAD_HOME=DIR scripts/vm/p8.sh
set -euo pipefail

exec "$(dirname "$0")/vmtest.sh" P8 P8 40m
