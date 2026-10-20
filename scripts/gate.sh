#!/usr/bin/env bash
# Quality gate. Set SKIP_VULN=1 only where vuln.go.dev is unreachable.
set -euo pipefail
cd "$(dirname "$0")/.."

gobin="$(go env GOPATH)/bin"

# tool NAME: print the path of a dev tool. GOPATH/bin (where "make tools"
# installs the pinned versions) wins over PATH, so a stale system copy cannot shadow it.
tool() {
  if [ -x "$gobin/$1" ]; then
    echo "$gobin/$1"
  elif [ -x "$gobin/$1.exe" ]; then
    echo "$gobin/$1.exe"
  elif command -v "$1" >/dev/null 2>&1; then
    command -v "$1"
  else
    echo "error: $1 not found; run 'make tools'" >&2
    return 1
  fi
}

step() { echo "== $1"; }

step format
unformatted="$(gofmt -l .)"
if [ -n "$unformatted" ]; then
  echo "gofmt: these files need formatting:" >&2
  echo "$unformatted" >&2
  exit 1
fi

step vet
go vet ./...

step lint
golangci_lint="$(tool golangci-lint)"
"$golangci_lint" run ./...

step build
for goos in linux darwin windows; do
  for goarch in amd64 arm64; do
    echo "build $goos/$goarch"
    CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" go build ./...
  done
done

step vuln
if [ "${SKIP_VULN:-}" = "1" ]; then
  echo "WARNING: SKIP_VULN=1, govulncheck skipped"
else
  govulncheck="$(tool govulncheck)"
  "$govulncheck" ./...
fi

step security
gosec="$(tool gosec)"
"$gosec" -quiet ./...

step test
go test -race -count=1 -cover ./...

step deps
go mod verify
main_module="$(go list -m)"
mods="$(go list -m -f '{{.Path}}' all)"
bad="$(printf '%s\n' "$mods" | grep -v -x -e "$main_module" | grep -v '^golang\.org/x/' || true)"
if [ -n "$bad" ]; then
  echo "disallowed modules (only the main module and golang.org/x/* are allowed):" >&2
  echo "$bad" >&2
  exit 1
fi

step acceptance smoke
if [ -d test/acceptance ]; then
  go test -count=1 -run Smoke ./test/acceptance/...
else
  echo "skipped (no acceptance tests yet)"
fi

echo "== gate passed"
