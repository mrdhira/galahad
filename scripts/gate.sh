#!/usr/bin/env bash
# Quality gate. Set SKIP_VULN=1 only where vuln.go.dev is unreachable.
set -euo pipefail
cd "$(dirname "$0")/.."

# "make tools" installs into GOBIN, or the first GOPATH entry's bin.
gobin="$(go env GOBIN)"
if [ -z "$gobin" ]; then
  gopath="$(go env GOPATH)"
  if [ "$(go env GOOS)" = windows ]; then gopath="${gopath%%;*}"; else gopath="${gopath%%:*}"; fi
  gobin="$gopath/bin"
fi

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
go vet -tags galahadtest ./...
# The vm tag is for tests that need a real VM. No file has it yet, which is not an error.
go vet -tags vm ./test/acceptance/

step lint
golangci_lint="$(tool golangci-lint)"
"$golangci_lint" run ./...
"$golangci_lint" run --build-tags galahadtest ./...

step build
for goos in linux darwin windows; do
  for goarch in amd64 arm64; do
    echo "build $goos/$goarch"
    CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" go build ./...
  done
done

step "host imports"
# The host binary must never link the code that parses untrusted bytes or runs in the guest.
main_module="$(go list -m)"
host_deps="$(go list -deps ./cmd/galahad)"
for pkg in analyze ingest vsock agent; do
  if printf '%s\n' "$host_deps" | grep -E -q "^$main_module/internal/$pkg(/|$)"; then
    echo "cmd/galahad must not depend on internal/$pkg (host never parses untrusted bytes)" >&2
    exit 1
  fi
done
# The fake sandbox backend exists only in galahadtest builds.
if printf '%s\n' "$host_deps" | grep -F -q "$main_module/internal/sandbox/fake"; then
  echo "a build without tags must not contain internal/sandbox/fake" >&2
  exit 1
fi
# The proxy test hooks (GALAHAD_TEST_RESOLVE, GALAHAD_TEST_SINKHOLE) exist only in galahadtest builds.
# Check the files the package compiles: a missing file in the tagged list would make this vacuous.
if ! go list -tags galahadtest -f '{{join .GoFiles " "}}' ./internal/proxy | grep -F -q testhooks_fake.go; then
  echo "internal/proxy/testhooks_fake.go is not part of a galahadtest build" >&2
  exit 1
fi
if go list -f '{{join .GoFiles " "}}' ./internal/proxy | grep -F -q testhooks_fake.go; then
  echo "a build without tags must not contain the proxy test hooks" >&2
  exit 1
fi
# The P8 probe flag exists only in galahadtest builds.
probe_dir="$(mktemp -d)"
exe=""
if [ "$(go env GOOS)" = windows ]; then exe=.exe; fi
go build -o "$probe_dir/galahad$exe" ./cmd/galahad
probe_code=0
probe_out="$("$probe_dir/galahad$exe" scan --p8-probe 2>&1)" || probe_code=$?
rm -rf "$probe_dir"
if [ "$probe_code" != 2 ] || ! printf '%s\n' "$probe_out" | grep -q "flag provided but not defined"; then
  echo "a build without tags must reject 'galahad scan --p8-probe' as an unknown flag (exit $probe_code)" >&2
  exit 1
fi

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
# The acceptance tests build their own binaries with the tag, so they run once above.
go test -race -count=1 -tags galahadtest ./cmd/... ./internal/...

step deps
go mod verify
mods="$(go list -m -f '{{.Path}}' all)"
bad="$(printf '%s\n' "$mods" | grep -v -x -F -e "$main_module" | grep -v '^golang\.org/x/' || true)"
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
