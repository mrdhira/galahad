#!/usr/bin/env bash
# Installs the pinned Firecracker into $GALAHAD_HOME/bin, after its sha256 matches pins.json.
# Used by .github/workflows/vm.yml. Failures print ::error:: lines, which GitHub shows as annotations.
#   GALAHAD_HOME=DIR scripts/vm/firecracker.sh
set -euo pipefail

: "${GALAHAD_HOME:?GALAHAD_HOME is not set}"
pins=${PINS:-internal/images/pins.json}
fail() {
	echo "::error::$*"
	exit 1
}

version=$(jq -r '.firecracker.version' "$pins")
url=$(jq -r '.firecracker.url' "$pins")
want=$(jq -r '.firecracker.sha256' "$pins")
arch=$(uname -m)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# The archive is about 3 MiB; the cap only stops a runaway download.
curl -fsSL --retry 3 --max-filesize 67108864 -o "$work/firecracker.tgz" "$url" || fail "cannot download $url"
got=$(sha256sum "$work/firecracker.tgz" | cut -d' ' -f1)
[ "$got" = "$want" ] || fail "the Firecracker archive has sha256 $got, pins.json says $want"

member=$(tar -tzf "$work/firecracker.tgz" | grep -E "/firecracker-$version-$arch\$" | head -n 1 || true)
[ -n "$member" ] || fail "the Firecracker archive has no firecracker-$version-$arch"
tar -xzf "$work/firecracker.tgz" -C "$work" "$member"
install -D -m 0755 "$work/$member" "$GALAHAD_HOME/bin/firecracker"

reported=$("$GALAHAD_HOME/bin/firecracker" --version | head -n 1)
case "$reported" in
*"${version#v}"*) echo "installed $reported" ;;
*) fail "the installed Firecracker says '$reported', pins.json says $version" ;;
esac
