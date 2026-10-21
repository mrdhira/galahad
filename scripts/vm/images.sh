#!/usr/bin/env bash
# Verifies the pinned vmlinux.gz and core.ext4.gz in a directory against pins.json, unpacks them
# into $GALAHAD_HOME/images/<version>, and checks the unpacked files too. Nothing is installed
# when a hash differs. Used by .github/workflows/vm.yml.
#   GALAHAD_HOME=DIR scripts/vm/images.sh GZ_DIR
set -euo pipefail

: "${GALAHAD_HOME:?GALAHAD_HOME is not set}"
gzdir=${1:?usage: images.sh GZ_DIR}
pins=${PINS:-internal/images/pins.json}
fail() {
	echo "::error::$*"
	exit 1
}

version=$(jq -r '.version' "$pins")
dest=$GALAHAD_HOME/images/$version
mkdir -p "$dest"

for name in vmlinux.gz core.ext4.gz; do
	field() { jq -r --arg n "$name" ".assets[] | select(.name == \$n) | .$1" "$pins"; }
	file=$(field file)
	[ -n "$file" ] || fail "pins.json has no asset $name"
	size=$(field size)
	raw_size=$(field raw_size)
	gz=$gzdir/$name

	[ -f "$gz" ] || fail "$gz is missing"
	[ "$(stat -c %s "$gz")" = "$size" ] || fail "$name is $(stat -c %s "$gz") bytes, pins.json says $size"
	[ "$(sha256sum "$gz" | cut -d' ' -f1)" = "$(field sha256)" ] || fail "$name does not match the sha256 in pins.json"

	# Unpack at most one byte more than pinned, so a decompression bomb is cut. head closes the pipe
	# early then, which fails gzip; the size check below is what decides.
	tmp=$dest/$file.tmp
	gzip -dc "$gz" | head -c "$((raw_size + 1))" >"$tmp" || true
	[ "$(stat -c %s "$tmp")" = "$raw_size" ] || {
		rm -f "$tmp"
		fail "$file unpacks to a size other than the pinned $raw_size bytes"
	}
	[ "$(sha256sum "$tmp" | cut -d' ' -f1)" = "$(field raw_sha256)" ] || {
		rm -f "$tmp"
		fail "$file does not match the raw_sha256 in pins.json"
	}
	mv "$tmp" "$dest/$file"
	echo "installed $dest/$file"
done
