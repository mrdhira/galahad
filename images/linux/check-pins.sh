#!/usr/bin/env bash
# Compares the built assets with internal/images/pins.json. On a difference it prints the new
# "assets" block to paste into the file, and fails.
#   images/linux/check-pins.sh OUT_DIR PINS_JSON VERSION_FILE
set -euo pipefail

out=$1 pins=$2 version_file=$3
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT

# Hash the compressed asset and what it unpacks to, the way a user's download is checked.
assets='[]'
for name in vmlinux.gz core.ext4.gz; do
	gzip -dc "$out/$name" >"$tmp"
	assets=$(jq -c \
		--arg name "$name" --arg file "${name%.gz}" \
		--arg sha "$(sha256sum "$out/$name" | cut -d' ' -f1)" --argjson size "$(stat -c %s "$out/$name")" \
		--arg raw_sha "$(sha256sum "$tmp" | cut -d' ' -f1)" --argjson raw_size "$(stat -c %s "$tmp")" \
		'. + [{name: $name, file: $file, sha256: $sha, size: $size, raw_sha256: $raw_sha, raw_size: $raw_size}]' <<<"$assets")
done

status=0
version=$(tr -d '[:space:]' <"$version_file")
if ! jq -e --arg v "$version" '.version == $v and .tag == "images-" + $v' "$pins" >/dev/null; then
	echo "pins.json: version and tag must be $version and images-$version (images/linux/VERSION)" >&2
	status=1
fi
if [ "$(jq -c --sort-keys '.assets' "$pins")" != "$(jq -c --sort-keys '.' <<<"$assets")" ]; then
	echo "pins.json: the built assets differ from the pinned ones. Use this \"assets\" block:" >&2
	jq '.' <<<"$assets" >&2
	status=1
fi
exit "$status"
