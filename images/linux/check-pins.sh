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
for name in vmlinux.gz core.ext4.gz re.ext4.gz; do
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
	echo "assets=$(jq -c '.' <<<"$assets")" >&2
	status=1
fi
# Firecracker is downloaded by galahad setup, not built here. Check the pin against the file
# and against the checksum the Firecracker release publishes next to it.
fc_url=$(jq -r '.firecracker.url' "$pins")
fc_pin=$(jq -r '.firecracker.sha256' "$pins")
fc_file=$(curl -fsSL --retry 3 "$fc_url" | sha256sum | cut -d' ' -f1)
fc_published=$(curl -fsSL --retry 3 "$fc_url.sha256.txt" | cut -d' ' -f1)
if [ "$fc_file" != "$fc_pin" ] || [ "$fc_published" != "$fc_pin" ]; then
	echo "pins.json: firecracker sha256 is $fc_pin; the file hashes to $fc_file and the release publishes $fc_published" >&2
	status=1
fi
exit "$status"
