#!/usr/bin/env bash
# Builds the guest root filesystem: core.ext4.gz, its hashes, the package manifest and the GPL sources.
# Run it as root inside the pinned debian:trixie container (see .github/workflows/image.yml):
#   images/linux/build.sh core
# Environment: OUT (results, default ./out) and CACHE (downloaded debs, default ./cache).
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=common.sh
. "$here/common.sh"

OUT=${OUT:-$PWD/out}
CACHE=${CACHE:-$PWD/cache}
WORK=/tmp/galahad-core

# The filesystem identity is fixed so the image bytes depend only on the content.
FS_UUID=7f3c1a52-8c64-4b0e-9d0a-5a7e1c2b4d10
HASH_SEED=2b9d6c1e-4f55-4c2a-8b7d-3e1f0a9c6d84
IMAGE_MIB=384
MAX_CONTENT_MIB=300
MAX_GZ_MIB=150

fail() {
	echo "build.sh: $*" >&2
	exit 1
}

core() {
	local rootfs=$WORK/rootfs packages
	rm -rf "$WORK"
	mkdir -p "$WORK" "$OUT" "$CACHE/debs"
	umask 022

	use_snapshot
	apt-get install -y mmdebstrap dpkg-dev
	dpkg-query -W mmdebstrap e2fsprogs gzip tar

	# The packages are checked by apt against the signed indexes, so a cached deb is safe to reuse.
	export DEB_CACHE=$CACHE/debs
	write_sources "$WORK/chroot.sources" deb
	packages=$(paste -sd, "$here/packages-core.txt")
	# The hooks run in a shell of their own, which expands $1 (the new root) and $DEB_CACHE.
	# shellcheck disable=SC2016
	mmdebstrap --mode=root --variant=minbase --architectures=amd64 \
		--include="$packages" \
		--aptopt='APT::Install-Recommends "false"' \
		--dpkgopt='path-exclude=/usr/share/doc/*' \
		--dpkgopt='path-include=/usr/share/doc/*/copyright' \
		--dpkgopt='path-exclude=/usr/share/man/*' \
		--dpkgopt='path-exclude=/usr/share/info/*' \
		--dpkgopt='path-exclude=/usr/share/locale/*' \
		--dpkgopt='path-exclude=/usr/share/lintian/*' \
		--setup-hook='mkdir -p "$1/var/cache/apt/archives" && cp -a "$DEB_CACHE/." "$1/var/cache/apt/archives/"' \
		--customize-hook='cp -u "$1"/var/cache/apt/archives/*.deb "$DEB_CACHE/"' \
		trixie "$rootfs" "$WORK/chroot.sources"

	finish_rootfs "$rootfs"
	check_rootfs "$rootfs"
	manifest "$rootfs"
	make_image "$rootfs"
	gpl_sources "$rootfs"
}

# finish_rootfs: add the overlay and the galahad user, strip what the guest never uses and clamp
# everything that would differ between two builds.
finish_rootfs() {
	local rootfs=$1 src dest day

	# The overlay may name /sbin or /bin, which are symlinks into /usr, so resolve the directory first.
	while IFS= read -r -d '' src; do
		src=${src#./}
		dest=$(realpath -m "$rootfs/$(dirname "$src")")/$(basename "$src")
		if [ -x "$here/overlay/$src" ]; then
			install -D -m 0755 "$here/overlay/$src" "$dest"
		else
			install -D -m 0644 "$here/overlay/$src" "$dest"
		fi
	done < <(cd "$here/overlay" && find . -type f -print0 | sort -z)

	# The agent drops to this user after it has mounted the disks and set the clock.
	day=$((SOURCE_DATE_EPOCH / 86400))
	echo 'galahad:x:1000:1000:Galahad guest user:/home/galahad:/usr/sbin/nologin' >>"$rootfs/etc/passwd"
	echo 'galahad:x:1000:' >>"$rootfs/etc/group"
	echo "galahad:!:$day:0:99999:7:::" >>"$rootfs/etc/shadow"
	echo 'galahad:!::' >>"$rootfs/etc/gshadow"
	mkdir -p "$rootfs/work" "$rootfs/sig" "$rootfs/run" "$rootfs/tmp"
	install -d -m 0755 -o 1000 -g 1000 "$rootfs/home/galahad"

	# Docs, man pages, info, locales and package lists go; every copyright file stays.
	rm -rf "$rootfs"/usr/share/{man,info,locale,lintian,doc-base}
	find "$rootfs/usr/share/doc" -mindepth 2 \( -type f -o -type l \) ! -name copyright -delete
	find "$rootfs/usr/share/doc" -mindepth 1 -type d -empty -delete
	rm -rf "$rootfs"/var/lib/apt/lists/* "$rootfs"/var/cache/* "$rootfs"/var/log/* "$rootfs"/var/lib/clamav/*
	rm -f "$rootfs"/etc/apt/sources.list "$rootfs"/etc/apt/sources.list.d/* "$rootfs/etc/resolv.conf"
	rm -f "$rootfs"/etc/{passwd,shadow,group,gshadow}- "$rootfs"/var/lib/dpkg/*-old

	# Files that tools fill with the build time, the host name or random data.
	: >"$rootfs/etc/machine-id"
	echo galahad >"$rootfs/etc/hostname"
	printf '127.0.0.1 localhost\n' >"$rootfs/etc/hosts"
	ln -sf ../proc/self/mounts "$rootfs/etc/mtab"
	awk -F: -v OFS=: -v day="$day" '$3 ~ /^[0-9]+$/ { $3 = day } { print }' "$rootfs/etc/shadow" >"$WORK/shadow"
	cat "$WORK/shadow" >"$rootfs/etc/shadow"

	# The kernel opens /dev/console for init before devtmpfs is mounted, so the node must exist.
	rm -f "$rootfs/dev/console" "$rootfs/dev/null"
	mknod -m 0600 "$rootfs/dev/console" c 5 1
	mknod -m 0666 "$rootfs/dev/null" c 1 3

	find "$rootfs" -depth -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
}

check_rootfs() {
	local rootfs=$1 content
	[ -f "$rootfs/etc/galahad-guest" ] || fail "the guest marker is missing"
	[ -x "$rootfs/sbin/galahad-init" ] || fail "/sbin/galahad-init is missing or not executable"
	[ -x "$rootfs/bin/busybox" ] || fail "busybox is missing"
	grep -q '^galahad:x:1000:1000:' "$rootfs/etc/passwd" || fail "user galahad is not uid 1000"
	[ -s "$rootfs/usr/share/doc/git/copyright" ] || fail "the git copyright file is missing"
	[ ! -e "$rootfs/lib/modules" ] || fail "the image must not carry kernel modules"
	[ -z "$(ls -A "$rootfs/usr/share/man" 2>/dev/null)" ] || fail "man pages are still there"
	content=$(du -sb "$rootfs" | cut -f1)
	echo "content: $content bytes"
	[ "$content" -le $((MAX_CONTENT_MIB * 1024 * 1024)) ] || fail "content is over $MAX_CONTENT_MIB MiB"
}

# manifest: one line per package: name, version, source package, source version.
manifest() {
	dpkg-query --admindir="$1/var/lib/dpkg" -W \
		-f='${binary:Package}\t${Version}\t${source:Package}\t${source:Version}\n' | sort >"$OUT/core.manifest"
}

make_image() {
	local rootfs=$1 img=$WORK/core.ext4

	truncate -s "${IMAGE_MIB}M" "$img"
	# The guest kernel is 6.1, which cannot mount a journal-less ext4 with orphan_file read-write.
	E2FSPROGS_FAKE_TIME=$SOURCE_DATE_EPOCH mkfs.ext4 -q -F -b 4096 -i 8192 -m 0 -L galahad-core \
		-U "$FS_UUID" -O '^has_journal,^orphan_file' \
		-E "hash_seed=$HASH_SEED,root_owner=0:0,lazy_itable_init=0,lazy_journal_init=0" \
		-d "$rootfs" "$img"
	e2fsck -fn "$img"

	gzip -n -9 -c "$img" >"$OUT/core.ext4.gz"
	(cd "$OUT" && sha256sum core.ext4.gz >core.ext4.gz.sha256)
	(cd "$WORK" && sha256sum core.ext4) >"$OUT/core.ext4.sha256"
	cat "$OUT/core.ext4.gz.sha256" "$OUT/core.ext4.sha256"

	[ "$(stat -c %s "$OUT/core.ext4.gz")" -le $((MAX_GZ_MIB * 1024 * 1024)) ] || fail "core.ext4.gz is over $MAX_GZ_MIB MiB"
}

# gpl_sources: download the source packages of every package whose copyright file mentions the GPL
# (LGPL included), or that has no copyright file, at the version installed in the image.
gpl_sources() {
	local rootfs=$1 bin srcpkg srcver
	mkdir -p "$OUT/sources"
	while IFS=$'\t' read -r bin _ srcpkg srcver; do
		if [ ! -e "$rootfs/usr/share/doc/$bin/copyright" ] || grep -qE 'GPL|General Public License' "$rootfs/usr/share/doc/$bin/copyright"; then
			echo "$srcpkg=$srcver"
		fi
	done <"$OUT/core.manifest" | sort -u >"$OUT/core.gpl-sources"
	(cd "$OUT/sources" && xargs -a "$OUT/core.gpl-sources" apt-get -q -o APT::Sandbox::User=root source --download-only)
}

case ${1:-} in
core) core ;;
*)
	echo "usage: $0 core" >&2
	exit 2
	;;
esac
