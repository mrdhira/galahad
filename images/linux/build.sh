#!/usr/bin/env bash
# Builds a guest root filesystem: core.ext4.gz or re.ext4.gz, its hashes, the package manifest and
# the GPL sources. The re image is core plus Java, capa and Ghidra.
# Run it as root inside the pinned debian:trixie container (see .github/workflows/image.yml):
#   images/linux/build.sh core
#   images/linux/build.sh re
# Environment: OUT (results, default ./out) and CACHE (downloaded debs and zips, default ./cache).
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=common.sh
. "$here/common.sh"

OUT=${OUT:-$PWD/out}
CACHE=${CACHE:-$PWD/cache}

# The filesystem identity is fixed so the image bytes depend only on the content.
FS_UUID=7f3c1a52-8c64-4b0e-9d0a-5a7e1c2b4d10
HASH_SEED=2b9d6c1e-4f55-4c2a-8b7d-3e1f0a9c6d84
# core has a fixed size. re is sized from its content, see image_mib.
CORE_IMAGE_MIB=384
CORE_MAX_CONTENT_MIB=300
CORE_MAX_GZ_MIB=150
RE_MAX_IMAGE_MIB=1536
RE_MAX_GZ_MIB=700

# The standalone capa release and Ghidra, both Apache-2.0. A pin must also match what the project
# publishes: Ghidra lists the SHA-256 of each zip in its release notes; capa lists none, so its pin
# is the hash of the release asset. To update one, change the version and URL and set the hash to
# 64 zeros: the build fails and prints the hash it computed.
CAPA_VERSION=v10.0.0
CAPA_URL=https://github.com/mandiant/capa/releases/download/$CAPA_VERSION/capa-$CAPA_VERSION-linux.zip
CAPA_SHA256=96cb5115f495024a478b0e9f9f77f9027058155589235fbd4c50e7382055fcca
# The capa zip holds only the binary, so its license comes from the repository at the same tag.
CAPA_LICENSE_URL=https://raw.githubusercontent.com/mandiant/capa/$CAPA_VERSION/LICENSE.txt
CAPA_LICENSE_SHA256=cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30
GHIDRA_VERSION=12.0
GHIDRA_DATE=20251205
GHIDRA_URL=https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_$GHIDRA_DATE.zip
GHIDRA_SHA256=af43e8cfb2fa4490cf6020c3a2bde25c159d83f45236a0542688a024e8fc1941

fail() {
	echo "build.sh: $*" >&2
	exit 1
}

# build_image NAME MAX_GZ_MIB: build NAME.ext4.gz from packages-NAME.txt. The re image also gets
# capa and Ghidra.
build_image() {
	local name=$1 max_gz_mib=$2 rootfs packages content mib
	WORK=/tmp/galahad-$name
	rootfs=$WORK/rootfs
	rm -rf "$WORK"
	mkdir -p "$WORK" "$OUT" "$CACHE/debs"
	umask 022

	use_snapshot
	apt-get install -y mmdebstrap dpkg-dev e2fsprogs
	dpkg-query -W mmdebstrap e2fsprogs gzip tar

	# The packages are checked by apt against the signed indexes, so a cached deb is safe to reuse.
	export DEB_CACHE=$CACHE/debs
	write_sources "$WORK/chroot.sources" deb
	packages=$(paste -sd, "$here/packages-$name.txt")
	# The Java packages register man page alternatives under /usr/share/man/man1, which the
	# path-exclude below leaves out, so their postinst fails unless the directory exists.
	# Only the re image gets it, so the core image bytes stay the same.
	local extra=()
	if [ "$name" = re ]; then
		# shellcheck disable=SC2016 # $1 is expanded by the hook's own shell
		extra=(--essential-hook='mkdir -p "$1/usr/share/man/man1"')
	fi
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
		"${extra[@]}" \
		trixie "$rootfs" "$WORK/chroot.sources"

	if [ "$name" = re ]; then
		install_re_tools "$rootfs"
	fi
	finish_rootfs "$rootfs"
	check_rootfs "$rootfs"
	content=$(du -sb "$rootfs" | cut -f1)
	echo "content: $content bytes"
	mib=$(image_mib "$name" "$content")
	manifest "$rootfs" "$name"
	if [ "$name" = re ]; then
		check_re "$rootfs"
	fi
	make_image "$rootfs" "$name" "$mib" "$max_gz_mib"
	gpl_sources "$rootfs" "$name"
}

# fetch URL SHA256: download URL into the cache, check the pin and print the path of the file.
fetch() {
	local url=$1 sha=$2 file got
	file=$CACHE/$(basename "$url")
	if [ ! -f "$file" ]; then
		curl -fsSL --retry 5 --max-time 900 -o "$file.part" "$url" || fail "curl: cannot download $url"
		mv "$file.part" "$file"
	fi
	got=$(sha256sum "$file" | cut -d' ' -f1)
	if [ "$got" != "$sha" ]; then
		rm -f "$file"
		fail "$(basename "$url") has sha256 $got, pinned $sha"
	fi
	echo "$file"
}

# install_re_tools: unpack capa into /opt/capa and Ghidra into /opt/ghidra, each with its license.
install_re_tools() {
	local rootfs=$1 capa_zip capa_license ghidra_zip
	apt-get install -y curl ca-certificates unzip
	# ca-certificates-java writes a Java trust store with a fresh salt or timestamp on every build,
	# which would change the image bytes. The guest has no network of its own, so it is not needed.
	rm -f "$rootfs/etc/ssl/certs/java/cacerts"

	capa_zip=$(fetch "$CAPA_URL" "$CAPA_SHA256")
	capa_license=$(fetch "$CAPA_LICENSE_URL" "$CAPA_LICENSE_SHA256")
	ghidra_zip=$(fetch "$GHIDRA_URL" "$GHIDRA_SHA256")

	mkdir -p "$rootfs/opt/capa" "$rootfs/usr/local/bin"
	unzip -q -d "$rootfs/opt/capa" "$capa_zip"
	chmod 0755 "$rootfs/opt/capa/capa"
	install -m 0644 "$capa_license" "$rootfs/opt/capa/LICENSE.txt"
	ln -s /opt/capa/capa "$rootfs/usr/local/bin/capa"

	unzip -q -d "$WORK" "$ghidra_zip"
	mv "$WORK/ghidra_${GHIDRA_VERSION}_PUBLIC" "$rootfs/opt/ghidra"
	# The docs, the IDE plugins and the Docker files are not used by the headless analyzer. LICENSE,
	# licenses/ and GPL/ (the sources of Ghidra's GPL parts) stay.
	rm -rf "$rootfs"/opt/ghidra/{docs,Extensions,docker}
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

	# The agent drops to this user after its root-only work (it mounts the signatures drive of an update job)
	# and before it reads any input.
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
	local rootfs=$1
	[ -f "$rootfs/etc/galahad-guest" ] || fail "the guest marker is missing"
	[ -x "$rootfs/sbin/galahad-init" ] || fail "/sbin/galahad-init is missing or not executable"
	[ -x "$rootfs/bin/busybox" ] || fail "busybox is missing"
	grep -q '^galahad:x:1000:1000:' "$rootfs/etc/passwd" || fail "user galahad is not uid 1000"
	[ -s "$rootfs/usr/share/doc/git/copyright" ] || fail "the git copyright file is missing"
	[ ! -e "$rootfs/lib/modules" ] || fail "the image must not carry kernel modules"
	[ -z "$(ls -A "$rootfs/usr/share/man" 2>/dev/null)" ] || fail "man pages are still there"
}

# image_mib NAME CONTENT_BYTES: print the size of the ext4 file in MiB. core has a fixed size. re is
# its content plus 10% and 64 MiB of headroom, rounded up to 64 MiB, so one content gives one size.
image_mib() {
	local name=$1 content=$2 step=$((64 * 1024 * 1024)) steps mib
	if [ "$name" = core ]; then
		[ "$content" -le $((CORE_MAX_CONTENT_MIB * 1024 * 1024)) ] || fail "content is over $CORE_MAX_CONTENT_MIB MiB"
		echo "$CORE_IMAGE_MIB"
		return
	fi
	steps=$(((content + content / 10 + step + step - 1) / step))
	mib=$((steps * 64))
	[ "$mib" -le "$RE_MAX_IMAGE_MIB" ] || fail "$name.ext4 needs $mib MiB for $content bytes of content, over $RE_MAX_IMAGE_MIB MiB"
	echo "$mib"
}

# chroot_run ROOTFS COMMAND...: run COMMAND in a chroot of ROOTFS with an empty environment. The
# root is read-only, and /tmp and /root (Java takes user.home from the passwd entry, not from HOME)
# are tmpfs, so the run cannot change the image. The mounts live in a mount namespace of their own
# and go away with the command.
chroot_run() {
	# The inner shell expands its own arguments.
	# shellcheck disable=SC2016
	unshare --mount --propagation private bash -c '
		set -eu
		root=$1
		shift
		mount --bind "$root" "$root"
		mount -o remount,bind,ro "$root"
		mount -t proc proc "$root/proc"
		mount --bind /dev "$root/dev"
		mount -t tmpfs -o mode=1777 tmpfs "$root/tmp"
		mount -t tmpfs -o mode=0700 tmpfs "$root/root"
		exec timeout 300 chroot "$root" /usr/bin/env -i PATH=/usr/local/bin:/usr/bin:/bin HOME=/tmp TMPDIR=/tmp "$@"
	' bash "$@"
}

# check_re: the licenses are in the image, capa starts, and Ghidra finds a Java it supports. The
# analyzer prints its usage and exits non-zero without arguments, so its output is read, not its code.
check_re() {
	local rootfs=$1 out rc=0
	[ -s "$rootfs/opt/capa/LICENSE.txt" ] || fail "the capa license file is missing"
	[ -s "$rootfs/opt/ghidra/LICENSE" ] || fail "the Ghidra license file is missing"
	[ -d "$rootfs/opt/ghidra/licenses" ] || fail "the Ghidra licenses directory is missing"

	out=$(chroot_run "$rootfs" capa --version 2>&1) || rc=$?
	if [ "$rc" -ne 0 ] || ! grep -q '^capa [0-9]' <<<"$out"; then
		echo "$out" >&2
		fail "capa --version failed with exit $rc: $(tail -n 1 <<<"$out")"
	fi
	echo "$out"

	out=$(chroot_run "$rootfs" /opt/ghidra/support/analyzeHeadless -help 2>&1) || true
	if ! grep -q 'Headless Analyzer Usage' <<<"$out" || grep -qiE 'error|exception|unsupported' <<<"$out"; then
		echo "$out" >&2
		fail "analyzeHeadless -help failed: $(grep -iE 'error|exception|unsupported' <<<"$out" | head -n 1 || tail -n 1 <<<"$out")"
	fi
	echo "analyzeHeadless -help: ok"
}

# manifest ROOTFS NAME: one line per package: name, version, source package, source version.
manifest() {
	dpkg-query --admindir="$1/var/lib/dpkg" -W \
		-f='${Package}\t${Version}\t${source:Package}\t${source:Version}\n' | sort >"$OUT/$2.manifest"
}

# make_image ROOTFS NAME MIB MAX_GZ_MIB
make_image() {
	local rootfs=$1 name=$2 mib=$3 max_gz_mib=$4 img=$WORK/$2.ext4

	truncate -s "${mib}M" "$img"
	# The guest kernel is 6.1, which cannot mount a journal-less ext4 with orphan_file read-write.
	E2FSPROGS_FAKE_TIME=$SOURCE_DATE_EPOCH mkfs.ext4 -q -F -b 4096 -i 8192 -m 0 -L "galahad-$name" \
		-U "$FS_UUID" -O '^has_journal,^orphan_file' \
		-E "hash_seed=$HASH_SEED,root_owner=0:0,lazy_itable_init=0,lazy_journal_init=0" \
		-d "$rootfs" "$img"
	e2fsck -fn "$img"

	gzip -n -9 -c "$img" >"$OUT/$name.ext4.gz"
	(cd "$OUT" && sha256sum "$name.ext4.gz" >"$name.ext4.gz.sha256")
	(cd "$WORK" && sha256sum "$name.ext4") >"$OUT/$name.ext4.sha256"
	cat "$OUT/$name.ext4.gz.sha256" "$OUT/$name.ext4.sha256"

	[ "$(stat -c %s "$OUT/$name.ext4.gz")" -le $((max_gz_mib * 1024 * 1024)) ] || fail "$name.ext4.gz is over $max_gz_mib MiB"
}

# gpl_sources ROOTFS NAME: download the source packages of every package whose copyright file mentions
# the GPL (LGPL included), or that has no copyright file, at the version installed in the image.
gpl_sources() {
	local rootfs=$1 name=$2 bin srcpkg srcver
	mkdir -p "$OUT/sources-$name"
	while IFS=$'\t' read -r bin _ srcpkg srcver; do
		if [ ! -e "$rootfs/usr/share/doc/$bin/copyright" ] || grep -qiE 'GPL|General Public License' "$rootfs/usr/share/doc/$bin/copyright"; then
			echo "$srcpkg=$srcver"
		fi
	done <"$OUT/$name.manifest" | sort -u >"$OUT/$name.gpl-sources"
	(cd "$OUT/sources-$name" && xargs -a "$OUT/$name.gpl-sources" apt-get -q -o APT::Sandbox::User=root source --download-only)
}

case ${1:-} in
core) build_image core "$CORE_MAX_GZ_MIB" ;;
re) build_image re "$RE_MAX_GZ_MIB" ;;
*)
	echo "usage: $0 core|re" >&2
	exit 2
	;;
esac
