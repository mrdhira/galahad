#!/usr/bin/env bash
# Builds the guest kernel: vmlinux.gz, its hashes, the final config and the source tarball.
# Run it as root inside the pinned debian:trixie container (see .github/workflows/image.yml):
#   images/linux/kernel/build.sh
# Environment: OUT (results, default ./out) and CACHE (downloaded files, default ./cache).
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=../common.sh
. "$here/../common.sh"

OUT=${OUT:-$PWD/out}
CACHE=${CACHE:-$PWD/cache}
WORK=/tmp/galahad-kernel

KERNEL_VERSION=6.1.190
KERNEL_URL=https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-$KERNEL_VERSION.tar.xz
# PLACEHOLDER: replace with the line for linux-$KERNEL_VERSION.tar.xz in
# https://cdn.kernel.org/pub/linux/kernel/v6.x/sha256sums.asc. Until then the build fails and prints
# the hash it computed, which must be compared with kernel.org's list before it is pinned here.
KERNEL_SHA256=0000000000000000000000000000000000000000000000000000000000000000

MAX_VMLINUX_MIB=40
MAX_GZ_MIB=15

fail() {
	echo "kernel/build.sh: $*" >&2
	exit 1
}

# The same timestamp, user and host on every build, so the kernel banner does not change.
KBUILD_BUILD_TIMESTAMP=$(date -u -d "@$SOURCE_DATE_EPOCH")
export KBUILD_BUILD_TIMESTAMP
export KBUILD_BUILD_USER=galahad KBUILD_BUILD_HOST=galahad KBUILD_BUILD_VERSION=1

umask 022
use_snapshot
apt-get install -y build-essential bc flex bison libelf-dev xz-utils curl ca-certificates

mkdir -p "$OUT" "$CACHE"
tarball=$CACHE/linux-$KERNEL_VERSION.tar.xz
if [ ! -f "$tarball" ]; then
	curl -fsSL --retry 5 --max-time 600 -o "$tarball" "$KERNEL_URL"
fi
got=$(sha256sum "$tarball" | cut -d' ' -f1)
if [ "$got" != "$KERNEL_SHA256" ]; then
	rm -f "$tarball"
	fail "linux-$KERNEL_VERSION.tar.xz has sha256 $got, pinned $KERNEL_SHA256"
fi

rm -rf "$WORK"
mkdir -p "$WORK"
tar -xJf "$tarball" -C "$WORK" --no-same-owner
cd "$WORK/linux-$KERNEL_VERSION"

make ARCH=x86_64 tinyconfig
scripts/kconfig/merge_config.sh -m .config "$here/config"
make ARCH=x86_64 olddefconfig

# olddefconfig drops a symbol without saying so when its dependencies are missing. Check that every
# line of the fragment is in the final config, and that nothing that reaches the outside is.
while IFS= read -r line; do
	case $line in
	CONFIG_*=*)
		grep -qxF -- "$line" .config || fail "config line lost: $line"
		;;
	"# CONFIG_"*" is not set")
		sym=${line#"# "}
		sym=${sym%" is not set"}
		if grep -q "^$sym=" .config; then fail "config line lost: $line"; fi
		;;
	esac
done <"$here/config"
if grep -E '^CONFIG_(MODULES|PCI|ETHERNET|WLAN|VIRTIO_NET|NET_9P|9P_FS|VIRTIO_FS|USB|NET_VENDOR_[A-Z0-9_]+)=' .config; then
	fail "the final config enables a module loader, a bus or a device the guest must not have"
fi

make ARCH=x86_64 -j"$(nproc)" vmlinux

size=$(stat -c %s vmlinux)
echo "vmlinux: $size bytes"
[ "$size" -le $((MAX_VMLINUX_MIB * 1024 * 1024)) ] || fail "vmlinux is over $MAX_VMLINUX_MIB MiB"

gzip -n -9 -c vmlinux >"$OUT/vmlinux.gz"
(cd "$OUT" && sha256sum vmlinux.gz >vmlinux.gz.sha256)
sha256sum vmlinux >"$OUT/vmlinux.sha256"
cat "$OUT/vmlinux.gz.sha256" "$OUT/vmlinux.sha256"
[ "$(stat -c %s "$OUT/vmlinux.gz")" -le $((MAX_GZ_MIB * 1024 * 1024)) ] || fail "vmlinux.gz is over $MAX_GZ_MIB MiB"

# The kernel is GPL-2.0: the source and the exact config ship with the release.
cp .config "$OUT/vmlinux.config"
cp "$tarball" "$OUT/"
