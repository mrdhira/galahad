# shellcheck shell=bash
# Settings shared by build.sh and kernel/build.sh. Sourced inside the pinned build container.

# Every Debian package, in the container tools and in the images, comes from this
# snapshot.debian.org timestamp. Change it to take newer packages, then update the pins.
SNAPSHOT=20261020T000000Z

# The snapshot time is the build time of everything: file times, user records, kernel banner.
SOURCE_DATE_EPOCH=$(date -u -d "${SNAPSHOT:0:4}-${SNAPSHOT:4:2}-${SNAPSHOT:6:2} ${SNAPSHOT:9:2}:${SNAPSHOT:11:2}:${SNAPSHOT:13:2}" +%s)
export SOURCE_DATE_EPOCH
export LC_ALL=C TZ=UTC

# write_sources FILE TYPES: write the deb822 sources of the snapshot to FILE.
write_sources() {
	cat >"$1" <<SRC
Types: $2
URIs: http://snapshot.debian.org/archive/debian/$SNAPSHOT/
Suites: trixie trixie-updates
Components: main
Check-Valid-Until: no

Types: $2
URIs: http://snapshot.debian.org/archive/debian-security/$SNAPSHOT/
Suites: trixie-security
Components: main
Check-Valid-Until: no
SRC
}

# use_snapshot: point the container's apt at the snapshot and refresh the package lists.
use_snapshot() {
	rm -f /etc/apt/sources.list /etc/apt/sources.list.d/*
	write_sources /etc/apt/sources.list.d/snapshot.sources "deb deb-src"
	cat >/etc/apt/apt.conf.d/99galahad <<'CONF'
Acquire::Retries "5";
Acquire::Languages "none";
APT::Install-Recommends "false";
CONF
	apt-get update -qq
}
