#!/usr/bin/env bash
set -Eeuo pipefail
umask 022

usage() {
  echo "usage: $0 --output DIR --pulse-binary FILE --bootstrap-binary FILE --version SEMVER --ubuntu-snapshot-id ID --release-public-key BASE64" >&2
  exit 2
}

repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
output=""
pulse_binary=""
bootstrap_binary=""
version=""
snapshot_id=""
release_public_key=""
while (($#)); do
  case "$1" in
    --output) output="${2:-}"; shift 2 ;;
    --pulse-binary) pulse_binary="${2:-}"; shift 2 ;;
    --bootstrap-binary) bootstrap_binary="${2:-}"; shift 2 ;;
    --version) version="${2:-}"; shift 2 ;;
    --ubuntu-snapshot-id) snapshot_id="${2:-}"; shift 2 ;;
    --release-public-key) release_public_key="${2:-}"; shift 2 ;;
    *) usage ;;
  esac
done
test -n "$output" && test -n "$pulse_binary" && test -n "$bootstrap_binary"
test -n "$version" && test -n "$snapshot_id" && test -n "$release_public_key"
test -x "$pulse_binary" && test -x "$bootstrap_binary"
python3 -B "$repository_root/tools/pulse-release.py" validate-public-key \
  --trusted-public-key "$release_public_key" >/dev/null
[[ "$snapshot_id" =~ ^[0-9]{8}T[0-9]{6}Z$ ]]

mkdir -p -- "$output"
output="$(cd -- "$output" && pwd -P)"
work_dir="$(mktemp -d "$output/.packages.XXXXXXXX")"
cleanup() { rm -rf -- "$work_dir"; }
trap cleanup EXIT

build_package() {
  local root="$1"
  local package="$2"
  dpkg-deb --root-owner-group --build "$root" "$output/${package}_${version}-1_amd64.deb" >/dev/null
  dpkg-deb --info "$output/${package}_${version}-1_amd64.deb" >/dev/null
}

pulse_root="$work_dir/cybex-pulse"
mkdir -p -- "$pulse_root/DEBIAN" "$pulse_root/usr/bin"
install -m 0755 "$pulse_binary" "$pulse_root/usr/bin/cybex-pulse"
cat > "$pulse_root/DEBIAN/control" <<EOF
Package: cybex-pulse
Version: ${version}-1
Section: admin
Priority: optional
Architecture: amd64
Maintainer: Cybex <support@cybex.net>
Depends: libc6, libgcc-s1, ca-certificates
Description: Cybex Pulse build and network-boot service
EOF
build_package "$pulse_root" cybex-pulse

bootstrap_root="$work_dir/cybex-pulse-bootstrap"
mkdir -p -- "$bootstrap_root/DEBIAN" "$bootstrap_root/usr/lib/cybex-pulse"
install -m 0755 "$bootstrap_binary" "$bootstrap_root/usr/lib/cybex-pulse/cybex-pulse-bootstrap"
cat > "$bootstrap_root/DEBIAN/control" <<EOF
Package: cybex-pulse-bootstrap
Version: ${version}-1
Section: admin
Priority: optional
Architecture: amd64
Maintainer: Cybex <support@cybex.net>
Depends: libc6, libgcc-s1, ca-certificates, iproute2, util-linux, gdisk, e2fsprogs, efibootmgr, parted, iputils-arping, systemd
Description: Fail-closed Cybex Pulse provisioned-media bootstrap
EOF
build_package "$bootstrap_root" cybex-pulse-bootstrap

appliance_root="$work_dir/cybex-pulse-appliance"
mkdir -p -- "$appliance_root/DEBIAN" "$appliance_root/usr/share/cybex-pulse"
cp -a "$repository_root/ubuntu-appliance/rootfs/." "$appliance_root/"
printf '%s\n' "$release_public_key" > "$appliance_root/usr/share/cybex-pulse/release-public-key"
chmod 0644 "$appliance_root/usr/share/cybex-pulse/release-public-key"
install -m 0755 "$repository_root/ubuntu-appliance/package/cybex-pulse-appliance.postinst" "$appliance_root/DEBIAN/postinst"
jq -n \
  --arg schema 'cybex.pulse.appliance-release.v1' \
  --arg release_id "$version" \
  --arg ubuntu_snapshot_id "$snapshot_id" \
  '{schema:$schema,release_id:$release_id,ubuntu_snapshot_id:$ubuntu_snapshot_id,root_generation:"0"}' \
  > "$appliance_root/usr/share/cybex-pulse/appliance-release.json"
chmod 0644 "$appliance_root/usr/share/cybex-pulse/appliance-release.json"
cat > "$appliance_root/DEBIAN/control" <<EOF
Package: cybex-pulse-appliance
Version: ${version}-1
Section: admin
Priority: optional
Architecture: amd64
Maintainer: Cybex <support@cybex.net>
Depends: cybex-pulse (= ${version}-1), cybex-pulse-bootstrap (= ${version}-1), systemd, nginx-core, tftpd-hpa, ipxe, openssh-server, nftables, netplan.io, btrfs-progs, watchdog, nix-bin, nix-setup-systemd, curl, dnsutils, jq, mokutil, sbsigntool, shim-signed, grub-efi-amd64-signed, secureboot-db, linux-generic, linux-firmware, intel-microcode, amd64-microcode
Description: Managed Ubuntu host integration for Cybex Pulse
EOF
build_package "$appliance_root" cybex-pulse-appliance

sha256sum "$output"/*.deb | LC_ALL=C sort -k2 > "$output/CYBEX-PACKAGES.sha256"
