#!/usr/bin/env bash
set -Eeuo pipefail
umask 022

usage() {
  echo "usage: $0 --output DIR --forge-binary FILE --bootstrap-binary FILE --version SEMVER --ubuntu-snapshot-id ID --release-public-key BASE64" >&2
  exit 2
}

repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
output=""
forge_binary=""
bootstrap_binary=""
version=""
snapshot_id=""
release_public_key=""
while (($#)); do
  case "$1" in
    --output) output="${2:-}"; shift 2 ;;
    --forge-binary) forge_binary="${2:-}"; shift 2 ;;
    --bootstrap-binary) bootstrap_binary="${2:-}"; shift 2 ;;
    --version) version="${2:-}"; shift 2 ;;
    --ubuntu-snapshot-id) snapshot_id="${2:-}"; shift 2 ;;
    --release-public-key) release_public_key="${2:-}"; shift 2 ;;
    *) usage ;;
  esac
done
test -n "$output" && test -n "$forge_binary" && test -n "$bootstrap_binary"
test -n "$version" && test -n "$snapshot_id" && test -n "$release_public_key"
test -x "$forge_binary" && test -x "$bootstrap_binary"
python3 -B "$repository_root/tools/forge-release.py" validate-public-key \
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

forge_root="$work_dir/cybex-forge"
mkdir -p -- "$forge_root/DEBIAN" "$forge_root/usr/bin"
install -m 0755 "$forge_binary" "$forge_root/usr/bin/cybex-forge"
cat > "$forge_root/DEBIAN/control" <<EOF
Package: cybex-forge
Version: ${version}-1
Section: admin
Priority: optional
Architecture: amd64
Maintainer: Cybex <support@cybex.net>
Depends: libc6, libgcc-s1, ca-certificates
Description: Cybex Forge build and network-boot service
EOF
build_package "$forge_root" cybex-forge

bootstrap_root="$work_dir/cybex-forge-bootstrap"
mkdir -p -- "$bootstrap_root/DEBIAN" "$bootstrap_root/usr/lib/cybex-forge"
install -m 0755 "$bootstrap_binary" "$bootstrap_root/usr/lib/cybex-forge/cybex-forge-bootstrap"
cat > "$bootstrap_root/DEBIAN/control" <<EOF
Package: cybex-forge-bootstrap
Version: ${version}-1
Section: admin
Priority: optional
Architecture: amd64
Maintainer: Cybex <support@cybex.net>
Depends: libc6, libgcc-s1, ca-certificates, iproute2, util-linux, gdisk, e2fsprogs, efibootmgr, parted, iputils-arping, systemd
Description: Fail-closed Cybex Forge provisioned-media bootstrap
EOF
build_package "$bootstrap_root" cybex-forge-bootstrap

appliance_root="$work_dir/cybex-forge-appliance"
mkdir -p -- "$appliance_root/DEBIAN" "$appliance_root/usr/share/cybex-forge"
cp -a "$repository_root/ubuntu-appliance/rootfs/." "$appliance_root/"
printf '%s\n' "$release_public_key" > "$appliance_root/usr/share/cybex-forge/release-public-key"
chmod 0644 "$appliance_root/usr/share/cybex-forge/release-public-key"
install -m 0755 "$repository_root/ubuntu-appliance/package/cybex-forge-appliance.postinst" "$appliance_root/DEBIAN/postinst"
jq -n \
  --arg schema 'cybex.forge.appliance-release.v1' \
  --arg release_id "$version" \
  --arg ubuntu_snapshot_id "$snapshot_id" \
  '{schema:$schema,release_id:$release_id,ubuntu_snapshot_id:$ubuntu_snapshot_id,root_generation:"0"}' \
  > "$appliance_root/usr/share/cybex-forge/appliance-release.json"
chmod 0644 "$appliance_root/usr/share/cybex-forge/appliance-release.json"
cat > "$appliance_root/DEBIAN/control" <<EOF
Package: cybex-forge-appliance
Version: ${version}-1
Section: admin
Priority: optional
Architecture: amd64
Maintainer: Cybex <support@cybex.net>
Depends: cybex-forge (= ${version}-1), cybex-forge-bootstrap (= ${version}-1), systemd, nginx-core, tftpd-hpa, ipxe, openssh-server, nftables, netplan.io, btrfs-progs, watchdog, nix-bin, nix-setup-systemd, curl, dnsutils, jq, mokutil, sbsigntool, linux-generic, linux-firmware, intel-microcode, amd64-microcode
Description: Managed Ubuntu host integration for Cybex Forge
EOF
build_package "$appliance_root" cybex-forge-appliance

sha256sum "$output"/*.deb | LC_ALL=C sort -k2 > "$output/CYBEX-PACKAGES.sha256"
