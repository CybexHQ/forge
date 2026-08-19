#!/usr/bin/env bash
set -Eeuo pipefail
umask 022

usage() {
  echo "usage: $0 --output DIR --james-binary FILE --bootstrap-binary FILE --version SEMVER --ubuntu-snapshot-id ID --manage-source-dir DIR --manage-source-revision 40_HEX --release-public-key BASE64 --provisioning-public-key BASE64 [--provisioning-public-key BASE64 ...]" >&2
  exit 2
}

repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
output=""
james_binary=""
bootstrap_binary=""
version=""
snapshot_id=""
manage_source_dir=""
manage_source_revision=""
release_public_key=""
declare -a provisioning_public_keys=()
while (($#)); do
  case "$1" in
    --output) output="${2:-}"; shift 2 ;;
    --james-binary) james_binary="${2:-}"; shift 2 ;;
    --bootstrap-binary) bootstrap_binary="${2:-}"; shift 2 ;;
    --version) version="${2:-}"; shift 2 ;;
    --ubuntu-snapshot-id) snapshot_id="${2:-}"; shift 2 ;;
    --manage-source-dir) manage_source_dir="${2:-}"; shift 2 ;;
    --manage-source-revision) manage_source_revision="${2:-}"; shift 2 ;;
    --release-public-key) release_public_key="${2:-}"; shift 2 ;;
    --provisioning-public-key) provisioning_public_keys+=("${2:-}"); shift 2 ;;
    *) usage ;;
  esac
done
test -n "$output" && test -n "$james_binary" && test -n "$bootstrap_binary"
test -n "$version" && test -n "$snapshot_id" && test -n "$release_public_key"
test -n "$manage_source_dir" && test -n "$manage_source_revision"
test "${#provisioning_public_keys[@]}" -ge 1 && test "${#provisioning_public_keys[@]}" -le 8
test -x "$james_binary" && test -x "$bootstrap_binary"
python3 -B "$repository_root/tools/james-release.py" validate-public-key \
  --trusted-public-key "$release_public_key" >/dev/null
mapfile -t sorted_provisioning_keys < <(printf '%s\n' "${provisioning_public_keys[@]}" | LC_ALL=C sort -u)
test "${#sorted_provisioning_keys[@]}" -eq "${#provisioning_public_keys[@]}"
for index in "${!provisioning_public_keys[@]}"; do
  test "${provisioning_public_keys[$index]}" = "${sorted_provisioning_keys[$index]}"
  python3 -B "$repository_root/tools/james-release.py" validate-public-key \
    --trusted-public-key "${provisioning_public_keys[$index]}" >/dev/null
done
[[ "$snapshot_id" =~ ^[0-9]{8}T[0-9]{6}Z$ ]]
SOURCE_DATE_EPOCH="$(
  python3 -B "$repository_root/ubuntu-appliance/snapshot-release-date.py" \
    --epoch "$snapshot_id"
)"
export SOURCE_DATE_EPOCH

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

james_root="$work_dir/cybex-james"
mkdir -p -- \
  "$james_root/DEBIAN" \
  "$james_root/usr/bin" \
  "$james_root/usr/share/cybex-james/manage-source"
install -m 0755 "$james_binary" "$james_root/usr/bin/cybex-james"
"$repository_root/ubuntu-appliance/build-manage-source-archive.sh" \
  --source-dir "$manage_source_dir" \
  --revision "$manage_source_revision" \
  --output-dir "$james_root/usr/share/cybex-james/manage-source" \
  >/dev/null
cat > "$james_root/DEBIAN/control" <<EOF
Package: cybex-james
Version: ${version}-1
Section: admin
Priority: optional
Architecture: amd64
Maintainer: Cybex <support@cybex.net>
Depends: libc6, libgcc-s1, ca-certificates
Description: Cybex James build and network-boot service
EOF
build_package "$james_root" cybex-james

bootstrap_root="$work_dir/cybex-james-bootstrap"
mkdir -p -- "$bootstrap_root/DEBIAN" "$bootstrap_root/usr/lib/cybex-james"
install -m 0755 "$bootstrap_binary" "$bootstrap_root/usr/lib/cybex-james/cybex-james-bootstrap"
cat > "$bootstrap_root/DEBIAN/control" <<EOF
Package: cybex-james-bootstrap
Version: ${version}-1
Section: admin
Priority: optional
Architecture: amd64
Maintainer: Cybex <support@cybex.net>
Depends: libc6, libgcc-s1, ca-certificates, iproute2, util-linux, gdisk, e2fsprogs, efibootmgr, parted, iputils-arping, systemd
Description: Fail-closed Cybex James provisioned-media bootstrap
EOF
build_package "$bootstrap_root" cybex-james-bootstrap

appliance_root="$work_dir/cybex-james-appliance"
mkdir -p -- "$appliance_root/DEBIAN" "$appliance_root/usr/share/cybex-james"
cp -a "$repository_root/ubuntu-appliance/rootfs/." "$appliance_root/"
install -D -m 0644 "$repository_root/assets/pxe-menu.png" \
  "$appliance_root/usr/share/cybex-james/assets/pxe-menu.png"
printf '%s\n' "$release_public_key" > "$appliance_root/usr/share/cybex-james/release-public-key"
printf '%s\n' "${provisioning_public_keys[@]}" \
  > "$appliance_root/usr/share/cybex-james/provisioning-public-keys"
chmod 0644 "$appliance_root/usr/share/cybex-james/release-public-key" \
  "$appliance_root/usr/share/cybex-james/provisioning-public-keys"
install -m 0755 "$repository_root/ubuntu-appliance/package/cybex-james-appliance.postinst" "$appliance_root/DEBIAN/postinst"
jq -n \
  --arg schema 'cybex.james.appliance-release.v1' \
  --arg release_id "$version" \
  --arg ubuntu_snapshot_id "$snapshot_id" \
  '{schema:$schema,release_id:$release_id,ubuntu_snapshot_id:$ubuntu_snapshot_id,root_generation:"0"}' \
  > "$appliance_root/usr/share/cybex-james/appliance-release.json"
chmod 0644 "$appliance_root/usr/share/cybex-james/appliance-release.json"
cat > "$appliance_root/DEBIAN/control" <<EOF
Package: cybex-james-appliance
Version: ${version}-1
Section: admin
Priority: optional
Architecture: amd64
Maintainer: Cybex <support@cybex.net>
Depends: cybex-james (= ${version}-1), cybex-james-bootstrap (= ${version}-1), systemd, nginx-core, tftpd-hpa, ipxe, iproute2, openssh-server, nftables, netplan.io, btrfs-progs, watchdog, nix-bin, nix-setup-systemd, curl, dnsutils, jq, python3, mokutil, sbsigntool, shim-signed, grub-efi-amd64-signed, secureboot-db, linux-generic, linux-firmware, intel-microcode, amd64-microcode
Description: Managed Ubuntu host integration for Cybex James
EOF
build_package "$appliance_root" cybex-james-appliance

sha256sum "$output"/*.deb | LC_ALL=C sort -k2 > "$output/CYBEX-PACKAGES.sha256"
