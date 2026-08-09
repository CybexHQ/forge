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
test -n "$version" && test -n "$release_public_key"
[[ "$snapshot_id" =~ ^[0-9]{8}T[0-9]{6}Z$ ]]
python3 -B "$repository_root/tools/pulse-release.py" validate-public-key \
  --trusted-public-key "$release_public_key" >/dev/null
mkdir -p -- "$output"
output="$(cd -- "$output" && pwd -P)"
test -z "$(find "$output" -mindepth 1 -maxdepth 1 -print -quit)" || {
  echo "error: offline repository output must be empty" >&2
  exit 1
}

work_dir="$(mktemp -d)"
cleanup() { rm -rf -- "$work_dir"; }
trap cleanup EXIT
local_packages="$work_dir/local"
mkdir -p -- "$local_packages"
"$repository_root/ubuntu-appliance/build-packages.sh" \
  --output "$local_packages" \
  --pulse-binary "$pulse_binary" \
  --bootstrap-binary "$bootstrap_binary" \
  --version "$version" \
  --ubuntu-snapshot-id "$snapshot_id" \
  --release-public-key "$release_public_key"

apt_root="$work_dir/apt-root"
mkdir -p \
  "$apt_root/etc/apt/apt.conf.d" \
  "$apt_root/etc/apt/sources.list.d" \
  "$apt_root/var/lib/apt/lists/partial" \
  "$apt_root/var/lib/dpkg" \
  "$apt_root/var/cache/apt/archives/partial" \
  "$apt_root/var/log/apt"
: > "$apt_root/var/lib/dpkg/status"
snapshot_base="https://snapshot.ubuntu.com/ubuntu/$snapshot_id"
cat > "$apt_root/etc/apt/sources.list" <<EOF
deb [arch=amd64 signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] $snapshot_base/ resolute main restricted universe multiverse
deb [arch=amd64 signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] $snapshot_base/ resolute-updates main restricted universe multiverse
deb [arch=amd64 signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] $snapshot_base/ resolute-security main restricted universe multiverse
EOF
cat > "$apt_root/etc/apt/apt.conf.d/99cybex-snapshot" <<'EOF'
Acquire::Check-Valid-Until "false";
Acquire::Languages "none";
APT::Install-Recommends "false";
APT::Install-Suggests "false";
EOF

declare -a apt_options=(
  -o "Dir=$apt_root"
  -o "Dir::Etc::sourcelist=$apt_root/etc/apt/sources.list"
  -o "Dir::Etc::sourceparts=$apt_root/etc/apt/sources.list.d"
  -o "Dir::Etc::main=$apt_root/etc/apt/apt.conf"
  -o "Dir::State::status=$apt_root/var/lib/dpkg/status"
  -o "Dir::Cache::archives=$apt_root/var/cache/apt/archives"
  -o APT::Architecture=amd64
  -o Acquire::Check-Valid-Until=false
)
apt-get "${apt_options[@]}" update

declare -a packages=(
  amd64-microcode
  btrfs-progs
  ca-certificates
  curl
  dnsutils
  e2fsprogs
  efibootmgr
  gdisk
  grub-efi-amd64
  grub-efi-amd64-signed
  intel-microcode
  iproute2
  iputils-arping
  ipxe
  jq
  libgcc-s1
  libc6
  linux-firmware
  linux-generic
  mokutil
  netplan.io
  nftables
  nginx-core
  nix-bin
  nix-setup-systemd
  openssh-server
  parted
  sbsigntool
  secureboot-db
  shim-signed
  systemd
  tftpd-hpa
  ubuntu-keyring
  util-linux
  watchdog
)
apt-get "${apt_options[@]}" --yes --download-only --no-install-recommends install "${packages[@]}"

find "$apt_root/var/cache/apt/archives" -maxdepth 1 -type f -name '*.deb' -exec cp -t "$output" -- {} +
find "$local_packages" -maxdepth 1 -type f -name '*.deb' -exec cp -t "$output" -- {} +

while IFS= read -r -d '' package; do
  architecture="$(dpkg-deb -f "$package" Architecture)"
  case "$architecture" in amd64|all) ;; *) echo "error: unexpected package architecture $architecture" >&2; exit 1 ;; esac
  dpkg-deb --info "$package" >/dev/null
done < <(find "$output" -maxdepth 1 -type f -name '*.deb' -print0)

(
  cd -- "$output"
  dpkg-scanpackages --multiversion . /dev/null > Packages
  gzip -n -9 -c Packages > Packages.gz
  apt-ftparchive \
    -o APT::FTPArchive::Release::Origin='Cybex' \
    -o APT::FTPArchive::Release::Label='Cybex Pulse Offline' \
    -o APT::FTPArchive::Release::Suite='resolute' \
    -o APT::FTPArchive::Release::Codename='resolute' \
    -o APT::FTPArchive::Release::Architectures='amd64' \
    release . > Release
  sha256sum ./*.deb Packages Packages.gz Release | LC_ALL=C sort -k2 > SHA256SUMS
  printf '%s\n' "$snapshot_id" > UBUNTU-SNAPSHOT-ID
)
