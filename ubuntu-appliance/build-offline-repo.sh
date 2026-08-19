#!/usr/bin/env bash
set -Eeuo pipefail
umask 022

usage() {
  echo "usage: $0 --output DIR --james-binary FILE --bootstrap-binary FILE --version SEMVER --ubuntu-snapshot-id ID --manage-source-dir DIR --manage-source-revision 40_HEX --release-public-key BASE64 --provisioning-public-key BASE64 [--provisioning-public-key BASE64 ...] [--previous-package-snapshot FILE]" >&2
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
previous_package_snapshot=""
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
    --previous-package-snapshot)
      if [[ -n "$previous_package_snapshot" || -z "${2:-}" ]]; then
        usage
      fi
      previous_package_snapshot="$2"
      shift 2
      ;;
    *) usage ;;
  esac
done
test -n "$output" && test -n "$james_binary" && test -n "$bootstrap_binary"
test -n "$version" && test -n "$release_public_key"
test -n "$manage_source_dir" && test -n "$manage_source_revision"
test "${#provisioning_public_keys[@]}" -ge 1 && test "${#provisioning_public_keys[@]}" -le 8
declare -a provisioning_key_arguments=()
for key in "${provisioning_public_keys[@]}"; do
  provisioning_key_arguments+=(--provisioning-public-key "$key")
done
[[ "$snapshot_id" =~ ^[0-9]{8}T[0-9]{6}Z$ ]]
if [[ -n "$previous_package_snapshot" ]]; then
  if [[ ! -f "$previous_package_snapshot" || -L "$previous_package_snapshot" ]]; then
    echo "error: previous package snapshot must be a regular, non-symlink file" >&2
    exit 1
  fi
fi
python3 -B "$repository_root/tools/james-release.py" validate-public-key \
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
  --james-binary "$james_binary" \
  --bootstrap-binary "$bootstrap_binary" \
  --version "$version" \
  --ubuntu-snapshot-id "$snapshot_id" \
  --manage-source-dir "$manage_source_dir" \
  --manage-source-revision "$manage_source_revision" \
  --release-public-key "$release_public_key" \
  "${provisioning_key_arguments[@]}"

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
  -o Acquire::ForceHash=sha256
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
  python3
  sbsigntool
  secureboot-db
  shim-signed
  systemd
  tftpd-hpa
  ubuntu-keyring
  util-linux
  watchdog
)

if [[ -n "$previous_package_snapshot" ]]; then
  apt_uri_plan="$work_dir/apt-print-uris"
  apt-get "${apt_options[@]}" \
    --yes --download-only --no-install-recommends --print-uris \
    install "${packages[@]}" > "$apt_uri_plan"

  seed_packages="$work_dir/seed-packages"
  mkdir -p -- "$seed_packages"
  python3 -B "$repository_root/ubuntu-appliance/extract-package-cache-seed.py" \
    --snapshot "$previous_package_snapshot" \
    --expected-ubuntu-snapshot-id "$snapshot_id" \
    --apt-print-uris "$apt_uri_plan" \
    --output "$seed_packages"

  while IFS= read -r -d '' package; do
    destination="$apt_root/var/cache/apt/archives/${package##*/}"
    test ! -e "$destination" || {
      echo "error: refusing to overwrite an existing APT archive cache entry" >&2
      exit 1
    }
    # The private work tree is one filesystem. The seed reader has already
    # matched this byte stream to the strong SHA256 in APT's authenticated
    # current-snapshot plan. A hard link is an atomic, no-overwrite import.
    ln -- "$package" "$destination"
  done < <(find "$seed_packages" -maxdepth 1 -type f -name '*.deb' -print0 | LC_ALL=C sort -z)
fi

apt-get "${apt_options[@]}" --yes --download-only --no-install-recommends install "${packages[@]}"

find "$apt_root/var/cache/apt/archives" -maxdepth 1 -type f -name '*.deb' -exec cp -t "$output" -- {} +
find "$local_packages" -maxdepth 1 -type f -name '*.deb' -exec cp -t "$output" -- {} +

while IFS= read -r -d '' package; do
  architecture="$(dpkg-deb -f "$package" Architecture)"
  case "$architecture" in amd64|all) ;; *) echo "error: unexpected package architecture $architecture" >&2; exit 1 ;; esac
  dpkg-deb --info "$package" >/dev/null
done < <(find "$output" -maxdepth 1 -type f -name '*.deb' -print0)

release_date="$(
  python3 -B "$repository_root/ubuntu-appliance/snapshot-release-date.py" "$snapshot_id"
)"

(
  cd -- "$output"
  dpkg-scanpackages --multiversion . /dev/null > Packages
  gzip -n -9 -c Packages > Packages.gz
  apt-ftparchive \
    -o APT::FTPArchive::Release::Origin='Cybex' \
    -o APT::FTPArchive::Release::Label='Cybex James Offline' \
    -o APT::FTPArchive::Release::Suite='resolute' \
    -o APT::FTPArchive::Release::Codename='resolute' \
    -o APT::FTPArchive::Release::Architectures='amd64' \
    -o APT::FTPArchive::Release::Date="$release_date" \
    release . > Release
  sha256sum ./*.deb Packages Packages.gz Release | LC_ALL=C sort -k2 > SHA256SUMS
  printf '%s\n' "$snapshot_id" > UBUNTU-SNAPSHOT-ID
)
