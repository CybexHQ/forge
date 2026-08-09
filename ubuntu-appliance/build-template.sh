#!/usr/bin/env bash
set -Eeuo pipefail
umask 022

usage() {
  echo "usage: $0 --output-dir DIR --bootstrap-binary FILE --version SEMVER --ubuntu-snapshot-id ID --release-public-key BASE64 --provisioning-public-key BASE64 [--provisioning-public-key BASE64 ...] [--cache-dir DIR]" >&2
  exit 2
}

hidden_efi_image_sha256() {
  local iso="$1" report="$2"
  local start_lba sector_size sector_count block_size
  local -a geometries=()
  xorriso -indev "$iso" -report_el_torito plain > "$report" 2>&1
  mapfile -t geometries < <(
    sed -n -E \
      's/.*EFI image start and size: ([0-9]+) \* ([0-9]+) , ([0-9]+) \* ([0-9]+).*/\1 \2 \3 \4/p' \
      "$report"
  )
  test "${#geometries[@]}" -eq 1 || {
    echo "error: could not resolve the hidden UEFI El Torito image" >&2
    return 1
  }
  read -r start_lba sector_size sector_count block_size <<<"${geometries[0]}"
  [[ "$start_lba" =~ ^[1-9][0-9]*$ ]]
  [[ "$sector_size" =~ ^[1-9][0-9]*$ ]]
  [[ "$sector_count" =~ ^[1-9][0-9]*$ ]]
  [[ "$block_size" =~ ^[1-9][0-9]*$ ]]
  dd if="$iso" iflag=skip_bytes,count_bytes \
    skip="$((start_lba * sector_size))" \
    count="$((sector_count * block_size))" status=none \
    | sha256sum | awk '{print $1}'
}

repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
lock_file="$repository_root/ubuntu-appliance/base-iso.json"
output_dir=""
bootstrap_binary=""
version=""
snapshot_id=""
release_public_key=""
cache_dir=""
declare -a provisioning_keys=()

while (($#)); do
  case "$1" in
    --output-dir) output_dir="${2:-}"; shift 2 ;;
    --bootstrap-binary) bootstrap_binary="${2:-}"; shift 2 ;;
    --version) version="${2:-}"; shift 2 ;;
    --ubuntu-snapshot-id) snapshot_id="${2:-}"; shift 2 ;;
    --release-public-key) release_public_key="${2:-}"; shift 2 ;;
    --provisioning-public-key) provisioning_keys+=("${2:-}"); shift 2 ;;
    --cache-dir) cache_dir="${2:-}"; shift 2 ;;
    *) usage ;;
  esac
done

test -n "$output_dir" && test -n "$bootstrap_binary"
test -n "$version" && test -n "$snapshot_id" && test -n "$release_public_key"
test "${#provisioning_keys[@]}" -ge 1
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.-]+)?$ ]]
[[ "$snapshot_id" =~ ^[0-9]{8}T[0-9]{6}Z$ ]]
test -f "$bootstrap_binary" && test -x "$bootstrap_binary"
test -f "$lock_file"
python3 -B "$repository_root/tools/forge-release.py" validate-public-key \
  --trusted-public-key "$release_public_key" >/dev/null

for command_name in curl gpgv jq sha256sum stat xorriso sed cmp awk; do
  command -v "$command_name" >/dev/null || {
    echo "error: required command is unavailable: $command_name" >&2
    exit 1
  }
done

mapfile -t sorted_keys < <(printf '%s\n' "${provisioning_keys[@]}" | LC_ALL=C sort -u)
test "${#sorted_keys[@]}" -eq "${#provisioning_keys[@]}" || {
  echo "error: provisioning public keys must be unique" >&2
  exit 1
}
for index in "${!sorted_keys[@]}"; do
  test "${sorted_keys[$index]}" = "${provisioning_keys[$index]}" || {
    echo "error: provisioning public keys must be supplied in sorted order" >&2
    exit 1
  }
  python3 -B "$repository_root/tools/forge-release.py" validate-public-key \
    --trusted-public-key "${sorted_keys[$index]}" >/dev/null
done

mkdir -p -- "$output_dir"
output_dir="$(cd -- "$output_dir" && pwd -P)"
if [[ -z "$cache_dir" ]]; then
  cache_dir="$output_dir/cache"
fi
mkdir -p -- "$cache_dir"
cache_dir="$(cd -- "$cache_dir" && pwd -P)"

base_filename="$(jq -er '.filename' "$lock_file")"
base_url="$(jq -er '.url' "$lock_file")"
base_sha256="$(jq -er '.sha256' "$lock_file")"
base_size="$(jq -er '.size_bytes' "$lock_file")"
checksums_url="$(jq -er '.checksums_url' "$lock_file")"
signature_url="$(jq -er '.checksums_signature_url' "$lock_file")"
test "$(jq -er '.schema' "$lock_file")" = "cybex.forge.ubuntu-base-iso.v1"
test "$(jq -er '.version' "$lock_file")" = "26.04"
test "$(jq -er '.architecture' "$lock_file")" = "amd64"
[[ "$base_sha256" =~ ^[0-9a-f]{64}$ ]]
[[ "$base_size" =~ ^[1-9][0-9]*$ ]]

base_iso="$cache_dir/$base_filename"
checksums="$cache_dir/SHA256SUMS"
checksums_signature="$cache_dir/SHA256SUMS.gpg"
if [[ ! -f "$base_iso" ]] \
  || [[ "$(stat -c '%s' "$base_iso")" != "$base_size" ]] \
  || [[ "$(sha256sum "$base_iso" | awk '{print $1}')" != "$base_sha256" ]]; then
  curl --fail --location --proto '=https' --tlsv1.2 --retry 5 --output "$base_iso.part" "$base_url"
  mv -- "$base_iso.part" "$base_iso"
fi
curl --fail --location --proto '=https' --tlsv1.2 --retry 5 --output "$checksums.part" "$checksums_url"
mv -- "$checksums.part" "$checksums"
curl --fail --location --proto '=https' --tlsv1.2 --retry 5 --output "$checksums_signature.part" "$signature_url"
mv -- "$checksums_signature.part" "$checksums_signature"

ubuntu_keyring=/usr/share/keyrings/ubuntu-archive-keyring.gpg
test -f "$ubuntu_keyring" || {
  echo "error: ubuntu-keyring is required to authenticate the Canonical ISO" >&2
  exit 1
}
gpgv --keyring "$ubuntu_keyring" "$checksums_signature" "$checksums"
grep -Fx "$base_sha256 *$base_filename" "$checksums" >/dev/null
test "$(sha256sum "$base_iso" | awk '{print $1}')" = "$base_sha256"
test "$(stat -c '%s' "$base_iso")" = "$base_size"

work_dir="$(mktemp -d "$output_dir/.ubuntu-template.XXXXXXXX")"
cleanup() {
  rm -rf -- "$work_dir"
}
trap cleanup EXIT
iso_tree="$work_dir/iso"
mkdir -p -- "$iso_tree"
xorriso -osirrox on -indev "$base_iso" -extract / "$iso_tree"
chmod -R u+w -- "$iso_tree"

find "$iso_tree" -type f -iname '*.efi' -print0 \
  | LC_ALL=C sort -z \
  | xargs -0 -r sha256sum > "$work_dir/efi-before.sha256"
base_hidden_efi_sha256="$(hidden_efi_image_sha256 \
  "$base_iso" "$work_dir/base-el-torito.txt")"

declare -a required_casper_paths=(
  casper/vmlinuz
  casper/initrd
  casper/install-sources.yaml
  casper/ubuntu-server-minimal.squashfs
  casper/ubuntu-server-minimal.ubuntu-server.squashfs
  casper/ubuntu-server-minimal.ubuntu-server.installer.squashfs
)
for live_path in "${required_casper_paths[@]}"; do
  test -f "$iso_tree/$live_path" || {
    echo "error: pinned Ubuntu ISO omitted required live installer payload /$live_path" >&2
    exit 1
  }
done

# The downloaded, release-signed package snapshot supplies the complete target
# closure. Ubuntu's target package pools duplicate that closure and include
# hardware-specific proprietary drivers which are not needed by the live
# installer environment in /casper.
rm -rf -- "$iso_tree/pool" "$iso_tree/dists"
test ! -e "$iso_tree/pool" && test ! -e "$iso_tree/dists"

mkdir -p -- "$iso_tree/nocloud" "$iso_tree/cybex/bootstrap"
install -m 0644 "$repository_root/ubuntu-appliance/nocloud/user-data" "$iso_tree/nocloud/user-data"
install -m 0644 "$repository_root/ubuntu-appliance/nocloud/meta-data" "$iso_tree/nocloud/meta-data"
install -m 0755 "$bootstrap_binary" "$iso_tree/cybex/bootstrap/cybex-forge-bootstrap"
printf '%s\n' "${provisioning_keys[@]}" > "$iso_tree/cybex/provisioning-public-keys"
printf '%s\n' "$release_public_key" > "$iso_tree/cybex/release-public-key"
chmod 0644 "$iso_tree/cybex/provisioning-public-keys" "$iso_tree/cybex/release-public-key"
truncate -s 8192 "$iso_tree/CYBEX_PROVISIONING.BIN"

kernel_arguments='autoinstall ds=nocloud\\;s=/cdrom/nocloud/ console=tty0 console=ttyS0,115200n8'
while IFS= read -r -d '' grub_config; do
  if ! grep -F 'ds=nocloud' "$grub_config" >/dev/null; then
    sed -i -E "s#([[:space:]]+---[[:space:]]*)\$# ${kernel_arguments} ---#" "$grub_config"
  fi
done < <(find "$iso_tree" -type f \( -name 'grub.cfg' -o -name 'loopback.cfg' -o -name 'txt.cfg' \) -print0)

find "$iso_tree" -type f -iname '*.efi' -print0 \
  | LC_ALL=C sort -z \
  | xargs -0 -r sha256sum > "$work_dir/efi-after.sha256"
cmp "$work_dir/efi-before.sha256" "$work_dir/efi-after.sha256"

output_iso="$output_dir/cybex-forge-appliance-template-$version-x86_64-linux.iso"
test ! -e "$output_iso" || {
  echo "error: refusing to overwrite existing release candidate $output_iso" >&2
  exit 1
}
xorriso \
  -indev "$base_iso" \
  -outdev "$output_iso" \
  -update_r "$iso_tree" / \
  -boot_image any replay \
  -compliance no_emul_toc \
  -padding 0
output_hidden_efi_sha256="$(hidden_efi_image_sha256 \
  "$output_iso" "$work_dir/output-el-torito.txt")"
test "$output_hidden_efi_sha256" = "$base_hidden_efi_sha256" || {
  echo "error: remastered ISO changed the hidden UEFI El Torito image bytes" >&2
  exit 1
}

iso_top_level="$work_dir/iso-top-level.txt"
xorriso -indev "$output_iso" -find / -maxdepth 2 -exec echo -- \
  2>/dev/null | sed -E "s/^'(.*)'$/\1/" > "$iso_top_level"
if grep -E '^/(pool|dists)(/|$)|^/cybex/apt(/|$)' "$iso_top_level" >/dev/null; then
  echo "error: thin installer ISO retained a target package repository" >&2
  exit 1
fi
for live_path in "${required_casper_paths[@]}"; do
  grep -Fx "/$live_path" "$iso_top_level" >/dev/null || {
    echo "error: thin installer ISO omitted required live payload /$live_path" >&2
    exit 1
  }
done

lba_report="$work_dir/personalization-lba.txt"
xorriso -indev "$output_iso" -find /CYBEX_PROVISIONING.BIN -exec report_lba -- \
  > "$lba_report" 2>&1
personalization_lba="$(sed -n -E 's/.*File data lba:[[:space:]]*[0-9]+[[:space:]]*,[[:space:]]*([0-9]+)[[:space:]]*,.*/\1/p' "$lba_report")"
[[ "$personalization_lba" =~ ^[1-9][0-9]*$ ]] || {
  echo "error: could not resolve the fixed ISO personalization slot" >&2
  exit 1
}
personalization_offset=$((personalization_lba * 2048))
placeholder_sha256="$(dd if="$output_iso" iflag=skip_bytes,count_bytes skip="$personalization_offset" count=8192 status=none | sha256sum | awk '{print $1}')"
expected_placeholder_sha256="$(head -c 8192 /dev/zero | sha256sum | awk '{print $1}')"
test "$placeholder_sha256" = "$expected_placeholder_sha256"
template_sha256="$(sha256sum "$output_iso" | awk '{print $1}')"
template_size="$(stat -c '%s' "$output_iso")"

metadata="$output_dir/cybex-forge-appliance-template-$version-x86_64-linux.json"
jq -n \
  --arg schema 'cybex.forge.installer-template-build.v1' \
  --arg version "$version" \
  --arg package_delivery 'network-snapshot-v1' \
  --arg template_sha256 "$template_sha256" \
  --arg placeholder_sha256 "$placeholder_sha256" \
  --arg ubuntu_snapshot_id "$snapshot_id" \
  --argjson size_bytes "$template_size" \
  --argjson personalization_offset "$personalization_offset" \
  --argjson personalization_size 8192 \
  --argjson provisioning_public_keys "$(printf '%s\n' "${provisioning_keys[@]}" | jq -R . | jq -s .)" \
  '{schema:$schema,version:$version,architecture:"x86_64-linux",base_os:"ubuntu",base_os_version:"26.04",package_delivery:$package_delivery,size_bytes:$size_bytes,template_sha256:$template_sha256,personalization_offset:$personalization_offset,personalization_size:$personalization_size,placeholder_sha256:$placeholder_sha256,ubuntu_snapshot_id:$ubuntu_snapshot_id,provisioning_public_keys:$provisioning_public_keys}' \
  > "$metadata"
echo "built provisionable Ubuntu Forge ISO template: $output_iso"
echo "personalization_offset=$personalization_offset"
