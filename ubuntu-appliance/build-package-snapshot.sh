#!/usr/bin/env bash
set -Eeuo pipefail
umask 022

usage() {
  echo "usage: $0 --output-dir DIR --pulse-binary FILE --bootstrap-binary FILE --version SEMVER --ubuntu-snapshot-id ID --release-public-key BASE64" >&2
  exit 2
}

repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
output_dir=""
pulse_binary=""
bootstrap_binary=""
version=""
snapshot_id=""
release_public_key=""

while (($#)); do
  case "$1" in
    --output-dir) output_dir="${2:-}"; shift 2 ;;
    --pulse-binary) pulse_binary="${2:-}"; shift 2 ;;
    --bootstrap-binary) bootstrap_binary="${2:-}"; shift 2 ;;
    --version) version="${2:-}"; shift 2 ;;
    --ubuntu-snapshot-id) snapshot_id="${2:-}"; shift 2 ;;
    --release-public-key) release_public_key="${2:-}"; shift 2 ;;
    *) usage ;;
  esac
done

test -n "$output_dir" && test -n "$pulse_binary" && test -n "$bootstrap_binary"
test -n "$version" && test -n "$snapshot_id" && test -n "$release_public_key"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.-]+)?$ ]]
[[ "$snapshot_id" =~ ^[0-9]{8}T[0-9]{6}Z$ ]]
test -f "$pulse_binary" && test -x "$pulse_binary"
test -f "$bootstrap_binary" && test -x "$bootstrap_binary"

for command_name in \
  apt-ftparchive \
  apt-get \
  awk \
  dpkg-deb \
  dpkg-scanpackages \
  gzip \
  jq \
  python3 \
  sha256sum \
  sort \
  stat \
  tar \
  zstd
do
  command -v "$command_name" >/dev/null || {
    echo "error: required command is unavailable: $command_name" >&2
    exit 1
  }
done
python3 -B "$repository_root/tools/pulse-release.py" validate-public-key \
  --trusted-public-key "$release_public_key" >/dev/null

mkdir -p -- "$output_dir"
output_dir="$(cd -- "$output_dir" && pwd -P)"
package_bundle_name="cybex-pulse-appliance-packages-$version-x86_64-linux.tar.zst"
package_metadata_name="cybex-pulse-appliance-packages-$version-x86_64-linux.json"
test ! -e "$output_dir/$package_bundle_name" || {
  echo "error: refusing to overwrite existing release candidate $output_dir/$package_bundle_name" >&2
  exit 1
}
test ! -e "$output_dir/$package_metadata_name" || {
  echo "error: refusing to overwrite existing release candidate $output_dir/$package_metadata_name" >&2
  exit 1
}

work_dir="$(mktemp -d "$output_dir/.package-snapshot.XXXXXXXX")"
cleanup() {
  rm -rf -- "$work_dir"
}
trap cleanup EXIT
offline_repository="$work_dir/apt"
mkdir -p -- "$offline_repository"

"$repository_root/ubuntu-appliance/build-offline-repo.sh" \
  --output "$offline_repository" \
  --pulse-binary "$pulse_binary" \
  --bootstrap-binary "$bootstrap_binary" \
  --version "$version" \
  --ubuntu-snapshot-id "$snapshot_id" \
  --release-public-key "$release_public_key"

package_bundle="$work_dir/$package_bundle_name"
tar --format=ustar --sort=name --numeric-owner --owner=0 --group=0 \
  --mode=u=rwX,go=rX --mtime='@0' -C "$offline_repository" -cf - . \
  | zstd -19 --threads=1 --no-progress --no-dictID -o "$package_bundle"

required_versions='{}'
for package_name in \
  cybex-pulse \
  cybex-pulse-bootstrap \
  cybex-pulse-appliance \
  linux-generic \
  linux-firmware \
  nix-bin
do
  package_version=""
  while IFS= read -r -d '' package_file; do
    if [[ "$(dpkg-deb -f "$package_file" Package)" = "$package_name" ]]; then
      package_version="$(dpkg-deb -f "$package_file" Version)"
      break
    fi
  done < <(find "$offline_repository" -maxdepth 1 -type f -name '*.deb' -print0 | LC_ALL=C sort -z)
  test -n "$package_version" || {
    echo "error: offline repository omitted required package $package_name" >&2
    exit 1
  }
  required_versions="$(jq -c --arg package "$package_name" --arg version "$package_version" '. + {($package):$version}' <<<"$required_versions")"
done

# These packages are required only by thin-media installation. Keep them out
# of appliance_release_v1.required_package_versions, whose exact historical
# six-package map is consumed by already-deployed agents. The signed snapshot
# digest binds these installer packages along with the rest of the repository.
for package_name in grub-efi-amd64 grub-efi-amd64-signed shim-signed; do
  package_present=false
  while IFS= read -r -d '' package_file; do
    if [[ "$(dpkg-deb -f "$package_file" Package)" = "$package_name" ]]; then
      package_present=true
      break
    fi
  done < <(find "$offline_repository" -maxdepth 1 -type f -name '*.deb' -print0 | LC_ALL=C sort -z)
  test "$package_present" = true || {
    echo "error: thin installer repository omitted required package $package_name" >&2
    exit 1
  }
done

package_metadata="$work_dir/$package_metadata_name"
jq -n \
  --arg schema 'cybex.pulse.appliance-package-snapshot.v1' \
  --arg release_id "$version" \
  --arg ubuntu_snapshot_id "$snapshot_id" \
  --arg filename "$package_bundle_name" \
  --arg sha256 "$(sha256sum "$package_bundle" | awk '{print $1}')" \
  --argjson size_bytes "$(stat -c '%s' "$package_bundle")" \
  --argjson required_package_versions "$required_versions" \
  '{schema:$schema,release_id:$release_id,ubuntu_snapshot_id:$ubuntu_snapshot_id,filename:$filename,sha256:$sha256,size_bytes:$size_bytes,required_package_versions:$required_package_versions,expected_kernel:$required_package_versions["linux-generic"],minimum_protocol:4,minimum_state_schema:1,rollback_compatible:true}' \
  > "$package_metadata"

mv -- "$package_bundle" "$output_dir/$package_bundle_name"
mv -- "$package_metadata" "$output_dir/$package_metadata_name"

echo "built Pulse appliance package snapshot: $output_dir/$package_bundle_name"
