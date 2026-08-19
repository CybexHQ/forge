#!/usr/bin/env bash
set -Eeuo pipefail
umask 022

usage() {
  echo "usage: $0 --output-dir DIR --james-binary FILE --bootstrap-binary FILE --version SEMVER --ubuntu-snapshot-id ID --manage-source-dir DIR --manage-source-revision 40_HEX --expected-manage-origin HTTPS_ORIGIN --release-public-key BASE64 --provisioning-public-key BASE64 [--provisioning-public-key BASE64 ...] [--previous-package-snapshot FILE]" >&2
  exit 2
}

repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
output_dir=""
james_binary=""
bootstrap_binary=""
version=""
snapshot_id=""
manage_source_dir=""
manage_source_revision=""
expected_manage_origin=""
release_public_key=""
declare -a provisioning_public_keys=()
previous_package_snapshot=""

while (($#)); do
  case "$1" in
    --output-dir) output_dir="${2:-}"; shift 2 ;;
    --james-binary) james_binary="${2:-}"; shift 2 ;;
    --bootstrap-binary) bootstrap_binary="${2:-}"; shift 2 ;;
    --version) version="${2:-}"; shift 2 ;;
    --ubuntu-snapshot-id) snapshot_id="${2:-}"; shift 2 ;;
    --manage-source-dir) manage_source_dir="${2:-}"; shift 2 ;;
    --manage-source-revision) manage_source_revision="${2:-}"; shift 2 ;;
    --expected-manage-origin) expected_manage_origin="${2:-}"; shift 2 ;;
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

test -n "$output_dir" && test -n "$james_binary" && test -n "$bootstrap_binary"
test -n "$version" && test -n "$snapshot_id" && test -n "$expected_manage_origin"
test -n "$manage_source_dir" && test -n "$manage_source_revision"
test -n "$release_public_key"
test "${#provisioning_public_keys[@]}" -ge 1 && test "${#provisioning_public_keys[@]}" -le 8
declare -a provisioning_key_arguments=()
for key in "${provisioning_public_keys[@]}"; do
  provisioning_key_arguments+=(--provisioning-public-key "$key")
done
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.-]+)?$ ]]
[[ "$snapshot_id" =~ ^[0-9]{8}T[0-9]{6}Z$ ]]
test -f "$james_binary" && test -x "$james_binary"
test -f "$bootstrap_binary" && test -x "$bootstrap_binary"
if [[ -n "$previous_package_snapshot" ]]; then
  if [[ ! -f "$previous_package_snapshot" || -L "$previous_package_snapshot" ]]; then
    echo "error: previous package snapshot must be a regular, non-symlink file" >&2
    exit 1
  fi
fi

for command_name in \
  apt-ftparchive \
  apt-get \
  awk \
  cmp \
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
python3 -B "$repository_root/tools/james-release.py" validate-public-key \
  --trusted-public-key "$release_public_key" >/dev/null
python3 -B "$repository_root/tools/james-release.py" validate-manage-origin \
  --expected-manage-origin "$expected_manage_origin" >/dev/null
bootstrap_manage_origin="$("$bootstrap_binary" required-manage-origin)"
test "$bootstrap_manage_origin" = "$expected_manage_origin" || {
  echo "error: package bootstrap requires $bootstrap_manage_origin but the explicit expected Management origin is $expected_manage_origin" >&2
  exit 1
}

mkdir -p -- "$output_dir"
output_dir="$(cd -- "$output_dir" && pwd -P)"
package_bundle_name="cybex-james-appliance-packages-$version-x86_64-linux.tar.zst"
package_metadata_name="cybex-james-appliance-packages-$version-x86_64-linux.json"
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
manage_source_reference="$work_dir/manage-source"
"$repository_root/ubuntu-appliance/build-manage-source-archive.sh" \
  --source-dir "$manage_source_dir" \
  --revision "$manage_source_revision" \
  --output-dir "$manage_source_reference" \
  >/dev/null
manage_source_metadata="$manage_source_reference/$manage_source_revision.json"
manage_source_sha256="$(jq -er '.sha256' "$manage_source_metadata")"
manage_source_size_bytes="$(jq -er '.size_bytes' "$manage_source_metadata")"
offline_repository="$work_dir/apt"
mkdir -p -- "$offline_repository"

declare -a previous_snapshot_arguments=()
if [[ -n "$previous_package_snapshot" ]]; then
  previous_snapshot_arguments=(--previous-package-snapshot "$previous_package_snapshot")
fi

"$repository_root/ubuntu-appliance/build-offline-repo.sh" \
  --output "$offline_repository" \
  --james-binary "$james_binary" \
  --bootstrap-binary "$bootstrap_binary" \
  --version "$version" \
  --ubuntu-snapshot-id "$snapshot_id" \
  --manage-source-dir "$manage_source_dir" \
  --manage-source-revision "$manage_source_revision" \
  --release-public-key "$release_public_key" \
  "${provisioning_key_arguments[@]}" \
  "${previous_snapshot_arguments[@]}"

package_bundle="$work_dir/$package_bundle_name"
tar --format=ustar --sort=name --numeric-owner --owner=0 --group=0 \
  --mode=u=rwX,go=rX --mtime='@0' -C "$offline_repository" -cf - . \
  | zstd -19 --threads=1 --no-progress --no-dictID -o "$package_bundle"

required_versions='{}'
for package_name in \
  cybex-james \
  cybex-james-bootstrap \
  cybex-james-appliance \
  linux-generic \
  linux-firmware \
  nix-bin \
  python3
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

declare -a james_packages=()
while IFS= read -r -d '' package_file; do
  if [[ "$(dpkg-deb -f "$package_file" Package)" == cybex-james ]]; then
    james_packages+=("$package_file")
  fi
done < <(find "$offline_repository" -maxdepth 1 -type f -name '*.deb' -print0 | LC_ALL=C sort -z)
if [[ "${#james_packages[@]}" -ne 1 ]]; then
  echo "error: offline repository must contain exactly one cybex-james package" >&2
  exit 1
fi
packaged_james_root="$work_dir/packaged-james"
dpkg-deb --extract "${james_packages[0]}" "$packaged_james_root"
packaged_manage_source="$packaged_james_root/usr/share/cybex-james/manage-source"
test "$(stat -c '%a' "$packaged_manage_source")" = 755
for suffix in tar json; do
  test "$(stat -c '%a' "$packaged_manage_source/$manage_source_revision.$suffix")" = 444
  cmp \
    "$manage_source_reference/$manage_source_revision.$suffix" \
    "$packaged_manage_source/$manage_source_revision.$suffix"
done

# These packages are required only by thin-media installation. Keep them out
# of appliance_release_v1.required_package_versions. The signed snapshot
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
  --arg schema 'cybex.james.appliance-package-snapshot.v1' \
  --arg release_id "$version" \
  --arg ubuntu_snapshot_id "$snapshot_id" \
  --arg manage_origin "$expected_manage_origin" \
  --arg manage_source_revision "$manage_source_revision" \
  --arg manage_source_sha256 "$manage_source_sha256" \
  --argjson manage_source_size_bytes "$manage_source_size_bytes" \
  --arg filename "$package_bundle_name" \
  --arg sha256 "$(sha256sum "$package_bundle" | awk '{print $1}')" \
  --argjson size_bytes "$(stat -c '%s' "$package_bundle")" \
  --argjson required_package_versions "$required_versions" \
  '{schema:$schema,release_id:$release_id,ubuntu_snapshot_id:$ubuntu_snapshot_id,manage_origin:$manage_origin,manage_source_revision:$manage_source_revision,manage_source_sha256:$manage_source_sha256,manage_source_size_bytes:$manage_source_size_bytes,filename:$filename,sha256:$sha256,size_bytes:$size_bytes,required_package_versions:$required_package_versions,expected_kernel:$required_package_versions["linux-generic"],minimum_protocol:4,minimum_state_schema:2,rollback_compatible:true}' \
  > "$package_metadata"

mv -- "$package_bundle" "$output_dir/$package_bundle_name"
mv -- "$package_metadata" "$output_dir/$package_metadata_name"

echo "built James appliance package snapshot: $output_dir/$package_bundle_name"
