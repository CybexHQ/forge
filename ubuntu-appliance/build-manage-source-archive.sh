#!/usr/bin/env bash
set -Eeuo pipefail
umask 022

usage() {
  echo "usage: $0 --source-dir DIR --revision 40_HEX --output-dir DIR" >&2
  exit 2
}

source_dir=""
revision=""
output_dir=""
while (($#)); do
  case "$1" in
    --source-dir) source_dir="${2:-}"; shift 2 ;;
    --revision) revision="${2:-}"; shift 2 ;;
    --output-dir) output_dir="${2:-}"; shift 2 ;;
    *) usage ;;
  esac
done

if [[ -z "$source_dir" || -z "$revision" || -z "$output_dir" ]]; then
  usage
fi
[[ "$revision" =~ ^[0-9a-f]{40}$ ]] || {
  echo "error: Manage source revision must be exact lowercase 40-hex" >&2
  exit 1
}
for command_name in awk git jq sha256sum stat; do
  command -v "$command_name" >/dev/null || {
    echo "error: required command is unavailable: $command_name" >&2
    exit 1
  }
done
if [[ ! -d "$source_dir" || -L "$source_dir" ]]; then
  echo "error: Manage source must be a non-symlink directory" >&2
  exit 1
fi
source_dir="$(cd -- "$source_dir" && pwd -P)"
actual_revision="$(git -C "$source_dir" rev-parse --verify 'HEAD^{commit}')"
resolved_revision="$(git -C "$source_dir" rev-parse --verify "$revision^{commit}")"
if [[ "$actual_revision" != "$revision" || "$resolved_revision" != "$revision" ]]; then
  echo "error: Manage source checkout does not match the exact requested revision" >&2
  exit 1
fi
if [[ -n "$(git -C "$source_dir" status --porcelain --untracked-files=all)" ]]; then
  echo "error: Manage source checkout must be exact and clean" >&2
  exit 1
fi

while IFS= read -r mode; do
  case "$mode" in
    100644|100755) ;;
    *)
      echo "error: Manage source commit contains a symlink, submodule, or unsupported tree entry" >&2
      exit 1
      ;;
  esac
done < <(git -C "$source_dir" ls-tree -r --format='%(objectmode)' "$revision")
for required_path in \
  agent/cybex-agent/Cargo.toml \
  agent/cybex-agent/Cargo.lock \
  agent/cybex-agent/src/hardware_inventory.rs \
  agent/cybex-agent/src/installer_boot.rs \
  agent/cybex-agent/src/lib.rs \
  agent/cybex-agent/src/main.rs \
  agent/cybex-agent/src/managed_wifi.rs \
  deploy/nixos/cybex-agent-module.nix \
  deploy/nixos/cybex-apply-blueprint.sh \
  deploy/nixos/cybex-authd-packages.nix \
  deploy/nixos/cybex-authd.nix \
  deploy/nixos/cybex-blueprints.nix \
  deploy/nixos/cybex-himmelblau-packages.nix \
  deploy/nixos/cybex-himmelblau.nix \
  deploy/nixos/cybex-ldap.nix
do
  required_type=""
  if ! required_type="$(
    git -C "$source_dir" cat-file -t "$revision:$required_path" 2>/dev/null
  )" || [[ "$required_type" != blob ]]; then
    echo "error: Manage source commit omits required path $required_path" >&2
    exit 1
  fi
done

mkdir -p -- "$output_dir"
if [[ -L "$output_dir" || ! -d "$output_dir" ]]; then
  echo "error: Manage source output must be a non-symlink directory" >&2
  exit 1
fi
output_dir="$(cd -- "$output_dir" && pwd -P)"
if [[ -n "$(find "$output_dir" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
  echo "error: Manage source output directory must be empty" >&2
  exit 1
fi
chmod 0755 "$output_dir"

work_dir="$(mktemp -d)"
cleanup() { rm -rf -- "$work_dir"; }
trap cleanup EXIT
archive_name="$revision.tar"
archive="$work_dir/$archive_name"
git -c tar.umask=0022 -C "$source_dir" \
  archive --format=tar --output="$archive" "$revision"
embedded_revision="$(git get-tar-commit-id < "$archive")"
if [[ "$embedded_revision" != "$revision" ]]; then
  echo "error: deterministic Manage source archive lost its exact commit identity" >&2
  exit 1
fi
archive_size="$(stat -c '%s' "$archive")"
if [[ ! "$archive_size" =~ ^[1-9][0-9]*$ || "$archive_size" -gt 268435456 ]]; then
  echo "error: deterministic Manage source archive size is outside its bound" >&2
  exit 1
fi
archive_sha256="$(sha256sum "$archive" | awk '{print $1}')"
[[ "$archive_sha256" =~ ^[0-9a-f]{64}$ ]]

install -m 0444 "$archive" "$output_dir/$archive_name"
jq -cnS \
  --arg filename "$archive_name" \
  --arg revision "$revision" \
  --arg schema 'cybex.james.manage-source.v1' \
  --arg sha256 "$archive_sha256" \
  --argjson size_bytes "$archive_size" \
  '{filename:$filename,revision:$revision,schema:$schema,sha256:$sha256,size_bytes:$size_bytes}' \
  > "$output_dir/$revision.json"
chmod 0444 "$output_dir/$revision.json"

printf '%s\n' "$output_dir/$archive_name"
