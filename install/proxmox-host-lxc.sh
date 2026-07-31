#!/usr/bin/env bash
set -euo pipefail

FORGE_GIT_URL_DEFAULT="https://github.com/CybexHQ/forge.git"
FORGE_REF_DEFAULT="main"
FORGE_SOURCE_DIR_DEFAULT="/root/forge"
LXC_INSTALLER_RELATIVE_PATH="install/cybex-forge-lxc-install.sh"

api_url="${CYBEX_MANAGE_API_URL:-}"
organization_id="${CYBEX_ORGANIZATION_ID:-}"
auth_code="${CYBEX_FORGE_AUTH_CODE:-}"
unset CYBEX_FORGE_AUTH_CODE
auth_code_file="${CYBEX_FORGE_AUTH_CODE_FILE:-}"
public_base_url="${CYBEX_FORGE_PUBLIC_BASE_URL:-}"
listen_addr="${CYBEX_FORGE_LISTEN_ADDR:-127.0.0.1:8080}"
tftp_root="${CYBEX_FORGE_TFTP_ROOT:-/srv/cybex-forge/tftp}"
http_root="${CYBEX_FORGE_HTTP_ROOT:-/srv/cybex-forge/www}"
bootloader_filename="${CYBEX_FORGE_BOOTLOADER_FILENAME:-snponly.efi}"
menu_timeout_ms="${CYBEX_FORGE_BOOT_MENU_TIMEOUT_MS:-0}"
update_trusted_public_key="${CYBEX_FORGE_UPDATE_TRUSTED_PUBLIC_KEY:-}"
allow_insecure_manage_http="${CYBEX_FORGE_ALLOW_INSECURE_MANAGE_HTTP:-0}"

vmid="${CYBEX_FORGE_PROXMOX_VMID:-}"
hostname="${CYBEX_FORGE_PROXMOX_HOSTNAME:-cybex-forge}"
storage="${CYBEX_FORGE_PROXMOX_STORAGE:-}"
template_storage="${CYBEX_FORGE_PROXMOX_TEMPLATE_STORAGE:-}"
bridge="${CYBEX_FORGE_PROXMOX_BRIDGE:-}"
template="${CYBEX_FORGE_PROXMOX_TEMPLATE:-}"
disk_gb="${CYBEX_FORGE_PROXMOX_DISK_GB:-128}"
cpu_cores="${CYBEX_FORGE_PROXMOX_CPU_CORES:-4}"
memory_mb="${CYBEX_FORGE_PROXMOX_MEMORY_MB:-16384}"
swap_mb="${CYBEX_FORGE_PROXMOX_SWAP_MB:-8192}"
forge_git_url="${CYBEX_FORGE_GIT_URL:-$FORGE_GIT_URL_DEFAULT}"
forge_ref="${CYBEX_FORGE_REF:-$FORGE_REF_DEFAULT}"
forge_source_dir="${CYBEX_FORGE_SOURCE_DIR:-$FORGE_SOURCE_DIR_DEFAULT}"
dry_run=0
created_container=0
started_container=0
completed=0
current_step="initialization"
temporary_auth_code_file=""
guest_auth_code_file="/root/.cybex-forge-bootstrap/enrollment-code"
guest_bootstrap_auth_code_file="/var/lib/cybex-forge/bootstrap/enrollment-code"
guest_bootstrap_auth_code_tomb="/var/lib/cybex-forge/bootstrap/.enrollment-code.consumed"
guest_bootstrap_auth_code_staged_file="/var/lib/cybex-forge/bootstrap/.enrollment-code.staged"
guest_bootstrap_auth_code_identity_file="/var/lib/cybex-forge-bootstrap.identity"
guest_auth_code_staged=0

usage() {
  cat <<'EOF'
Usage:
  proxmox-host-lxc.sh --api-url URL --organization-id UUID [options]

Run this on a Proxmox host as root. It creates a Debian/Ubuntu LXC, clones
Forge inside it, installs Cybex Forge, submits a one-time install code, and
leaves a pending cybex-forge enrollment in Cybex Manage.

Required:
  --api-url URL                  Cybex Manage public API URL
  --organization-id UUID         Cybex organization UUID
Enrollment secret (choose one; otherwise a hidden /dev/tty prompt is used):
  --auth-code CODE               Legacy process-visible automation input
  --auth-code-file PATH          Root-owned mode-0600 code file below a root-owned, non-writable path; consumed after staging

Generated resource options:
  --proxmox-disk-gb GiB          Root disk size (default/recommended: 128)
  --proxmox-cpu-cores COUNT      CPU cores (default/recommended: 4)
  --proxmox-memory-mb MiB        Memory (minimum/recommended: 16384)
  --proxmox-swap-mb MiB          Emergency swap headroom (default/recommended: 8192)

Boot runtime options:
  --public-base-url URL          Override the auto-detected URL PXE clients use for this Forge node
  --listen ADDR                  Local Boot address behind nginx (default: 127.0.0.1:8080)
  --tftp-root PATH               TFTP root below /srv/cybex-forge (default: /srv/cybex-forge/tftp)
  --http-root PATH               HTTP asset root below /srv/cybex-forge (default: /srv/cybex-forge/www)
  --bootloader NAME              UEFI iPXE loader filename (default: snponly.efi)
  --menu-timeout-ms MS           Boot menu timeout; 0 disables it (default: 0)
  --update-trusted-public-key KEY
                                Standard-Base64 raw 32-byte Ed25519 update public key
  --allow-insecure-manage-http  Explicit development-only opt-in to an HTTP Manage URL

Advanced Proxmox options:
  --vmid ID                      Container VMID (default: next cluster id)
  --hostname NAME                Container hostname (default: cybex-forge)
  --storage NAME                 Rootfs storage (default: first rootdir-capable storage)
  --template-storage NAME        Template storage (default: first vztmpl-capable storage)
  --bridge NAME                  Network bridge (default: vmbr0 or first vmbr*)
  --template TEMPLATE            Existing template path or storage:vztmpl/name
  --forge-git-url URL            Forge source repository (default: https://github.com/CybexHQ/forge.git)
  --forge-ref REF                Branch, tag, or commit to install (default: main)
  --forge-source-dir PATH        Source checkout inside LXC (default: /root/forge)
  --dry-run, --validate-only     Validate inputs/environment and print selections without creating the LXC
  -h, --help                     Show this help
EOF
}

section() {
  current_step="$1"
  printf '\n==> %s\n' "$1"
}

info() {
  printf '    %s\n' "$1"
}

warn() {
  printf 'WARN: %s\n' "$1" >&2
}

die() {
  printf 'ERROR: %s\n' "$1" >&2
  exit 1
}

on_exit() {
  local status="$?"
  local cleanup_failed=0
  trap - EXIT
  if [ "$guest_auth_code_staged" -eq 1 ] && [ -n "$vmid" ] && command -v pct >/dev/null 2>&1; then
    secure_remove_guest_auth_code >/dev/null 2>&1 || {
      warn "partial LXC may retain its protected bootstrap source credential"
      cleanup_failed=1
    }
  fi
  if [ "$started_container" -eq 1 ] && [ -n "$vmid" ] && command -v pct >/dev/null 2>&1; then
    secure_remove_guest_bootstrap_auth_code >/dev/null 2>&1 || {
      warn "partial LXC may retain protected Forge enrollment state; inspect it before reuse"
      cleanup_failed=1
    }
  fi
  if [ -n "$temporary_auth_code_file" ] && [ -f "$temporary_auth_code_file" ]; then
    if command -v shred >/dev/null 2>&1; then
      shred -u -n 1 -z -- "$temporary_auth_code_file" >/dev/null 2>&1 || rm -f -- "$temporary_auth_code_file"
    else
      rm -f -- "$temporary_auth_code_file"
    fi
  fi
  if [ "$cleanup_failed" -eq 1 ] && [ "$status" -eq 0 ]; then
    status=1
  fi
  if [ "$completed" -eq 0 ] && [ "$status" -ne 0 ] &&
    { [ "$created_container" -ne 0 ] || [ "$current_step" != "initialization" ]; }; then
    printf '\nERROR: failed during %s (exit %s)\n' "$current_step" "$status" >&2
    if [ -n "$vmid" ] && command -v pct >/dev/null 2>&1 && pct status "$vmid" >/dev/null 2>&1; then
      pct status "$vmid" >&2 || true
      if [ "$created_container" -eq 1 ]; then
        printf 'Partial LXC VMID %s remains. Inspect it with: pct status %s; pct enter %s\n' "$vmid" "$vmid" "$vmid" >&2
        if [ "$started_container" -eq 1 ]; then
          printf 'The LXC was started before the failure; collect logs with: pct exec %s -- journalctl --no-pager -n 200\n' "$vmid" >&2
        fi
        printf 'Remove it after collecting evidence with: pct destroy %s\n' "$vmid" >&2
      fi
    elif [ "$created_container" -eq 1 ] && [ -n "$vmid" ]; then
      printf 'LXC creation was attempted for VMID %s, but pct status is unavailable.\n' "$vmid" >&2
    fi
  fi
  exit "$status"
}

trap on_exit EXIT

while [ "$#" -gt 0 ]; do
  case "$1" in
    --api-url) api_url="${2:-}"; shift 2 ;;
    --organization-id) organization_id="${2:-}"; shift 2 ;;
    --auth-code) auth_code="${2:-}"; shift 2 ;;
    --auth-code-file) auth_code_file="${2:-}"; shift 2 ;;
    --public-base-url) public_base_url="${2:-}"; shift 2 ;;
    --listen) listen_addr="${2:-}"; shift 2 ;;
    --tftp-root) tftp_root="${2:-}"; shift 2 ;;
    --http-root) http_root="${2:-}"; shift 2 ;;
    --bootloader) bootloader_filename="${2:-}"; shift 2 ;;
    --menu-timeout-ms) menu_timeout_ms="${2:-}"; shift 2 ;;
    --update-trusted-public-key) update_trusted_public_key="${2:-}"; shift 2 ;;
    --allow-insecure-manage-http) allow_insecure_manage_http=1; shift ;;
    --vmid) vmid="${2:-}"; shift 2 ;;
    --hostname) hostname="${2:-}"; shift 2 ;;
    --storage) storage="${2:-}"; shift 2 ;;
    --template-storage) template_storage="${2:-}"; shift 2 ;;
    --bridge) bridge="${2:-}"; shift 2 ;;
    --template) template="${2:-}"; shift 2 ;;
    --proxmox-disk-gb) disk_gb="${2:-}"; shift 2 ;;
    --proxmox-cpu-cores) cpu_cores="${2:-}"; shift 2 ;;
    --proxmox-memory-mb) memory_mb="${2:-}"; shift 2 ;;
    --proxmox-swap-mb) swap_mb="${2:-}"; shift 2 ;;
    --forge-git-url) forge_git_url="${2:-}"; shift 2 ;;
    --forge-ref) forge_ref="${2:-}"; shift 2 ;;
    --forge-source-dir) forge_source_dir="${2:-}"; shift 2 ;;
    --dry-run|--validate-only) dry_run=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

require_value() {
  local name="$1"
  local value="$2"
  [ -n "$value" ] || {
    usage >&2
    die "$name is required"
  }
}

require_root() {
  [ "$(id -u)" -eq 0 ] || die "run this script as root on the Proxmox host"
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

validate_plain_value() {
  local name="$1"
  local value="$2"
  if printf '%s' "$value" | LC_ALL=C grep -q '[[:cntrl:]"\\]'; then
    die "$name contains unsupported characters"
  fi
}

validate_url() {
  local name="$1"
  local value="$2"
  local rest authority port
  case "$value" in
    http://*) rest="${value#http://}" ;;
    https://*) rest="${value#https://}" ;;
    *) die "$name must start with http:// or https://" ;;
  esac
  if printf '%s' "$value" | LC_ALL=C grep -q '[[:space:]"\\]'; then
    die "$name contains unsupported characters"
  fi
  if printf '%s' "$value" | LC_ALL=C grep -q '[;&|`$<>(){}]'; then
    die "$name contains unsupported characters"
  fi
  case "$value" in
    *'?'*|*'#'*|*@*) die "$name contains unsupported characters" ;;
  esac
  if ! printf '%s' "$value" | LC_ALL=C grep -Eq '^https?://[A-Za-z0-9.-]+(:[0-9]+)?(/[^[:space:]"\\?#@]*)?$'; then
    die "$name must be an absolute http(s) URL with a host and optional path"
  fi
  authority="${rest%%/*}"
  case "$authority" in
    *:*)
      port="${authority##*:}"
      if ! printf '%s' "$port" | LC_ALL=C grep -Eq '^[0-9]+$'; then
        die "$name port must be numeric"
      fi
      if [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
        die "$name port must be between 1 and 65535"
      fi
      ;;
  esac
}

validate_manage_transport() {
  case "$allow_insecure_manage_http" in 0|1) ;; *) die "CYBEX_FORGE_ALLOW_INSECURE_MANAGE_HTTP must be 0 or 1" ;; esac
  case "$api_url" in
    https://*) ;;
    http://*) [ "$allow_insecure_manage_http" -eq 1 ] || die "--api-url must use HTTPS; development HTTP requires --allow-insecure-manage-http" ;;
    *) die "--api-url must use HTTPS" ;;
  esac
}

validate_uuid() {
  validate_plain_value "--organization-id" "$organization_id"
  printf '%s' "$organization_id" | LC_ALL=C grep -Eq '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$' ||
    die "--organization-id must be a UUID"
}

validate_auth_code_value() {
  local value="$1"
  validate_plain_value "Forge install authorization code" "$value"
  [ "${#value}" -ge 16 ] || die "Forge install authorization code is too short"
  [ "${#value}" -le 512 ] || die "Forge install authorization code is too long"
  if printf '%s' "$value" | LC_ALL=C grep -q '[[:space:]]'; then
    die "Forge install authorization code contains unsupported characters"
  fi
}

validate_root_protected_auth_code_parent() {
  local path="$1"
  local label="${2:---auth-code-file}"
  local parent canonical current component owner mode mode_value
  local -a components=()
  parent="$(dirname -- "$path")"
  require_command realpath
  canonical="$(realpath -e -- "$parent")" ||
    die "$label parent path must exist"
  [ "$canonical" = "$parent" ] ||
    die "$label parent path must be canonical and contain no symlink"
  IFS='/' read -r -a components <<< "${parent#/}"
  current="/"
  for component in "" "${components[@]}"; do
    if [ -n "$component" ]; then
      current="${current%/}/$component"
    fi
    if [ -L "$current" ] || [ ! -d "$current" ]; then
      die "$label parent path must contain only directories, not symlinks"
    fi
    owner="$(stat -c '%u' -- "$current")"
    mode="$(stat -c '%a' -- "$current")"
    [ "$owner" = "0" ] ||
      die "$label parent path must be entirely root-owned"
    [[ "$mode" =~ ^[0-7]{3,4}$ ]] ||
      die "$label parent path has invalid permissions"
    mode_value=$((8#$mode))
    (( (mode_value & 0022) == 0 )) ||
      die "$label parent path must not be group- or other-writable"
  done
}

validate_auth_code_file() {
  local path="$1"
  local owner mode links size value
  validate_absolute_path "--auth-code-file" "$path"
  validate_root_protected_auth_code_parent "$path" "--auth-code-file"
  [ ! -L "$path" ] || die "--auth-code-file must not be a symlink"
  [ -f "$path" ] || die "--auth-code-file must be a regular file"
  owner="$(stat -c '%u' -- "$path")"
  mode="$(stat -c '%a' -- "$path")"
  links="$(stat -c '%h' -- "$path")"
  size="$(stat -c '%s' -- "$path")"
  [ "$owner" = "$(id -u)" ] || die "--auth-code-file must be owned by root"
  [ "$mode" = "600" ] || die "--auth-code-file must have mode 0600"
  [ "$links" = "1" ] || die "--auth-code-file must have exactly one hard link"
  [ "$size" -le 512 ] || die "--auth-code-file is too large"
  value="$(<"$path")"
  validate_auth_code_value "$value"
  value=""
}

secure_remove_local_auth_code() {
  local path="$1" size parent
  validate_auth_code_file "$path"
  size="$(stat -c '%s' -- "$path")"
  if [ "$size" -gt 0 ]; then
    dd if=/dev/zero of="$path" bs=1 count="$size" conv=notrunc status=none
  fi
  : > "$path"
  sync -f "$path"
  rm -f -- "$path"
  parent="$(dirname "$path")"
  sync -f "$parent"
}

secure_remove_guest_auth_code() {
  # Expansion in this single-quoted program intentionally happens in the guest.
  # shellcheck disable=SC2016
  pct exec "$vmid" -- sh -ceu '
    path=$1
    if [ ! -e "$path" ] && [ ! -L "$path" ]; then
      exit 0
    fi
    [ ! -L "$path" ] && [ -f "$path" ] || exit 1
    metadata=$(stat -c "%u:%a:%h:%s" -- "$path")
    case "$metadata" in 0:600:1:*) ;; *) exit 1 ;; esac
    size=${metadata##*:}
    [ "$size" -ge 16 ] && [ "$size" -le 512 ] || exit 1
    if [ "$size" -gt 0 ]; then
      dd if=/dev/zero of="$path" bs=1 count="$size" conv=notrunc status=none
    fi
    : > "$path"
    sync -f "$path"
    rm -f -- "$path"
    sync -f "$(dirname "$path")"
  ' sh "$guest_auth_code_file"
}

secure_remove_guest_bootstrap_auth_code() {
  # All paths are fixed constants. The guest helper binds the exact staged
  # inode before erasure and refuses a same-UID pathname replacement.
  # shellcheck disable=SC2016
  pct exec "$vmid" -- bash -ceu '
    source_path=$1
    tomb_path=$2
    staged_path=$3
    identity_file=$4
    helper=/usr/local/libexec/cybex-forge-secure-input
    source_present=0
    tomb_present=0
    staged_present=0
    [ ! -e "$source_path" ] && [ ! -L "$source_path" ] || source_present=1
    [ ! -e "$tomb_path" ] && [ ! -L "$tomb_path" ] || tomb_present=1
    [ ! -e "$staged_path" ] && [ ! -L "$staged_path" ] || staged_present=1
    if [ $((source_present + tomb_present + staged_present)) -gt 1 ]; then
      exit 1
    fi
    if [ ! -e "$identity_file" ] && [ ! -L "$identity_file" ]; then
      identity=pending
    else
      [ ! -L "$identity_file" ] && [ -f "$identity_file" ] || exit 1
      [ "$(stat -c "%u:%a:%h" -- "$identity_file")" = "$(id -u):600:1" ] || exit 1
      identity=$(cat -- "$identity_file")
      if [ "$identity" != pending ]; then
        printf "%s" "$identity" | grep -Eq "^[0-9]+(:[0-9]+){6}$" || exit 1
      fi
    fi
    if [ "$source_present" -eq 1 ]; then
      candidate=$source_path
    elif [ "$tomb_present" -eq 1 ]; then
      candidate=$tomb_path
    elif [ "$staged_present" -eq 1 ]; then
      candidate=$staged_path
    else
      candidate=
    fi
    if [ -n "$candidate" ]; then
      [ -x "$helper" ] || exit 1
      if [ "$identity" = pending ]; then
        rebound=$(runuser -u cybex-forge -- "$helper" identity "$candidate" 512 secret)
        runuser -u cybex-forge -- "$helper" erase-if-same "$candidate" "$rebound"
      elif ! runuser -u cybex-forge -- "$helper" erase-if-same "$candidate" "$identity"; then
        rebound=$(runuser -u cybex-forge -- "$helper" identity "$candidate" 512 secret)
        [ "${rebound%:*:*:*:*}" = "${identity%:*:*:*:*}" ] || exit 1
        runuser -u cybex-forge -- "$helper" erase-if-same "$candidate" "$rebound"
      fi
    fi
    [ ! -e "$source_path" ] && [ ! -L "$source_path" ] || exit 1
    [ ! -e "$tomb_path" ] && [ ! -L "$tomb_path" ] || exit 1
    [ ! -e "$staged_path" ] && [ ! -L "$staged_path" ] || exit 1
    if [ -e "$identity_file" ] || [ -L "$identity_file" ]; then
      : > "$identity_file"
      sync -f "$identity_file"
      rm -f -- "$identity_file"
      sync -f "$(dirname "$identity_file")"
    fi
  ' bash \
    "$guest_bootstrap_auth_code_file" \
    "$guest_bootstrap_auth_code_tomb" \
    "$guest_bootstrap_auth_code_staged_file" \
    "$guest_bootstrap_auth_code_identity_file"
}

validate_staged_guest_auth_code() {
  # Expansion in this single-quoted program intentionally happens in the guest.
  # shellcheck disable=SC2016
  pct exec "$vmid" -- sh -ceu '
    path=$1
    [ ! -L "$path" ] && [ -f "$path" ] || exit 1
    metadata=$(stat -c "%u:%a:%h:%s" -- "$path")
    case "$metadata" in 0:600:1:*) ;; *) exit 1 ;; esac
    size=${metadata##*:}
    [ "$size" -ge 16 ] && [ "$size" -le 512 ]
  ' sh "$guest_auth_code_file"
}

prepare_auth_code_file() {
  if [ -n "$auth_code" ] && [ -n "$auth_code_file" ]; then
    die "--auth-code and --auth-code-file are mutually exclusive"
  fi
  if [ -z "$auth_code" ] && [ -z "$auth_code_file" ]; then
    [ -r /dev/tty ] || die "no enrollment code was supplied and /dev/tty is unavailable; use --auth-code-file"
    IFS= read -r -s -p "One-time Cybex Forge install code: " auth_code </dev/tty || die "could not read the enrollment code from /dev/tty"
    printf '\n' >/dev/tty
  fi
  if [ -n "$auth_code" ]; then
    validate_auth_code_value "$auth_code"
    umask 077
    temporary_auth_code_file="$(mktemp /run/cybex-forge-enrollment-code.XXXXXX)"
    printf '%s\n' "$auth_code" > "$temporary_auth_code_file"
    chmod 0600 "$temporary_auth_code_file"
    auth_code=""
    auth_code_file="$temporary_auth_code_file"
  fi
  validate_auth_code_file "$auth_code_file"
}

validate_int_range() {
  local name="$1"
  local value="$2"
  local min="$3"
  local max="$4"
  printf '%s' "$value" | LC_ALL=C grep -Eq '^[0-9]+$' || die "$name must be numeric"
  if [ "$value" -lt "$min" ] || [ "$value" -gt "$max" ]; then
    die "$name must be between $min and $max"
  fi
}

validate_name() {
  local name="$1"
  local value="$2"
  validate_plain_value "$name" "$value"
  printf '%s' "$value" | LC_ALL=C grep -Eq '^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$' || die "$name contains unsupported characters"
}

validate_absolute_path() {
  local name="$1"
  local value="$2"
  validate_plain_value "$name" "$value"
  case "$value" in
    /*) ;;
    *) die "$name must be an absolute path" ;;
  esac
  [ "$value" != "/" ] || die "$name must not be /"
  case "$value" in
    *'//'*) die "$name must be normalized" ;;
    */) die "$name must be normalized" ;;
  esac
  local old_ifs="$IFS"
  local part
  local has_backslash
  IFS='/'
  for part in $value; do
    case "$part" in
      *\\*) has_backslash=1 ;;
      *) has_backslash=0 ;;
    esac
    if [ "$part" = "." ] || [ "$part" = ".." ] || [ "$has_backslash" -eq 1 ]; then
      IFS="$old_ifs"
      die "$name must be normalized"
    fi
  done
  IFS="$old_ifs"
}

validate_runtime_root() {
  local name="$1"
  local value="$2"
  local allowed_root="/srv/cybex-forge"
  validate_absolute_path "$name" "$value"
  if printf '%s' "$value" | LC_ALL=C grep -q '[[:space:]]'; then
    die "$name must not contain whitespace"
  fi
  if ! printf '%s' "$value" | LC_ALL=C grep -Eq '^/[A-Za-z0-9._/-]+$'; then
    die "$name contains unsupported characters"
  fi
  case "$value" in
    "$allowed_root"/*) ;;
    "$allowed_root") die "$name must be below $allowed_root, not $allowed_root itself" ;;
    *) die "$name must be under $allowed_root" ;;
  esac
}

validate_runtime_roots() {
  validate_runtime_root "--tftp-root" "$tftp_root"
  validate_runtime_root "--http-root" "$http_root"
  case "$http_root/" in
    "$tftp_root/"*) die "--http-root must not be inside --tftp-root" ;;
  esac
  case "$tftp_root/" in
    "$http_root/"*) die "--tftp-root must not be inside --http-root" ;;
  esac
}

validate_bootloader_filename() {
  validate_plain_value "--bootloader" "$bootloader_filename"
  case "$bootloader_filename" in
    ""|*/*|*\\*|.*|*' '*|*$'\t'*) die "--bootloader must be a simple filename" ;;
  esac
  printf '%s' "$bootloader_filename" | LC_ALL=C grep -Eq '^[A-Za-z0-9._-]+$' ||
    die "--bootloader must use only letters, numbers, dot, underscore, or hyphen"
}

validate_update_trusted_public_key() {
  local value="$update_trusted_public_key"
  local decoded_size canonical
  [ -n "$value" ] || return 0
  require_command base64
  if ! printf '%s' "$value" | LC_ALL=C grep -Eq '^[A-Za-z0-9+/]{43}=$'; then
    die "--update-trusted-public-key must be canonical standard Base64 for exactly 32 bytes"
  fi
  if ! decoded_size="$(printf '%s' "$value" | base64 --decode 2>/dev/null | wc -c | tr -d '[:space:]')"; then
    die "--update-trusted-public-key is not valid standard Base64"
  fi
  [ "$decoded_size" = "32" ] ||
    die "--update-trusted-public-key must decode to exactly 32 bytes"
  if ! canonical="$(printf '%s' "$value" | base64 --decode 2>/dev/null | base64 | tr -d '\n')"; then
    die "--update-trusted-public-key is not valid standard Base64"
  fi
  [ "$canonical" = "$value" ] ||
    die "--update-trusted-public-key must use canonical standard Base64"
}

validate_forge_ref() {
  validate_plain_value "--forge-ref" "$forge_ref"
  [ -n "$forge_ref" ] || die "--forge-ref is required"
  printf '%s' "$forge_ref" | LC_ALL=C grep -Eq '^[A-Za-z0-9._/@+-]+$' ||
    die "--forge-ref must contain only letters, numbers, dot, underscore, slash, at, plus, or hyphen"
  case "$forge_ref" in
    -*|*..*|*//*|*/.|*.|*~*|*^*|*:*|*'?'*|*'['*|*\\*|*' '*|*$'\t'*)
      die "--forge-ref is not a safe git ref"
      ;;
  esac
}

tooling_preflight() {
  require_root
  require_command pct
  require_command pvesm
  require_command pveam
  require_command pvesh
  require_command ip
}

storage_for_content() {
  local content="$1"
  pvesm status --content "$content" 2>/dev/null | awk 'NR > 1 && $1 != "" { print $1; exit }'
}

storage_exists() {
  local name="$1"
  pvesm status 2>/dev/null | awk 'NR > 1 { print $1 }' | grep -Fx -- "$name" >/dev/null
}

choose_vmid() {
  local next_id
  next_id="$(pvesh get /cluster/nextid 2>/dev/null || true)"
  printf '%s' "$next_id" | LC_ALL=C grep -Eq '^[0-9]+$' || die "could not determine next Proxmox VMID; pass --vmid"
  vmid="$next_id"
}

choose_bridge() {
  if ip link show vmbr0 >/dev/null 2>&1; then
    bridge="vmbr0"
    return
  fi
  bridge="$(ip -o link show | awk -F': ' '$2 ~ /^vmbr[0-9A-Za-z_.-]+$/ { print $2; exit }')"
  [ -n "$bridge" ] || die "could not find a vmbr* bridge; pass --bridge"
}

cached_template() {
  local cached
  cached="$(find /var/lib/vz/template/cache -maxdepth 1 -type f \
    \( -name 'debian-12-standard_*_amd64.tar.*' -o -name 'ubuntu-24.04-standard_*_amd64.tar.*' -o -name 'ubuntu-22.04-standard_*_amd64.tar.*' \) \
    2>/dev/null | sort -V | tail -n 1)"
  [ -n "$cached" ] && printf '%s\n' "$cached"
}

listed_template() {
  local storage_name="$1"
  pveam list "$storage_name" 2>/dev/null |
    awk '/debian-12-standard_.*_amd64\.tar\.(zst|xz|gz)$/ || /ubuntu-24\.04-standard_.*_amd64\.tar\.(zst|xz|gz)$/ || /ubuntu-22\.04-standard_.*_amd64\.tar\.(zst|xz|gz)$/ { print $1 }' |
    sort -V |
    tail -n 1
}

download_template() {
  local storage_name="$1"
  local template_name
  section "Template"
  info "Updating Proxmox appliance metadata."
  pveam update >/dev/null
  template_name="$(pveam available --section system 2>/dev/null |
    awk '/debian-12-standard_.*_amd64\.tar\.(zst|xz|gz)$/ || /ubuntu-24\.04-standard_.*_amd64\.tar\.(zst|xz|gz)$/ || /ubuntu-22\.04-standard_.*_amd64\.tar\.(zst|xz|gz)$/ { print $2 }' |
    sort -V |
    tail -n 1)"
  [ -n "$template_name" ] || die "could not find a Debian/Ubuntu LXC template in pveam"
  info "Downloading $template_name to $storage_name."
  pveam download "$storage_name" "$template_name"
  template="${storage_name}:vztmpl/${template_name}"
}

choose_template() {
  if [ -n "$template" ]; then
    case "$template" in
      /*|*:*) ;;
      *) template="${template_storage}:vztmpl/${template}" ;;
    esac
    return
  fi
  local listed cached
  listed="$(listed_template "$template_storage")"
  if [ -n "$listed" ]; then
    template="$listed"
    return
  fi
  cached="$(cached_template)"
  if [ -n "$cached" ]; then
    template="$cached"
    return
  fi
  if [ "$dry_run" -eq 1 ]; then
    template="will-download:debian-or-ubuntu-standard-template"
    return
  fi
  download_template "$template_storage"
}

validate_and_select_proxmox() {
  [ -n "$vmid" ] || choose_vmid
  validate_int_range "--vmid" "$vmid" 100 999999999
  if pct status "$vmid" >/dev/null 2>&1; then
    die "VMID $vmid already exists"
  fi

  [ -n "$storage" ] || storage="$(storage_for_content rootdir)"
  [ -n "$storage" ] || die "could not find rootdir-capable storage; pass --storage"
  storage_exists "$storage" || die "storage does not exist: $storage"

  [ -n "$template_storage" ] || template_storage="$(storage_for_content vztmpl)"
  [ -n "$template_storage" ] || die "could not find template-capable storage; pass --template-storage"
  storage_exists "$template_storage" || die "template storage does not exist: $template_storage"

  [ -n "$bridge" ] || choose_bridge
  ip link show "$bridge" >/dev/null 2>&1 || die "bridge does not exist: $bridge"
  validate_name "--hostname" "$hostname"
  choose_template
}

resource_warnings() {
  [ "$disk_gb" -ge 128 ] || warn "disk is below the 128 GiB recommendation"
  [ "$cpu_cores" -ge 4 ] || warn "CPU allocation is below the 4-core recommendation"
  [ "$swap_mb" -ge 8192 ] || warn "swap is below the 8192 MiB recommendation"
}

print_summary() {
  section "Selected Proxmox LXC"
  info "VMID: $vmid"
  info "Hostname: $hostname"
  info "Storage: $storage"
  info "Bridge: $bridge"
  info "Template: $template"
  info "Disk: ${disk_gb} GiB"
  info "CPU: ${cpu_cores} cores"
  info "Memory: ${memory_mb} MiB"
  info "Swap: ${swap_mb} MiB"
  info "Manage API: $api_url"
  info "Organization: $organization_id"
  if [ -n "$public_base_url" ]; then
    info "Public Boot URL: $public_base_url"
  else
    info "Public Boot URL: auto-detect from the LXC address"
  fi
  info "Forge source: $forge_git_url"
  info "Forge ref: $forge_ref"
  info "Forge checkout: $forge_source_dir"
  if [ -n "$update_trusted_public_key" ]; then
    info "Forge update trust: configured"
  else
    info "Forge update trust: not configured (managed updates will be refused)"
  fi
}

create_container() {
  section "Create LXC"
  pct create "$vmid" "$template" \
    --hostname "$hostname" \
    --cores "$cpu_cores" \
    --memory "$memory_mb" \
    --swap "$swap_mb" \
    --rootfs "${storage}:${disk_gb}" \
    --net0 "name=eth0,bridge=${bridge},ip=dhcp" \
    --ostype debian \
    --unprivileged 0 \
    --features nesting=1 \
    --onboot 1
  created_container=1
}

start_container() {
  section "Start LXC"
  pct start "$vmid"
  started_container=1
  info "Waiting for systemd and outbound network."
  # shellcheck disable=SC2016
  pct exec "$vmid" -- bash -lc '
    set -e
    for _ in $(seq 1 90); do
      if [ -d /run/systemd/system ] && ip route get 1.1.1.1 >/dev/null 2>&1; then
        exit 0
      fi
      sleep 2
    done
    exit 1
  ' || die "container did not become network-ready"
}

detect_container_ip() {
  local ip_address
  ip_address="$(pct exec "$vmid" -- sh -c "ip -4 -o addr show scope global up 2>/dev/null | awk '{ split(\$4, a, \"/\"); if (a[1] !~ /^127\\./) { print a[1]; exit } }'" 2>/dev/null || true)"
  if [ -z "$ip_address" ]; then
    ip_address="$(pct exec "$vmid" -- hostname -I 2>/dev/null | awk '{ for (i = 1; i <= NF; i++) if ($i ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ && $i !~ /^127\./) { print $i; exit } }' || true)"
  fi
  printf '%s\n' "$ip_address"
}

ensure_public_base_url() {
  if [ -n "$public_base_url" ]; then
    validate_url "--public-base-url" "$public_base_url"
    return
  fi
  local container_ip
  container_ip="$(detect_container_ip | head -n 1)"
  [ -n "$container_ip" ] || die "could not auto-detect LXC IPv4 address; pass --public-base-url"
  public_base_url="http://$container_ip"
  validate_url "--public-base-url" "$public_base_url"
  section "Detected Forge URL"
  info "Public Boot URL: $public_base_url"
}

prepare_forge_source() {
  section "Stage Forge"
  # shellcheck disable=SC2016
  pct exec "$vmid" -- bash -lc '
    set -euo pipefail
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y --no-install-recommends ca-certificates curl git
  '
  # shellcheck disable=SC2016
  pct exec "$vmid" -- bash -lc '
    set -euo pipefail
    source_dir="$1"
    git_url="$2"
    forge_ref="$3"
    if [ -d "$source_dir/.git" ]; then
      git -C "$source_dir" remote set-url origin "$git_url" || true
      git -C "$source_dir" fetch --depth 1 origin "$forge_ref"
      git -C "$source_dir" checkout --detach -f FETCH_HEAD
    else
      rm -rf "$source_dir"
      git init "$source_dir"
      git -C "$source_dir" remote add origin "$git_url"
      git -C "$source_dir" fetch --depth 1 origin "$forge_ref"
      git -C "$source_dir" checkout --detach -f FETCH_HEAD
    fi
    test -f "$source_dir/install/cybex-forge-lxc-install.sh"
    chmod 0755 "$source_dir/install/cybex-forge-lxc-install.sh"
    git -C "$source_dir" rev-parse HEAD > "$source_dir/.cybex-forge-revision"
  ' sh "$forge_source_dir" "$forge_git_url" "$forge_ref"
}

stage_enrollment_code() {
  section "Stage enrollment credential"
  validate_auth_code_file "$auth_code_file"
  pct exec "$vmid" -- install -m 0700 -o root -g root -d /root/.cybex-forge-bootstrap
  pct push "$vmid" "$auth_code_file" "$guest_auth_code_file" --perms 0600
  pct exec "$vmid" -- chown root:root "$guest_auth_code_file"
  pct exec "$vmid" -- chmod 0600 "$guest_auth_code_file"
  guest_auth_code_staged=1
  validate_staged_guest_auth_code
  secure_remove_local_auth_code "$auth_code_file"
  if [ "$temporary_auth_code_file" = "$auth_code_file" ]; then
    temporary_auth_code_file=""
  fi
  auth_code_file=""
  info "The one-time credential is staged in a protected guest file and consumed on the host."
}

run_lxc_installer() {
  section "Install Cybex Forge"
  info "Running the LXC installer with a protected file-backed one-time credential."
  local installer="${forge_source_dir}/${LXC_INSTALLER_RELATIVE_PATH}"
  local installer_args=(
    --api-url "$api_url" \
    --organization-id "$organization_id" \
    --auth-code-file "$guest_auth_code_file" \
    --public-base-url "$public_base_url" \
    --source-dir "$forge_source_dir" \
    --git-url "$forge_git_url" \
    --forge-ref "$forge_ref" \
    --listen "$listen_addr" \
    --tftp-root "$tftp_root" \
    --http-root "$http_root" \
    --bootloader "$bootloader_filename" \
    --menu-timeout-ms "$menu_timeout_ms" \
    --update-trusted-public-key "$update_trusted_public_key"
  )
  if [ "$allow_insecure_manage_http" -eq 1 ]; then
    installer_args+=(--allow-insecure-manage-http)
  fi
  pct exec "$vmid" -- "$installer" "${installer_args[@]}"
  guest_auth_code_staged=0
}

print_final() {
  local container_ip
  container_ip="$(pct exec "$vmid" -- hostname -I 2>/dev/null | awk '{ print $1 }' || true)"
  section "Next"
  info "A pending cybex-forge enrollment has been submitted to Cybex Manage."
  if [ -n "$container_ip" ]; then
    info "Detected LXC address: $container_ip"
    info "Open Enrollments, adopt the Cybex Forge server, then configure DHCP option 66 to $container_ip and option 67 to $bootloader_filename."
  else
    info "Open Enrollments, adopt the Cybex Forge server, then configure DHCP option 66 to the LXC address and option 67 to $bootloader_filename."
  fi
  info "Container VMID $vmid is running as $hostname."
}

require_value "--api-url" "$api_url"
require_value "--organization-id" "$organization_id"
require_root
prepare_auth_code_file
validate_url "--api-url" "$api_url"
validate_manage_transport
if [ -n "$public_base_url" ]; then
  validate_url "--public-base-url" "$public_base_url"
fi
validate_url "--forge-git-url" "$forge_git_url"
validate_forge_ref
validate_uuid
validate_runtime_roots
validate_absolute_path "--forge-source-dir" "$forge_source_dir"
validate_bootloader_filename
validate_update_trusted_public_key
if [ "$menu_timeout_ms" != "0" ]; then
  validate_int_range "--menu-timeout-ms" "$menu_timeout_ms" 1000 600000
fi
validate_int_range "--proxmox-disk-gb" "$disk_gb" 8 4096
validate_int_range "--proxmox-cpu-cores" "$cpu_cores" 1 128
validate_int_range "--proxmox-memory-mb" "$memory_mb" 16384 1048576
validate_int_range "--proxmox-swap-mb" "$swap_mb" 0 1048576
tooling_preflight
validate_and_select_proxmox
resource_warnings
print_summary
if [ "$dry_run" -eq 1 ]; then
  completed=1
  section "Validation complete"
  info "Dry run completed without creating or modifying an LXC."
  exit 0
fi
create_container
start_container
ensure_public_base_url
prepare_forge_source
stage_enrollment_code
run_lxc_installer
print_final
completed=1
