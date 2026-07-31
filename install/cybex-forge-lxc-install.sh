#!/usr/bin/env bash
set -euo pipefail

FORGE_GIT_URL_DEFAULT="https://github.com/CybexHQ/forge.git"
FORGE_REF_DEFAULT="main"
FORGE_SOURCE_DIR_DEFAULT="/root/forge"
NIXPKGS_REVISION="74cc63f702f7d60a557e152a57b40fb1fd0f72ac"
NIXPKGS_FLAKE="github:NixOS/nixpkgs/$NIXPKGS_REVISION"

usage() {
  cat <<'EOF'
Usage:
  cybex-forge-lxc-install.sh --api-url URL --organization-id UUID [options]

Run this inside a Debian/Ubuntu Proxmox LXC that will host Cybex Forge.

Required:
  --api-url URL             Cybex Manage public API URL, for example https://manage.example.com
  --organization-id UUID    Cybex organization UUID from the install authorization
Enrollment secret (choose exactly one):
  --auth-code-file PATH     Root-owned mode-0600 file below a root-owned, non-writable path; consumed after staging
  --auth-code CODE          Legacy process-visible input; converted to a protected file

Options:
  --public-base-url URL     Override the auto-detected URL PXE clients use for this Forge node
  --source-dir PATH         Existing Forge source directory (default: /root/forge)
  --git-url URL             Clone source when --source-dir is missing
  --forge-ref REF           Branch, tag, or commit to install (default: main)
  --listen ADDR             Local loopback Cybex Forge address behind nginx (default: 127.0.0.1:8080)
  --tftp-root PATH          TFTP root below /srv/cybex-forge (default: /srv/cybex-forge/tftp)
  --http-root PATH          HTTP asset root below /srv/cybex-forge (default: /srv/cybex-forge/www)
  --bootloader NAME         UEFI iPXE loader filename (default: snponly.efi)
  --menu-timeout-ms MS      Boot menu timeout desired by Cybex Manage; 0 disables it (default: 0)
  --update-trusted-public-key KEY
                            Standard-Base64 raw 32-byte Ed25519 update public key
  --allow-insecure-manage-http
                            Explicit development-only opt-in to an HTTP Manage URL
  --dry-run, --validate-only
                            Validate inputs/environment without installing or enrolling
  -h, --help                Show this help

Environment alternatives:
  CYBEX_MANAGE_API_URL, CYBEX_ORGANIZATION_ID, CYBEX_FORGE_AUTH_CODE,
  CYBEX_FORGE_AUTH_CODE_FILE,
  CYBEX_FORGE_PUBLIC_BASE_URL, CYBEX_FORGE_SOURCE_DIR, CYBEX_FORGE_GIT_URL,
  CYBEX_FORGE_REF, CYBEX_FORGE_LISTEN_ADDR, CYBEX_FORGE_TFTP_ROOT,
  CYBEX_FORGE_HTTP_ROOT, CYBEX_FORGE_BOOTLOADER_FILENAME,
  CYBEX_FORGE_BOOT_MENU_TIMEOUT_MS, CYBEX_FORGE_UPDATE_TRUSTED_PUBLIC_KEY
EOF
}

api_url="${CYBEX_MANAGE_API_URL:-}"
organization_id="${CYBEX_ORGANIZATION_ID:-}"
auth_code="${CYBEX_FORGE_AUTH_CODE:-}"
unset CYBEX_FORGE_AUTH_CODE
auth_code_file="${CYBEX_FORGE_AUTH_CODE_FILE:-}"
public_base_url="${CYBEX_FORGE_PUBLIC_BASE_URL:-}"
source_dir="${CYBEX_FORGE_SOURCE_DIR:-$FORGE_SOURCE_DIR_DEFAULT}"
git_url="${CYBEX_FORGE_GIT_URL:-$FORGE_GIT_URL_DEFAULT}"
forge_ref="${CYBEX_FORGE_REF:-$FORGE_REF_DEFAULT}"
listen_addr="${CYBEX_FORGE_LISTEN_ADDR:-127.0.0.1:8080}"
tftp_root="${CYBEX_FORGE_TFTP_ROOT:-/srv/cybex-forge/tftp}"
http_root="${CYBEX_FORGE_HTTP_ROOT:-/srv/cybex-forge/www}"
bootloader_filename="${CYBEX_FORGE_BOOTLOADER_FILENAME:-snponly.efi}"
menu_timeout_ms="${CYBEX_FORGE_BOOT_MENU_TIMEOUT_MS:-0}"
update_trusted_public_key="${CYBEX_FORGE_UPDATE_TRUSTED_PUBLIC_KEY:-}"
allow_insecure_manage_http="${CYBEX_FORGE_ALLOW_INSECURE_MANAGE_HTTP:-0}"
dry_run=0
temporary_auth_code_file=""
bootstrap_auth_code_file="/var/lib/cybex-forge/bootstrap/enrollment-code"
bootstrap_auth_code_tomb="/var/lib/cybex-forge/bootstrap/.enrollment-code.consumed"
bootstrap_auth_code_staged_file="/var/lib/cybex-forge/bootstrap/.enrollment-code.staged"
bootstrap_auth_code_identity_file="/var/lib/cybex-forge-bootstrap.identity"
bootstrap_auth_code_identity=""
bootstrap_auth_code_pending=0

cleanup_sensitive_auth_codes() {
  local status="$?"
  local cleanup_failed=0
  trap - EXIT
  if [ "$bootstrap_auth_code_pending" -eq 1 ]; then
    if ! secure_remove_bootstrap_auth_code; then
      echo "failed to securely remove the staged Forge enrollment code" >&2
      cleanup_failed=1
    fi
  fi
  if [ -n "$temporary_auth_code_file" ] && [ -f "$temporary_auth_code_file" ]; then
    if command -v shred >/dev/null 2>&1; then
      shred -u -n 1 -z -- "$temporary_auth_code_file" >/dev/null 2>&1 ||
        rm -f -- "$temporary_auth_code_file" || cleanup_failed=1
    else
      rm -f -- "$temporary_auth_code_file" || cleanup_failed=1
    fi
  fi
  if [ "$cleanup_failed" -eq 1 ] && [ "$status" -eq 0 ]; then
    status=1
  fi
  exit "$status"
}

trap cleanup_sensitive_auth_codes EXIT

while [ "$#" -gt 0 ]; do
  case "$1" in
    --api-url) api_url="${2:-}"; shift 2 ;;
    --organization-id) organization_id="${2:-}"; shift 2 ;;
    --auth-code) auth_code="${2:-}"; shift 2 ;;
    --auth-code-file) auth_code_file="${2:-}"; shift 2 ;;
    --public-base-url) public_base_url="${2:-}"; shift 2 ;;
    --source-dir) source_dir="${2:-}"; shift 2 ;;
    --git-url) git_url="${2:-}"; shift 2 ;;
    --forge-ref) forge_ref="${2:-}"; shift 2 ;;
    --listen) listen_addr="${2:-}"; shift 2 ;;
    --tftp-root) tftp_root="${2:-}"; shift 2 ;;
    --http-root) http_root="${2:-}"; shift 2 ;;
    --bootloader) bootloader_filename="${2:-}"; shift 2 ;;
    --menu-timeout-ms) menu_timeout_ms="${2:-}"; shift 2 ;;
    --update-trusted-public-key) update_trusted_public_key="${2:-}"; shift 2 ;;
    --allow-insecure-manage-http) allow_insecure_manage_http=1; shift ;;
    --dry-run|--validate-only) dry_run=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

require_value() {
  local name="$1"
  local value="$2"
  if [ -z "$value" ]; then
    echo "$name is required" >&2
    usage >&2
    exit 2
  fi
}

require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "run as root inside the Cybex Forge LXC" >&2
    exit 1
  fi
}

validate_url() {
  local name="$1"
  local value="$2"
  local rest authority port
  case "$value" in
    http://*) rest="${value#http://}" ;;
    https://*) rest="${value#https://}" ;;
    *) echo "$name must start with http:// or https://" >&2; exit 2 ;;
  esac
  if printf '%s' "$value" | LC_ALL=C grep -q '[[:space:]"\\]'; then
    echo "$name contains unsupported characters" >&2
    exit 2
  fi
  if printf '%s' "$value" | LC_ALL=C grep -q '[;&|`$<>(){}]'; then
    echo "$name contains unsupported characters" >&2
    exit 2
  fi
  case "$value" in
    *'?'*|*'#'*|*@*) echo "$name contains unsupported characters" >&2; exit 2 ;;
  esac
  if ! printf '%s' "$value" | LC_ALL=C grep -Eq '^https?://[A-Za-z0-9.-]+(:[0-9]+)?(/[^[:space:]"\\?#@]*)?$'; then
    echo "$name must be an absolute http(s) URL with a host and optional path" >&2
    exit 2
  fi
  authority="${rest%%/*}"
  case "$authority" in
    *:*)
      port="${authority##*:}"
      if ! printf '%s' "$port" | LC_ALL=C grep -Eq '^[0-9]+$'; then
        echo "$name port must be numeric" >&2
        exit 2
      fi
      if [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
        echo "$name port must be between 1 and 65535" >&2
        exit 2
      fi
      ;;
  esac
}

validate_manage_transport() {
  case "$allow_insecure_manage_http" in
    0|1) ;;
    *) echo "CYBEX_FORGE_ALLOW_INSECURE_MANAGE_HTTP must be 0 or 1" >&2; exit 2 ;;
  esac
  case "$api_url" in
    https://*) ;;
    http://*)
      if [ "$allow_insecure_manage_http" -ne 1 ]; then
        echo "--api-url must use HTTPS; development HTTP requires --allow-insecure-manage-http" >&2
        exit 2
      fi
      ;;
    *) echo "--api-url must use HTTPS" >&2; exit 2 ;;
  esac
}

validate_plain_value() {
  local name="$1"
  local value="$2"
  if printf '%s' "$value" | LC_ALL=C grep -q '[[:cntrl:]"\\]'; then
    echo "$name contains unsupported characters" >&2
    exit 2
  fi
}

validate_organization_id() {
  validate_plain_value "--organization-id" "$organization_id"
  if ! printf '%s' "$organization_id" | LC_ALL=C grep -Eq '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'; then
    echo "--organization-id must be a UUID" >&2
    exit 2
  fi
}

validate_auth_code_value() {
  local value="$1"
  validate_plain_value "Forge install authorization code" "$value"
  if [ "${#value}" -lt 16 ]; then
    echo "Forge install authorization code is too short" >&2
    exit 2
  fi
  if [ "${#value}" -gt 512 ]; then
    echo "Forge install authorization code is too long" >&2
    exit 2
  fi
  if printf '%s' "$value" | LC_ALL=C grep -q '[[:space:]]'; then
    echo "Forge install authorization code contains unsupported characters" >&2
    exit 2
  fi
}

validate_root_protected_auth_code_parent() {
  local path="$1"
  local label="$2"
  local parent canonical current component owner mode mode_value
  local -a components=()
  parent="$(dirname -- "$path")"
  canonical="$(realpath -e -- "$parent")" || {
    echo "$label parent path must exist" >&2
    exit 2
  }
  if [ "$canonical" != "$parent" ]; then
    echo "$label parent path must be canonical and contain no symlink" >&2
    exit 2
  fi
  IFS='/' read -r -a components <<< "${parent#/}"
  current="/"
  for component in "" "${components[@]}"; do
    if [ -n "$component" ]; then
      current="${current%/}/$component"
    fi
    if [ -L "$current" ] || [ ! -d "$current" ]; then
      echo "$label parent path must contain only directories, not symlinks" >&2
      exit 2
    fi
    owner="$(stat -c '%u' -- "$current")"
    mode="$(stat -c '%a' -- "$current")"
    if [ "$owner" != "0" ]; then
      echo "$label parent path must be entirely root-owned" >&2
      exit 2
    fi
    if ! [[ "$mode" =~ ^[0-7]{3,4}$ ]]; then
      echo "$label parent path has invalid permissions" >&2
      exit 2
    fi
    mode_value=$((8#$mode))
    if (( (mode_value & 0022) != 0 )); then
      echo "$label parent path must not be group- or other-writable" >&2
      exit 2
    fi
  done
}

validate_auth_code_file() {
  local path="$1"
  local expected_uid="$2"
  local label="$3"
  local owner mode links size value
  validate_absolute_path "$label" "$path"
  if [ -L "$path" ] || [ ! -f "$path" ]; then
    echo "$label must be a regular file, not a symlink" >&2
    exit 2
  fi
  owner="$(stat -c '%u' -- "$path")"
  mode="$(stat -c '%a' -- "$path")"
  links="$(stat -c '%h' -- "$path")"
  size="$(stat -c '%s' -- "$path")"
  if [ "$owner" != "$expected_uid" ] || [ "$mode" != "600" ] || [ "$links" != "1" ]; then
    echo "$label has unsafe ownership, permissions, or link count" >&2
    exit 2
  fi
  if [ "$size" -gt 512 ]; then
    echo "$label is too large" >&2
    exit 2
  fi
  value="$(<"$path")"
  validate_auth_code_value "$value"
  value=""
}

secure_remove_bootstrap_auth_code() {
  local helper="/usr/local/libexec/cybex-forge-secure-input"
  local candidate=""
  local present=0
  local source_present=0
  local tomb_present=0
  local staged_present=0
  [ "$bootstrap_auth_code_pending" -eq 1 ] || return 0
  if [ -e "$bootstrap_auth_code_file" ] || [ -L "$bootstrap_auth_code_file" ]; then
    source_present=1
  fi
  if [ -e "$bootstrap_auth_code_tomb" ] || [ -L "$bootstrap_auth_code_tomb" ]; then
    tomb_present=1
  fi
  if [ -e "$bootstrap_auth_code_staged_file" ] || [ -L "$bootstrap_auth_code_staged_file" ]; then
    staged_present=1
  fi
  present=$((source_present + tomb_present + staged_present))
  if [ "$present" -gt 1 ]; then
    echo "multiple Forge enrollment code paths exist" >&2
    return 1
  fi
  if [ "$source_present" -eq 1 ]; then
    candidate="$bootstrap_auth_code_file"
  elif [ "$tomb_present" -eq 1 ]; then
    candidate="$bootstrap_auth_code_tomb"
  elif [ "$staged_present" -eq 1 ]; then
    candidate="$bootstrap_auth_code_staged_file"
  fi
  if [ -n "$candidate" ]; then
    local rebound_identity
    [ -x "$helper" ] || return 1
    if [ -z "$bootstrap_auth_code_identity" ] &&
      [ -e "$bootstrap_auth_code_identity_file" ] &&
      [ ! -L "$bootstrap_auth_code_identity_file" ] &&
      [ -f "$bootstrap_auth_code_identity_file" ] &&
      [ "$(stat -c '%u:%a:%h' -- "$bootstrap_auth_code_identity_file")" = "$(id -u):600:1" ]; then
      bootstrap_auth_code_identity="$(<"$bootstrap_auth_code_identity_file")"
    fi
    if [ "$bootstrap_auth_code_identity" = "pending" ] ||
      ! printf '%s' "$bootstrap_auth_code_identity" | grep -Eq '^[0-9]+(:[0-9]+){6}$'; then
      rebound_identity="$(runuser -u cybex-forge -- \
        "$helper" identity "$candidate" 512 secret)" || return 1
      bootstrap_auth_code_identity="$rebound_identity"
    elif ! runuser -u cybex-forge -- \
      "$helper" erase-if-same "$candidate" "$bootstrap_auth_code_identity" \
      >/dev/null 2>&1; then
      rebound_identity="$(runuser -u cybex-forge -- \
        "$helper" identity "$candidate" 512 secret)" || return 1
      [ "${rebound_identity%:*:*:*:*}" = \
        "${bootstrap_auth_code_identity%:*:*:*:*}" ] || return 1
      bootstrap_auth_code_identity="$rebound_identity"
    else
      bootstrap_auth_code_identity=""
    fi
    if [ -n "$bootstrap_auth_code_identity" ]; then
      runuser -u cybex-forge -- \
        "$helper" erase-if-same "$candidate" "$bootstrap_auth_code_identity" ||
        return 1
    fi
  fi
  [ ! -e "$bootstrap_auth_code_file" ] && [ ! -L "$bootstrap_auth_code_file" ] || return 1
  [ ! -e "$bootstrap_auth_code_tomb" ] && [ ! -L "$bootstrap_auth_code_tomb" ] || return 1
  [ ! -e "$bootstrap_auth_code_staged_file" ] && [ ! -L "$bootstrap_auth_code_staged_file" ] || return 1
  if [ -e "$bootstrap_auth_code_identity_file" ] || [ -L "$bootstrap_auth_code_identity_file" ]; then
    [ ! -L "$bootstrap_auth_code_identity_file" ] &&
      [ -f "$bootstrap_auth_code_identity_file" ] &&
      [ "$(stat -c '%u:%a:%h' -- "$bootstrap_auth_code_identity_file")" = "$(id -u):600:1" ] ||
      return 1
    : > "$bootstrap_auth_code_identity_file"
    sync -f "$bootstrap_auth_code_identity_file"
    rm -f -- "$bootstrap_auth_code_identity_file"
    sync -f "$(dirname "$bootstrap_auth_code_identity_file")"
  fi
  bootstrap_auth_code_identity=""
  bootstrap_auth_code_pending=0
}

persist_bootstrap_auth_code_identity() {
  local identity="$1"
  local identity_temporary
  if [ "$identity" != "pending" ] &&
    ! printf '%s' "$identity" | grep -Eq '^[0-9]+(:[0-9]+){6}$'; then
    echo "refusing to persist an invalid Forge enrollment code identity" >&2
    return 1
  fi
  identity_temporary="$(mktemp "${bootstrap_auth_code_identity_file}.tmp.XXXXXX")"
  printf '%s\n' "$identity" > "$identity_temporary"
  chown root:root "$identity_temporary"
  chmod 0600 "$identity_temporary"
  sync -f "$identity_temporary"
  mv -T -- "$identity_temporary" "$bootstrap_auth_code_identity_file"
  sync -f "$(dirname "$bootstrap_auth_code_identity_file")"
}

prepare_auth_code_source() {
  if [ -n "$auth_code" ] && [ -n "$auth_code_file" ]; then
    echo "--auth-code and --auth-code-file are mutually exclusive" >&2
    exit 2
  fi
  if [ -z "$auth_code" ] && [ -z "$auth_code_file" ]; then
    echo "one of --auth-code-file or --auth-code is required" >&2
    exit 2
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
  validate_root_protected_auth_code_parent "$auth_code_file" "--auth-code-file"
  validate_auth_code_file "$auth_code_file" "$(id -u)" "--auth-code-file"
}

validate_listen_addr() {
  validate_plain_value "--listen" "$listen_addr"
  case "$listen_addr" in
    127.0.0.1:[0-9]*)
      ;;
    *)
      echo "--listen must be a loopback host:port such as 127.0.0.1:8080" >&2
      exit 2
      ;;
  esac
  local port="${listen_addr##*:}"
  if ! printf '%s' "$port" | LC_ALL=C grep -Eq '^[0-9]+$'; then
    echo "--listen port must be numeric" >&2
    exit 2
  fi
  if [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
    echo "--listen port must be between 1 and 65535" >&2
    exit 2
  fi
}

validate_absolute_path() {
  local name="$1"
  local value="$2"
  validate_plain_value "$name" "$value"
  case "$value" in
    /*) ;;
    *) echo "$name must be an absolute path" >&2; exit 2 ;;
  esac
  if [ "$value" = "/" ] || printf '%s' "$value" | LC_ALL=C grep -q '//'; then
    echo "$name must be a normalized absolute path" >&2
    exit 2
  fi
  case "$value" in
    */)
      echo "$name must be a normalized absolute path" >&2
      exit 2
      ;;
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
      echo "$name must be a normalized absolute path" >&2
      exit 2
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
    echo "$name must not contain whitespace" >&2
    exit 2
  fi
  if ! printf '%s' "$value" | LC_ALL=C grep -Eq '^/[A-Za-z0-9._/-]+$'; then
    echo "$name contains unsupported characters" >&2
    exit 2
  fi
  case "$value" in
    "$allowed_root"/*) ;;
    "$allowed_root")
      echo "$name must be below $allowed_root, not $allowed_root itself" >&2
      exit 2
      ;;
    *)
      echo "$name must be under $allowed_root" >&2
      exit 2
      ;;
  esac
}

validate_runtime_roots() {
  validate_runtime_root "--tftp-root" "$tftp_root"
  validate_runtime_root "--http-root" "$http_root"
  case "$http_root/" in
    "$tftp_root/"*)
      echo "--http-root must not be inside --tftp-root" >&2
      exit 2
      ;;
  esac
  case "$tftp_root/" in
    "$http_root/"*)
      echo "--tftp-root must not be inside --http-root" >&2
      exit 2
      ;;
  esac
}

validate_bootloader_filename() {
  case "$bootloader_filename" in
    ""|*/*|*\\*|.*|*' '*|*$'\t'*)
      echo "--bootloader must be a simple filename such as snponly.efi" >&2
      exit 2
      ;;
  esac
  validate_plain_value "--bootloader" "$bootloader_filename"
  if ! printf '%s' "$bootloader_filename" | LC_ALL=C grep -Eq '^[A-Za-z0-9._-]+$'; then
    echo "--bootloader must use only letters, numbers, dot, underscore, or hyphen" >&2
    exit 2
  fi
}

validate_update_trusted_public_key() {
  local value="$update_trusted_public_key"
  local decoded_size canonical
  [ -n "$value" ] || return 0
  require_command base64
  if ! printf '%s' "$value" | LC_ALL=C grep -Eq '^[A-Za-z0-9+/]{43}=$'; then
    echo "--update-trusted-public-key must be canonical standard Base64 for exactly 32 bytes" >&2
    exit 2
  fi
  if ! decoded_size="$(printf '%s' "$value" | base64 --decode 2>/dev/null | wc -c | tr -d '[:space:]')"; then
    echo "--update-trusted-public-key is not valid standard Base64" >&2
    exit 2
  fi
  if [ "$decoded_size" != "32" ]; then
    echo "--update-trusted-public-key must decode to exactly 32 bytes" >&2
    exit 2
  fi
  if ! canonical="$(printf '%s' "$value" | base64 --decode 2>/dev/null | base64 | tr -d '\n')"; then
    echo "--update-trusted-public-key is not valid standard Base64" >&2
    exit 2
  fi
  if [ "$canonical" != "$value" ]; then
    echo "--update-trusted-public-key must use canonical standard Base64" >&2
    exit 2
  fi
}

validate_menu_timeout() {
  if ! printf '%s' "$menu_timeout_ms" | LC_ALL=C grep -Eq '^[0-9]+$'; then
    echo "--menu-timeout-ms must be numeric" >&2
    exit 2
  fi
  if [ "$menu_timeout_ms" -ne 0 ] && { [ "$menu_timeout_ms" -lt 1000 ] || [ "$menu_timeout_ms" -gt 600000 ]; }; then
    echo "--menu-timeout-ms must be 0 or between 1000 and 600000" >&2
    exit 2
  fi
}

validate_forge_ref() {
  validate_plain_value "--forge-ref" "$forge_ref"
  if [ -z "$forge_ref" ]; then
    echo "--forge-ref is required" >&2
    exit 2
  fi
  if ! printf '%s' "$forge_ref" | LC_ALL=C grep -Eq '^[A-Za-z0-9._/@+-]+$'; then
    echo "--forge-ref must contain only letters, numbers, dot, underscore, slash, at, plus, or hyphen" >&2
    exit 2
  fi
  case "$forge_ref" in
    -*|*..*|*//*|*/.|*.|*~*|*^*|*:*|*'?'*|*'['*|*\\*|*' '*|*$'\t'*)
      echo "--forge-ref is not a safe git ref" >&2
      exit 2
      ;;
  esac
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "required command not found: $1" >&2
    exit 1
  }
}

installer_preflight() {
  require_root
  require_command apt-get
  require_command realpath
  require_command stat
  require_command systemctl
  if [ ! -d /run/systemd/system ]; then
    echo "systemd is not running inside this LXC" >&2
    exit 1
  fi
}

detect_local_ipv4() {
  local ip_address
  if command -v ip >/dev/null 2>&1; then
    ip_address="$(ip -4 -o addr show scope global up 2>/dev/null | awk '{ split($4, a, "/"); if (a[1] !~ /^127\./) { print a[1]; exit } }' || true)"
  fi
  if [ -z "${ip_address:-}" ]; then
    ip_address="$(hostname -I 2>/dev/null | awk '{ for (i = 1; i <= NF; i++) if ($i ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ && $i !~ /^127\./) { print $i; exit } }' || true)"
  fi
  printf '%s\n' "${ip_address:-}"
}

ensure_public_base_url() {
  if [ -n "$public_base_url" ]; then
    validate_url "--public-base-url" "$public_base_url"
    return
  fi
  local local_ip
  local_ip="$(detect_local_ipv4 | head -n 1)"
  if [ -z "$local_ip" ]; then
    echo "could not auto-detect this LXC's IPv4 address; pass --public-base-url" >&2
    exit 2
  fi
  public_base_url="http://$local_ip"
  validate_url "--public-base-url" "$public_base_url"
}

bootloader_supports_embedded_script() {
  local name="${1:-$bootloader_filename}"
  case "$name" in
    snponly.efi|ipxe.efi) return 0 ;;
    *) return 1 ;;
  esac
}

bootloader_embeds_current_chain() {
  local path="$1"
  [ -f "$path" ] || return 1
  LC_ALL=C grep -aFx -- "set boot-url $public_base_url" "$path" >/dev/null &&
    LC_ALL=C grep -aFx -- "chain --autofree \${boot-url}/boot/\${mac} || goto failed" "$path" >/dev/null &&
    LC_ALL=C grep -aFx -- "exit 1" "$path" >/dev/null &&
    ! LC_ALL=C grep -aFx -- "echo Dropping to iPXE shell." "$path" >/dev/null &&
    LC_ALL=C grep -aFx -- "# Embedded chainloader for Cybex Forge UEFI PXE clients." "$path" >/dev/null
}

run_as_boot() {
  runuser -u cybex-forge -- bash -c 'umask 077; exec "$@"' bash "$@"
}

install_packages() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y --no-install-recommends \
    ca-certificates curl git build-essential pkg-config libssl-dev \
    tftpd-hpa ipxe ipxe-qemu nginx logrotate openssl python3-minimal \
    sqlite3 xorriso zstd squashfs-tools
}

set_nix_conf_value() {
  local key="$1"
  local value="$2"
  local config="/etc/nix/nix.conf"
  local tmp
  install -m 0755 -d /etc/nix
  [ -f "$config" ] || : > "$config"
  tmp="$(mktemp "$config.tmp.XXXXXX")"
  awk -v key="$key" '
    BEGIN { FS = "=" }
    {
      field = $1
      sub(/^[[:space:]]+/, "", field)
      sub(/[[:space:]]+$/, "", field)
      if (field != key) {
        print
      }
    }
  ' "$config" > "$tmp"
  printf '%s = %s\n' "$key" "$value" >> "$tmp"
  install -m 0644 -o root -g root "$tmp" "$config"
  rm -f "$tmp"
}

nix_version_at_least() {
  local version="$1"
  local minimum_major="$2"
  local minimum_minor="$3"
  local major minor rest
  IFS=. read -r major minor rest <<EOF
$version
EOF
  case "$major:$minor" in
    *[!0-9:]*|:|*:)
      return 1
      ;;
  esac
  if [ "$major" -gt "$minimum_major" ]; then
    return 0
  fi
  if [ "$major" -eq "$minimum_major" ] && [ "$minor" -ge "$minimum_minor" ]; then
    return 0
  fi
  return 1
}

ensure_current_nix_profile() {
  local profile_nix="/nix/var/nix/profiles/default/bin/nix"
  local version=""
  if [ -x "$profile_nix" ]; then
    version="$("$profile_nix" --version 2>/dev/null | awk '{print $3}')"
    if nix_version_at_least "$version" 2 18; then
      return
    fi
  fi

  NIX_CONFIG="experimental-features = nix-command flakes" nix upgrade-nix -p /nix/var/nix/profiles/default
  if [ ! -x "$profile_nix" ]; then
    echo "Nix profile upgrade did not install $profile_nix" >&2
    exit 1
  fi
  version="$("$profile_nix" --version 2>/dev/null | awk '{print $3}')"
  if ! nix_version_at_least "$version" 2 18; then
    echo "Forge Build requires Nix 2.18 or newer at $profile_nix, found ${version:-unknown}" >&2
    exit 1
  fi
}

ensure_nix_toolchain() {
  if ! command -v nix >/dev/null 2>&1 || ! command -v nix-store >/dev/null 2>&1; then
    if ! apt-cache show nix-bin >/dev/null 2>&1 || ! apt-cache show nix-setup-systemd >/dev/null 2>&1; then
      echo "Debian Nix packages nix-bin and nix-setup-systemd are required for Forge Build/Cache" >&2
      exit 1
    fi

    export DEBIAN_FRONTEND=noninteractive
    apt-get install -y --no-install-recommends nix-bin nix-setup-systemd
  fi
  set_nix_conf_value experimental-features "nix-command flakes"
  set_nix_conf_value trusted-users "root cybex-forge"
  systemctl enable --now nix-daemon.socket >/dev/null 2>&1 || \
    systemctl enable --now nix-daemon.service >/dev/null 2>&1 || true

  require_command nix
  require_command nix-store
  ensure_current_nix_profile
}

ensure_rust() {
  if command -v cargo >/dev/null 2>&1 && rustc --version >/dev/null 2>&1; then
    local version
    version="$(rustc --version | awk '{print $2}')"
    case "$version" in
      1.8[5-9].*|1.9[0-9].*|[2-9].*) return ;;
    esac
  fi
  curl --proto '=https' --tlsv1.2 -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable
  # shellcheck disable=SC1091
  . /root/.cargo/env
}

prepare_source() {
  if [ -d "$source_dir/.git" ]; then
    git -C "$source_dir" remote set-url origin "$git_url" || true
    git -C "$source_dir" fetch --depth 1 origin "$forge_ref"
    git -C "$source_dir" checkout --detach -f FETCH_HEAD
    git -C "$source_dir" rev-parse HEAD > "$source_dir/.cybex-forge-revision"
    return
  fi
  if [ -f "$source_dir/Cargo.toml" ]; then
    echo "using existing non-git source directory $source_dir; --forge-ref cannot be verified" >&2
    return
  fi
  if [ -z "$git_url" ]; then
    echo "source directory $source_dir is missing; pass --git-url or pre-stage the source" >&2
    exit 1
  fi
  rm -rf "$source_dir"
  git init "$source_dir"
  git -C "$source_dir" remote add origin "$git_url"
  git -C "$source_dir" fetch --depth 1 origin "$forge_ref"
  git -C "$source_dir" checkout --detach -f FETCH_HEAD
  git -C "$source_dir" rev-parse HEAD > "$source_dir/.cybex-forge-revision"
}

require_source_file_contains() {
  local path="$1"
  local expected="$2"
  local label="$3"
  if grep -F -- "$expected" "$path" >/dev/null 2>&1; then
    return
  fi
  echo "source compatibility check failed: $label is missing from $path" >&2
  echo "update the Cybex Forge source before running this helper" >&2
  exit 1
}

verify_source_compatibility() {
  if [ ! -f "$source_dir/Cargo.toml" ]; then
    echo "source directory $source_dir is missing Cargo.toml" >&2
    exit 1
  fi
  if [ ! -f "$source_dir/systemd/cybex-forge.service" ]; then
    echo "source directory $source_dir is missing systemd/cybex-forge.service" >&2
    exit 1
  fi
  if [ ! -f "$source_dir/systemd/cybex-forge-runtime-apply.service" ] || [ ! -f "$source_dir/systemd/cybex-forge-runtime-apply.timer" ]; then
    echo "source directory $source_dir is missing managed runtime apply systemd units" >&2
    exit 1
  fi
  for required in \
    systemd/cybex-forge-control.slice \
    systemd/cybex-forge-build.slice \
    systemd/cybex-forge-sentinel.service \
    systemd/cybex-forge-sentinel.timer \
    systemd/nix-daemon-cybex-forge.conf \
    appliance/cybex-forge-secure-input.c \
    install/cybex-forge-check \
    install/cybex-forge-sync-once \
    install/cybex-forge-sentinel; do
    if [ ! -f "$source_dir/$required" ]; then
      echo "source directory $source_dir is missing $required" >&2
      exit 1
    fi
  done
  require_source_file_contains "$source_dir/src/routes/mod.rs" 'route("/boot.ipxe", get(boot::boot_root))' "direct /boot.ipxe route"
  if grep -F 'route("/login"' "$source_dir/src/routes/mod.rs" >/dev/null 2>&1 || grep -F '.nest("/api"' "$source_dir/src/routes/mod.rs" >/dev/null 2>&1; then
    echo "source compatibility check failed: local login/API routes are still present in $source_dir/src/routes/mod.rs" >&2
    exit 1
  fi
  require_source_file_contains "$source_dir/src/routes/boot.rs" "cybex_check" "loopback checker marker query"
  require_source_file_contains "$source_dir/src/routes/boot.rs" "is_local_checker_request" "loopback checker marker guard"
  require_source_file_contains "$source_dir/src/config.rs" "normalize_absolute_config_path" "normalized absolute path validation"
  require_source_file_contains "$source_dir/src/config.rs" "is_ascii_alphanumeric()" "strict bootloader filename validation"
  require_source_file_contains "$source_dir/src/assets.rs" "reject_symlink_components" "public file symlink rejection"
  require_source_file_contains "$source_dir/src/assets.rs" "prune_missing_iso_assets" "authoritative ISO asset pruning"
  require_source_file_contains "$source_dir/src/db.rs" "seen_device_serial_number" "serial/MAC seen-device reconciliation"
  require_source_file_contains "$source_dir/src/db.rs" "boot_event_retention_preserves_known_selected_profile_events" "known selected event retention"
  require_source_file_contains "$source_dir/src/routes/mod.rs" "request_trace_path" "privacy-minimized request tracing"
  require_source_file_contains "$source_dir/src/error.rs" "response_message" "generic internal error responses"
  require_source_file_contains "$source_dir/src/routes/boot.rs" "boot_profile_id_from_path" "safe boot profile path parsing"
  require_source_file_contains "$source_dir/src/boot.rs" "profile_has_boot_action" "selectable profiles require a boot action"
  require_source_file_contains "$source_dir/src/boot.rs" "append_ipxe_menu_theme" "themed iPXE menu renderer"
  require_source_file_contains "$source_dir/src/boot.rs" "PXE BOOT - FORGE BOOT - X86_64 - UEFI" "themed iPXE menu subtitle"
  require_source_file_contains "$source_dir/src/manage.rs" "validate_assignable_profile" "managed config assignable profile validation"
  require_source_file_contains "$source_dir/src/manage.rs" "managed_profile_has_boot_action" "managed config boot-action validation"
  require_source_file_contains "$source_dir/src/manage.rs" "multiple default profiles" "managed config single-default validation"
  require_source_file_contains "$source_dir/src/manage.rs" "clear_synced_default_profiles" "managed sync default mirroring"
  require_source_file_contains "$source_dir/src/manage.rs" "managed_sync_preserves_omitted_profiles_when_window_incomplete" "managed profile window completeness"
  require_source_file_contains "$source_dir/src/manage.rs" "managed_sync_preserves_omitted_clients_when_window_incomplete" "managed client window completeness"
  require_source_file_contains "$source_dir/src/manage.rs" "managed_sync_deletes_tombstoned_profiles_when_window_incomplete" "managed profile deletion tombstones"
  require_source_file_contains "$source_dir/src/manage.rs" "managed_sync_deletes_tombstoned_clients_when_window_incomplete" "managed client deletion tombstones"
  require_source_file_contains "$source_dir/src/manage.rs" "installer_iso_source" "managed installer ISO source support"
  require_source_file_contains "$source_dir/src/manage.rs" "Default Enrollment" "managed Default Enrollment seed support"
  require_source_file_contains "$source_dir/src/manage.rs" "enrollment" "managed enrollment ISO sync support"
  require_source_file_contains "$source_dir/src/boot.rs" "profile.name" "PXE managed profile menu labels"
  require_source_file_contains "$source_dir/src/manage.rs" "boot_report_body_fitter_trims_inventory_before_events" "managed report body byte budget"
  require_source_file_contains "$source_dir/src/manage.rs" "selected_profile_id: Option<String>" "managed selected profile event field"
  require_source_file_contains "$source_dir/src/manage.rs" "managed_profile_id AS selected_profile_id" "managed selected profile event lookup"
  require_source_file_contains "$source_dir/src/manage.rs" "selected_profile_id: optional_report_uuid(event.selected_profile_id)" "managed selected profile event report"
  require_source_file_contains "$source_dir/src/manage.rs" "has_unreported_known_profile_events" "pre-config known-profile event reporting"
  require_source_file_contains "$source_dir/src/manage.rs" "apply_runtime_config_once" "root managed runtime apply command"
  require_source_file_contains "$source_dir/src/manage.rs" "managed runtime configuration is pending adoption; skipping apply" "pending runtime apply no-op"
  require_source_file_contains "$source_dir/src/config.rs" "organization_id" "managed organization id enrollment"
  require_source_file_contains "$source_dir/src/config.rs" "forge_install_code_file" "protected file-backed Forge install code enrollment"
}

install_binary() {
  local secure_input
  # shellcheck disable=SC1091
  [ -f /root/.cargo/env ] && . /root/.cargo/env
  cargo build --quiet --release --manifest-path "$source_dir/Cargo.toml"
  rm -f /usr/local/bin/cybex-forge
  install -m 0755 -o root -g root "$source_dir/target/release/cybex-forge" /usr/local/bin/cybex-forge
  secure_input="$(mktemp /run/cybex-forge-secure-input.XXXXXX)"
  cc -std=c11 -O2 -Wall -Wextra -Werror \
    "$source_dir/appliance/cybex-forge-secure-input.c" -o "$secure_input"
  install -d -m 0755 -o root -g root /usr/local/libexec
  install -m 0755 -o root -g root \
    "$secure_input" /usr/local/libexec/cybex-forge-secure-input
  rm -f -- "$secure_input"
}

prepare_user_and_dirs() {
  if ! id cybex-forge >/dev/null 2>&1; then
    useradd --system --home /var/lib/cybex-forge --shell /usr/sbin/nologin cybex-forge
  fi
  if getent group nix-users >/dev/null 2>&1; then
    usermod -aG nix-users cybex-forge
  fi
  install -m 0750 -o root -g cybex-forge -d /etc/cybex-forge
  install -m 0700 -o cybex-forge -g cybex-forge -d /var/lib/cybex-forge
  install -m 0700 -o cybex-forge -g cybex-forge -d /var/lib/cybex-forge/bootstrap /var/lib/cybex-forge/build /var/lib/cybex-forge/build-outputs /var/lib/cybex-forge/cache /var/lib/cybex-forge/updates
  install -m 0755 -o root -g root -d /opt/cybex-forge/releases
  install -m 0755 -o root -g cybex-forge -d /srv/cybex-forge
  install -m 0755 -o cybex-forge -g cybex-forge -d "$http_root" "$http_root/isos" "$http_root/assets" "$http_root/cache"
  install -m 0555 -o root -g root -d "$tftp_root"
  chown -R cybex-forge:cybex-forge /var/lib/cybex-forge "$http_root"
  chmod 0700 /var/lib/cybex-forge
  chmod 0755 "$http_root" "$http_root/isos" "$http_root/assets" "$http_root/cache"
  find "$http_root" -xdev \( -type f -o -type d \) \( -perm -020 -o -perm -002 \) -exec chmod go-w {} +
  rm -f "$http_root/boot.ipxe"
  find "$http_root" -maxdepth 1 \( -type f -o -type l \) -name '.cybex-check.*' -delete
  if [ -f "$http_root/README.txt" ] && grep -Eq 'Cybex Forge HTTP root|/srv/cybex-forge/app' "$http_root/README.txt"; then
    rm -f "$http_root/README.txt"
  fi
  if [ -d /srv/cybex-forge/app ] && [ -z "$(find /srv/cybex-forge/app -mindepth 1 -print -quit)" ]; then
    rmdir /srv/cybex-forge/app
  fi
  harden_tftp_tree
}

install_enrollment_code() {
  local rebound_identity
  local source="$auth_code_file"
  validate_root_protected_auth_code_parent "$source" "--auth-code-file"
  validate_auth_code_file "$source" "$(id -u)" "--auth-code-file"
  if [ -e "$bootstrap_auth_code_file" ] || [ -L "$bootstrap_auth_code_file" ] \
    || [ -e "$bootstrap_auth_code_tomb" ] || [ -L "$bootstrap_auth_code_tomb" ] \
    || [ -e "$bootstrap_auth_code_staged_file" ] || [ -L "$bootstrap_auth_code_staged_file" ] \
    || [ -e "$bootstrap_auth_code_identity_file" ] || [ -L "$bootstrap_auth_code_identity_file" ]; then
    echo "refusing to overwrite residual Forge enrollment credential state" >&2
    exit 1
  fi
  bootstrap_auth_code_pending=1
  bootstrap_auth_code_identity="pending"
  persist_bootstrap_auth_code_identity "$bootstrap_auth_code_identity"
  install -m 0600 -o cybex-forge -g cybex-forge -- \
    "$source" "$bootstrap_auth_code_staged_file"
  validate_auth_code_file "$bootstrap_auth_code_staged_file" \
    "$(id -u cybex-forge)" "staged enrollment code"
  bootstrap_auth_code_identity="$(runuser -u cybex-forge -- \
    /usr/local/libexec/cybex-forge-secure-input \
    identity "$bootstrap_auth_code_staged_file" 512 secret)"
  if ! printf '%s' "$bootstrap_auth_code_identity" | \
    grep -Eq '^[0-9]+(:[0-9]+){6}$'; then
    echo "could not bind staged Forge enrollment code identity" >&2
    exit 1
  fi
  persist_bootstrap_auth_code_identity "$bootstrap_auth_code_identity"
  mv -T -- "$bootstrap_auth_code_staged_file" "$bootstrap_auth_code_file"
  sync -f "$(dirname "$bootstrap_auth_code_file")"
  rebound_identity="$(runuser -u cybex-forge -- \
    /usr/local/libexec/cybex-forge-secure-input \
    identity "$bootstrap_auth_code_file" 512 secret)"
  [ "${rebound_identity%:*:*:*:*}" = \
    "${bootstrap_auth_code_identity%:*:*:*:*}" ] || {
    echo "staged Forge enrollment code identity changed during publication" >&2
    exit 1
  }
  bootstrap_auth_code_identity="$rebound_identity"
  persist_bootstrap_auth_code_identity "$bootstrap_auth_code_identity"
  validate_auth_code_file "$bootstrap_auth_code_file" "$(id -u cybex-forge)" "installed enrollment code"

  if [ "$source" != "$bootstrap_auth_code_file" ]; then
    if command -v shred >/dev/null 2>&1; then
      shred -u -n 1 -z -- "$source" >/dev/null 2>&1 || rm -f -- "$source"
    else
      rm -f -- "$source"
    fi
  fi
  if [ "$temporary_auth_code_file" = "$source" ]; then
    temporary_auth_code_file=""
  fi
  auth_code_file="$bootstrap_auth_code_file"
}

install_theme_assets() {
  local menu_background="$source_dir/assets/pxe-menu.png"
  if [ -f "$menu_background" ]; then
    install -m 0644 -o cybex-forge -g cybex-forge "$menu_background" "$http_root/assets/pxe-menu.png"
  fi
}

write_config() {
  local config_path="/etc/cybex-forge/config.toml"
  local config_tmp
  install -m 0750 -o root -g cybex-forge -d /etc/cybex-forge
  config_tmp="$(mktemp "$config_path.tmp.XXXXXX")"
  trap 'if [ -n "${config_tmp:-}" ]; then rm -f "$config_tmp"; fi' RETURN
  cat > "$config_tmp" <<EOF
[server]
listen_addr = "$listen_addr"
public_base_url = "$public_base_url"

[paths]
data_dir = "/var/lib/cybex-forge"
database_path = "/var/lib/cybex-forge/cybex-forge.sqlite"
boot_assets_dir = "$http_root"
iso_dir = "$http_root/isos"
static_dir = "$http_root/assets"
tftp_dir = "$tftp_root"

[boot]
bootloader_filename = "$bootloader_filename"
menu_timeout_ms = $menu_timeout_ms

[build]
enabled = true
max_concurrent_builds = 1
max_build_cores = 4
minimum_memory_bytes = 17179869184
minimum_swap_bytes = 8589934592
timeout_seconds = 3600
cancel_grace_seconds = 10
max_log_bytes = 65536
max_artifact_size_bytes = 21474836480
allowed_systems = ["x86_64-linux"]
work_dir = "/var/lib/cybex-forge/build"
output_dir = "/var/lib/cybex-forge/build-outputs"
nix_binary = "/nix/var/nix/profiles/default/bin/nix"

[[build.targets]]
artifact_type = "nixos_closure"
target = "blueprint"
system = "x86_64-linux"
flake = "$NIXPKGS_FLAKE"
attr = "packages.x86_64-linux.desktop-experience"

[cache]
enabled = true
root_dir = "$http_root/cache"
signing_key_name = "cybex-forge-cache"
private_key_path = "/var/lib/cybex-forge/cache/cache-priv-key.pem"
public_key_path = "/var/lib/cybex-forge/cache/cache-pub-key.pem"
max_bytes = 68719476736
retain_recent_builds = 50

[update]
enabled = true
work_dir = "/var/lib/cybex-forge/updates"
releases_dir = "/opt/cybex-forge/releases"
binary_path = "/usr/local/bin/cybex-forge"
config_path = "/etc/cybex-forge/config.toml"
service_name = "cybex-forge.service"
health_url = ""
max_artifact_size_bytes = 134217728
trusted_public_key = "$update_trusted_public_key"

[manage]
enabled = true
api_url = "$api_url"
organization_id = "$organization_id"
forge_install_code_file = "$bootstrap_auth_code_file"
state_path = "/var/lib/cybex-forge/manage-state.json"
sync_interval_seconds = 30
enrollment_poll_seconds = 10
http_timeout_seconds = 30
EOF
  install -m 0640 -o root -g cybex-forge "$config_tmp" "$config_path"
  rm -f "$config_tmp"
  config_tmp=""
  trap - RETURN
}

validate_pinned_build_inputs() {
  local profile_nix="/nix/var/nix/profiles/default/bin/nix"
  local package output hash
  echo "Validating pinned nixpkgs revision $NIXPKGS_REVISION and representative heavy packages."
  runuser -u cybex-forge -- "$profile_nix" flake metadata --no-write-lock-file "$NIXPKGS_FLAKE" >/dev/null
  for package in firefox-devedition firefox-esr; do
    output="$(runuser -u cybex-forge -- "$profile_nix" eval --raw "$NIXPKGS_FLAKE#$package.outPath")"
    case "$output" in
      /nix/store/*) ;;
      *) echo "Pinned nixpkgs validation returned an invalid store path for $package" >&2; exit 1 ;;
    esac
    hash="$(basename "$output" | cut -d- -f1)"
    curl -fsS --max-time 30 -o /dev/null "https://cache.nixos.org/$hash.narinfo" || {
      echo "Pinned nixpkgs package $package is not available from cache.nixos.org" >&2
      exit 1
    }
  done
}

install_systemd() {
  install -m 0644 "$source_dir/systemd/cybex-forge.service" /etc/systemd/system/cybex-forge.service
  install -m 0644 "$source_dir/systemd/cybex-forge-runtime-apply.service" /etc/systemd/system/cybex-forge-runtime-apply.service
  install -m 0644 "$source_dir/systemd/cybex-forge-runtime-apply.timer" /etc/systemd/system/cybex-forge-runtime-apply.timer
  install -m 0644 "$source_dir/systemd/cybex-forge-control.slice" /etc/systemd/system/cybex-forge-control.slice
  install -m 0644 "$source_dir/systemd/cybex-forge-build.slice" /etc/systemd/system/cybex-forge-build.slice
  install -m 0644 "$source_dir/systemd/cybex-forge-sentinel.service" /etc/systemd/system/cybex-forge-sentinel.service
  install -m 0644 "$source_dir/systemd/cybex-forge-sentinel.timer" /etc/systemd/system/cybex-forge-sentinel.timer
  install -m 0755 -o root -g root "$source_dir/install/cybex-forge-sentinel" /usr/local/bin/cybex-forge-sentinel
  install -m 0755 -d /etc/systemd/system/cybex-forge.service.d
  cat > /etc/systemd/system/cybex-forge.service.d/10-logging.conf <<'EOF'
[Service]
Environment="RUST_LOG=cybex_forge=info,tower_http=warn"
EOF
  cat > /etc/systemd/system/cybex-forge.service.d/20-migrate.conf <<'EOF'
[Service]
ExecStartPre=/usr/local/bin/cybex-forge --config /etc/cybex-forge/config.toml migrate
EOF
  cat > /etc/systemd/system/cybex-forge.service.d/30-address-families.conf <<'EOF'
[Service]
RestrictAddressFamilies=
RestrictAddressFamilies=AF_INET AF_UNIX
EOF
  if getent group nix-users >/dev/null 2>&1; then
    cat > /etc/systemd/system/cybex-forge.service.d/35-nix-groups.conf <<'EOF'
[Service]
SupplementaryGroups=nix-users
EOF
  else
    rm -f /etc/systemd/system/cybex-forge.service.d/35-nix-groups.conf
  fi
  cat > /etc/systemd/system/cybex-forge.service.d/40-write-paths.conf <<EOF
[Service]
ReadWritePaths=
ReadWritePaths=/var/lib/cybex-forge $http_root
EOF
  cat > /etc/systemd/system/cybex-forge.service.d/50-proc.conf <<'EOF'
[Service]
ProtectProc=invisible
ProcSubset=pid
EOF
  cat > /etc/systemd/system/cybex-forge.service.d/55-nix-daemon.conf <<'EOF'
[Unit]
Wants=nix-daemon.socket
After=nix-daemon.socket
EOF
  install -m 0755 -d /etc/systemd/system/nix-daemon.service.d
  install -m 0644 "$source_dir/systemd/nix-daemon-cybex-forge.conf" \
    /etc/systemd/system/nix-daemon.service.d/10-cybex-forge-restart.conf
  install -m 0755 -d /etc/systemd/system/systemd-resolved.service.d
  cat > /etc/systemd/system/systemd-resolved.service.d/10-cybex-forge-recovery.conf <<'EOF'
[Unit]
StartLimitIntervalSec=0

[Service]
Restart=always
RestartSec=2s
Slice=cybex-forge-control.slice
CPUWeight=1000
IOWeight=1000
OOMScoreAdjust=-750
EOF
  install -m 0755 -d /etc/systemd/system/nginx.service.d /etc/systemd/system/tftpd-hpa.service.d
  cat > /etc/systemd/system/nginx.service.d/20-cybex-availability.conf <<'EOF'
[Unit]
StartLimitIntervalSec=0

[Service]
Restart=always
RestartSec=2s
Slice=cybex-forge-control.slice
CPUWeight=1000
IOWeight=1000
OOMScoreAdjust=-500
EOF
  cat > /etc/systemd/system/tftpd-hpa.service.d/20-cybex-availability.conf <<'EOF'
[Unit]
StartLimitIntervalSec=0

[Service]
Restart=always
RestartSec=2s
Slice=cybex-forge-control.slice
CPUWeight=1000
IOWeight=1000
OOMScoreAdjust=-500
EOF
  chown root:root \
    /etc/systemd/system/cybex-forge.service \
    /etc/systemd/system/cybex-forge-runtime-apply.service \
    /etc/systemd/system/cybex-forge-runtime-apply.timer \
    /etc/systemd/system/cybex-forge-control.slice \
    /etc/systemd/system/cybex-forge-build.slice \
    /etc/systemd/system/cybex-forge-sentinel.service \
    /etc/systemd/system/cybex-forge-sentinel.timer \
    /etc/systemd/system/cybex-forge.service.d/10-logging.conf \
    /etc/systemd/system/cybex-forge.service.d/20-migrate.conf \
    /etc/systemd/system/cybex-forge.service.d/30-address-families.conf \
    /etc/systemd/system/cybex-forge.service.d/40-write-paths.conf \
    /etc/systemd/system/cybex-forge.service.d/50-proc.conf \
    /etc/systemd/system/cybex-forge.service.d/55-nix-daemon.conf \
    /etc/systemd/system/nix-daemon.service.d/10-cybex-forge-restart.conf \
    /etc/systemd/system/systemd-resolved.service.d/10-cybex-forge-recovery.conf \
    /etc/systemd/system/nginx.service.d/20-cybex-availability.conf \
    /etc/systemd/system/tftpd-hpa.service.d/20-cybex-availability.conf
  if [ -f /etc/systemd/system/cybex-forge.service.d/35-nix-groups.conf ]; then
    chown root:root /etc/systemd/system/cybex-forge.service.d/35-nix-groups.conf
  fi
  chmod 0644 \
    /etc/systemd/system/cybex-forge.service \
    /etc/systemd/system/cybex-forge-runtime-apply.service \
    /etc/systemd/system/cybex-forge-runtime-apply.timer \
    /etc/systemd/system/cybex-forge-control.slice \
    /etc/systemd/system/cybex-forge-build.slice \
    /etc/systemd/system/cybex-forge-sentinel.service \
    /etc/systemd/system/cybex-forge-sentinel.timer \
    /etc/systemd/system/cybex-forge.service.d/10-logging.conf \
    /etc/systemd/system/cybex-forge.service.d/20-migrate.conf \
    /etc/systemd/system/cybex-forge.service.d/30-address-families.conf \
    /etc/systemd/system/cybex-forge.service.d/40-write-paths.conf \
    /etc/systemd/system/cybex-forge.service.d/50-proc.conf \
    /etc/systemd/system/cybex-forge.service.d/55-nix-daemon.conf \
    /etc/systemd/system/nix-daemon.service.d/10-cybex-forge-restart.conf \
    /etc/systemd/system/systemd-resolved.service.d/10-cybex-forge-recovery.conf \
    /etc/systemd/system/nginx.service.d/20-cybex-availability.conf \
    /etc/systemd/system/tftpd-hpa.service.d/20-cybex-availability.conf
  if [ -f /etc/systemd/system/cybex-forge.service.d/35-nix-groups.conf ]; then
    chmod 0644 /etc/systemd/system/cybex-forge.service.d/35-nix-groups.conf
  fi
  systemctl daemon-reload
  # nix-setup-systemd can leave the daemon running directly while this
  # installer upgrades Nix. Stop it before switching back to socket
  # activation; systemd refuses to start the socket while its service is
  # already active.
  systemctl stop nix-daemon.service nix-daemon.socket || true
  systemctl reset-failed nix-daemon.service nix-daemon.socket || true
  systemctl enable --now nix-daemon.socket
  systemctl enable --now cybex-forge-runtime-apply.timer
  systemctl enable cybex-forge-sentinel.timer
}

install_maintenance_tools() {
  install -o root -g root -m 0755 \
    "$source_dir/install/cybex-forge-sync-once" \
    /usr/local/sbin/cybex-forge-sync-once

  rm -f /usr/local/sbin/cybex-forge-check
  install -o root -g root -m 0755 \
    "$source_dir/install/cybex-forge-check" \
    /usr/local/bin/cybex-forge-check.new
  mv -f /usr/local/bin/cybex-forge-check.new /usr/local/bin/cybex-forge-check

  cat > /etc/systemd/system/cybex-forge-check.service <<EOF
[Unit]
Description=Cybex Forge local health check
Wants=network-online.target
After=network-online.target cybex-forge.service nginx.service tftpd-hpa.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/cybex-forge-check --quiet
Nice=5
IOSchedulingClass=best-effort
IOSchedulingPriority=7
AmbientCapabilities=
CapabilityBoundingSet=CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH CAP_NET_BIND_SERVICE CAP_SETUID CAP_SETGID
LockPersonality=true
MemoryDenyWriteExecute=true
NoNewPrivileges=true
PrivateDevices=true
PrivateTmp=true
ProtectClock=true
ProtectControlGroups=true
ProtectHome=true
ProtectHostname=true
ProtectKernelLogs=true
ProtectKernelModules=true
ProtectKernelTunables=true
ProtectProc=invisible
ProtectSystem=strict
ProcSubset=pid
ReadOnlyPaths=/etc/cybex-forge /etc/default/tftpd-hpa /etc/nginx $tftp_root
ReadWritePaths=/run $http_root /var/lib/cybex-forge /var/lib/nginx /var/log/nginx
RemoveIPC=true
RestrictAddressFamilies=
RestrictAddressFamilies=AF_INET AF_UNIX AF_NETLINK
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
SystemCallArchitectures=native
UMask=0077
EOF

  cat > /etc/systemd/system/cybex-forge-check.timer <<'EOF'
[Unit]
Description=Run Cybex Forge local health check periodically

[Timer]
OnCalendar=hourly
AccuracySec=5m
RandomizedDelaySec=15m
Persistent=true
Unit=cybex-forge-check.service

[Install]
WantedBy=timers.target
EOF

  chown root:root /etc/systemd/system/cybex-forge-check.service /etc/systemd/system/cybex-forge-check.timer
  chmod 0644 /etc/systemd/system/cybex-forge-check.service /etc/systemd/system/cybex-forge-check.timer
  systemctl daemon-reload
  systemctl enable --now cybex-forge-check.timer
}

install_tftp_loader() {
  local candidate=""
  local installed_loader="$tftp_root/$bootloader_filename"
  for path in \
    "/usr/lib/ipxe/$bootloader_filename" \
    "/usr/lib/ipxe-qemu/$bootloader_filename" \
    "/usr/share/ipxe/$bootloader_filename"; do
    if [ -f "$path" ]; then candidate="$path"; break; fi
  done
  if [ -z "$candidate" ]; then
    if bootloader_supports_embedded_script "$bootloader_filename"; then
      candidate="$(find /usr/lib /usr/share -type f \( -name "$bootloader_filename" -o -name snponly.efi -o -name ipxe.efi \) 2>/dev/null | head -n 1 || true)"
    else
      candidate="$(find /usr/lib /usr/share -type f -name "$bootloader_filename" 2>/dev/null | head -n 1 || true)"
    fi
  fi
  if [ -n "$candidate" ]; then
    install -m 0444 -o root -g root "$candidate" "$tftp_root/debian-$bootloader_filename"
  fi
  if bootloader_supports_embedded_script "$bootloader_filename"; then
    if build_embedded_ipxe_loader; then
      if ! bootloader_embeds_current_chain "$installed_loader"; then
        echo "error: built $bootloader_filename does not embed $public_base_url/boot/\${mac}" >&2
        exit 1
      fi
    elif bootloader_embeds_current_chain "$installed_loader"; then
      echo "warning: embedded iPXE loader build failed; preserving existing verified $bootloader_filename" >&2
    else
      echo "error: embedded iPXE loader build failed and no existing $bootloader_filename embeds $public_base_url/boot/\${mac}" >&2
      exit 1
    fi
  elif [ -n "$candidate" ]; then
    install -m 0444 -o root -g root "$candidate" "$installed_loader"
    echo "warning: $bootloader_filename is operator-managed; helper cannot verify an embedded chain URL" >&2
  elif [ -f "$installed_loader" ]; then
    echo "warning: preserving existing operator-managed $bootloader_filename; helper cannot verify an embedded chain URL" >&2
  else
    echo "error: no UEFI iPXE loader found; place $bootloader_filename in $tftp_root" >&2
    exit 1
  fi
  prune_tftp_artifacts
  write_tftp_checksums
  harden_tftp_tree
}

prune_tftp_artifacts() {
  local path
  local name
  while IFS= read -r -d '' path; do
    name="${path##*/}"
    case "$name" in
      "$bootloader_filename"|"debian-$bootloader_filename"|"SHA256SUMS") ;;
      *) rm -rf -- "$path" ;;
    esac
  done < <(find "$tftp_root" -mindepth 1 -maxdepth 1 -print0 2>/dev/null)
}

build_embedded_ipxe_loader() {
  bootloader_supports_embedded_script "$bootloader_filename" || return 1

  local ipxe_dir="/usr/local/src/ipxe"
  local embed_script
  embed_script="$(mktemp)"
  write_embedded_ipxe_script "$embed_script"

  if [ ! -d "$ipxe_dir/src" ]; then
    install -m 0755 -d /usr/local/src
    git clone --depth 1 https://github.com/ipxe/ipxe.git "$ipxe_dir" || {
      rm -f "$embed_script"
      return 1
    }
  fi

  if ! (cd "$ipxe_dir/src" && make -j"$(nproc)" "bin-x86_64-efi/$bootloader_filename" EMBED="$embed_script"); then
    rm -f "$embed_script"
    return 1
  fi
  rm -f "$embed_script"

  install -m 0444 -o root -g root "$ipxe_dir/src/bin-x86_64-efi/$bootloader_filename" "$tftp_root/$bootloader_filename"
}

write_embedded_ipxe_script() {
  local script_path="$1"
  cat > "$script_path" <<EOF
#!ipxe
# Embedded chainloader for Cybex Forge UEFI PXE clients.
# This avoids DHCP/iPXE loops on DHCP servers that cannot hand different
# filenames to native PXE and iPXE clients.
isset \${net0/ip} || dhcp || goto failed
set boot-url $public_base_url
chain --autofree \${boot-url}/boot/\${mac} || goto failed

:failed
echo Cybex Forge: failed to load \${boot-url}/boot/\${mac}
echo Returning failure to UEFI firmware.
exit 1
EOF
}

write_tftp_checksums() {
  local sums
  sums="$(mktemp)"
  (
    cd "$tftp_root"
    find . -maxdepth 1 -type f ! -name SHA256SUMS -printf '%P\n' | sort | xargs -r sha256sum > "$sums"
    install -m 0444 -o root -g root "$sums" SHA256SUMS
  )
  rm -f "$sums"
}

harden_tftp_tree() {
  chown root:root "$tftp_root"
  find "$tftp_root" -mindepth 1 -maxdepth 1 ! -type f -exec rm -rf -- {} +
  chmod 0555 "$tftp_root"
  find "$tftp_root" -maxdepth 1 -type f -exec chown root:root {} + -exec chmod 0444 {} +
}

configure_tftp() {
  install -m 0755 -d /etc/systemd/system/tftpd-hpa.service.d
  cat > /etc/systemd/system/tftpd-hpa.service.d/10-cybex-hardening.conf <<EOF
[Service]
AmbientCapabilities=
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_SETUID CAP_SETGID CAP_SYS_CHROOT
InaccessiblePaths=/etc/cybex-forge /var/lib/cybex-forge $http_root
LockPersonality=true
MemoryDenyWriteExecute=true
NoNewPrivileges=true
ReadOnlyPaths=$tftp_root
ProtectProc=invisible
ProcSubset=pid
RemoveIPC=true
RestrictAddressFamilies=
RestrictAddressFamilies=AF_INET AF_UNIX
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
UMask=0077
EOF
  cat > /etc/default/tftpd-hpa <<EOF
TFTP_USERNAME="cybex-forge"
TFTP_DIRECTORY="$tftp_root"
TFTP_ADDRESS="0.0.0.0:69"
TFTP_OPTIONS="--ipv4 --secure"
EOF
  chown root:root /etc/systemd/system/tftpd-hpa.service.d/10-cybex-hardening.conf /etc/default/tftpd-hpa
  chmod 0644 /etc/systemd/system/tftpd-hpa.service.d/10-cybex-hardening.conf /etc/default/tftpd-hpa
  systemctl daemon-reload
  systemctl enable tftpd-hpa
  systemctl restart tftpd-hpa
}

configure_nginx() {
  install -m 0755 -d /etc/systemd/system/nginx.service.d
  cat > /etc/systemd/system/nginx.service.d/10-cybex-hardening.conf <<EOF
[Service]
AmbientCapabilities=
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_SETUID CAP_SETGID CAP_DAC_OVERRIDE CAP_KILL
InaccessiblePaths=/etc/cybex-forge /var/lib/cybex-forge $tftp_root
LockPersonality=true
NoNewPrivileges=true
PrivateDevices=true
PrivateTmp=true
ProtectControlGroups=true
ProtectHome=true
ProtectKernelModules=true
ProtectKernelTunables=true
ProtectProc=invisible
ProtectSystem=strict
ProcSubset=pid
ReadOnlyPaths=$http_root
ReadWritePaths=/run /var/lib/nginx /var/log/nginx
RemoveIPC=true
RestrictAddressFamilies=
RestrictAddressFamilies=AF_INET AF_UNIX
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
UMask=0027
EOF
  cat > /etc/nginx/sites-available/cybex-forge <<EOF
log_format cybex_forge_safe '\$remote_addr [\$time_local] "\$request_method \$uri \$server_protocol" \$status \$body_bytes_sent';

server {
    listen 80 default_server;
    server_name _;

    root $http_root;

    access_log /var/log/nginx/cybex-forge.access.log cybex_forge_safe;
    error_log  /var/log/nginx/cybex-forge.error.log crit;

    server_tokens off;
    add_header X-Content-Type-Options nosniff always;
    add_header X-Frame-Options DENY always;
    add_header Referrer-Policy no-referrer always;
    add_header Content-Security-Policy "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'" always;

    client_max_body_size 1k;
    client_body_timeout 5s;
    client_header_timeout 5s;
    keepalive_timeout 10s;
    large_client_header_buffers 4 8k;
    send_timeout 60s;

    if (\$request_method !~ ^(GET|HEAD)\$) {
        return 405;
    }

    location = /healthz {
        proxy_pass http://$listen_addr;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_hide_header X-Content-Type-Options;
        proxy_hide_header X-Frame-Options;
        proxy_hide_header Referrer-Policy;
        proxy_hide_header Content-Security-Policy;
        proxy_connect_timeout 2s;
        proxy_send_timeout 5s;
        proxy_read_timeout 5s;
    }

    location = / {
        return 204;
    }

    location = /boot.ipxe {
        proxy_pass http://$listen_addr;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_hide_header X-Content-Type-Options;
        proxy_hide_header X-Frame-Options;
        proxy_hide_header Referrer-Policy;
        proxy_hide_header Content-Security-Policy;
        proxy_connect_timeout 2s;
        proxy_send_timeout 10s;
        proxy_read_timeout 30s;
    }

    location = /boot {
        proxy_pass http://$listen_addr;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_hide_header X-Content-Type-Options;
        proxy_hide_header X-Frame-Options;
        proxy_hide_header Referrer-Policy;
        proxy_hide_header Content-Security-Policy;
        proxy_connect_timeout 2s;
        proxy_send_timeout 10s;
        proxy_read_timeout 30s;
    }

    location /boot/ {
        proxy_pass http://$listen_addr;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_hide_header X-Content-Type-Options;
        proxy_hide_header X-Frame-Options;
        proxy_hide_header Referrer-Policy;
        proxy_hide_header Content-Security-Policy;
        proxy_connect_timeout 2s;
        proxy_send_timeout 10s;
        proxy_read_timeout 30s;
    }

    location /files/ {
        proxy_pass http://$listen_addr;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_hide_header X-Content-Type-Options;
        proxy_hide_header X-Frame-Options;
        proxy_hide_header Referrer-Policy;
        proxy_hide_header Content-Security-Policy;
        proxy_connect_timeout 2s;
        proxy_send_timeout 10s;
        proxy_read_timeout 300s;
        proxy_buffering off;
    }

    location /cache/ {
        proxy_pass http://$listen_addr;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_hide_header X-Content-Type-Options;
        proxy_hide_header X-Frame-Options;
        proxy_hide_header Referrer-Policy;
        proxy_hide_header Content-Security-Policy;
        proxy_connect_timeout 2s;
        proxy_send_timeout 10s;
        proxy_read_timeout 300s;
        proxy_buffering off;
    }

    location = /isos/ {
        return 204;
    }

    location = /assets/ {
        return 204;
    }

    location / {
        return 404;
    }
}
EOF
  chown root:root /etc/systemd/system/nginx.service.d/10-cybex-hardening.conf /etc/nginx/sites-available/cybex-forge
  chmod 0644 /etc/systemd/system/nginx.service.d/10-cybex-hardening.conf /etc/nginx/sites-available/cybex-forge
  find /etc/nginx/sites-enabled -mindepth 1 -maxdepth 1 ! -name cybex-forge \( -type f -o -type l \) -delete
  ln -sfn /etc/nginx/sites-available/cybex-forge /etc/nginx/sites-enabled/cybex-forge
  prepare_nginx_logs
  nginx -t
  systemctl daemon-reload
  systemctl enable nginx
  systemctl restart nginx
}

prepare_nginx_logs() {
  touch /var/log/nginx/cybex-forge.access.log /var/log/nginx/cybex-forge.error.log
  if getent passwd www-data >/dev/null && getent group adm >/dev/null; then
    chown www-data:adm /var/log/nginx/cybex-forge.access.log /var/log/nginx/cybex-forge.error.log
  else
    chown root:root /var/log/nginx/cybex-forge.access.log /var/log/nginx/cybex-forge.error.log
  fi
  chmod 0640 /var/log/nginx/cybex-forge.access.log /var/log/nginx/cybex-forge.error.log
}

fix_database_permissions() {
  local database_path="/var/lib/cybex-forge/cybex-forge.sqlite"
  local path
  for path in "$database_path" "$database_path-wal" "$database_path-shm"; do
    if [ -e "$path" ]; then
      chown cybex-forge:cybex-forge "$path"
      chmod 0600 "$path"
    fi
  done
}

wait_for_boot_ready() {
  local url="http://$listen_addr/healthz"
  local code=""
  local remaining=60
  while [ "$remaining" -gt 0 ]; do
    code="$(curl -sS -o /dev/null -w '%{http_code}' --connect-timeout 1 --max-time 3 "$url" 2>/dev/null || true)"
    if [ "$code" = "200" ]; then
      return
    fi
    remaining=$((remaining - 1))
    sleep 0.25
  done
  echo "cybex-forge did not become ready at $url; last HTTP status: ${code:-none}" >&2
  systemctl status cybex-forge --no-pager --lines=20 >&2 || true
  exit 1
}

prepare_database() {
  run_as_boot /usr/local/bin/cybex-forge --config /etc/cybex-forge/config.toml migrate
  fix_database_permissions
}

start_service() {
  systemctl enable cybex-forge
  systemctl restart cybex-forge
  wait_for_boot_ready
  systemctl start cybex-forge-sentinel.timer
}

submit_enrollment() {
  run_as_boot /usr/local/bin/cybex-forge --config /etc/cybex-forge/config.toml enroll || {
    echo "enrollment command failed; inspect journalctl -u cybex-forge" >&2
    exit 1
  }
  if [ -e "$bootstrap_auth_code_file" ] || [ -L "$bootstrap_auth_code_file" ] \
    || [ -e "$bootstrap_auth_code_tomb" ] || [ -L "$bootstrap_auth_code_tomb" ] \
    || [ -e "$bootstrap_auth_code_staged_file" ] || [ -L "$bootstrap_auth_code_staged_file" ]; then
    echo "enrollment succeeded but the one-time credential was not scrubbed" >&2
    exit 1
  fi
  secure_remove_bootstrap_auth_code || {
    echo "enrollment succeeded but credential cleanup could not be finalized" >&2
    exit 1
  }
  fix_database_permissions
}

verify_installation() {
  local check_args=(--quiet --skip-managed-sync)
  /usr/local/bin/cybex-forge-check "${check_args[@]}" || {
    echo "post-install Cybex Forge check failed; inspect /usr/local/bin/cybex-forge-check output" >&2
    exit 1
  }
  echo "Cybex Forge post-install check passed."
}

installer_preflight
require_value "--api-url" "$api_url"
require_value "--organization-id" "$organization_id"
prepare_auth_code_source
validate_url "--api-url" "$api_url"
validate_manage_transport
ensure_public_base_url
validate_url "--git-url" "$git_url"
validate_organization_id
validate_listen_addr
validate_absolute_path "--source-dir" "$source_dir"
validate_runtime_roots
validate_bootloader_filename
validate_update_trusted_public_key
validate_menu_timeout
validate_forge_ref
if [ "$dry_run" -eq 1 ]; then
  echo "Cybex Forge LXC installer validation passed."
  echo "Source: $git_url"
  echo "Forge ref: $forge_ref"
  echo "Checkout: $source_dir"
  echo "Manage API: $api_url"
  echo "Organization: $organization_id"
  echo "Public Boot URL: $public_base_url"
  exit 0
fi
install_packages
ensure_nix_toolchain
ensure_rust
prepare_source
verify_source_compatibility
install_binary
prepare_user_and_dirs
install_enrollment_code
install_theme_assets
validate_pinned_build_inputs
write_config
install_systemd
install_maintenance_tools
install_tftp_loader
configure_tftp
configure_nginx
prepare_database
submit_enrollment
start_service
verify_installation

echo "Cybex Forge installed. Accept the pending cybex-forge enrollment in Cybex Manage."
