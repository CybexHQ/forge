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
  cybex-forge-lxc-install.sh --api-url URL --organization-id UUID --auth-code CODE [options]

Run this inside a Debian/Ubuntu Proxmox LXC that will host Cybex Forge.

Required:
  --api-url URL             Cybex Manage public API URL, for example https://manage.example.com
  --organization-id UUID    Cybex organization UUID from the install authorization
  --auth-code CODE          One-time Cybex Forge install authorization code

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
  --dry-run, --validate-only
                            Validate inputs/environment without installing or enrolling
  -h, --help                Show this help

Environment alternatives:
  CYBEX_MANAGE_API_URL, CYBEX_ORGANIZATION_ID, CYBEX_FORGE_AUTH_CODE,
  CYBEX_FORGE_PUBLIC_BASE_URL, CYBEX_FORGE_SOURCE_DIR, CYBEX_FORGE_GIT_URL,
  CYBEX_FORGE_REF, CYBEX_FORGE_LISTEN_ADDR, CYBEX_FORGE_TFTP_ROOT,
  CYBEX_FORGE_HTTP_ROOT, CYBEX_FORGE_BOOTLOADER_FILENAME,
  CYBEX_FORGE_BOOT_MENU_TIMEOUT_MS
EOF
}

api_url="${CYBEX_MANAGE_API_URL:-}"
organization_id="${CYBEX_ORGANIZATION_ID:-}"
auth_code="${CYBEX_FORGE_AUTH_CODE:-}"
public_base_url="${CYBEX_FORGE_PUBLIC_BASE_URL:-}"
source_dir="${CYBEX_FORGE_SOURCE_DIR:-$FORGE_SOURCE_DIR_DEFAULT}"
git_url="${CYBEX_FORGE_GIT_URL:-$FORGE_GIT_URL_DEFAULT}"
forge_ref="${CYBEX_FORGE_REF:-$FORGE_REF_DEFAULT}"
listen_addr="${CYBEX_FORGE_LISTEN_ADDR:-127.0.0.1:8080}"
tftp_root="${CYBEX_FORGE_TFTP_ROOT:-/srv/cybex-forge/tftp}"
http_root="${CYBEX_FORGE_HTTP_ROOT:-/srv/cybex-forge/www}"
bootloader_filename="${CYBEX_FORGE_BOOTLOADER_FILENAME:-snponly.efi}"
menu_timeout_ms="${CYBEX_FORGE_BOOT_MENU_TIMEOUT_MS:-0}"
dry_run=0

while [ "$#" -gt 0 ]; do
  case "$1" in
    --api-url) api_url="${2:-}"; shift 2 ;;
    --organization-id) organization_id="${2:-}"; shift 2 ;;
    --auth-code) auth_code="${2:-}"; shift 2 ;;
    --public-base-url) public_base_url="${2:-}"; shift 2 ;;
    --source-dir) source_dir="${2:-}"; shift 2 ;;
    --git-url) git_url="${2:-}"; shift 2 ;;
    --forge-ref) forge_ref="${2:-}"; shift 2 ;;
    --listen) listen_addr="${2:-}"; shift 2 ;;
    --tftp-root) tftp_root="${2:-}"; shift 2 ;;
    --http-root) http_root="${2:-}"; shift 2 ;;
    --bootloader) bootloader_filename="${2:-}"; shift 2 ;;
    --menu-timeout-ms) menu_timeout_ms="${2:-}"; shift 2 ;;
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

validate_auth_code() {
  validate_plain_value "--auth-code" "$auth_code"
  if [ "${#auth_code}" -lt 16 ]; then
    echo "--auth-code is too short" >&2
    exit 2
  fi
  if printf '%s' "$auth_code" | LC_ALL=C grep -q '[[:space:]]'; then
    echo "--auth-code contains unsupported characters" >&2
    exit 2
  fi
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
  require_source_file_contains "$source_dir/src/config.rs" "forge_install_code" "managed Forge install code enrollment"
}

install_binary() {
  # shellcheck disable=SC1091
  [ -f /root/.cargo/env ] && . /root/.cargo/env
  cargo build --quiet --release --manifest-path "$source_dir/Cargo.toml"
  rm -f /usr/local/bin/cybex-forge
  install -m 0755 -o root -g root "$source_dir/target/release/cybex-forge" /usr/local/bin/cybex-forge
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
  install -m 0700 -o cybex-forge -g cybex-forge -d /var/lib/cybex-forge/build /var/lib/cybex-forge/build-outputs /var/lib/cybex-forge/cache /var/lib/cybex-forge/updates
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
trusted_public_key = ""

[manage]
enabled = true
api_url = "$api_url"
organization_id = "$organization_id"
forge_install_code = "$auth_code"
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
  cat > /etc/systemd/system/nix-daemon.service.d/10-cybex-forge-restart.conf <<'EOF'
[Service]
Restart=on-failure
RestartSec=3s
EOF
  chown root:root \
    /etc/systemd/system/cybex-forge.service \
    /etc/systemd/system/cybex-forge-runtime-apply.service \
    /etc/systemd/system/cybex-forge-runtime-apply.timer \
    /etc/systemd/system/cybex-forge.service.d/10-logging.conf \
    /etc/systemd/system/cybex-forge.service.d/20-migrate.conf \
    /etc/systemd/system/cybex-forge.service.d/30-address-families.conf \
    /etc/systemd/system/cybex-forge.service.d/40-write-paths.conf \
    /etc/systemd/system/cybex-forge.service.d/50-proc.conf \
    /etc/systemd/system/cybex-forge.service.d/55-nix-daemon.conf \
    /etc/systemd/system/nix-daemon.service.d/10-cybex-forge-restart.conf
  if [ -f /etc/systemd/system/cybex-forge.service.d/35-nix-groups.conf ]; then
    chown root:root /etc/systemd/system/cybex-forge.service.d/35-nix-groups.conf
  fi
  chmod 0644 \
    /etc/systemd/system/cybex-forge.service \
    /etc/systemd/system/cybex-forge-runtime-apply.service \
    /etc/systemd/system/cybex-forge-runtime-apply.timer \
    /etc/systemd/system/cybex-forge.service.d/10-logging.conf \
    /etc/systemd/system/cybex-forge.service.d/20-migrate.conf \
    /etc/systemd/system/cybex-forge.service.d/30-address-families.conf \
    /etc/systemd/system/cybex-forge.service.d/40-write-paths.conf \
    /etc/systemd/system/cybex-forge.service.d/50-proc.conf \
    /etc/systemd/system/cybex-forge.service.d/55-nix-daemon.conf \
    /etc/systemd/system/nix-daemon.service.d/10-cybex-forge-restart.conf
  if [ -f /etc/systemd/system/cybex-forge.service.d/35-nix-groups.conf ]; then
    chmod 0644 /etc/systemd/system/cybex-forge.service.d/35-nix-groups.conf
  fi
  systemctl daemon-reload
  systemctl reset-failed nix-daemon.service nix-daemon.socket || true
  systemctl enable --now nix-daemon.socket
  systemctl enable --now cybex-forge-runtime-apply.timer
}

install_maintenance_tools() {
  rm -f /usr/local/sbin/cybex-forge-sync-once
  cat > /usr/local/sbin/cybex-forge-sync-once <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

if [ "$(id -u)" -eq 0 ]; then
  exec runuser -u cybex-forge -- /usr/local/bin/cybex-forge --config /etc/cybex-forge/config.toml sync-once
fi

exec /usr/local/bin/cybex-forge --config /etc/cybex-forge/config.toml sync-once
EOF
  chown root:root /usr/local/sbin/cybex-forge-sync-once
  chmod 0755 /usr/local/sbin/cybex-forge-sync-once

  rm -f /usr/local/sbin/cybex-forge-check
cat > /usr/local/sbin/cybex-forge-check <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

failures=0
quiet=0
skip_managed_sync=0
tmp_files=()
http_check_asset_path=""
http_check_asset_rel=""

cleanup_tmp_files() {
  local path
  for path in "${tmp_files[@]}"; do
    if [ -n "$path" ]; then
      rm -f "$path"
    fi
  done
}

track_tmp_file() {
  tmp_files+=("$1")
}

untrack_tmp_file() {
  local target="$1"
  local retained=()
  local path
  for path in "${tmp_files[@]}"; do
    if [ "$path" != "$target" ]; then
      retained+=("$path")
    fi
  done
  tmp_files=("${retained[@]}")
}

trap cleanup_tmp_files EXIT
trap 'cleanup_tmp_files; exit 130' HUP INT TERM

usage() {
  cat <<'USAGE'
Usage: cybex-forge-check [--quiet] [--skip-managed-sync]

Checks the local Cybex Forge LXC services, HTTP edge, TFTP artifacts, and
managed sync path. Use --quiet for systemd timer runs so only failures are
written to the journal. Use --skip-managed-sync only during initial helper
installation before the pending Cybex Forge enrollment has been adopted.
USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --quiet) quiet=1; shift ;;
    --skip-managed-sync) skip_managed_sync=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

ok() {
  if [ "$quiet" -eq 0 ]; then
    printf 'ok: %s\n' "$1"
  fi
}

fail() {
  printf 'fail: %s\n' "$1" >&2
  failures=$((failures + 1))
}

require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "run as root on the Cybex Forge LXC" >&2
    exit 1
  fi
}

check_service() {
  local unit="$1"
  if systemctl is-active --quiet "$unit"; then
    ok "$unit active"
  else
    fail "$unit is not active"
  fi
}

check_unit_enabled() {
  local unit="$1"
  local state
  state="$(systemctl is-enabled "$unit" 2>/dev/null || true)"
  if [ "$state" = "enabled" ]; then
    ok "$unit enabled"
  else
    fail "$unit is '$state', expected enabled"
  fi
}

check_http_code() {
  local label="$1"
  local expected="$2"
  shift 2
  local code
  code="$(curl -sS -o /dev/null -w '%{http_code}' --connect-timeout 5 --max-time 15 "$@" || true)"
  if [ "$code" = "$expected" ]; then
    ok "$label returned $expected"
  else
    fail "$label returned $code, expected $expected"
  fi
}

check_http_not_2xx() {
  local label="$1"
  shift
  local code
  code="$(curl -sS -o /dev/null -w '%{http_code}' --connect-timeout 5 --max-time 15 "$@" || true)"
  case "$code" in
    2*)
      fail "$label returned $code, expected non-2xx"
      ;;
    *)
      ok "$label returned non-2xx ($code)"
      ;;
  esac
}

check_header_once() {
  local label="$1"
  local headers_file="$2"
  local header_name="$3"
  local expected_value="$4"
  local header_name_lower
  local expected_lower
  local count
  local matched
  header_name_lower="$(printf '%s' "$header_name" | tr '[:upper:]' '[:lower:]')"
  expected_lower="$(printf '%s' "$expected_value" | tr '[:upper:]' '[:lower:]')"
  count="$(awk -v name="$header_name_lower" '
    {
      line = tolower($0)
      sub(/\r$/, "", line)
      if (index(line, name ":") == 1) {
        count++
      }
    }
    END { print count + 0 }
  ' "$headers_file")"
  if [ "$count" != "1" ]; then
    fail "$label $header_name count is $count, expected 1"
    return
  fi
  matched="$(awk -v name="$header_name_lower" -v expected="$expected_lower" '
    {
      line = tolower($0)
      sub(/\r$/, "", line)
      if (index(line, name ":") == 1 && index(line, expected) > 0) {
        found = 1
      }
    }
    END {
      if (found) {
        print "yes"
      } else {
        print "no"
      }
    }
  ' "$headers_file")"
  if [ "$matched" = "yes" ]; then
    ok "$label includes $header_name"
  else
    fail "$label $header_name is missing expected value"
  fi
}

check_response_headers() {
  local label="$1"
  shift
  local headers_file
  headers_file="$(mktemp)"
  track_tmp_file "$headers_file"
  if ! curl -sS -D "$headers_file" -o /dev/null --connect-timeout 5 --max-time 15 "$@"; then
    fail "$label header probe failed"
    rm -f "$headers_file"
    untrack_tmp_file "$headers_file"
    return
  fi
  check_header_once "$label" "$headers_file" "X-Content-Type-Options" "nosniff"
  check_header_once "$label" "$headers_file" "X-Frame-Options" "DENY"
  check_header_once "$label" "$headers_file" "Referrer-Policy" "no-referrer"
  check_header_once "$label" "$headers_file" "Content-Security-Policy" "frame-ancestors 'none'"
  rm -f "$headers_file"
  untrack_tmp_file "$headers_file"
}

check_command_success() {
  local label="$1"
  shift
  if "$@" >/dev/null 2>&1; then
    ok "$label"
  else
    fail "$label"
  fi
}

check_user_group() {
  local user="$1"
  local group="$2"
  if id -nG "$user" 2>/dev/null | tr ' ' '\n' | grep -Fx "$group" >/dev/null; then
    ok "$user is in $group"
  else
    fail "$user is not in $group"
  fi
}

systemd_property_is_container_relaxed() {
  local property="$1"
  [ -f /run/systemd/system/service.d/zzz-lxc-service.conf ] || [ -s /run/systemd/container ] || return 1
  case "$property" in
    NoNewPrivileges|PrivateDevices|PrivateTmp|ProtectControlGroups|ProtectHome|ProtectKernelLogs|ProtectKernelModules|ProtectKernelTunables|ProtectProc|ProtectSystem|ProcSubset|ReadOnlyPaths|ReadWritePaths)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

systemd_configured_property_lines() {
  local unit="$1"
  local property="$2"
  systemctl cat "$unit" 2>/dev/null | awk -v property="$property" '
    /^# / {
      skip = ($0 ~ /^# \/run\/systemd\/system\/service\.d\//)
      next
    }
    skip { next }
    {
      line = $0
      sub(/^[[:space:]]+/, "", line)
      if (index(line, property "=") == 1) {
        sub("^" property "=", "", line)
        print line
      }
    }
  '
}

systemd_configured_value() {
  local unit="$1"
  local property="$2"
  local line
  local value=""
  while IFS= read -r line; do
    value="$line"
  done < <(systemd_configured_property_lines "$unit" "$property")
  printf '%s' "$value"
}

normalize_systemd_scalar() {
  case "$1" in
    true) printf 'yes' ;;
    false) printf 'no' ;;
    *) printf '%s' "$1" ;;
  esac
}

normalize_systemd_set() {
  printf '%s\n' "$1" | tr ' ' '\n' | sed '/^$/d' | LC_ALL=C sort | xargs
}

systemd_configured_set() {
  local unit="$1"
  local property="$2"
  local line
  local items=""
  while IFS= read -r line; do
    if [ -z "$line" ]; then
      items=""
    else
      items="${items:+$items }$line"
    fi
  done < <(systemd_configured_property_lines "$unit" "$property")
  normalize_systemd_set "$items"
}

check_systemd_value() {
  local unit="$1"
  local property="$2"
  local expected="$3"
  local value
  value="$(systemctl show "$unit" -p "$property" --value 2>/dev/null || true)"
  if [ "$value" = "$expected" ]; then
    ok "$unit $property is $expected"
  elif systemd_property_is_container_relaxed "$property" && [ "$(normalize_systemd_scalar "$(systemd_configured_value "$unit" "$property")")" = "$expected" ]; then
    ok "$unit $property is configured as $expected; effective value is relaxed by container runtime"
  else
    fail "$unit $property is '$value', expected '$expected'"
  fi
}

check_systemd_contains() {
  local unit="$1"
  local property="$2"
  local expected="$3"
  local value
  value="$(systemctl show "$unit" -p "$property" --value 2>/dev/null || true)"
  if printf '%s\n' "$value" | grep -F -- "$expected" >/dev/null; then
    ok "$unit $property contains $expected"
  elif systemd_property_is_container_relaxed "$property" && printf '%s\n' "$(systemd_configured_property_lines "$unit" "$property")" | grep -F -- "$expected" >/dev/null; then
    ok "$unit $property is configured with $expected; effective value is relaxed by container runtime"
  else
    fail "$unit $property does not contain $expected"
  fi
}

check_systemd_exact_paths() {
  local unit="$1"
  local property="$2"
  local expected="$3"
  check_systemd_exact_set "$unit" "$property" "$expected"
}

check_systemd_exact_set() {
  local unit="$1"
  local property="$2"
  local expected="$3"
  local value
  value="$(systemctl show "$unit" -p "$property" --value 2>/dev/null || true)"
  if [ "$(printf '%s\n' "$value" | tr ' ' '\n' | LC_ALL=C sort | xargs)" = "$(printf '%s\n' "$expected" | tr ' ' '\n' | LC_ALL=C sort | xargs)" ]; then
    ok "$unit $property is $expected"
  elif systemd_property_is_container_relaxed "$property" && [ "$(systemd_configured_set "$unit" "$property")" = "$(normalize_systemd_set "$expected")" ]; then
    ok "$unit $property is configured as $expected; effective value is relaxed by container runtime"
  else
    fail "$unit $property is '$value', expected '$expected'"
  fi
}

check_tftpd_capabilities() {
  local allowed=" cap_setgid cap_setuid cap_net_bind_service cap_sys_chroot "
  local caps cap
  caps="$(systemctl show tftpd-hpa -p CapabilityBoundingSet --value 2>/dev/null || true)"
  for cap in cap_setgid cap_setuid cap_net_bind_service cap_sys_chroot; do
    if printf ' %s ' "$caps" | grep -F " $cap " >/dev/null; then
      :
    else
      fail "tftpd-hpa CapabilityBoundingSet is missing $cap"
      return
    fi
  done
  for cap in $caps; do
    if printf '%s' "$allowed" | grep -F " $cap " >/dev/null; then
      :
    else
      fail "tftpd-hpa CapabilityBoundingSet has unexpected $cap"
      return
    fi
  done
  ok "tftpd-hpa CapabilityBoundingSet is bounded"
}

check_tftpd_address_families() {
  local allowed=" AF_INET AF_UNIX "
  local families family
  families="$(systemctl show tftpd-hpa -p RestrictAddressFamilies --value 2>/dev/null || true)"
  for family in AF_INET AF_UNIX; do
    if printf ' %s ' "$families" | grep -F " $family " >/dev/null; then
      :
    else
      fail "tftpd-hpa RestrictAddressFamilies is missing $family"
      return
    fi
  done
  for family in $families; do
    if printf '%s' "$allowed" | grep -F " $family " >/dev/null; then
      :
    else
      fail "tftpd-hpa RestrictAddressFamilies has unexpected $family"
      return
    fi
  done
  ok "tftpd-hpa RestrictAddressFamilies is bounded"
}

check_cybex_forge_address_families() {
  local allowed=" AF_INET AF_UNIX "
  local families family
  families="$(systemctl show cybex-forge -p RestrictAddressFamilies --value 2>/dev/null || true)"
  for family in AF_INET AF_UNIX; do
    if printf ' %s ' "$families" | grep -F " $family " >/dev/null; then
      :
    else
      fail "cybex-forge RestrictAddressFamilies is missing $family"
      return
    fi
  done
  for family in $families; do
    if printf '%s' "$allowed" | grep -F " $family " >/dev/null; then
      :
    else
      fail "cybex-forge RestrictAddressFamilies has unexpected $family"
      return
    fi
  done
  ok "cybex-forge RestrictAddressFamilies is bounded"
}

check_nginx_capabilities() {
  local allowed=" cap_dac_override cap_kill cap_setgid cap_setuid cap_net_bind_service "
  local caps cap
  caps="$(systemctl show nginx -p CapabilityBoundingSet --value 2>/dev/null || true)"
  for cap in cap_dac_override cap_kill cap_setgid cap_setuid cap_net_bind_service; do
    if printf ' %s ' "$caps" | grep -F " $cap " >/dev/null; then
      :
    else
      fail "nginx CapabilityBoundingSet is missing $cap"
      return
    fi
  done
  for cap in $caps; do
    if printf '%s' "$allowed" | grep -F " $cap " >/dev/null; then
      :
    else
      fail "nginx CapabilityBoundingSet has unexpected $cap"
      return
    fi
  done
  ok "nginx CapabilityBoundingSet is bounded"
}

check_file_contains() {
  local label="$1"
  local path="$2"
  local expected="$3"
  if grep -F -- "$expected" "$path" >/dev/null 2>&1; then
    ok "$label"
  else
    fail "$label"
  fi
}

check_path_stat() {
  local label="$1"
  local path="$2"
  local expected="$3"
  local actual
  if [ -L "$path" ]; then
    fail "$label is a symlink at $path"
    return
  fi
  actual="$(stat -c '%U:%G %a' "$path" 2>/dev/null || true)"
  if [ "$actual" = "$expected" ]; then
    ok "$label is $expected"
  else
    fail "$label is '$actual', expected '$expected'"
  fi
}

check_nix_toolchain() {
  local key_dir="$1"
  local private_key=""
  local public_key=""

  check_command_success "nix command available" command -v nix
  check_command_success "nix-store command available" command -v nix-store
  if ! command -v nix-store >/dev/null 2>&1; then
    return
  fi

  private_key="$(mktemp "$key_dir/.cybex-check-cache-priv.XXXXXX")" || {
    fail "cache key generation probe setup failed"
    return
  }
  public_key="$(mktemp "$key_dir/.cybex-check-cache-pub.XXXXXX")" || {
    rm -f "$private_key"
    fail "cache key generation probe setup failed"
    return
  }
  rm -f "$private_key" "$public_key"

  if runuser -u cybex-forge -- nix-store --generate-binary-cache-key cybex-forge-check "$private_key" "$public_key" >/dev/null 2>&1; then
    ok "nix-store can generate binary cache keys"
  else
    fail "nix-store cannot generate binary cache keys"
  fi
  rm -f "$private_key" "$public_key"
}

check_optional_path_stat() {
  local label="$1"
  local path="$2"
  local expected="$3"
  if [ -e "$path" ]; then
    check_path_stat "$label" "$path" "$expected"
  fi
}

check_path_absent() {
  local label="$1"
  local path="$2"
  if [ -e "$path" ]; then
    fail "$label exists at $path"
  else
    ok "$label is absent"
  fi
}

check_symlink_target() {
  local label="$1"
  local path="$2"
  local expected="$3"
  local actual
  if [ ! -L "$path" ]; then
    fail "$label is not a symlink at $path"
    return
  fi
  actual="$(readlink "$path" 2>/dev/null || true)"
  if [ "$actual" = "$expected" ]; then
    ok "$label points to $expected"
  else
    fail "$label points to '$actual', expected '$expected'"
  fi
}

check_nginx_enabled_sites() {
  local bad_entries
  bad_entries="$(find /etc/nginx/sites-enabled -mindepth 1 -maxdepth 1 ! -name cybex-forge -printf '%f\n' 2>/dev/null | sort | xargs || true)"
  if [ -z "$bad_entries" ]; then
    ok "nginx has no unexpected enabled sites"
  else
    fail "nginx has unexpected enabled sites: $bad_entries"
  fi
  check_symlink_target "nginx enabled Cybex site" /etc/nginx/sites-enabled/cybex-forge /etc/nginx/sites-available/cybex-forge
}

check_nginx_public_listen_config() {
  local counts
  local default_count
  local public_http_count
  counts="$(nginx -T 2>/dev/null | awk '
    /^[[:space:]]*listen[[:space:]]/ {
      line = $0
      sub(/^[[:space:]]+/, "", line)
      sub(/[[:space:]]+$/, "", line)
      if (line == "listen 80 default_server;") {
        default_count++
      }
      if (line ~ /^listen / && line ~ /(^|[^0-9])80([^0-9]|$)/) {
        public_http_count++
      }
    }
    END { print default_count + 0, public_http_count + 0 }
  ')"
  default_count="${counts%% *}"
  public_http_count="${counts##* }"
  if [ "$default_count" = "1" ] && [ "$public_http_count" = "1" ]; then
    ok "nginx has exactly one public HTTP listen directive"
  else
    fail "nginx listen directives include $default_count Cybex defaults and $public_http_count public HTTP listeners"
  fi
}

check_service_asset_root_boundary() {
  local bad_entries
  local http_top
  http_top="$(runtime_top_entry "$http_root" "$runtime_root")"
  bad_entries="$(find "$runtime_root" -mindepth 1 -maxdepth 1 ! -name "$http_top" \( -user cybex-forge -o -group cybex-forge -o -perm -020 -o -perm -002 \) -printf '%M %u:%g %p\n' 2>/dev/null || true)"
  if [ -z "$bad_entries" ]; then
    ok "service asset root has no service-writable top-level entries outside $http_top"
  else
    fail "service asset root has service-writable top-level entries outside $http_top: $bad_entries"
  fi
}

check_public_asset_tree_permissions() {
  local bad_entries
  bad_entries="$(find "$http_root" -xdev \( -type f -o -type d \) \( -perm -020 -o -perm -002 \) -printf '%M %u:%g %p\n' 2>/dev/null || true)"
  if [ -z "$bad_entries" ]; then
    ok "public asset tree has no group/world-writable files or directories"
  else
    fail "public asset tree has group/world-writable entries: $bad_entries"
  fi
}

check_nginx_config_contains() {
  local label="$1"
  local expected="$2"
  if nginx -T 2>/dev/null | grep -F -- "$expected" >/dev/null; then
    ok "$label"
  else
    fail "$label"
  fi
}

check_nginx_config_not_contains() {
  local label="$1"
  local unexpected="$2"
  if nginx -T 2>/dev/null | grep -F -- "$unexpected" >/dev/null; then
    fail "$label"
  else
    ok "$label"
  fi
}

check_nginx_log_format() {
  local line
  line="$(nginx -T 2>/dev/null | awk '/log_format cybex_forge_safe/ { print; exit }')"
  if [ -z "$line" ]; then
    fail "nginx cybex_forge_safe log format is missing"
    return
  fi
  if printf '%s\n' "$line" | grep -F "\$request_method \$uri \$server_protocol" >/dev/null \
    && ! printf '%s\n' "$line" | grep -F "\$request_uri" >/dev/null \
    && ! printf '%s\n' "$line" | grep -F "\$args" >/dev/null \
    && ! printf '%s\n' "$line" | grep -F "\$query_string" >/dev/null \
    && ! printf '%s\n' "$line" | grep -F "\$http_user_agent" >/dev/null \
    && ! printf '%s\n' "$line" | grep -F "\$http_referer" >/dev/null; then
    ok "nginx access log format is privacy-minimized"
  else
    fail "nginx access log format may include query, referrer, or user-agent data"
  fi
}

check_log_path_stat() {
  local label="$1"
  local path="$2"
  local actual
  actual="$(stat -c '%U:%G %a' "$path" 2>/dev/null || true)"
  if [ "$actual" = "www-data:adm 640" ] || [ "$actual" = "root:root 640" ]; then
    ok "$label is $actual"
  else
    fail "$label is '$actual', expected www-data:adm 640 or root:root 640"
  fi
}

check_nginx_logrotate_policy() {
  local conf="/etc/logrotate.d/nginx"
  if [ ! -f "$conf" ]; then
    fail "nginx logrotate policy is missing"
    return
  fi
  if grep -Eq '^[[:space:]]*/var/log/nginx/\*\.log[[:space:]]*\{' "$conf"; then
    ok "nginx logrotate covers /var/log/nginx/*.log"
  else
    fail "nginx logrotate does not cover /var/log/nginx/*.log"
  fi
  if grep -Eq '^[[:space:]]*create[[:space:]]+0640[[:space:]]+www-data[[:space:]]+adm([[:space:]]|$)' "$conf"; then
    ok "nginx logrotate preserves 0640 www-data:adm logs"
  else
    fail "nginx logrotate does not preserve 0640 www-data:adm logs"
  fi
  check_command_success "logrotate configuration parses" logrotate -d /etc/logrotate.conf
}

config_string_value() {
  local key="$1"
  awk -v key="$key" -F '"' '$0 ~ "^[[:space:]]*" key "[[:space:]]*=" { print $2; exit }' /etc/cybex-forge/config.toml 2>/dev/null
}

config_number_value() {
  local key="$1"
  awk -v key="$key" '$0 ~ "^[[:space:]]*" key "[[:space:]]*=" { print $3; exit }' /etc/cybex-forge/config.toml 2>/dev/null
}

config_path_value() {
  local key="$1"
  local fallback="$2"
  local value
  value="$(config_string_value "$key")"
  if [ -n "$value" ]; then
    printf '%s\n' "$value"
  else
    printf '%s\n' "$fallback"
  fi
}

runtime_top_entry() {
  local path="$1"
  local root="$2"
  local rel
  rel="${path#"$root"/}"
  printf '%s\n' "${rel%%/*}"
}

check_local_management_routes_unavailable() {
  check_http_code "local /login" 404 "http://127.0.0.1/login"
  check_http_code "local /api/health" 404 "http://127.0.0.1/api/health"
}

boot_event_user_agent_count() {
  local user_agent="$1"
  case "$user_agent" in
    *[!A-Za-z0-9._:-]*) return 1 ;;
  esac
  sqlite3 -readonly "$database_path" "SELECT COUNT(*) FROM boot_events WHERE user_agent = '$user_agent';"
}

check_boot_listener() {
  local listen_addr
  local port
  local listeners
  listen_addr="$(config_string_value listen_addr)"
  case "$listen_addr" in
    127.0.0.1:[0-9]*)
      ok "Boot listen_addr is loopback"
      ;;
    *)
      fail "Boot listen_addr is '$listen_addr', expected 127.0.0.1:<port>"
      return
      ;;
  esac
  port="${listen_addr##*:}"
  listeners="$(ss -ltnH | awk '{print $4}')"
  if printf '%s\n' "$listeners" | grep -Fx "127.0.0.1:$port" >/dev/null; then
    ok "Boot TCP listener is bound to $listen_addr"
  else
    fail "Boot TCP listener is not bound to $listen_addr"
  fi
  if printf '%s\n' "$listeners" | grep -E "^(0\\.0\\.0\\.0|\\[::\\]|\\*):$port$" >/dev/null; then
    fail "Boot TCP port $port is exposed on a wildcard listener"
  else
    ok "Boot TCP port $port is not exposed on wildcard addresses"
  fi
}

check_tcp_listener() {
  local label="$1"
  local expected="$2"
  if ss -ltnH | awk '{print $4}' | grep -Fx "$expected" >/dev/null; then
    ok "$label listens on $expected"
  else
    fail "$label is not listening on $expected"
  fi
}

check_no_tcp_listener() {
  local label="$1"
  local expected="$2"
  if ss -ltnH | awk '{print $4}' | grep -Fx "$expected" >/dev/null; then
    fail "$label unexpectedly listens on $expected"
  else
    ok "$label does not listen on $expected"
  fi
}

check_udp_listener() {
  local label="$1"
  local expected="$2"
  if ss -lunH | awk '{print $4}' | grep -Fx "$expected" >/dev/null; then
    ok "$label listens on $expected"
  else
    fail "$label is not listening on $expected"
  fi
}

check_no_udp_listener() {
  local label="$1"
  local expected="$2"
  if ss -lunH | awk '{print $4}' | grep -Fx "$expected" >/dev/null; then
    fail "$label unexpectedly listens on $expected"
  else
    ok "$label does not listen on $expected"
  fi
}

cleanup_stale_http_check_assets() {
  find "$http_root" -maxdepth 1 \( -type f -o -type l \) -name '.cybex-check.*' -mmin +15 -delete 2>/dev/null || true
}

create_http_check_asset() {
  http_check_asset_path="$(mktemp "$http_root/.cybex-check.XXXXXX")"
  track_tmp_file "$http_check_asset_path"
  printf 'Cybex Forge checker asset\n%s\n' "$(date +%s)" > "$http_check_asset_path"
  chmod 0644 "$http_check_asset_path"
  http_check_asset_rel="${http_check_asset_path#"$http_root"/}"
}

remove_http_check_asset() {
  if [ -n "$http_check_asset_path" ]; then
    rm -f "$http_check_asset_path"
    untrack_tmp_file "$http_check_asset_path"
    http_check_asset_path=""
    http_check_asset_rel=""
  fi
}

check_file_symlink_rejected() {
  local link_path
  local link_rel
  if [ -z "$http_check_asset_path" ]; then
    fail "file symlink rejection probe has no target asset"
    return
  fi
  link_path="$(mktemp "$http_root/.cybex-check-link.XXXXXX")"
  rm -f "$link_path"
  if ! ln -s "$http_check_asset_path" "$link_path"; then
    fail "file symlink rejection probe setup failed"
    return
  fi
  track_tmp_file "$link_path"
  link_rel="${link_path#"$http_root"/}"
  check_http_code "file symlink rejected" 403 "http://127.0.0.1/files/$link_rel"
  rm -f "$link_path"
  untrack_tmp_file "$link_path"
}

check_file_path_boundary() {
  check_http_code "file absolute path rejected" 403 --path-as-is "http://127.0.0.1/files/%2fetc%2fpasswd"
  check_http_code "file current-directory path rejected" 403 --path-as-is "http://127.0.0.1/files/."
  check_http_not_2xx "file parent traversal rejected" --path-as-is "http://127.0.0.1/files/%2e%2e%2fetc%2fpasswd"
}

check_nginx_log_redaction() {
  local asset_path="$1"
  local probe
  probe="cybex-check-$$-$(date +%s)"
  if ! curl -fsS -A "${probe}-agent" -r 0-0 -o /dev/null "http://127.0.0.1/files/${asset_path}?probe=${probe}" >/dev/null; then
    fail "nginx log redaction probe request failed"
    return
  fi
  sleep 1
  if tail -n 30 /var/log/nginx/cybex-forge.access.log 2>/dev/null | grep -F "$probe" >/dev/null; then
    fail "nginx access log includes query string or user-agent probe"
  else
    ok "nginx access log redacts query strings and user agents"
  fi
}

check_ipxe_menu_response() {
  local label="$1"
  local headers_file="$2"
  local body_file="$3"
  local first_line
  local expected
  local menu_timeout
  local public_base_url
  public_base_url="$(config_string_value public_base_url)"
  menu_timeout="$(config_number_value menu_timeout_ms)"
  menu_timeout="${menu_timeout:-0}"
  check_header_once "$label" "$headers_file" "Content-Type" "text/plain"
  check_header_once "$label" "$headers_file" "Cache-Control" "no-store"
  check_header_once "$label" "$headers_file" "Pragma" "no-cache"
  check_header_once "$label" "$headers_file" "Expires" "0"
  first_line="$(sed -n '1{s/\r$//;p;}' "$body_file")"
  if [ "$first_line" = "#!ipxe" ]; then
    ok "$label starts with iPXE header"
  else
    fail "$label first line is '$first_line', expected '#!ipxe'"
  fi
  for expected in \
    "set cybex-title CYBEX" \
    "set cybex-subtitle PXE BOOT - FORGE BOOT - X86_64 - UEFI" \
    "console --x 1024 --y 864 --picture ${public_base_url}/files/assets/pxe-menu.png --left 280 --right 280 --top 260 --bottom 140 --depth 32 || console --x 1024 --y 768 --depth 32 || echo Cybex Forge: using firmware text console" \
    "colour --basic 0 --rgb 0x0e0f12 0" \
    "colour --basic 3 --rgb 0xeb9b46 1" \
    "colour --basic 4 --rgb 0x241a10 4" \
    "cpair --foreground 1 --background 4 2" \
    'menu ${cybex-title}' \
    'item --gap ${cybex-subtitle}' \
    ":local" \
    "exit 1"; do
    if grep -Fx -- "$expected" "$body_file" >/dev/null; then
      ok "$label contains $expected"
    else
      fail "$label is missing $expected"
    fi
  done
  if [ "$menu_timeout" = "0" ]; then
    if grep -F -- "choose --timeout" "$body_file" >/dev/null; then
      fail "$label unexpectedly includes a timed menu"
    elif grep -Fx -- "choose --default local selected || goto local" "$body_file" >/dev/null; then
      ok "$label uses non-timed menu selection"
    else
      fail "$label is missing non-timed menu selection"
    fi
  else
    for expected in \
      "set menu-timeout ${menu_timeout}" \
      'item --gap ${cybex-timeout-copy}' \
      'choose --timeout ${menu-timeout} --default local selected || goto local'; do
      if grep -Fx -- "$expected" "$body_file" >/dev/null; then
        ok "$label contains $expected"
      else
        fail "$label is missing $expected"
      fi
    done
  fi
  if grep -F "iPXE shell" "$body_file" >/dev/null; then
    fail "$label still exposes iPXE shell"
  else
    ok "$label omits iPXE shell"
  fi
}

check_ipxe_profile_response() {
  local label="$1"
  local headers_file="$2"
  local body_file="$3"
  local first_line
  check_header_once "$label" "$headers_file" "Content-Type" "text/plain"
  check_header_once "$label" "$headers_file" "Cache-Control" "no-store"
  check_header_once "$label" "$headers_file" "Pragma" "no-cache"
  check_header_once "$label" "$headers_file" "Expires" "0"
  first_line="$(sed -n '1{s/\r$//;p;}' "$body_file")"
  if [ "$first_line" = "#!ipxe" ]; then
    ok "$label starts with iPXE header"
  else
    fail "$label first line is '$first_line', expected '#!ipxe'"
  fi
  if [ "$(wc -c < "$body_file" | xargs)" -gt 8 ]; then
    ok "$label is not empty"
  else
    fail "$label is empty"
  fi
  if grep -F "nixos-netboot.cpio" "$body_file" >/dev/null; then
    if grep -Eq '^kernel .+ initrd=initrd initrd=nixos-netboot\.cpio .+' "$body_file"; then
      ok "$label declares all NixOS netboot initrds on the kernel line"
    else
      fail "$label does not declare all NixOS netboot initrds on the kernel line"
    fi
    if grep -Eq '^initrd --name initrd [^ ]+/initrd$' "$body_file"; then
      ok "$label passes the NixOS initrd as a raw named initrd"
    else
      fail "$label does not pass the NixOS initrd as a raw named initrd"
    fi
    if grep -Eq '^initrd --name nixos-netboot\.cpio [^ ]+/nixos-netboot\.cpio$' "$body_file"; then
      ok "$label passes the NixOS netboot cpio as a raw named initrd"
    else
      fail "$label does not pass the NixOS netboot cpio as a raw named initrd"
    fi
    if grep -Eq '/initrd initrd$|/nixos-netboot\.cpio nixos-netboot\.cpio$' "$body_file"; then
      fail "$label uses iPXE cpio-wrapping syntax for a raw initrd image"
    else
      ok "$label avoids iPXE cpio-wrapping syntax for raw initrd images"
    fi
  elif grep -F "/files/installers/" "$body_file" >/dev/null; then
    if grep -Eq '^kernel .+ initrd=initrd .+' "$body_file"; then
      ok "$label declares the combined NixOS netboot initrd on the kernel line"
    else
      fail "$label does not declare the combined NixOS netboot initrd on the kernel line"
    fi
    if grep -Eq '^initrd --name initrd [^ ]+/initrd$' "$body_file"; then
      ok "$label passes the combined NixOS netboot initrd as a raw named initrd"
    else
      fail "$label does not pass the combined NixOS netboot initrd as a raw named initrd"
    fi
  fi
}

check_marked_boot_probe_non_mutating() {
  local probe
  local before
  local after
  local headers_file
  local body_file
  probe="cybex-forge-check-marker-$$-$(date +%s)"
  if ! before="$(boot_event_user_agent_count "$probe" 2>/dev/null)"; then
    fail "Boot event count query failed before marked boot probe"
    return
  fi
  headers_file="$(mktemp)"
  body_file="$(mktemp)"
  track_tmp_file "$headers_file"
  track_tmp_file "$body_file"
  if ! curl -fsS -A "$probe" -D "$headers_file" -o "$body_file" --connect-timeout 5 --max-time 15 "http://127.0.0.1/boot.ipxe?cybex_check=1"; then
    fail "marked boot probe request failed"
    rm -f "$headers_file" "$body_file"
    untrack_tmp_file "$headers_file"
    untrack_tmp_file "$body_file"
    return
  fi
  check_ipxe_menu_response "marked boot probe payload" "$headers_file" "$body_file"
  rm -f "$headers_file" "$body_file"
  untrack_tmp_file "$headers_file"
  untrack_tmp_file "$body_file"
  if ! after="$(boot_event_user_agent_count "$probe" 2>/dev/null)"; then
    fail "Boot event count query failed after marked boot probe"
    return
  fi
  if [ "$before" = "$after" ]; then
    ok "marked boot probe does not create boot events"
  else
    fail "marked boot probe created boot event records"
  fi
}

check_marked_boot_path_non_mutating() {
  local label="$1"
  local url="$2"
  local probe
  local before
  local after
  local headers_file
  local body_file
  probe="cybex-forge-check-${label//[^A-Za-z0-9]/-}-$$-$(date +%s)"
  if ! before="$(boot_event_user_agent_count "$probe" 2>/dev/null)"; then
    fail "Boot event count query failed before $label probe"
    return
  fi
  headers_file="$(mktemp)"
  body_file="$(mktemp)"
  track_tmp_file "$headers_file"
  track_tmp_file "$body_file"
  if ! curl -fsS -A "$probe" -D "$headers_file" -o "$body_file" --connect-timeout 5 --max-time 15 "$url"; then
    fail "$label probe request failed"
    rm -f "$headers_file" "$body_file"
    untrack_tmp_file "$headers_file"
    untrack_tmp_file "$body_file"
    return
  fi
  check_ipxe_menu_response "$label payload" "$headers_file" "$body_file"
  rm -f "$headers_file" "$body_file"
  untrack_tmp_file "$headers_file"
  untrack_tmp_file "$body_file"
  if ! after="$(boot_event_user_agent_count "$probe" 2>/dev/null)"; then
    fail "Boot event count query failed after $label probe"
    return
  fi
  if [ "$before" = "$after" ]; then
    ok "$label probe does not create boot events"
  else
    fail "$label probe created boot event records"
  fi
}

check_first_profile_select_non_mutating() {
  local menu_file
  local select_path
  local probe
  local before
  local after
  local headers_file
  local body_file
  menu_file="$(mktemp)"
  track_tmp_file "$menu_file"
  if ! curl -fsS -A "cybex-forge-check-profile-menu" -o "$menu_file" --connect-timeout 5 --max-time 15 "http://127.0.0.1/boot.ipxe?cybex_check=1"; then
    fail "profile select menu discovery failed"
    rm -f "$menu_file"
    untrack_tmp_file "$menu_file"
    return
  fi
  select_path="$(awk '
    /^chain[[:space:]]/ {
      for (i = 2; i <= NF; i++) {
        if ($i ~ /\/boot\/select\/[0-9]+/) {
          value = $i
          sub(/^https?:\/\/[^/]+/, "", value)
          sub(/\?.*$/, "", value)
          print value
          exit
        }
      }
    }
  ' "$menu_file")"
  rm -f "$menu_file"
  untrack_tmp_file "$menu_file"
  if [ -z "$select_path" ]; then
    ok "profile select probe skipped because menu has no selectable profile"
    return
  fi
  probe="cybex-forge-check-select-$$-$(date +%s)"
  if ! before="$(boot_event_user_agent_count "$probe" 2>/dev/null)"; then
    fail "Boot event count query failed before profile select probe"
    return
  fi
  headers_file="$(mktemp)"
  body_file="$(mktemp)"
  track_tmp_file "$headers_file"
  track_tmp_file "$body_file"
  if ! curl -fsS -A "$probe" -D "$headers_file" -o "$body_file" --connect-timeout 5 --max-time 15 "http://127.0.0.1${select_path}?cybex_check=1"; then
    fail "profile select probe request failed for $select_path"
    rm -f "$headers_file" "$body_file"
    untrack_tmp_file "$headers_file"
    untrack_tmp_file "$body_file"
    return
  fi
  check_ipxe_profile_response "profile select payload" "$headers_file" "$body_file"
  rm -f "$headers_file" "$body_file"
  untrack_tmp_file "$headers_file"
  untrack_tmp_file "$body_file"
  if ! after="$(boot_event_user_agent_count "$probe" 2>/dev/null)"; then
    fail "Boot event count query failed after profile select probe"
    return
  fi
  if [ "$before" = "$after" ]; then
    ok "profile select probe does not create boot events"
  else
    fail "profile select probe created boot event records"
  fi
}

check_spoofed_forwarded_for_marker_non_mutating() {
  local probe
  local before
  local after
  probe="cybex-forge-check-xff-$$-$(date +%s)"
  if ! before="$(boot_event_user_agent_count "$probe" 2>/dev/null)"; then
    fail "Boot event count query failed before spoofed forwarded-for marker probe"
    return
  fi
  if ! curl -fsS -A "$probe" -H "X-Forwarded-For: 10.9.8.7" -o /dev/null --connect-timeout 5 --max-time 15 "http://127.0.0.1/boot.ipxe?cybex_check=1"; then
    fail "spoofed forwarded-for marker probe request failed"
    return
  fi
  if ! after="$(boot_event_user_agent_count "$probe" 2>/dev/null)"; then
    fail "Boot event count query failed after spoofed forwarded-for marker probe"
    return
  fi
  if [ "$before" = "$after" ]; then
    ok "spoofed forwarded-for marker does not create boot events"
  else
    fail "spoofed forwarded-for marker created boot event records"
  fi
}

check_tftp_permissions() {
  local bad_entries=""
  if [ "$(stat -c '%U:%G %a' "$tftp_root" 2>/dev/null || true)" = "root:root 555" ]; then
    ok "TFTP directory is root-owned read-only"
  else
    fail "TFTP directory is not root:root 0555"
  fi
  bad_entries="$(find "$tftp_root" -mindepth 1 -maxdepth 1 ! -type f -printf '%y %p\n' 2>/dev/null || true)"
  if [ -z "$bad_entries" ]; then
    ok "TFTP root contains only regular files"
  else
    fail "TFTP root contains non-regular entries: $bad_entries"
  fi
  bad_entries="$(find "$tftp_root" -maxdepth 1 -type f \( ! -user root -o ! -group root -o ! -perm 0444 \) -print 2>/dev/null || true)"
  if [ -z "$bad_entries" ]; then
    ok "TFTP files are root-owned read-only"
  else
    fail "one or more TFTP files are not root:root 0444"
  fi
}

check_tftp_checksum_file() {
  if [ ! -f "$tftp_root/SHA256SUMS" ]; then
    fail "TFTP SHA256SUMS is missing"
    return
  fi
  if (cd "$tftp_root" && sha256sum -c SHA256SUMS >/dev/null); then
    ok "TFTP SHA256SUMS verifies"
  else
    fail "TFTP SHA256SUMS verification failed"
  fi
}

check_tftp_artifact_allowlist() {
  local bootloader="${1:-snponly.efi}"
  local bad_entries=""
  local line
  local name
  local kind
  while IFS= read -r line; do
    name="${line%%	*}"
    kind="${line#*	}"
    case "$name" in
      "$bootloader"|"debian-$bootloader"|"SHA256SUMS")
        if [ "$kind" != "f" ]; then
          bad_entries="${bad_entries}${bad_entries:+, }$name($kind)"
        fi
        ;;
      *) bad_entries="${bad_entries}${bad_entries:+, }$name" ;;
    esac
  done < <(find "$tftp_root" -mindepth 1 -maxdepth 1 -printf '%f\t%y\n' 2>/dev/null | sort)
  if [ -z "$bad_entries" ]; then
    ok "TFTP root contains only regular managed artifacts"
  else
    fail "TFTP root contains unmanaged artifacts: $bad_entries"
  fi
}

check_tftp_transfer() {
  local bootloader="${1:-snponly.efi}"
  local source_file="$tftp_root/$bootloader"
  local tmp_file
  if [ ! -f "$source_file" ]; then
    fail "TFTP bootloader $bootloader is missing"
    return
  fi
  tmp_file="$(mktemp)"
  track_tmp_file "$tmp_file"
  if curl -fsS --tftp-no-options --connect-timeout 5 --max-time 30 -o "$tmp_file" "tftp://127.0.0.1/$bootloader"; then
    if [ "$(sha256sum "$source_file" | awk '{print $1}')" = "$(sha256sum "$tmp_file" | awk '{print $1}')" ]; then
      ok "TFTP transfer hash matches $bootloader"
    else
      fail "TFTP transfer hash mismatch for $bootloader"
    fi
  else
    fail "TFTP transfer failed for $bootloader"
  fi
  rm -f "$tmp_file"
  untrack_tmp_file "$tmp_file"
}

check_tftp_path_escape_rejected() {
  local path
  local tmp_file
  for path in "../etc/passwd" "%2e%2e/etc/passwd" "/etc/passwd"; do
    tmp_file="$(mktemp)"
    track_tmp_file "$tmp_file"
    if curl -fsS --tftp-no-options --connect-timeout 5 --max-time 15 -o "$tmp_file" "tftp://127.0.0.1/$path" >/dev/null 2>&1; then
      fail "TFTP path escape $path unexpectedly transferred"
    else
      ok "TFTP path escape $path rejected"
    fi
    rm -f "$tmp_file"
    untrack_tmp_file "$tmp_file"
  done
}

bootloader_requires_embedded_script() {
  local bootloader="${1:-snponly.efi}"
  case "$bootloader" in
    snponly.efi|ipxe.efi) return 0 ;;
    *) return 1 ;;
  esac
}

check_tftp_embedded_chain() {
  local bootloader="${1:-snponly.efi}"
  local source_file="$tftp_root/$bootloader"
  local public_base_url
  if ! bootloader_requires_embedded_script "$bootloader"; then
    ok "TFTP bootloader $bootloader is operator-managed"
    return
  fi
  if [ ! -f "$source_file" ]; then
    fail "TFTP bootloader $bootloader is missing"
    return
  fi
  public_base_url="$(config_string_value public_base_url)"
  if [ -z "$public_base_url" ]; then
    fail "public_base_url is missing from Cybex Forge config"
    return
  fi
  if LC_ALL=C grep -aFx -- "set boot-url $public_base_url" "$source_file" >/dev/null &&
    LC_ALL=C grep -aFx -- "chain --autofree \${boot-url}/boot/\${mac} || goto failed" "$source_file" >/dev/null &&
    LC_ALL=C grep -aFx -- "exit 1" "$source_file" >/dev/null &&
    ! LC_ALL=C grep -aFx -- "echo Dropping to iPXE shell." "$source_file" >/dev/null &&
    LC_ALL=C grep -aFx -- "# Embedded chainloader for Cybex Forge UEFI PXE clients." "$source_file" >/dev/null; then
    ok "TFTP bootloader $bootloader embeds Cybex Forge chain URL"
  else
    fail "TFTP bootloader $bootloader does not embed $public_base_url/boot/\${mac} with firmware fallback"
  fi
}

bootloader_filename() {
  config_string_value bootloader_filename
}

data_dir="$(config_path_value data_dir /var/lib/cybex-forge)"
database_path="$(config_path_value database_path "$data_dir/cybex-forge.sqlite")"
http_root="$(config_path_value boot_assets_dir /srv/cybex-forge/www)"
iso_dir="$(config_path_value iso_dir "$http_root/isos")"
static_dir="$(config_path_value static_dir "$http_root/assets")"
tftp_root="$(config_path_value tftp_dir /srv/cybex-forge/tftp)"
state_path="$(config_path_value state_path "$data_dir/manage-state.json")"
build_work_dir="$(config_path_value work_dir "$data_dir/build")"
build_output_dir="$(config_path_value output_dir "$data_dir/build-outputs")"
cache_root="$(config_path_value root_dir "$http_root/cache")"
cache_private_key_path="$(config_path_value private_key_path "$data_dir/cache/cache-priv-key.pem")"
cache_key_dir="$(dirname "$cache_private_key_path")"
runtime_root="/srv/cybex-forge"

require_root

check_service cybex-forge
check_service nginx
check_service tftpd-hpa
check_service cybex-forge-check.timer
check_service cybex-forge-runtime-apply.timer
check_unit_enabled cybex-forge
check_unit_enabled nginx
check_unit_enabled tftpd-hpa
check_unit_enabled cybex-forge-check.timer
check_unit_enabled cybex-forge-runtime-apply.timer

check_command_success "nginx configuration syntax is valid" nginx -t
check_systemd_value cybex-forge-check.timer Unit cybex-forge-check.service
check_systemd_contains cybex-forge-check.timer TimersCalendar "OnCalendar=*-*-* *:00:00"
check_systemd_value cybex-forge-check.timer AccuracyUSec 5min
check_systemd_value cybex-forge-check.timer RandomizedDelayUSec 15min
check_systemd_value cybex-forge-check.timer Persistent yes
check_systemd_value cybex-forge-runtime-apply.timer Unit cybex-forge-runtime-apply.service
check_systemd_contains cybex-forge-runtime-apply.timer TimersMonotonic "OnBootUSec=45s"
check_systemd_contains cybex-forge-runtime-apply.timer TimersMonotonic "OnUnitActiveUSec=1min"
check_systemd_value cybex-forge-runtime-apply.timer AccuracyUSec 15s
check_systemd_value cybex-forge-runtime-apply.timer Persistent yes
check_systemd_value cybex-forge-check.service Type oneshot
check_systemd_contains cybex-forge-check.service ExecStart "cybex-forge-check --quiet"
check_systemd_value cybex-forge-check.service AmbientCapabilities ""
check_systemd_exact_set cybex-forge-check.service CapabilityBoundingSet "cap_dac_override cap_dac_read_search cap_setgid cap_setuid cap_net_bind_service"
check_systemd_value cybex-forge-check.service LockPersonality yes
check_systemd_value cybex-forge-check.service MemoryDenyWriteExecute yes
check_systemd_value cybex-forge-check.service NoNewPrivileges yes
check_systemd_value cybex-forge-check.service PrivateDevices yes
check_systemd_value cybex-forge-check.service PrivateTmp yes
check_systemd_value cybex-forge-check.service ProtectClock yes
check_systemd_value cybex-forge-check.service ProtectControlGroups yes
check_systemd_value cybex-forge-check.service ProtectHome yes
check_systemd_value cybex-forge-check.service ProtectHostname yes
check_systemd_value cybex-forge-check.service ProtectKernelLogs yes
check_systemd_value cybex-forge-check.service ProtectKernelModules yes
check_systemd_value cybex-forge-check.service ProtectKernelTunables yes
check_systemd_value cybex-forge-check.service ProtectProc invisible
check_systemd_value cybex-forge-check.service ProtectSystem strict
check_systemd_value cybex-forge-check.service ProcSubset pid
check_systemd_value cybex-forge-check.service RemoveIPC yes
check_systemd_value cybex-forge-check.service RestrictNamespaces yes
check_systemd_value cybex-forge-check.service RestrictRealtime yes
check_systemd_value cybex-forge-check.service RestrictSUIDSGID yes
check_systemd_value cybex-forge-check.service SystemCallArchitectures native
check_systemd_exact_set cybex-forge-check.service ReadOnlyPaths "/etc/cybex-forge /etc/default/tftpd-hpa /etc/nginx $tftp_root"
check_systemd_exact_set cybex-forge-check.service ReadWritePaths "/run $http_root /var/lib/cybex-forge /var/lib/nginx /var/log/nginx"
check_systemd_exact_set cybex-forge-check.service RestrictAddressFamilies "AF_INET AF_NETLINK AF_UNIX"
check_systemd_value cybex-forge-check.service UMask 0077
check_systemd_contains cybex-forge-check.service Wants network-online.target
check_systemd_contains cybex-forge-check.service After cybex-forge.service
check_systemd_contains cybex-forge-check.service After nginx.service
check_systemd_contains cybex-forge-check.service After tftpd-hpa.service
check_systemd_value cybex-forge User cybex-forge
check_systemd_value cybex-forge Group cybex-forge
check_systemd_value cybex-forge Type simple
check_systemd_value cybex-forge Restart on-failure
check_systemd_value cybex-forge RestartUSec 3s
check_systemd_value cybex-forge StateDirectory cybex-forge
check_systemd_value cybex-forge UMask 0077
check_systemd_contains cybex-forge Wants network-online.target
check_systemd_contains cybex-forge Wants nix-daemon.socket
check_systemd_contains cybex-forge After network-online.target
check_systemd_contains cybex-forge After nix-daemon.socket
check_systemd_value nix-daemon Restart on-failure
check_systemd_value nix-daemon RestartUSec 3s
check_systemd_value cybex-forge AmbientCapabilities ""
check_systemd_value cybex-forge CapabilityBoundingSet ""
check_systemd_value cybex-forge LockPersonality yes
check_systemd_value cybex-forge MemoryDenyWriteExecute yes
check_systemd_value cybex-forge NoNewPrivileges yes
check_systemd_value cybex-forge PrivateDevices yes
check_systemd_value cybex-forge PrivateTmp yes
check_systemd_value cybex-forge ProtectClock yes
check_systemd_value cybex-forge ProtectControlGroups yes
check_systemd_value cybex-forge ProtectHome yes
check_systemd_value cybex-forge ProtectHostname yes
check_systemd_value cybex-forge ProtectKernelLogs yes
check_systemd_value cybex-forge ProtectKernelModules yes
check_systemd_value cybex-forge ProtectKernelTunables yes
check_systemd_value cybex-forge ProtectProc invisible
check_systemd_value cybex-forge ProtectSystem strict
check_systemd_value cybex-forge ProcSubset pid
check_systemd_value cybex-forge RemoveIPC yes
check_systemd_value cybex-forge RestrictNamespaces yes
check_systemd_value cybex-forge RestrictRealtime yes
check_systemd_value cybex-forge RestrictSUIDSGID yes
check_systemd_value cybex-forge SystemCallArchitectures native
check_cybex_forge_address_families
check_systemd_exact_paths cybex-forge ReadWritePaths "/var/lib/cybex-forge $http_root"
check_systemd_contains cybex-forge ExecStart "cybex-forge --config /etc/cybex-forge/config.toml serve"
check_systemd_contains cybex-forge ExecStartPre "cybex-forge --config /etc/cybex-forge/config.toml migrate"
check_systemd_contains cybex-forge SupplementaryGroups nix-users
check_systemd_value cybex-forge WorkingDirectory /var/lib/cybex-forge
check_systemd_contains cybex-forge Environment "RUST_LOG=cybex_forge=info,tower_http=warn"
check_systemd_value nginx LockPersonality yes
check_systemd_value nginx NoNewPrivileges yes
check_systemd_value nginx PrivateDevices yes
check_systemd_value nginx PrivateTmp yes
check_systemd_value nginx ProtectControlGroups yes
check_systemd_value nginx ProtectHome yes
check_systemd_value nginx ProtectKernelModules yes
check_systemd_value nginx ProtectKernelTunables yes
check_systemd_value nginx ProtectProc invisible
check_systemd_value nginx ProtectSystem strict
check_systemd_value nginx ProcSubset pid
check_systemd_value nginx RestrictNamespaces yes
check_systemd_value nginx RestrictRealtime yes
check_systemd_value nginx RestrictSUIDSGID yes
check_systemd_value nginx UMask 0027
check_nginx_capabilities
check_systemd_exact_set nginx InaccessiblePaths "/etc/cybex-forge /var/lib/cybex-forge $tftp_root"
check_systemd_exact_set nginx ReadOnlyPaths "$http_root"
check_systemd_exact_set nginx ReadWritePaths "/run /var/lib/nginx /var/log/nginx"
check_systemd_exact_set nginx RestrictAddressFamilies "AF_INET AF_UNIX"
check_systemd_value tftpd-hpa NoNewPrivileges yes
check_systemd_value tftpd-hpa ProtectProc invisible
check_systemd_value tftpd-hpa ProcSubset pid
check_systemd_value tftpd-hpa UMask 0077
check_tftpd_capabilities
check_tftpd_address_families
check_systemd_contains tftpd-hpa ReadOnlyPaths "$tftp_root"
check_systemd_contains tftpd-hpa InaccessiblePaths /etc/cybex-forge
check_systemd_contains tftpd-hpa InaccessiblePaths /var/lib/cybex-forge
check_systemd_contains tftpd-hpa InaccessiblePaths "$http_root"
check_file_contains "TFTP uses Cybex service user" /etc/default/tftpd-hpa 'TFTP_USERNAME="cybex-forge"'
check_file_contains "TFTP serves managed root" /etc/default/tftpd-hpa "TFTP_DIRECTORY=\"$tftp_root\""
check_file_contains "TFTP listens on IPv4 wildcard" /etc/default/tftpd-hpa 'TFTP_ADDRESS="0.0.0.0:69"'
check_file_contains "TFTP uses secure IPv4 options" /etc/default/tftpd-hpa 'TFTP_OPTIONS="--ipv4 --secure"'
check_path_stat "Boot binary permissions" /usr/local/bin/cybex-forge "root:root 755"
check_path_stat "sync helper permissions" /usr/local/sbin/cybex-forge-sync-once "root:root 755"
check_file_contains "sync helper drops root to service user" /usr/local/sbin/cybex-forge-sync-once 'exec runuser -u cybex-forge -- /usr/local/bin/cybex-forge --config /etc/cybex-forge/config.toml sync-once'
check_file_contains "sync helper uses service config" /usr/local/sbin/cybex-forge-sync-once 'exec /usr/local/bin/cybex-forge --config /etc/cybex-forge/config.toml sync-once'
check_path_stat "checker permissions" /usr/local/sbin/cybex-forge-check "root:root 755"
check_file_contains "Nix enables flake build commands" /etc/nix/nix.conf "experimental-features = nix-command flakes"
check_file_contains "Nix trusts Forge build user" /etc/nix/nix.conf "trusted-users = root cybex-forge"
check_file_contains "Forge Build uses current Nix profile" /etc/cybex-forge/config.toml 'nix_binary = "/nix/var/nix/profiles/default/bin/nix"'
check_file_contains "Forge Build limits per-derivation cores" /etc/cybex-forge/config.toml 'max_build_cores = 4'
check_file_contains "Forge Build requires 16 GiB memory" /etc/cybex-forge/config.toml 'minimum_memory_bytes = 17179869184'
check_file_contains "Forge Build requires 8 GiB emergency swap" /etc/cybex-forge/config.toml 'minimum_swap_bytes = 8589934592'
check_file_contains "Forge Build pins nixpkgs" /etc/cybex-forge/config.toml "flake = \"github:NixOS/nixpkgs/$NIXPKGS_REVISION\""
check_command_success "current Nix profile command available" /nix/var/nix/profiles/default/bin/nix --version
check_path_stat "Boot service unit permissions" /etc/systemd/system/cybex-forge.service "root:root 644"
check_path_stat "Boot logging drop-in permissions" /etc/systemd/system/cybex-forge.service.d/10-logging.conf "root:root 644"
check_path_stat "Boot migrate drop-in permissions" /etc/systemd/system/cybex-forge.service.d/20-migrate.conf "root:root 644"
check_path_stat "Boot address-family drop-in permissions" /etc/systemd/system/cybex-forge.service.d/30-address-families.conf "root:root 644"
check_path_stat "Boot Nix group drop-in permissions" /etc/systemd/system/cybex-forge.service.d/35-nix-groups.conf "root:root 644"
check_path_stat "Boot write-path drop-in permissions" /etc/systemd/system/cybex-forge.service.d/40-write-paths.conf "root:root 644"
check_path_stat "Boot proc drop-in permissions" /etc/systemd/system/cybex-forge.service.d/50-proc.conf "root:root 644"
check_path_stat "Boot Nix dependency drop-in permissions" /etc/systemd/system/cybex-forge.service.d/55-nix-daemon.conf "root:root 644"
check_path_stat "Nix daemon restart drop-in permissions" /etc/systemd/system/nix-daemon.service.d/10-cybex-forge-restart.conf "root:root 644"
check_path_stat "nginx hardening drop-in permissions" /etc/systemd/system/nginx.service.d/10-cybex-hardening.conf "root:root 644"
check_path_stat "nginx site permissions" /etc/nginx/sites-available/cybex-forge "root:root 644"
check_path_stat "TFTP hardening drop-in permissions" /etc/systemd/system/tftpd-hpa.service.d/10-cybex-hardening.conf "root:root 644"
check_path_stat "TFTP defaults permissions" /etc/default/tftpd-hpa "root:root 644"
check_path_stat "checker service unit permissions" /etc/systemd/system/cybex-forge-check.service "root:root 644"
check_path_stat "checker timer unit permissions" /etc/systemd/system/cybex-forge-check.timer "root:root 644"
check_path_stat "runtime apply service unit permissions" /etc/systemd/system/cybex-forge-runtime-apply.service "root:root 644"
check_path_stat "runtime apply timer unit permissions" /etc/systemd/system/cybex-forge-runtime-apply.timer "root:root 644"
check_path_stat "config directory permissions" /etc/cybex-forge "root:cybex-forge 750"
check_path_stat "config file permissions" /etc/cybex-forge/config.toml "root:cybex-forge 640"
check_local_management_routes_unavailable
check_path_stat "state directory permissions" "$data_dir" "cybex-forge:cybex-forge 700"
check_path_stat "build work directory permissions" "$build_work_dir" "cybex-forge:cybex-forge 700"
check_path_stat "build output directory permissions" "$build_output_dir" "cybex-forge:cybex-forge 700"
check_path_stat "cache key directory permissions" "$cache_key_dir" "cybex-forge:cybex-forge 700"
check_path_stat "service asset root permissions" "$runtime_root" "root:cybex-forge 755"
check_service_asset_root_boundary
check_path_stat "public asset root permissions" "$http_root" "cybex-forge:cybex-forge 755"
check_path_stat "public ISO directory permissions" "$iso_dir" "cybex-forge:cybex-forge 755"
check_path_stat "public static asset directory permissions" "$static_dir" "cybex-forge:cybex-forge 755"
check_path_stat "public cache directory permissions" "$cache_root" "cybex-forge:cybex-forge 755"
check_user_group cybex-forge nix-users
check_nix_toolchain "$cache_key_dir"
check_public_asset_tree_permissions
check_path_absent "stale static boot script" "$http_root/boot.ipxe"
cleanup_stale_http_check_assets
check_path_stat "managed state permissions" "$state_path" "cybex-forge:cybex-forge 600"
check_path_stat "SQLite database permissions" "$database_path" "cybex-forge:cybex-forge 600"
check_optional_path_stat "SQLite WAL permissions" "$database_path-wal" "cybex-forge:cybex-forge 600"
check_optional_path_stat "SQLite SHM permissions" "$database_path-shm" "cybex-forge:cybex-forge 600"
check_nginx_config_contains "nginx hides server tokens" "server_tokens off;"
check_nginx_config_contains "nginx enforces method gate" "if (\$request_method !~ ^(GET|HEAD)\$)"
check_nginx_config_contains "nginx limits request bodies" "client_max_body_size 1k;"
check_nginx_config_contains "nginx proxies health to Rust" "location = /healthz"
check_nginx_config_contains "nginx proxies alternate boot root" "location = /boot"
check_nginx_config_contains "nginx proxies alternate boot paths" "location /boot/"
check_nginx_config_contains "nginx streams boot files" "proxy_buffering off;"
check_nginx_config_contains "nginx appends forwarded-for" 'proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;'
check_nginx_config_contains "nginx access log uses safe format" "access_log /var/log/nginx/cybex-forge.access.log cybex_forge_safe;"
check_nginx_config_contains "nginx error log is critical only" "error_log  /var/log/nginx/cybex-forge.error.log crit;"
check_nginx_config_not_contains "nginx has no IPv6 HTTP listen directive" "listen [::]:80"
check_nginx_enabled_sites
check_nginx_public_listen_config
check_nginx_log_format
check_log_path_stat "nginx access log permissions" /var/log/nginx/cybex-forge.access.log
check_log_path_stat "nginx error log permissions" /var/log/nginx/cybex-forge.error.log
check_nginx_logrotate_policy
check_boot_listener
check_tcp_listener "nginx HTTP" "0.0.0.0:80"
check_no_tcp_listener "nginx HTTP IPv6 wildcard" "[::]:80"
check_udp_listener "TFTP" "0.0.0.0:69"
check_no_udp_listener "TFTP IPv6 wildcard" "[::]:69"

check_http_code "edge health" 200 http://127.0.0.1/healthz
check_http_code "root quiet response" 204 http://127.0.0.1/
check_http_code "admin login blocked on public edge" 404 http://127.0.0.1/login
check_http_code "admin settings blocked on public edge" 404 http://127.0.0.1/settings
check_http_code "standalone API blocked on public edge" 404 http://127.0.0.1/api/devices
check_http_code "boot script" 200 "http://127.0.0.1/boot.ipxe?cybex_check=1"
check_http_code "alternate boot root" 200 "http://127.0.0.1/boot?cybex_check=1"
check_http_code "alternate boot MAC route" 200 "http://127.0.0.1/boot/aa:bb:cc:dd:ee:ff?cybex_check=1"
check_http_code "alternate boot serial route" 200 "http://127.0.0.1/boot/by-serial/CYBEX-CHECK-SERIAL?cybex_check=1"
check_http_code "boot script HEAD" 200 -I "http://127.0.0.1/boot.ipxe?cybex_check=1"
check_http_code "malformed boot profile id rejected" 404 http://127.0.0.1/boot/select/999999999999999999999999999999
check_http_code "method gate" 405 -X POST http://127.0.0.1/boot.ipxe
check_http_code "file-root boot script unavailable" 404 http://127.0.0.1/files/boot.ipxe
check_response_headers "edge health headers" http://127.0.0.1/healthz
check_response_headers "root quiet response headers" http://127.0.0.1/
check_response_headers "admin login blocked headers" http://127.0.0.1/login
check_response_headers "standalone API blocked headers" http://127.0.0.1/api/devices
check_response_headers "missing path headers" http://127.0.0.1/no-such-path
check_response_headers "boot script headers" "http://127.0.0.1/boot.ipxe?cybex_check=1"
check_response_headers "alternate boot root headers" "http://127.0.0.1/boot?cybex_check=1"
check_response_headers "boot script HEAD headers" -I "http://127.0.0.1/boot.ipxe?cybex_check=1"
check_response_headers "method gate headers" -X POST http://127.0.0.1/boot.ipxe
check_marked_boot_probe_non_mutating
check_marked_boot_path_non_mutating "alternate boot root" "http://127.0.0.1/boot?cybex_check=1"
check_marked_boot_path_non_mutating "alternate boot MAC route" "http://127.0.0.1/boot/aa:bb:cc:dd:ee:ff?cybex_check=1"
check_marked_boot_path_non_mutating "alternate boot serial route" "http://127.0.0.1/boot/by-serial/CYBEX-CHECK-SERIAL?cybex_check=1"
check_first_profile_select_non_mutating
check_spoofed_forwarded_for_marker_non_mutating
create_http_check_asset
check_file_symlink_rejected
check_file_path_boundary
check_http_code "file range" 206 -r 0-15 "http://127.0.0.1/files/$http_check_asset_rel"
check_response_headers "file range headers" -r 0-15 "http://127.0.0.1/files/$http_check_asset_rel"
check_nginx_log_redaction "$http_check_asset_rel"
remove_http_check_asset

check_tftp_permissions
check_tftp_artifact_allowlist "$(bootloader_filename)"
check_tftp_checksum_file
check_tftp_transfer "$(bootloader_filename)"
check_tftp_path_escape_rejected
check_tftp_embedded_chain "$(bootloader_filename)"

if [ "$skip_managed_sync" -eq 1 ]; then
  ok "managed sync-once skipped"
elif /usr/local/sbin/cybex-forge-sync-once >/dev/null; then
  ok "managed sync-once completed"
  check_path_stat "managed state permissions after sync" "$state_path" "cybex-forge:cybex-forge 600"
  check_path_stat "SQLite database permissions after sync" "$database_path" "cybex-forge:cybex-forge 600"
  check_optional_path_stat "SQLite WAL permissions after sync" "$database_path-wal" "cybex-forge:cybex-forge 600"
  check_optional_path_stat "SQLite SHM permissions after sync" "$database_path-shm" "cybex-forge:cybex-forge 600"
else
  fail "managed sync-once failed"
fi

if [ "$failures" -eq 0 ]; then
  if [ "$quiet" -eq 0 ]; then
    printf 'Cybex Forge check passed\n'
  fi
else
  printf 'Cybex Forge check failed with %s issue(s)\n' "$failures" >&2
  exit 1
fi
EOF
  chown root:root /usr/local/sbin/cybex-forge-check
  chmod 0755 /usr/local/sbin/cybex-forge-check

  cat > /etc/systemd/system/cybex-forge-check.service <<EOF
[Unit]
Description=Cybex Forge local health check
Wants=network-online.target
After=network-online.target cybex-forge.service nginx.service tftpd-hpa.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/cybex-forge-check --quiet
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
}

submit_enrollment() {
  run_as_boot /usr/local/bin/cybex-forge --config /etc/cybex-forge/config.toml enroll || {
    echo "enrollment command failed; inspect journalctl -u cybex-forge" >&2
    exit 1
  }
  fix_database_permissions
}

verify_installation() {
  local check_args=(--quiet --skip-managed-sync)
  /usr/local/sbin/cybex-forge-check "${check_args[@]}" || {
    echo "post-install Cybex Forge check failed; inspect /usr/local/sbin/cybex-forge-check output" >&2
    exit 1
  }
  echo "Cybex Forge post-install check passed."
}

installer_preflight
require_value "--api-url" "$api_url"
require_value "--organization-id" "$organization_id"
require_value "--auth-code" "$auth_code"
validate_url "--api-url" "$api_url"
ensure_public_base_url
validate_url "--git-url" "$git_url"
validate_organization_id
validate_auth_code
validate_listen_addr
validate_absolute_path "--source-dir" "$source_dir"
validate_runtime_roots
validate_bootloader_filename
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
