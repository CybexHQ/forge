#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  cybex-boot-lxc-install.sh --api-url URL --organization-id UUID --auth-code CODE --public-base-url URL [options]

Run this inside a Debian/Ubuntu Proxmox LXC that will host Cybex Boot.

Required:
  --api-url URL             Cybex Manage public API URL, for example https://manage.example.com
  --organization-id UUID    Cybex organization UUID from the install authorization
  --auth-code CODE          One-time Cybex Boot install authorization code
  --public-base-url URL     URL PXE clients will use for this Boot server, for example http://10.10.0.239

Options:
  --source-dir PATH         Existing cybex-boot source directory (default: /root/cybex-boot)
  --git-url URL             Clone source when --source-dir is missing
  --listen ADDR             Local loopback Cybex Boot address behind nginx (default: 127.0.0.1:8080)
  --tftp-root PATH          TFTP root desired by Cybex Manage (default: /srv/cybex-boot/tftp)
  --http-root PATH          HTTP asset root desired by Cybex Manage (default: /srv/cybex-boot/www)
  --bootloader NAME         UEFI iPXE loader filename (default: snponly.efi)
  --menu-timeout-ms MS      Boot menu timeout desired by Cybex Manage (default: 8000)
  -h, --help                Show this help

Environment alternatives:
  CYBEX_MANAGE_API_URL, CYBEX_ORGANIZATION_ID, CYBEX_BOOT_AUTH_CODE,
  CYBEX_BOOT_PUBLIC_BASE_URL, CYBEX_BOOT_SOURCE_DIR, CYBEX_BOOT_GIT_URL,
  CYBEX_BOOT_LISTEN_ADDR, CYBEX_BOOT_TFTP_ROOT, CYBEX_BOOT_HTTP_ROOT,
  CYBEX_BOOTLOADER_FILENAME, CYBEX_BOOT_MENU_TIMEOUT_MS
EOF
}

api_url="${CYBEX_MANAGE_API_URL:-}"
organization_id="${CYBEX_ORGANIZATION_ID:-}"
auth_code="${CYBEX_BOOT_AUTH_CODE:-}"
public_base_url="${CYBEX_BOOT_PUBLIC_BASE_URL:-}"
source_dir="${CYBEX_BOOT_SOURCE_DIR:-/root/cybex-boot}"
git_url="${CYBEX_BOOT_GIT_URL:-}"
listen_addr="${CYBEX_BOOT_LISTEN_ADDR:-127.0.0.1:8080}"
tftp_root="${CYBEX_BOOT_TFTP_ROOT:-/srv/cybex-boot/tftp}"
http_root="${CYBEX_BOOT_HTTP_ROOT:-/srv/cybex-boot/www}"
bootloader_filename="${CYBEX_BOOTLOADER_FILENAME:-snponly.efi}"
menu_timeout_ms="${CYBEX_BOOT_MENU_TIMEOUT_MS:-8000}"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --api-url) api_url="${2:-}"; shift 2 ;;
    --organization-id) organization_id="${2:-}"; shift 2 ;;
    --auth-code) auth_code="${2:-}"; shift 2 ;;
    --public-base-url) public_base_url="${2:-}"; shift 2 ;;
    --source-dir) source_dir="${2:-}"; shift 2 ;;
    --git-url) git_url="${2:-}"; shift 2 ;;
    --listen) listen_addr="${2:-}"; shift 2 ;;
    --tftp-root) tftp_root="${2:-}"; shift 2 ;;
    --http-root) http_root="${2:-}"; shift 2 ;;
    --bootloader) bootloader_filename="${2:-}"; shift 2 ;;
    --menu-timeout-ms) menu_timeout_ms="${2:-}"; shift 2 ;;
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
    echo "run as root inside the Cybex Boot LXC" >&2
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
  if [ "$menu_timeout_ms" -lt 1000 ] || [ "$menu_timeout_ms" -gt 600000 ]; then
    echo "--menu-timeout-ms must be between 1000 and 600000" >&2
    exit 2
  fi
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
    LC_ALL=C grep -aFx -- "chain --autofree \${boot-url}/boot.ipxe || goto failed" "$path" >/dev/null &&
    LC_ALL=C grep -aFx -- "# Embedded chainloader for Cybex Boot UEFI PXE clients." "$path" >/dev/null
}

run_as_boot() {
  runuser -u cybex-boot -- "$@"
}

install_packages() {
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y --no-install-recommends \
    ca-certificates curl git build-essential pkg-config libssl-dev \
    tftpd-hpa ipxe ipxe-qemu nginx logrotate openssl python3-minimal \
    xorriso zstd
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
  if [ -d "$source_dir/.git" ] || [ -f "$source_dir/Cargo.toml" ]; then
    return
  fi
  if [ -z "$git_url" ]; then
    echo "source directory $source_dir is missing; pass --git-url or pre-stage the source" >&2
    exit 1
  fi
  git clone "$git_url" "$source_dir"
}

require_source_file_contains() {
  local path="$1"
  local expected="$2"
  local label="$3"
  if grep -F -- "$expected" "$path" >/dev/null 2>&1; then
    return
  fi
  echo "source compatibility check failed: $label is missing from $path" >&2
  echo "update the Cybex Boot source before running this helper" >&2
  exit 1
}

verify_source_compatibility() {
  if [ ! -f "$source_dir/Cargo.toml" ]; then
    echo "source directory $source_dir is missing Cargo.toml" >&2
    exit 1
  fi
  if [ ! -f "$source_dir/systemd/cybex-boot.service" ]; then
    echo "source directory $source_dir is missing systemd/cybex-boot.service" >&2
    exit 1
  fi
  if [ ! -f "$source_dir/systemd/cybex-boot-runtime-apply.service" ] || [ ! -f "$source_dir/systemd/cybex-boot-runtime-apply.timer" ]; then
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
  require_source_file_contains "$source_dir/src/boot.rs" "PXE BOOT - CYBEX BOOT - X86_64 - UEFI" "themed iPXE menu subtitle"
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
  require_source_file_contains "$source_dir/src/boot.rs" "Default Enrollment" "PXE Default Enrollment menu support"
  require_source_file_contains "$source_dir/src/manage.rs" "boot_report_body_fitter_trims_inventory_before_events" "managed report body byte budget"
  require_source_file_contains "$source_dir/src/manage.rs" "selected_profile_id: Option<String>" "managed selected profile event field"
  require_source_file_contains "$source_dir/src/manage.rs" "managed_profile_id AS selected_profile_id" "managed selected profile event lookup"
  require_source_file_contains "$source_dir/src/manage.rs" "selected_profile_id: event.selected_profile_id" "managed selected profile event report"
  require_source_file_contains "$source_dir/src/manage.rs" "has_unreported_known_profile_events" "pre-config known-profile event reporting"
  require_source_file_contains "$source_dir/src/manage.rs" "apply_runtime_config_once" "root managed runtime apply command"
  require_source_file_contains "$source_dir/src/manage.rs" "managed runtime configuration is pending adoption; skipping apply" "pending runtime apply no-op"
  require_source_file_contains "$source_dir/src/config.rs" "organization_id" "managed organization id enrollment"
  require_source_file_contains "$source_dir/src/config.rs" "boot_install_code" "managed Boot install code enrollment"
}

install_binary() {
  # shellcheck disable=SC1091
  [ -f /root/.cargo/env ] && . /root/.cargo/env
  cargo build --release --manifest-path "$source_dir/Cargo.toml"
  rm -f /usr/local/bin/cybex-boot
  install -m 0755 -o root -g root "$source_dir/target/release/cybex-boot" /usr/local/bin/cybex-boot
}

prepare_user_and_dirs() {
  if ! id cybex-boot >/dev/null 2>&1; then
    useradd --system --home /var/lib/cybex-boot --shell /usr/sbin/nologin cybex-boot
  fi
  install -m 0750 -o root -g cybex-boot -d /etc/cybex-boot
  install -m 0700 -o cybex-boot -g cybex-boot -d /var/lib/cybex-boot
  install -m 0755 -o root -g cybex-boot -d /srv/cybex-boot
  install -m 0755 -o cybex-boot -g cybex-boot -d "$http_root" "$http_root/isos" "$http_root/assets"
  install -m 0555 -o root -g root -d "$tftp_root"
  chown -R cybex-boot:cybex-boot /var/lib/cybex-boot "$http_root"
  chmod 0700 /var/lib/cybex-boot
  chmod 0755 "$http_root" "$http_root/isos" "$http_root/assets"
  find "$http_root" -xdev \( -type f -o -type d \) \( -perm -020 -o -perm -002 \) -exec chmod go-w {} +
  rm -f "$http_root/boot.ipxe"
  find "$http_root" -maxdepth 1 \( -type f -o -type l \) -name '.cybex-check.*' -delete
  if [ -f "$http_root/README.txt" ] && grep -Eq 'Cybex Boot HTTP root|/srv/cybex-boot/app' "$http_root/README.txt"; then
    rm -f "$http_root/README.txt"
  fi
  if [ -d /srv/cybex-boot/app ] && [ -z "$(find /srv/cybex-boot/app -mindepth 1 -print -quit)" ]; then
    rmdir /srv/cybex-boot/app
  fi
  harden_tftp_tree
}

write_config() {
  local config_path="/etc/cybex-boot/config.toml"
  local config_tmp
  install -m 0750 -o root -g cybex-boot -d /etc/cybex-boot
  config_tmp="$(mktemp "$config_path.tmp.XXXXXX")"
  trap 'if [ -n "${config_tmp:-}" ]; then rm -f "$config_tmp"; fi' RETURN
  cat > "$config_tmp" <<EOF
[server]
listen_addr = "$listen_addr"
public_base_url = "$public_base_url"

[paths]
data_dir = "/var/lib/cybex-boot"
database_path = "/var/lib/cybex-boot/cybex-boot.sqlite"
boot_assets_dir = "$http_root"
iso_dir = "$http_root/isos"
static_dir = "$http_root/assets"
tftp_dir = "$tftp_root"

[boot]
bootloader_filename = "$bootloader_filename"
menu_timeout_ms = $menu_timeout_ms

[manage]
enabled = true
api_url = "$api_url"
organization_id = "$organization_id"
boot_install_code = "$auth_code"
state_path = "/var/lib/cybex-boot/manage-state.json"
sync_interval_seconds = 30
enrollment_poll_seconds = 10
http_timeout_seconds = 30
EOF
  install -m 0640 -o root -g cybex-boot "$config_tmp" "$config_path"
  rm -f "$config_tmp"
  config_tmp=""
  trap - RETURN
}

install_systemd() {
  install -m 0644 "$source_dir/systemd/cybex-boot.service" /etc/systemd/system/cybex-boot.service
  install -m 0644 "$source_dir/systemd/cybex-boot-runtime-apply.service" /etc/systemd/system/cybex-boot-runtime-apply.service
  install -m 0644 "$source_dir/systemd/cybex-boot-runtime-apply.timer" /etc/systemd/system/cybex-boot-runtime-apply.timer
  install -m 0755 -d /etc/systemd/system/cybex-boot.service.d
  cat > /etc/systemd/system/cybex-boot.service.d/10-logging.conf <<'EOF'
[Service]
Environment="RUST_LOG=cybex_boot=info,tower_http=warn"
EOF
  cat > /etc/systemd/system/cybex-boot.service.d/20-migrate.conf <<'EOF'
[Service]
ExecStartPre=/usr/local/bin/cybex-boot --config /etc/cybex-boot/config.toml migrate
EOF
  cat > /etc/systemd/system/cybex-boot.service.d/30-address-families.conf <<'EOF'
[Service]
RestrictAddressFamilies=
RestrictAddressFamilies=AF_INET AF_UNIX
EOF
  cat > /etc/systemd/system/cybex-boot.service.d/40-write-paths.conf <<EOF
[Service]
ReadWritePaths=
ReadWritePaths=/var/lib/cybex-boot $http_root
EOF
  cat > /etc/systemd/system/cybex-boot.service.d/50-proc.conf <<'EOF'
[Service]
ProtectProc=invisible
ProcSubset=pid
EOF
  chown root:root \
    /etc/systemd/system/cybex-boot.service \
    /etc/systemd/system/cybex-boot-runtime-apply.service \
    /etc/systemd/system/cybex-boot-runtime-apply.timer \
    /etc/systemd/system/cybex-boot.service.d/10-logging.conf \
    /etc/systemd/system/cybex-boot.service.d/20-migrate.conf \
    /etc/systemd/system/cybex-boot.service.d/30-address-families.conf \
    /etc/systemd/system/cybex-boot.service.d/40-write-paths.conf \
    /etc/systemd/system/cybex-boot.service.d/50-proc.conf
  chmod 0644 \
    /etc/systemd/system/cybex-boot.service \
    /etc/systemd/system/cybex-boot-runtime-apply.service \
    /etc/systemd/system/cybex-boot-runtime-apply.timer \
    /etc/systemd/system/cybex-boot.service.d/10-logging.conf \
    /etc/systemd/system/cybex-boot.service.d/20-migrate.conf \
    /etc/systemd/system/cybex-boot.service.d/30-address-families.conf \
    /etc/systemd/system/cybex-boot.service.d/40-write-paths.conf \
    /etc/systemd/system/cybex-boot.service.d/50-proc.conf
  systemctl daemon-reload
  systemctl enable --now cybex-boot-runtime-apply.timer
}

install_maintenance_tools() {
  rm -f /usr/local/sbin/cybex-boot-sync-once
  cat > /usr/local/sbin/cybex-boot-sync-once <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

if [ "$(id -u)" -eq 0 ]; then
  exec runuser -u cybex-boot -- /usr/local/bin/cybex-boot --config /etc/cybex-boot/config.toml sync-once
fi

exec /usr/local/bin/cybex-boot --config /etc/cybex-boot/config.toml sync-once
EOF
  chown root:root /usr/local/sbin/cybex-boot-sync-once
  chmod 0755 /usr/local/sbin/cybex-boot-sync-once

  rm -f /usr/local/sbin/cybex-boot-check
cat > /usr/local/sbin/cybex-boot-check <<'EOF'
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
Usage: cybex-boot-check [--quiet] [--skip-managed-sync]

Checks the local Cybex Boot LXC services, HTTP edge, TFTP artifacts, and
managed sync path. Use --quiet for systemd timer runs so only failures are
written to the journal. Use --skip-managed-sync only during initial helper
installation before the pending Cybex Boot enrollment has been adopted.
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
    echo "run as root on the Cybex Boot LXC" >&2
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

check_systemd_value() {
  local unit="$1"
  local property="$2"
  local expected="$3"
  local value
  value="$(systemctl show "$unit" -p "$property" --value 2>/dev/null || true)"
  if [ "$value" = "$expected" ]; then
    ok "$unit $property is $expected"
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

check_cybex_boot_address_families() {
  local allowed=" AF_INET AF_UNIX "
  local families family
  families="$(systemctl show cybex-boot -p RestrictAddressFamilies --value 2>/dev/null || true)"
  for family in AF_INET AF_UNIX; do
    if printf ' %s ' "$families" | grep -F " $family " >/dev/null; then
      :
    else
      fail "cybex-boot RestrictAddressFamilies is missing $family"
      return
    fi
  done
  for family in $families; do
    if printf '%s' "$allowed" | grep -F " $family " >/dev/null; then
      :
    else
      fail "cybex-boot RestrictAddressFamilies has unexpected $family"
      return
    fi
  done
  ok "cybex-boot RestrictAddressFamilies is bounded"
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
  bad_entries="$(find /etc/nginx/sites-enabled -mindepth 1 -maxdepth 1 ! -name cybex-boot -printf '%f\n' 2>/dev/null | sort | xargs || true)"
  if [ -z "$bad_entries" ]; then
    ok "nginx has no unexpected enabled sites"
  else
    fail "nginx has unexpected enabled sites: $bad_entries"
  fi
  check_symlink_target "nginx enabled Cybex site" /etc/nginx/sites-enabled/cybex-boot /etc/nginx/sites-available/cybex-boot
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
  bad_entries="$(find /srv/cybex-boot -mindepth 1 -maxdepth 1 ! -name www \( -user cybex-boot -o -group cybex-boot -o -perm -020 -o -perm -002 \) -printf '%M %u:%g %p\n' 2>/dev/null || true)"
  if [ -z "$bad_entries" ]; then
    ok "service asset root has no service-writable top-level entries outside www"
  else
    fail "service asset root has service-writable top-level entries outside www: $bad_entries"
  fi
}

check_public_asset_tree_permissions() {
  local bad_entries
  bad_entries="$(find /srv/cybex-boot/www -xdev \( -type f -o -type d \) \( -perm -020 -o -perm -002 \) -printf '%M %u:%g %p\n' 2>/dev/null || true)"
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
  line="$(nginx -T 2>/dev/null | awk '/log_format cybex_boot_safe/ { print; exit }')"
  if [ -z "$line" ]; then
    fail "nginx cybex_boot_safe log format is missing"
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
  awk -v key="$key" -F '"' '$0 ~ "^[[:space:]]*" key "[[:space:]]*=" { print $2; exit }' /etc/cybex-boot/config.toml 2>/dev/null
}

check_local_management_routes_unavailable() {
  check_http_code "local /login" 404 "http://127.0.0.1/login"
  check_http_code "local /api/health" 404 "http://127.0.0.1/api/health"
}

boot_event_user_agent_count() {
  local user_agent="$1"
  local db_path
  db_path="$(config_string_value database_path)"
  if [ -z "$db_path" ]; then
    db_path="/var/lib/cybex-boot/cybex-boot.sqlite"
  fi
  python3 - "$db_path" "$user_agent" <<'PY'
import sqlite3
import sys

db_path = sys.argv[1]
user_agent = sys.argv[2]
conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
try:
    row = conn.execute(
        "SELECT COUNT(*) FROM boot_events WHERE user_agent = ?",
        (user_agent,),
    ).fetchone()
finally:
    conn.close()
print(row[0])
PY
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
  find /srv/cybex-boot/www -maxdepth 1 \( -type f -o -type l \) -name '.cybex-check.*' -mmin +15 -delete 2>/dev/null || true
}

create_http_check_asset() {
  http_check_asset_path="$(mktemp /srv/cybex-boot/www/.cybex-check.XXXXXX)"
  track_tmp_file "$http_check_asset_path"
  printf 'Cybex Boot checker asset\n%s\n' "$(date +%s)" > "$http_check_asset_path"
  chmod 0644 "$http_check_asset_path"
  http_check_asset_rel="${http_check_asset_path#/srv/cybex-boot/www/}"
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
  link_path="$(mktemp /srv/cybex-boot/www/.cybex-check-link.XXXXXX)"
  rm -f "$link_path"
  if ! ln -s "$http_check_asset_path" "$link_path"; then
    fail "file symlink rejection probe setup failed"
    return
  fi
  track_tmp_file "$link_path"
  link_rel="${link_path#/srv/cybex-boot/www/}"
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
  if tail -n 30 /var/log/nginx/cybex-boot.access.log 2>/dev/null | grep -F "$probe" >/dev/null; then
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
    "set cybex-subtitle PXE BOOT - CYBEX BOOT - X86_64 - UEFI" \
    "colour --basic 0 --rgb 0x0e0f12 0" \
    "colour --basic 3 --rgb 0xeb9b46 1" \
    "cpair --foreground 1 --background 4 2" \
    'menu ${cybex-title}' \
    'item --gap ${cybex-subtitle}' \
    'item --gap ${cybex-timeout-copy}' \
    'choose --timeout ${menu-timeout} --default local selected || goto local' \
    ":local" \
    "exit 0"; do
    if grep -Fx -- "$expected" "$body_file" >/dev/null; then
      ok "$label contains $expected"
    else
      fail "$label is missing $expected"
    fi
  done
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
}

check_marked_boot_probe_non_mutating() {
  local probe
  local before
  local after
  local headers_file
  local body_file
  probe="cybex-boot-check-marker-$$-$(date +%s)"
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
  probe="cybex-boot-check-${label//[^A-Za-z0-9]/-}-$$-$(date +%s)"
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
  if ! curl -fsS -A "cybex-boot-check-profile-menu" -o "$menu_file" --connect-timeout 5 --max-time 15 "http://127.0.0.1/boot.ipxe?cybex_check=1"; then
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
  probe="cybex-boot-check-select-$$-$(date +%s)"
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
  probe="cybex-boot-check-xff-$$-$(date +%s)"
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
  if [ "$(stat -c '%U:%G %a' /srv/cybex-boot/tftp 2>/dev/null || true)" = "root:root 555" ]; then
    ok "TFTP directory is root-owned read-only"
  else
    fail "TFTP directory is not root:root 0555"
  fi
  bad_entries="$(find /srv/cybex-boot/tftp -mindepth 1 -maxdepth 1 ! -type f -printf '%y %p\n' 2>/dev/null || true)"
  if [ -z "$bad_entries" ]; then
    ok "TFTP root contains only regular files"
  else
    fail "TFTP root contains non-regular entries: $bad_entries"
  fi
  bad_entries="$(find /srv/cybex-boot/tftp -maxdepth 1 -type f \( ! -user root -o ! -group root -o ! -perm 0444 \) -print 2>/dev/null || true)"
  if [ -z "$bad_entries" ]; then
    ok "TFTP files are root-owned read-only"
  else
    fail "one or more TFTP files are not root:root 0444"
  fi
}

check_tftp_checksum_file() {
  if [ ! -f /srv/cybex-boot/tftp/SHA256SUMS ]; then
    fail "TFTP SHA256SUMS is missing"
    return
  fi
  if (cd /srv/cybex-boot/tftp && sha256sum -c SHA256SUMS >/dev/null); then
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
  done < <(find /srv/cybex-boot/tftp -mindepth 1 -maxdepth 1 -printf '%f\t%y\n' 2>/dev/null | sort)
  if [ -z "$bad_entries" ]; then
    ok "TFTP root contains only regular managed artifacts"
  else
    fail "TFTP root contains unmanaged artifacts: $bad_entries"
  fi
}

check_tftp_transfer() {
  local bootloader="${1:-snponly.efi}"
  local source_file="/srv/cybex-boot/tftp/$bootloader"
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
  local source_file="/srv/cybex-boot/tftp/$bootloader"
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
    fail "public_base_url is missing from Cybex Boot config"
    return
  fi
  if LC_ALL=C grep -aFx -- "set boot-url $public_base_url" "$source_file" >/dev/null &&
    LC_ALL=C grep -aFx -- "chain --autofree \${boot-url}/boot.ipxe || goto failed" "$source_file" >/dev/null &&
    LC_ALL=C grep -aFx -- "# Embedded chainloader for Cybex Boot UEFI PXE clients." "$source_file" >/dev/null; then
    ok "TFTP bootloader $bootloader embeds Cybex Boot chain URL"
  else
    fail "TFTP bootloader $bootloader does not embed $public_base_url/boot.ipxe"
  fi
}

bootloader_filename() {
  awk -F '"' '/^[[:space:]]*bootloader_filename[[:space:]]*=/ { print $2; exit }' /etc/cybex-boot/config.toml 2>/dev/null
}

require_root

check_service cybex-boot
check_service nginx
check_service tftpd-hpa
check_service cybex-boot-check.timer
check_service cybex-boot-runtime-apply.timer
check_unit_enabled cybex-boot
check_unit_enabled nginx
check_unit_enabled tftpd-hpa
check_unit_enabled cybex-boot-check.timer
check_unit_enabled cybex-boot-runtime-apply.timer

check_command_success "nginx configuration syntax is valid" nginx -t
check_systemd_value cybex-boot-check.timer Unit cybex-boot-check.service
check_systemd_contains cybex-boot-check.timer TimersCalendar "OnCalendar=*-*-* *:00:00"
check_systemd_value cybex-boot-check.timer AccuracyUSec 5min
check_systemd_value cybex-boot-check.timer RandomizedDelayUSec 15min
check_systemd_value cybex-boot-check.timer Persistent yes
check_systemd_value cybex-boot-runtime-apply.timer Unit cybex-boot-runtime-apply.service
check_systemd_contains cybex-boot-runtime-apply.timer TimersMonotonic "OnBootUSec=45s"
check_systemd_contains cybex-boot-runtime-apply.timer TimersMonotonic "OnUnitActiveUSec=1min"
check_systemd_value cybex-boot-runtime-apply.timer AccuracyUSec 15s
check_systemd_value cybex-boot-runtime-apply.timer Persistent yes
check_systemd_value cybex-boot-check.service Type oneshot
check_systemd_contains cybex-boot-check.service ExecStart "cybex-boot-check --quiet"
check_systemd_value cybex-boot-check.service AmbientCapabilities ""
check_systemd_exact_set cybex-boot-check.service CapabilityBoundingSet "cap_dac_override cap_dac_read_search cap_setgid cap_setuid cap_net_bind_service"
check_systemd_value cybex-boot-check.service LockPersonality yes
check_systemd_value cybex-boot-check.service MemoryDenyWriteExecute yes
check_systemd_value cybex-boot-check.service NoNewPrivileges yes
check_systemd_value cybex-boot-check.service PrivateDevices yes
check_systemd_value cybex-boot-check.service PrivateTmp yes
check_systemd_value cybex-boot-check.service ProtectClock yes
check_systemd_value cybex-boot-check.service ProtectControlGroups yes
check_systemd_value cybex-boot-check.service ProtectHome yes
check_systemd_value cybex-boot-check.service ProtectHostname yes
check_systemd_value cybex-boot-check.service ProtectKernelLogs yes
check_systemd_value cybex-boot-check.service ProtectKernelModules yes
check_systemd_value cybex-boot-check.service ProtectKernelTunables yes
check_systemd_value cybex-boot-check.service ProtectProc invisible
check_systemd_value cybex-boot-check.service ProtectSystem strict
check_systemd_value cybex-boot-check.service ProcSubset pid
check_systemd_value cybex-boot-check.service RemoveIPC yes
check_systemd_value cybex-boot-check.service RestrictNamespaces yes
check_systemd_value cybex-boot-check.service RestrictRealtime yes
check_systemd_value cybex-boot-check.service RestrictSUIDSGID yes
check_systemd_value cybex-boot-check.service SystemCallArchitectures native
check_systemd_exact_set cybex-boot-check.service ReadOnlyPaths "/etc/cybex-boot /etc/default/tftpd-hpa /etc/nginx /srv/cybex-boot/tftp"
check_systemd_exact_set cybex-boot-check.service ReadWritePaths "/run /srv/cybex-boot/www /var/lib/cybex-boot /var/lib/nginx /var/log/nginx"
check_systemd_exact_set cybex-boot-check.service RestrictAddressFamilies "AF_INET AF_NETLINK AF_UNIX"
check_systemd_value cybex-boot-check.service UMask 0077
check_systemd_contains cybex-boot-check.service Wants network-online.target
check_systemd_contains cybex-boot-check.service After cybex-boot.service
check_systemd_contains cybex-boot-check.service After nginx.service
check_systemd_contains cybex-boot-check.service After tftpd-hpa.service
check_systemd_value cybex-boot User cybex-boot
check_systemd_value cybex-boot Group cybex-boot
check_systemd_value cybex-boot Type simple
check_systemd_value cybex-boot Restart on-failure
check_systemd_value cybex-boot RestartUSec 3s
check_systemd_value cybex-boot StateDirectory cybex-boot
check_systemd_value cybex-boot UMask 0077
check_systemd_contains cybex-boot Wants network-online.target
check_systemd_contains cybex-boot After network-online.target
check_systemd_value cybex-boot AmbientCapabilities ""
check_systemd_value cybex-boot CapabilityBoundingSet ""
check_systemd_value cybex-boot LockPersonality yes
check_systemd_value cybex-boot MemoryDenyWriteExecute yes
check_systemd_value cybex-boot NoNewPrivileges yes
check_systemd_value cybex-boot PrivateDevices yes
check_systemd_value cybex-boot PrivateTmp yes
check_systemd_value cybex-boot ProtectClock yes
check_systemd_value cybex-boot ProtectControlGroups yes
check_systemd_value cybex-boot ProtectHome yes
check_systemd_value cybex-boot ProtectHostname yes
check_systemd_value cybex-boot ProtectKernelLogs yes
check_systemd_value cybex-boot ProtectKernelModules yes
check_systemd_value cybex-boot ProtectKernelTunables yes
check_systemd_value cybex-boot ProtectProc invisible
check_systemd_value cybex-boot ProtectSystem strict
check_systemd_value cybex-boot ProcSubset pid
check_systemd_value cybex-boot RemoveIPC yes
check_systemd_value cybex-boot RestrictNamespaces yes
check_systemd_value cybex-boot RestrictRealtime yes
check_systemd_value cybex-boot RestrictSUIDSGID yes
check_systemd_value cybex-boot SystemCallArchitectures native
check_cybex_boot_address_families
check_systemd_exact_paths cybex-boot ReadWritePaths "/var/lib/cybex-boot /srv/cybex-boot/www"
check_systemd_contains cybex-boot ExecStart "cybex-boot --config /etc/cybex-boot/config.toml serve"
check_systemd_contains cybex-boot ExecStartPre "cybex-boot --config /etc/cybex-boot/config.toml migrate"
check_systemd_value cybex-boot WorkingDirectory /var/lib/cybex-boot
check_systemd_contains cybex-boot Environment "RUST_LOG=cybex_boot=info,tower_http=warn"
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
check_systemd_exact_set nginx InaccessiblePaths "/etc/cybex-boot /var/lib/cybex-boot /srv/cybex-boot/tftp"
check_systemd_exact_set nginx ReadOnlyPaths "/srv/cybex-boot/www"
check_systemd_exact_set nginx ReadWritePaths "/run /var/lib/nginx /var/log/nginx"
check_systemd_exact_set nginx RestrictAddressFamilies "AF_INET AF_UNIX"
check_systemd_value tftpd-hpa NoNewPrivileges yes
check_systemd_value tftpd-hpa ProtectProc invisible
check_systemd_value tftpd-hpa ProcSubset pid
check_systemd_value tftpd-hpa UMask 0077
check_tftpd_capabilities
check_tftpd_address_families
check_systemd_contains tftpd-hpa ReadOnlyPaths /srv/cybex-boot/tftp
check_systemd_contains tftpd-hpa InaccessiblePaths /etc/cybex-boot
check_systemd_contains tftpd-hpa InaccessiblePaths /var/lib/cybex-boot
check_systemd_contains tftpd-hpa InaccessiblePaths /srv/cybex-boot/www
check_systemd_contains tftpd-hpa EnvironmentFiles /etc/default/tftpd-hpa
check_systemd_contains tftpd-hpa ExecStart 'in.tftpd --listen --user $TFTP_USERNAME --address $TFTP_ADDRESS $TFTP_OPTIONS $TFTP_DIRECTORY'
check_file_contains "TFTP uses Cybex service user" /etc/default/tftpd-hpa 'TFTP_USERNAME="cybex-boot"'
check_file_contains "TFTP serves managed root" /etc/default/tftpd-hpa 'TFTP_DIRECTORY="/srv/cybex-boot/tftp"'
check_file_contains "TFTP listens on IPv4 wildcard" /etc/default/tftpd-hpa 'TFTP_ADDRESS="0.0.0.0:69"'
check_file_contains "TFTP uses secure IPv4 options" /etc/default/tftpd-hpa 'TFTP_OPTIONS="--ipv4 --secure"'
check_path_stat "Boot binary permissions" /usr/local/bin/cybex-boot "root:root 755"
check_path_stat "sync helper permissions" /usr/local/sbin/cybex-boot-sync-once "root:root 755"
check_file_contains "sync helper drops root to service user" /usr/local/sbin/cybex-boot-sync-once 'exec runuser -u cybex-boot -- /usr/local/bin/cybex-boot --config /etc/cybex-boot/config.toml sync-once'
check_file_contains "sync helper uses service config" /usr/local/sbin/cybex-boot-sync-once 'exec /usr/local/bin/cybex-boot --config /etc/cybex-boot/config.toml sync-once'
check_path_stat "checker permissions" /usr/local/sbin/cybex-boot-check "root:root 755"
check_path_stat "Boot service unit permissions" /etc/systemd/system/cybex-boot.service "root:root 644"
check_path_stat "Boot logging drop-in permissions" /etc/systemd/system/cybex-boot.service.d/10-logging.conf "root:root 644"
check_path_stat "Boot migrate drop-in permissions" /etc/systemd/system/cybex-boot.service.d/20-migrate.conf "root:root 644"
check_path_stat "Boot address-family drop-in permissions" /etc/systemd/system/cybex-boot.service.d/30-address-families.conf "root:root 644"
check_path_stat "Boot write-path drop-in permissions" /etc/systemd/system/cybex-boot.service.d/40-write-paths.conf "root:root 644"
check_path_stat "Boot proc drop-in permissions" /etc/systemd/system/cybex-boot.service.d/50-proc.conf "root:root 644"
check_path_stat "nginx hardening drop-in permissions" /etc/systemd/system/nginx.service.d/10-cybex-hardening.conf "root:root 644"
check_path_stat "nginx site permissions" /etc/nginx/sites-available/cybex-boot "root:root 644"
check_path_stat "TFTP hardening drop-in permissions" /etc/systemd/system/tftpd-hpa.service.d/10-cybex-hardening.conf "root:root 644"
check_path_stat "TFTP defaults permissions" /etc/default/tftpd-hpa "root:root 644"
check_path_stat "checker service unit permissions" /etc/systemd/system/cybex-boot-check.service "root:root 644"
check_path_stat "checker timer unit permissions" /etc/systemd/system/cybex-boot-check.timer "root:root 644"
check_path_stat "runtime apply service unit permissions" /etc/systemd/system/cybex-boot-runtime-apply.service "root:root 644"
check_path_stat "runtime apply timer unit permissions" /etc/systemd/system/cybex-boot-runtime-apply.timer "root:root 644"
check_path_stat "config directory permissions" /etc/cybex-boot "root:cybex-boot 750"
check_path_stat "config file permissions" /etc/cybex-boot/config.toml "root:cybex-boot 640"
check_local_management_routes_unavailable
check_path_stat "state directory permissions" /var/lib/cybex-boot "cybex-boot:cybex-boot 700"
check_path_stat "service asset root permissions" /srv/cybex-boot "root:cybex-boot 755"
check_service_asset_root_boundary
check_path_stat "public asset root permissions" /srv/cybex-boot/www "cybex-boot:cybex-boot 755"
check_path_stat "public ISO directory permissions" /srv/cybex-boot/www/isos "cybex-boot:cybex-boot 755"
check_path_stat "public static asset directory permissions" /srv/cybex-boot/www/assets "cybex-boot:cybex-boot 755"
check_public_asset_tree_permissions
check_path_absent "stale static boot script" /srv/cybex-boot/www/boot.ipxe
cleanup_stale_http_check_assets
check_path_stat "managed state permissions" /var/lib/cybex-boot/manage-state.json "cybex-boot:cybex-boot 600"
check_path_stat "SQLite database permissions" /var/lib/cybex-boot/cybex-boot.sqlite "cybex-boot:cybex-boot 600"
check_optional_path_stat "SQLite WAL permissions" /var/lib/cybex-boot/cybex-boot.sqlite-wal "cybex-boot:cybex-boot 600"
check_optional_path_stat "SQLite SHM permissions" /var/lib/cybex-boot/cybex-boot.sqlite-shm "cybex-boot:cybex-boot 600"
check_nginx_config_contains "nginx hides server tokens" "server_tokens off;"
check_nginx_config_contains "nginx enforces method gate" "if (\$request_method !~ ^(GET|HEAD)\$)"
check_nginx_config_contains "nginx limits request bodies" "client_max_body_size 1k;"
check_nginx_config_contains "nginx proxies health to Rust" "location = /healthz"
check_nginx_config_contains "nginx proxies alternate boot root" "location = /boot"
check_nginx_config_contains "nginx proxies alternate boot paths" "location /boot/"
check_nginx_config_contains "nginx streams boot files" "proxy_buffering off;"
check_nginx_config_contains "nginx appends forwarded-for" 'proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;'
check_nginx_config_contains "nginx access log uses safe format" "access_log /var/log/nginx/cybex-boot.access.log cybex_boot_safe;"
check_nginx_config_contains "nginx error log is critical only" "error_log  /var/log/nginx/cybex-boot.error.log crit;"
check_nginx_config_not_contains "nginx has no IPv6 HTTP listen directive" "listen [::]:80"
check_nginx_enabled_sites
check_nginx_public_listen_config
check_nginx_log_format
check_log_path_stat "nginx access log permissions" /var/log/nginx/cybex-boot.access.log
check_log_path_stat "nginx error log permissions" /var/log/nginx/cybex-boot.error.log
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
elif /usr/local/sbin/cybex-boot-sync-once >/dev/null; then
  ok "managed sync-once completed"
  check_path_stat "managed state permissions after sync" /var/lib/cybex-boot/manage-state.json "cybex-boot:cybex-boot 600"
  check_path_stat "SQLite database permissions after sync" /var/lib/cybex-boot/cybex-boot.sqlite "cybex-boot:cybex-boot 600"
  check_optional_path_stat "SQLite WAL permissions after sync" /var/lib/cybex-boot/cybex-boot.sqlite-wal "cybex-boot:cybex-boot 600"
  check_optional_path_stat "SQLite SHM permissions after sync" /var/lib/cybex-boot/cybex-boot.sqlite-shm "cybex-boot:cybex-boot 600"
else
  fail "managed sync-once failed"
fi

if [ "$failures" -eq 0 ]; then
  if [ "$quiet" -eq 0 ]; then
    printf 'Cybex Boot check passed\n'
  fi
else
  printf 'Cybex Boot check failed with %s issue(s)\n' "$failures" >&2
  exit 1
fi
EOF
  chown root:root /usr/local/sbin/cybex-boot-check
  chmod 0755 /usr/local/sbin/cybex-boot-check

  cat > /etc/systemd/system/cybex-boot-check.service <<'EOF'
[Unit]
Description=Cybex Boot local health check
Wants=network-online.target
After=network-online.target cybex-boot.service nginx.service tftpd-hpa.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/cybex-boot-check --quiet
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
ReadOnlyPaths=/etc/cybex-boot /etc/default/tftpd-hpa /etc/nginx /srv/cybex-boot/tftp
ReadWritePaths=/run /srv/cybex-boot/www /var/lib/cybex-boot /var/lib/nginx /var/log/nginx
RemoveIPC=true
RestrictAddressFamilies=
RestrictAddressFamilies=AF_INET AF_UNIX AF_NETLINK
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
SystemCallArchitectures=native
UMask=0077
EOF

  cat > /etc/systemd/system/cybex-boot-check.timer <<'EOF'
[Unit]
Description=Run Cybex Boot local health check periodically

[Timer]
OnCalendar=hourly
AccuracySec=5m
RandomizedDelaySec=15m
Persistent=true
Unit=cybex-boot-check.service

[Install]
WantedBy=timers.target
EOF

  chown root:root /etc/systemd/system/cybex-boot-check.service /etc/systemd/system/cybex-boot-check.timer
  chmod 0644 /etc/systemd/system/cybex-boot-check.service /etc/systemd/system/cybex-boot-check.timer
  systemctl daemon-reload
  systemctl enable --now cybex-boot-check.timer
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
        echo "error: built $bootloader_filename does not embed $public_base_url/boot.ipxe" >&2
        exit 1
      fi
    elif bootloader_embeds_current_chain "$installed_loader"; then
      echo "warning: embedded iPXE loader build failed; preserving existing verified $bootloader_filename" >&2
    else
      echo "error: embedded iPXE loader build failed and no existing $bootloader_filename embeds $public_base_url/boot.ipxe" >&2
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
# Embedded chainloader for Cybex Boot UEFI PXE clients.
# This avoids DHCP/iPXE loops on DHCP servers that cannot hand different
# filenames to native PXE and iPXE clients.
isset \${net0/ip} || dhcp || goto failed
set boot-url $public_base_url
chain --autofree \${boot-url}/boot.ipxe || goto failed

:failed
echo Cybex Boot: failed to load \${boot-url}/boot.ipxe
echo Dropping to iPXE shell.
shell
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
InaccessiblePaths=/etc/cybex-boot /var/lib/cybex-boot $http_root
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
TFTP_USERNAME="cybex-boot"
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
InaccessiblePaths=/etc/cybex-boot /var/lib/cybex-boot $tftp_root
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
  cat > /etc/nginx/sites-available/cybex-boot <<EOF
log_format cybex_boot_safe '\$remote_addr [\$time_local] "\$request_method \$uri \$server_protocol" \$status \$body_bytes_sent';

server {
    listen 80 default_server;
    server_name _;

    root $http_root;

    access_log /var/log/nginx/cybex-boot.access.log cybex_boot_safe;
    error_log  /var/log/nginx/cybex-boot.error.log crit;

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
  chown root:root /etc/systemd/system/nginx.service.d/10-cybex-hardening.conf /etc/nginx/sites-available/cybex-boot
  chmod 0644 /etc/systemd/system/nginx.service.d/10-cybex-hardening.conf /etc/nginx/sites-available/cybex-boot
  find /etc/nginx/sites-enabled -mindepth 1 -maxdepth 1 ! -name cybex-boot \( -type f -o -type l \) -delete
  ln -sfn /etc/nginx/sites-available/cybex-boot /etc/nginx/sites-enabled/cybex-boot
  prepare_nginx_logs
  nginx -t
  systemctl daemon-reload
  systemctl enable nginx
  systemctl restart nginx
}

prepare_nginx_logs() {
  touch /var/log/nginx/cybex-boot.access.log /var/log/nginx/cybex-boot.error.log
  if getent passwd www-data >/dev/null && getent group adm >/dev/null; then
    chown www-data:adm /var/log/nginx/cybex-boot.access.log /var/log/nginx/cybex-boot.error.log
  else
    chown root:root /var/log/nginx/cybex-boot.access.log /var/log/nginx/cybex-boot.error.log
  fi
  chmod 0640 /var/log/nginx/cybex-boot.access.log /var/log/nginx/cybex-boot.error.log
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
  echo "cybex-boot did not become ready at $url; last HTTP status: ${code:-none}" >&2
  systemctl status cybex-boot --no-pager --lines=20 >&2 || true
  exit 1
}

start_service() {
  run_as_boot /usr/local/bin/cybex-boot --config /etc/cybex-boot/config.toml migrate
  systemctl enable cybex-boot
  systemctl restart cybex-boot
  wait_for_boot_ready
}

submit_enrollment() {
  run_as_boot /usr/local/bin/cybex-boot --config /etc/cybex-boot/config.toml enroll || {
    echo "enrollment command failed; inspect journalctl -u cybex-boot" >&2
    exit 1
  }
}

verify_installation() {
  local check_args=(--quiet --skip-managed-sync)
  /usr/local/sbin/cybex-boot-check "${check_args[@]}" || {
    echo "post-install Cybex Boot check failed; inspect /usr/local/sbin/cybex-boot-check output" >&2
    exit 1
  }
  echo "Cybex Boot post-install check passed."
}

require_root
require_value "--api-url" "$api_url"
require_value "--organization-id" "$organization_id"
require_value "--auth-code" "$auth_code"
require_value "--public-base-url" "$public_base_url"
validate_url "--api-url" "$api_url"
validate_url "--public-base-url" "$public_base_url"
validate_organization_id
validate_auth_code
validate_listen_addr
validate_absolute_path "--tftp-root" "$tftp_root"
validate_absolute_path "--http-root" "$http_root"
validate_bootloader_filename
validate_menu_timeout
install_packages
ensure_rust
prepare_source
verify_source_compatibility
install_binary
prepare_user_and_dirs
write_config
install_systemd
install_maintenance_tools
install_tftp_loader
configure_tftp
configure_nginx
start_service
submit_enrollment
verify_installation

echo "Cybex Boot installed. Accept the pending cybex-boot enrollment in Cybex Manage."
