#!/usr/bin/env bash
set -euo pipefail

FORGE_GIT_URL_DEFAULT="https://github.com/CybexHQ/forge.git"
FORGE_SOURCE_DIR_DEFAULT="/root/forge"
LXC_INSTALLER_RELATIVE_PATH="install/cybex-boot-lxc-install.sh"

api_url="${CYBEX_MANAGE_API_URL:-}"
organization_id="${CYBEX_ORGANIZATION_ID:-}"
auth_code="${CYBEX_BOOT_AUTH_CODE:-}"
public_base_url="${CYBEX_BOOT_PUBLIC_BASE_URL:-}"
listen_addr="${CYBEX_BOOT_LISTEN_ADDR:-127.0.0.1:8080}"
tftp_root="${CYBEX_BOOT_TFTP_ROOT:-/srv/cybex-boot/tftp}"
http_root="${CYBEX_BOOT_HTTP_ROOT:-/srv/cybex-boot/www}"
bootloader_filename="${CYBEX_BOOTLOADER_FILENAME:-snponly.efi}"
menu_timeout_ms="${CYBEX_BOOT_MENU_TIMEOUT_MS:-8000}"

vmid="${CYBEX_BOOT_PROXMOX_VMID:-}"
hostname="${CYBEX_BOOT_PROXMOX_HOSTNAME:-cybex-boot}"
storage="${CYBEX_BOOT_PROXMOX_STORAGE:-}"
template_storage="${CYBEX_BOOT_PROXMOX_TEMPLATE_STORAGE:-}"
bridge="${CYBEX_BOOT_PROXMOX_BRIDGE:-}"
template="${CYBEX_BOOT_PROXMOX_TEMPLATE:-}"
disk_gb="${CYBEX_BOOT_PROXMOX_DISK_GB:-32}"
cpu_cores="${CYBEX_BOOT_PROXMOX_CPU_CORES:-2}"
memory_mb="${CYBEX_BOOT_PROXMOX_MEMORY_MB:-4096}"
forge_git_url="${CYBEX_BOOT_FORGE_GIT_URL:-$FORGE_GIT_URL_DEFAULT}"
forge_source_dir="${CYBEX_BOOT_FORGE_SOURCE_DIR:-$FORGE_SOURCE_DIR_DEFAULT}"

usage() {
  cat <<'EOF'
Usage:
  proxmox-host-lxc.sh --api-url URL --organization-id UUID --auth-code CODE --public-base-url URL [options]

Run this on a Proxmox host as root. It creates a Debian/Ubuntu LXC, clones
Forge inside it, installs Cybex Boot, submits the one-time install code, and
leaves a pending cybex-boot enrollment in Cybex Manage.

Required:
  --api-url URL                  Cybex Manage public API URL
  --organization-id UUID         Cybex organization UUID
  --auth-code CODE               One-time Boot install authorization code
  --public-base-url URL          URL PXE clients use for this Boot server

Generated resource options:
  --proxmox-disk-gb GiB          Root disk size (default/recommended: 32)
  --proxmox-cpu-cores COUNT      CPU cores (default/recommended: 2)
  --proxmox-memory-mb MiB        Memory (default/recommended: 4096)

Boot runtime options:
  --listen ADDR                  Local Boot address behind nginx (default: 127.0.0.1:8080)
  --tftp-root PATH               TFTP root (default: /srv/cybex-boot/tftp)
  --http-root PATH               HTTP asset root (default: /srv/cybex-boot/www)
  --bootloader NAME              UEFI iPXE loader filename (default: snponly.efi)
  --menu-timeout-ms MS           Boot menu timeout (default: 8000)

Advanced Proxmox options:
  --vmid ID                      Container VMID (default: next cluster id)
  --hostname NAME                Container hostname (default: cybex-boot)
  --storage NAME                 Rootfs storage (default: first rootdir-capable storage)
  --template-storage NAME        Template storage (default: first vztmpl-capable storage)
  --bridge NAME                  Network bridge (default: vmbr0 or first vmbr*)
  --template TEMPLATE            Existing template path or storage:vztmpl/name
  --forge-git-url URL            Forge source repository (default: https://github.com/CybexHQ/forge.git)
  --forge-source-dir PATH        Source checkout inside LXC (default: /root/forge)
  -h, --help                     Show this help
EOF
}

section() {
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

while [ "$#" -gt 0 ]; do
  case "$1" in
    --api-url) api_url="${2:-}"; shift 2 ;;
    --organization-id) organization_id="${2:-}"; shift 2 ;;
    --auth-code) auth_code="${2:-}"; shift 2 ;;
    --public-base-url) public_base_url="${2:-}"; shift 2 ;;
    --listen) listen_addr="${2:-}"; shift 2 ;;
    --tftp-root) tftp_root="${2:-}"; shift 2 ;;
    --http-root) http_root="${2:-}"; shift 2 ;;
    --bootloader) bootloader_filename="${2:-}"; shift 2 ;;
    --menu-timeout-ms) menu_timeout_ms="${2:-}"; shift 2 ;;
    --vmid) vmid="${2:-}"; shift 2 ;;
    --hostname) hostname="${2:-}"; shift 2 ;;
    --storage) storage="${2:-}"; shift 2 ;;
    --template-storage) template_storage="${2:-}"; shift 2 ;;
    --bridge) bridge="${2:-}"; shift 2 ;;
    --template) template="${2:-}"; shift 2 ;;
    --proxmox-disk-gb) disk_gb="${2:-}"; shift 2 ;;
    --proxmox-cpu-cores) cpu_cores="${2:-}"; shift 2 ;;
    --proxmox-memory-mb) memory_mb="${2:-}"; shift 2 ;;
    --forge-git-url) forge_git_url="${2:-}"; shift 2 ;;
    --forge-source-dir) forge_source_dir="${2:-}"; shift 2 ;;
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

validate_uuid() {
  validate_plain_value "--organization-id" "$organization_id"
  printf '%s' "$organization_id" | LC_ALL=C grep -Eq '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$' ||
    die "--organization-id must be a UUID"
}

validate_auth_code() {
  validate_plain_value "--auth-code" "$auth_code"
  [ "${#auth_code}" -ge 16 ] || die "--auth-code is too short"
  if printf '%s' "$auth_code" | LC_ALL=C grep -q '[[:space:]]'; then
    die "--auth-code contains unsupported characters"
  fi
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

validate_bootloader_filename() {
  validate_plain_value "--bootloader" "$bootloader_filename"
  case "$bootloader_filename" in
    ""|*/*|*\\*|.*|*' '*|*$'\t'*) die "--bootloader must be a simple filename" ;;
  esac
  printf '%s' "$bootloader_filename" | LC_ALL=C grep -Eq '^[A-Za-z0-9._-]+$' ||
    die "--bootloader must use only letters, numbers, dot, underscore, or hyphen"
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
  [ "$disk_gb" -ge 32 ] || warn "disk is below the 32 GiB recommendation"
  [ "$cpu_cores" -ge 2 ] || warn "CPU allocation is below the 2-core recommendation"
  [ "$memory_mb" -ge 4096 ] || warn "memory is below the 4096 MiB recommendation"
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
  info "Manage API: $api_url"
  info "Organization: $organization_id"
  info "Public Boot URL: $public_base_url"
  info "Forge source: $forge_git_url"
}

create_container() {
  section "Create LXC"
  pct create "$vmid" "$template" \
    --hostname "$hostname" \
    --cores "$cpu_cores" \
    --memory "$memory_mb" \
    --rootfs "${storage}:${disk_gb}" \
    --net0 "name=eth0,bridge=${bridge},ip=dhcp" \
    --ostype debian \
    --unprivileged 0 \
    --features nesting=1 \
    --onboot 1
}

start_container() {
  section "Start LXC"
  pct start "$vmid"
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
    if [ -d "$source_dir/.git" ]; then
      git -C "$source_dir" fetch --depth 1 origin main || true
      git -C "$source_dir" checkout -f FETCH_HEAD || git -C "$source_dir" pull --ff-only || true
    else
      rm -rf "$source_dir"
      git clone --depth 1 "$git_url" "$source_dir"
    fi
    test -f "$source_dir/install/cybex-boot-lxc-install.sh"
    chmod 0755 "$source_dir/install/cybex-boot-lxc-install.sh"
  ' sh "$forge_source_dir" "$forge_git_url"
}

run_lxc_installer() {
  section "Install Cybex Boot"
  info "Running the LXC installer. The one-time code is passed to the installer but not printed."
  local installer="${forge_source_dir}/${LXC_INSTALLER_RELATIVE_PATH}"
  pct exec "$vmid" -- "$installer" \
    --api-url "$api_url" \
    --organization-id "$organization_id" \
    --auth-code "$auth_code" \
    --public-base-url "$public_base_url" \
    --source-dir "$forge_source_dir" \
    --git-url "$forge_git_url" \
    --listen "$listen_addr" \
    --tftp-root "$tftp_root" \
    --http-root "$http_root" \
    --bootloader "$bootloader_filename" \
    --menu-timeout-ms "$menu_timeout_ms"
}

print_final() {
  local container_ip
  container_ip="$(pct exec "$vmid" -- hostname -I 2>/dev/null | awk '{ print $1 }' || true)"
  section "Next"
  info "A pending cybex-boot enrollment has been submitted to Cybex Manage."
  if [ -n "$container_ip" ]; then
    info "Detected LXC address: $container_ip"
    info "Open Enrollments, adopt the Cybex Boot server, then configure DHCP option 66 to $container_ip and option 67 to $bootloader_filename."
  else
    info "Open Enrollments, adopt the Cybex Boot server, then configure DHCP option 66 to the LXC address and option 67 to $bootloader_filename."
  fi
  info "Container VMID $vmid is running as $hostname."
}

require_value "--api-url" "$api_url"
require_value "--organization-id" "$organization_id"
require_value "--auth-code" "$auth_code"
require_value "--public-base-url" "$public_base_url"
validate_url "--api-url" "$api_url"
validate_url "--public-base-url" "$public_base_url"
validate_url "--forge-git-url" "$forge_git_url"
validate_uuid
validate_auth_code
validate_absolute_path "--tftp-root" "$tftp_root"
validate_absolute_path "--http-root" "$http_root"
validate_absolute_path "--forge-source-dir" "$forge_source_dir"
validate_bootloader_filename
validate_int_range "--menu-timeout-ms" "$menu_timeout_ms" 1000 600000
validate_int_range "--proxmox-disk-gb" "$disk_gb" 8 4096
validate_int_range "--proxmox-cpu-cores" "$cpu_cores" 1 128
validate_int_range "--proxmox-memory-mb" "$memory_mb" 1024 1048576
tooling_preflight
validate_and_select_proxmox
resource_warnings
print_summary
create_container
start_container
prepare_forge_source
run_lxc_installer
print_final
