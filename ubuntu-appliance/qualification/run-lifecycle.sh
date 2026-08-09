#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

usage() {
  echo "usage: $0 --template ISO --manifest JSON --manage-origin URL --token-file FILE --output FILE" >&2
  exit 2
}

repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
template=""
manifest=""
manage_origin=""
token_file=""
output=""
while (($#)); do
  case "$1" in
    --template) template="${2:-}"; shift 2 ;;
    --manifest) manifest="${2:-}"; shift 2 ;;
    --manage-origin) manage_origin="${2:-}"; shift 2 ;;
    --token-file) token_file="${2:-}"; shift 2 ;;
    --output) output="${2:-}"; shift 2 ;;
    *) usage ;;
  esac
done
test -f "$template" && test -f "$manifest" && test -f "$token_file" && test -n "$output"
[[ "$manage_origin" =~ ^https://[^/]+$ ]]
for command_name in curl ip jq python3 qemu-system-x86_64 truncate sha256sum openssl ssh-keygen; do
  command -v "$command_name" >/dev/null || { echo "error: missing $command_name" >&2; exit 1; }
done
bridge="${CYBEX_PULSE_QUALIFICATION_BRIDGE:?set the isolated qualification bridge}"
management_cidr="${CYBEX_PULSE_QUALIFICATION_MANAGEMENT_CIDR:?set the qualification Management CIDR}"
token="$(tr -d '\r\n' < "$token_file")"
test -n "$token"
release_version="$(jq -er '.version' "$manifest")"

work_dir="$(mktemp -d)"
qemu_pid=""
package_server_pid=""
session_id=""
lifecycle_succeeded=false
personalized="$work_dir/personalized.iso"
cleanup() {
  if [[ -n "$qemu_pid" ]] && kill -0 "$qemu_pid" 2>/dev/null; then
    kill "$qemu_pid" 2>/dev/null || true
    wait "$qemu_pid" 2>/dev/null || true
  fi
  if [[ -n "$package_server_pid" ]] && kill -0 "$package_server_pid" 2>/dev/null; then
    kill "$package_server_pid" 2>/dev/null || true
    wait "$package_server_pid" 2>/dev/null || true
  fi
  if [[ -n "$session_id" && "$lifecycle_succeeded" != true ]]; then
    cleanup_session="$work_dir/cleanup-session.json"
    if api GET "/v1/pulse/provisioning-sessions/$session_id" > "$cleanup_session" 2>/dev/null \
      && [[ "$(jq -r '.destructive_started_at // ""' "$cleanup_session")" = "" ]] \
      && [[ "$(jq -r '.state' "$cleanup_session")" =~ ^(created|claimed|awaiting_approval|approved|failed)$ ]]
    then
      api POST "/v1/pulse/provisioning-sessions/$session_id/revoke" >/dev/null 2>&1 || true
    fi
  fi
  if [[ -f "$personalized" ]]; then
    shred -u -n 1 -z -- "$personalized" 2>/dev/null || rm -f -- "$personalized"
  fi
  rm -rf -- "$work_dir"
}
trap cleanup EXIT

api() {
  local method="$1" path="$2" body="${3:-}"
  if [[ -n "$body" ]]; then
    curl --fail --silent --show-error --proto '=https' --tlsv1.2 \
      --request "$method" \
      --header "Authorization: Bearer $token" \
      --header 'Content-Type: application/json' \
      --data-binary "$body" "$manage_origin$path"
  else
    curl --fail --silent --show-error --proto '=https' --tlsv1.2 \
      --request "$method" --header "Authorization: Bearer $token" "$manage_origin$path"
  fi
}

package_delivery="$(jq -er '.installer_iso_template_v2.package_delivery // "embedded"' "$manifest")"
package_transport_url=""
case "$package_delivery" in
  embedded) ;;
  network-snapshot-v1)
    test "$(jq -er '.appliance_release_v1.schema' "$manifest")" = \
      cybex.pulse.appliance-release.v1
    package_filename="cybex-pulse-appliance-packages-$release_version-x86_64-linux.tar.zst"
    signed_package_url="$(jq -er '.appliance_release_v1.cybex_repository_snapshot.url' "$manifest")"
    [[ "$signed_package_url" = */"$package_filename" ]]
    manifest_directory="$(cd -- "$(dirname -- "$manifest")" && pwd -P)"
    package_snapshot="$manifest_directory/$package_filename"
    test -f "$package_snapshot" && test ! -L "$package_snapshot"
    test "$(stat -c '%s' "$package_snapshot")" = \
      "$(jq -er '.appliance_release_v1.cybex_repository_snapshot.size_bytes' "$manifest")"
    test "$(sha256sum "$package_snapshot" | awk '{print $1}')" = \
      "$(jq -er '.appliance_release_v1.cybex_repository_snapshot.sha256' "$manifest")"

    mapfile -t bridge_addresses < <(
      ip -4 -o address show dev "$bridge" scope global \
        | awk '{sub(/\/.*/, "", $4); print $4}'
    )
    bridge_ipv4="${CYBEX_PULSE_QUALIFICATION_PACKAGE_BIND_ADDRESS:-}"
    if [[ -n "$bridge_ipv4" ]]; then
      printf '%s\n' "${bridge_addresses[@]}" | grep -Fx "$bridge_ipv4" >/dev/null
    else
      for candidate in "${bridge_addresses[@]}"; do
        if python3 -B -c \
          'import ipaddress,sys; a=ipaddress.ip_address(sys.argv[1]); raise SystemExit(not (a.version == 4 and a.is_private and not a.is_loopback))' \
          "$candidate"
        then
          bridge_ipv4="$candidate"
          break
        fi
      done
    fi
    test -n "$bridge_ipv4" || {
      echo "error: qualification bridge $bridge has no private IPv4 address" >&2
      exit 1
    }
    python3 -B -c \
      'import ipaddress,sys; a=ipaddress.ip_address(sys.argv[1]); raise SystemExit(not (a.version == 4 and a.is_private and not a.is_loopback))' \
      "$bridge_ipv4"

    package_port_file="$work_dir/package-server.port"
    python3 -B \
      "$repository_root/ubuntu-appliance/qualification/serve-package-snapshot.py" \
      --bind "$bridge_ipv4" --file "$package_snapshot" \
      --port-file "$package_port_file" &
    package_server_pid=$!
    for _attempt in $(seq 1 100); do
      [[ -s "$package_port_file" ]] && break
      kill -0 "$package_server_pid"
      sleep 0.1
    done
    package_port="$(tr -d '\r\n' < "$package_port_file")"
    [[ "$package_port" =~ ^[1-9][0-9]{0,4}$ ]] && ((package_port <= 65535))
    package_transport_url="http://$bridge_ipv4:$package_port/$package_filename"
    curl --fail --silent --show-error --proto '=http' --head \
      "$package_transport_url" >/dev/null
    ;;
  *)
    echo "error: unsupported installer package delivery contract: $package_delivery" >&2
    exit 1
    ;;
esac

create_response="$work_dir/create.json"
if [[ -n "$package_transport_url" ]]; then
  create_body="$(jq -c --arg package_transport_url "$package_transport_url" \
    '{label:"release qualification",qualification_candidate:{release_version:.version,installer_iso_template_v2:.installer_iso_template_v2,appliance_release_v1:.appliance_release_v1,package_transport_url:$package_transport_url}}' \
    "$manifest")"
else
  create_body="$(jq -c '
    . as $manifest
    | {label:"release qualification",qualification_candidate:{release_version:$manifest.version,installer_iso_template_v2:$manifest.installer_iso_template_v2}}
    | if ($manifest | has("appliance_release_v1"))
      then .qualification_candidate.appliance_release_v1 = $manifest.appliance_release_v1
      else .
      end' "$manifest")"
fi
api POST /v1/pulse/provisioning-sessions "$create_body" > "$create_response"
session_id="$(jq -er '.session.id' "$create_response")"
media_secret="$(jq -er '.media_secret' "$create_response")"
download_path="$(jq -er '.download_path' "$create_response")"
[[ "$download_path" = "/v1/pulse/provisioning-sessions/$session_id/appliance-iso" ]]
personalization_path="$(jq -er '.personalization_path' "$create_response")"
[[ "$personalization_path" = "/v1/pulse/provisioning-sessions/$session_id/personalization-envelope" ]]

headers="$work_dir/download.headers"
envelope="$work_dir/personalization-envelope.bin"
curl --fail --silent --show-error --proto '=https' --tlsv1.2 \
  --header "Authorization: Bearer $token" \
  --header "X-Cybex-Pulse-Provisioning-Secret: $media_secret" \
  --dump-header "$headers" --output "$envelope" "$manage_origin$personalization_path"
test "$(stat -c '%s' "$envelope")" -eq 8192
cp --reflink=auto -- "$template" "$personalized"
personalization_offset="$(jq -er '.installer_iso_template_v2.personalization_offset' "$manifest")"
dd if="$envelope" of="$personalized" bs=1 seek="$personalization_offset" conv=notrunc status=none
rm -f -- "$envelope"
verification="$work_dir/media-verification.json"
CYBEX_PULSE_MEDIA_SECRET="$media_secret" \
  python3 -B "$repository_root/ubuntu-appliance/qualification/verify-personalized-media.py" \
    --iso "$personalized" --manifest "$manifest" --headers "$headers" \
    --session-id "$session_id" > "$verification"
unset media_secret
rm -f "$create_response"

disk="$work_dir/appliance.raw"
truncate -s 160G "$disk"
preapproval_digest="$(dd if="$disk" bs=1M count=16 status=none | sha256sum | awk '{print $1}')"
vars_template="${CYBEX_PULSE_OVMF_VARS:-/usr/share/OVMF/OVMF_VARS_4M.ms.fd}"
code="${CYBEX_PULSE_OVMF_CODE:-/usr/share/OVMF/OVMF_CODE_4M.secboot.fd}"
test -f "$vars_template" && test -f "$code"
cp -- "$vars_template" "$work_dir/OVMF_VARS.fd"

start_qemu() {
  local boot_mode="$1"
  local -a boot_arguments
  case "$boot_mode" in
    installer) boot_arguments=(-boot "once=d,menu=off") ;;
    installed) boot_arguments=(-boot "order=c,menu=off") ;;
    *) echo "error: unsupported qualification boot mode: $boot_mode" >&2; exit 1 ;;
  esac
  qemu-system-x86_64 \
    -enable-kvm -machine q35,smm=on -cpu host -smp 4 -m 32768 \
    -global driver=cfi.pflash01,property=secure,value=on \
    -drive "if=pflash,format=raw,unit=0,readonly=on,file=$code" \
    -drive "if=pflash,format=raw,unit=1,file=$work_dir/OVMF_VARS.fd" \
    -drive "if=none,id=system,format=raw,file=$disk,cache=none" \
    -device virtio-scsi-pci,id=scsi0 -device scsi-hd,drive=system,serial=CYBEXQUALIFICATION \
    -drive "if=none,id=installer,media=cdrom,readonly=on,format=raw,file=$personalized" \
    -device ide-cd,drive=installer \
    -netdev "bridge,id=net0,br=$bridge" -device virtio-net-pci,netdev=net0,mac=52:54:00:c7:be:01 \
    "${boot_arguments[@]}" -display none -serial "file:$work_dir/serial.log" &
  qemu_pid=$!
}

qemu_restart_count=0
cold_restart_deadline=0
start_qemu installer

session="$work_dir/session.json"
claimed=false
for _attempt in $(seq 1 180); do
  api GET "/v1/pulse/provisioning-sessions/$session_id" > "$session"
  state="$(jq -er '.state' "$session")"
  if [[ "$state" = awaiting_approval ]]; then claimed=true; break; fi
  [[ "$state" != failed && "$state" != revoked && "$state" != expired ]]
  kill -0 "$qemu_pid"
  sleep 5
done
test "$claimed" = true
test "$(jq -er '.inventory.secure_boot' "$session")" = true
test "$(jq -er '.inventory.boot_mode' "$session")" = uefi
test "$(jq -er '.blockers | length' "$session")" = 0
test "$(jq -er '[.inventory.disks[] | select(.eligible == true)] | length' "$session")" = 1
test "$(dd if="$disk" bs=1M count=16 status=none | sha256sum | awk '{print $1}')" = "$preapproval_digest"

revision="$(jq -er '.session_revision' "$session")"
inventory_sha="$(jq -er '.inventory_sha256' "$session")"
disk_id="$(jq -er '.inventory.disks[] | select(.eligible == true) | .id' "$session")"
interface_id="$(jq -er '.inventory.ethernet_interfaces[] | select(.link_up == true) | .id' "$session" | head -n 1)"
session_suffix="${session_id%%-*}"
approve_body="$(jq -cn \
  --argjson revision "$revision" --arg inventory "$inventory_sha" \
  --arg disk "$disk_id" --arg interface "$interface_id" --arg cidr "$management_cidr" \
  --arg display_name "Pulse release qualification $release_version $session_suffix" \
  '{session_revision:$revision,inventory_sha256:$inventory,display_name:$display_name,target_disk_id:$disk,network:{mode:"dhcp",interface_id:$interface,address_cidr:null,gateway:null,dns_servers:[]},maintenance_window:{timezone:"UTC",weekday:0,start:"02:00",duration_minutes:120},management_cidrs:[$cidr]}')"
api POST "/v1/pulse/provisioning-sessions/$session_id/approve" "$approve_body" >/dev/null

ready=false
pre_destructive_deadline=$((SECONDS + 300))
for _attempt in $(seq 1 1080); do
  api GET "/v1/pulse/provisioning-sessions/$session_id" > "$session"
  state="$(jq -er '.state' "$session")"
  if [[ "$state" = ready ]]; then ready=true; break; fi
  if [[ -s "$work_dir/serial.log" ]] \
    && grep -aF 'An error occurred. Press enter to start a shell' "$work_dir/serial.log" >/dev/null
  then
    echo 'error: Ubuntu installer entered its fatal recovery shell' >&2
    echo 'bounded qualification serial console follows:' >&2
    tail -n 500 "$work_dir/serial.log" >&2
    exit 1
  fi
  if [[ "$state" = failed || "$state" = revoked || "$state" = expired ]]; then
    jq '{state,failure_code,failure_message,progress}' "$session" >&2
    exit 1
  fi
  if [[ "$state" = approved ]] \
    && [[ "$(jq -r '.destructive_started_at // ""' "$session")" = "" ]] \
    && ((SECONDS >= pre_destructive_deadline))
  then
    echo 'error: approved Pulse candidate did not acknowledge its plan before the qualification deadline' >&2
    jq '{state,heartbeat_at,destructive_started_at,progress,failure_code,failure_message}' "$session" >&2
    if [[ -s "$work_dir/serial.log" ]]; then
      echo 'bounded qualification serial console follows:' >&2
      tail -n 500 "$work_dir/serial.log" >&2
    fi
    exit 1
  fi
  if [[ "$state" = rebooting && "$qemu_restart_count" -eq 0 ]] \
    && [[ -s "$work_dir/serial.log" ]] \
    && (( $(date +%s) - $(stat -c %Y "$work_dir/serial.log") >= 180 ))
  then
    echo 'qualification: reboot console stalled; cold-starting the installed disk once' >&2
    kill "$qemu_pid" 2>/dev/null || true
    wait "$qemu_pid" 2>/dev/null || true
    qemu_pid=""
    start_qemu installed
    qemu_restart_count=1
    cold_restart_deadline=$((SECONDS + 300))
  fi
  if [[ "$state" = rebooting && "$qemu_restart_count" -eq 1 ]] \
    && ((SECONDS >= cold_restart_deadline))
  then
    echo 'error: installed Pulse disk did not activate after its bounded cold restart' >&2
    if [[ -s "$work_dir/serial.log" ]]; then
      echo 'bounded qualification serial console follows:' >&2
      tail -n 500 "$work_dir/serial.log" >&2
    fi
    exit 1
  fi
  kill -0 "$qemu_pid"
  sleep 5
done
test "$ready" = true

device_id="$(jq -er '.reserved_device_id' "$session")"
nodes="$work_dir/nodes.json"
node="$work_dir/node.json"
appliance_projection_ready=false
for _attempt in $(seq 1 120); do
  api GET '/v1/pulse/nodes?limit=100&offset=0' > "$nodes"
  jq -e --arg device "$device_id" '.nodes[] | select(.device_id == $device)' "$nodes" > "$node" || true
  if [[ -s "$node" ]] \
    && [[ "$(jq -er '.appliance_base_os' "$node")" = ubuntu ]] \
    && [[ "$(jq -er '.appliance_base_os_version' "$node")" = 26.04 ]] \
    && [[ "$(jq -er '.appliance_secure_boot' "$node")" = true ]] \
    && [[ "$(jq -er '.appliance_boot_mode' "$node")" = uefi ]] \
    && [[ "$(jq -er '.at_rest_protection' "$node")" = none ]] \
    && [[ "$(jq -er '.appliance_local_health.status' "$node")" = healthy ]] \
    && [[ -n "$(jq -er '.kernel_version' "$node")" ]] \
    && [[ -n "$(jq -er '.root_generation' "$node")" ]]
  then
    appliance_projection_ready=true
    break
  fi
  kill -0 "$qemu_pid"
  sleep 5
done
test "$appliance_projection_ready" = true

network_change="$work_dir/network-change.json"
network_body="$(jq -cn --arg interface "$interface_id" \
  '{network:{mode:"dhcp",interface_id:$interface,address_cidr:null,gateway:null,dns_servers:[]}}')"
api POST "/v1/pulse/nodes/$device_id/network-changes" "$network_body" > "$network_change"
network_change_id="$(jq -er '.id' "$network_change")"
test "$(jq -er '.state' "$network_change")" = requested
network_acknowledged=false
for _attempt in $(seq 1 120); do
  api GET '/v1/pulse/nodes?limit=100&offset=0' > "$nodes"
  jq -e --arg device "$device_id" '.nodes[] | select(.device_id == $device)' "$nodes" > "$node"
  reported_change_id="$(jq -r '.appliance_network.network_change.change_id // ""' "$node")"
  reported_change_status="$(jq -r '.appliance_network.network_change.status // "idle"' "$node")"
  if [[ "$reported_change_id" = "$network_change_id" && "$reported_change_status" = acknowledged ]]; then
    network_acknowledged=true
    break
  fi
  [[ "$reported_change_status" != failed && "$reported_change_status" != rolled_back ]]
  kill -0 "$qemu_pid"
  sleep 5
done
test "$network_acknowledged" = true

ssh-keygen -q -t ed25519 -N '' -C qualification -f "$work_dir/operator-key"
certificate_response="$work_dir/ssh-certificate.json"
certificate_request="$(jq -cn \
  --arg public_key "$(cat "$work_dir/operator-key.pub")" \
  '{public_key:$public_key,reason:"exact candidate release qualification",validity_minutes:5,allow_forwarding:false}')"
api POST "/v1/pulse/nodes/$device_id/ssh-certificates" "$certificate_request" > "$certificate_response"
test "$(jq -er '.principal' "$certificate_response")" = "$device_id"
valid_after="$(date -u -d "$(jq -er '.valid_after' "$certificate_response")" +%s)"
valid_before="$(date -u -d "$(jq -er '.valid_before' "$certificate_response")" +%s)"
test "$((valid_before - valid_after))" -le 300
jq -er '.certificate' "$certificate_response" > "$work_dir/operator-key-cert.pub"
ssh-keygen -Lf "$work_dir/operator-key-cert.pub" > "$work_dir/certificate-inspection.txt"
grep -E "^[[:space:]]+${device_id}[[:space:]]*$" "$work_dir/certificate-inspection.txt" >/dev/null
if grep -F 'permit-agent-forwarding' "$work_dir/certificate-inspection.txt" >/dev/null \
  || grep -F 'permit-port-forwarding' "$work_dir/certificate-inspection.txt" >/dev/null
then
  echo 'error: non-forwarding qualification certificate contains forwarding extensions' >&2
  exit 1
fi
rm -f -- "$work_dir/operator-key" "$work_dir/operator-key.pub" \
  "$work_dir/operator-key-cert.pub" "$certificate_response" "$work_dir/certificate-inspection.txt"

template_sha="$(jq -er '.template_sha256' "$verification")"
personalized_sha="$(jq -er '.personalized_sha256' "$verification")"
jq -n \
  --arg schema 'cybex.pulse.ubuntu-appliance-qualification.v1' \
  --arg session_id "$session_id" --arg template_sha256 "$template_sha" \
  --arg personalized_sha256 "$personalized_sha" \
  --arg completed_at "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
  '{schema:$schema,ok:true,session_id:$session_id,template_sha256:$template_sha256,personalized_sha256:$personalized_sha256,secure_boot:true,no_disk_write_before_approval:true,identity_rotation:true,installed_media_left_attached:true,appliance_projection_healthy:true,two_phase_network_acknowledged:true,exact_principal_ssh_certificate:true,final_state:"ready",completed_at:$completed_at}' \
  > "$output"
chmod 0644 "$output"
lifecycle_succeeded=true
