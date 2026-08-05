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
for command_name in curl jq qemu-system-x86_64 truncate sha256sum openssl ssh-keygen; do
  command -v "$command_name" >/dev/null || { echo "error: missing $command_name" >&2; exit 1; }
done
bridge="${CYBEX_FORGE_QUALIFICATION_BRIDGE:?set the isolated qualification bridge}"
management_cidr="${CYBEX_FORGE_QUALIFICATION_MANAGEMENT_CIDR:?set the qualification Management CIDR}"
token="$(tr -d '\r\n' < "$token_file")"
test -n "$token"

work_dir="$(mktemp -d)"
qemu_pid=""
personalized="$work_dir/personalized.iso"
cleanup() {
  if [[ -n "$qemu_pid" ]] && kill -0 "$qemu_pid" 2>/dev/null; then
    kill "$qemu_pid" 2>/dev/null || true
    wait "$qemu_pid" 2>/dev/null || true
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

create_response="$work_dir/create.json"
create_body="$(jq -c \
  '{label:"release qualification",qualification_candidate:{release_version:.version,installer_iso_template_v2:.installer_iso_template_v2}}' \
  "$manifest")"
api POST /v1/forge/provisioning-sessions "$create_body" > "$create_response"
session_id="$(jq -er '.session.id' "$create_response")"
media_secret="$(jq -er '.media_secret' "$create_response")"
download_path="$(jq -er '.download_path' "$create_response")"
[[ "$download_path" = "/v1/forge/provisioning-sessions/$session_id/appliance-iso" ]]
personalization_path="$(jq -er '.personalization_path' "$create_response")"
[[ "$personalization_path" = "/v1/forge/provisioning-sessions/$session_id/personalization-envelope" ]]

headers="$work_dir/download.headers"
envelope="$work_dir/personalization-envelope.bin"
curl --fail --silent --show-error --proto '=https' --tlsv1.2 \
  --header "Authorization: Bearer $token" \
  --header "X-Cybex-Forge-Provisioning-Secret: $media_secret" \
  --dump-header "$headers" --output "$envelope" "$manage_origin$personalization_path"
test "$(stat -c '%s' "$envelope")" -eq 8192
cp --reflink=auto -- "$template" "$personalized"
personalization_offset="$(jq -er '.installer_iso_template_v2.personalization_offset' "$manifest")"
dd if="$envelope" of="$personalized" bs=1 seek="$personalization_offset" conv=notrunc status=none
rm -f -- "$envelope"
verification="$work_dir/media-verification.json"
CYBEX_FORGE_MEDIA_SECRET="$media_secret" \
  python3 -B "$repository_root/ubuntu-appliance/qualification/verify-personalized-media.py" \
    --iso "$personalized" --manifest "$manifest" --headers "$headers" \
    --session-id "$session_id" > "$verification"
unset media_secret
rm -f "$create_response"

disk="$work_dir/appliance.raw"
truncate -s 160G "$disk"
preapproval_digest="$(dd if="$disk" bs=1M count=16 status=none | sha256sum | awk '{print $1}')"
vars_template="${CYBEX_FORGE_OVMF_VARS:-/usr/share/OVMF/OVMF_VARS_4M.ms.fd}"
code="${CYBEX_FORGE_OVMF_CODE:-/usr/share/OVMF/OVMF_CODE_4M.secboot.fd}"
test -f "$vars_template" && test -f "$code"
cp -- "$vars_template" "$work_dir/OVMF_VARS.fd"

qemu-system-x86_64 \
  -enable-kvm -machine q35,smm=on -cpu host -smp 4 -m 32768 \
  -global driver=cfi.pflash01,property=secure,value=on \
  -drive "if=pflash,format=raw,unit=0,readonly=on,file=$code" \
  -drive "if=pflash,format=raw,unit=1,file=$work_dir/OVMF_VARS.fd" \
  -drive "if=none,id=system,format=raw,file=$disk,cache=none" \
  -device virtio-scsi-pci,id=scsi0 -device scsi-hd,drive=system \
  -drive "if=none,id=installer,media=cdrom,readonly=on,format=raw,file=$personalized" \
  -device ide-cd,drive=installer \
  -netdev "bridge,id=net0,br=$bridge" -device virtio-net-pci,netdev=net0 \
  -boot once=d,menu=off -display none -serial "file:$work_dir/serial.log" &
qemu_pid=$!

session="$work_dir/session.json"
claimed=false
for _attempt in $(seq 1 180); do
  api GET "/v1/forge/provisioning-sessions/$session_id" > "$session"
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
approve_body="$(jq -cn \
  --argjson revision "$revision" --arg inventory "$inventory_sha" \
  --arg disk "$disk_id" --arg interface "$interface_id" --arg cidr "$management_cidr" \
  '{session_revision:$revision,inventory_sha256:$inventory,display_name:"Forge release qualification",target_disk_id:$disk,network:{mode:"dhcp",interface_id:$interface,address_cidr:null,gateway:null,dns_servers:[]},maintenance_window:{timezone:"UTC",weekday:0,start:"02:00",duration_minutes:120},management_cidrs:[$cidr]}')"
api POST "/v1/forge/provisioning-sessions/$session_id/approve" "$approve_body" >/dev/null

ready=false
for _attempt in $(seq 1 1080); do
  api GET "/v1/forge/provisioning-sessions/$session_id" > "$session"
  state="$(jq -er '.state' "$session")"
  if [[ "$state" = ready ]]; then ready=true; break; fi
  if [[ "$state" = failed || "$state" = revoked || "$state" = expired ]]; then
    jq '{state,failure_code,failure_message,progress}' "$session" >&2
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
  api GET '/v1/forge/nodes?limit=100&offset=0' > "$nodes"
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
api POST "/v1/forge/nodes/$device_id/network-changes" "$network_body" > "$network_change"
network_change_id="$(jq -er '.id' "$network_change")"
test "$(jq -er '.state' "$network_change")" = requested
network_acknowledged=false
for _attempt in $(seq 1 120); do
  api GET '/v1/forge/nodes?limit=100&offset=0' > "$nodes"
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
api POST "/v1/forge/nodes/$device_id/ssh-certificates" "$certificate_request" > "$certificate_response"
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
  --arg schema 'cybex.forge.ubuntu-appliance-qualification.v1' \
  --arg session_id "$session_id" --arg template_sha256 "$template_sha" \
  --arg personalized_sha256 "$personalized_sha" \
  --arg completed_at "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
  '{schema:$schema,ok:true,session_id:$session_id,template_sha256:$template_sha256,personalized_sha256:$personalized_sha256,secure_boot:true,no_disk_write_before_approval:true,identity_rotation:true,installed_media_left_attached:true,appliance_projection_healthy:true,two_phase_network_acknowledged:true,exact_principal_ssh_certificate:true,final_state:"ready",completed_at:$completed_at}' \
  > "$output"
chmod 0644 "$output"
