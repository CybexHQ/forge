#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

usage() {
  echo "usage: $0 --predecessor-evidence JSON --candidate-manifest JSON [--qualification-package-transport-url URL] --manage-origin URL --token-file FILE --server-device-id ID --output FILE" >&2
  exit 2
}

repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
predecessor_evidence=""
candidate_manifest=""
qualification_package_transport_url=""
manage_origin=""
token_file=""
server_device_id=""
output=""
while (($#)); do
  case "$1" in
    --predecessor-evidence) predecessor_evidence="${2:-}"; shift 2 ;;
    --candidate-manifest) candidate_manifest="${2:-}"; shift 2 ;;
    --qualification-package-transport-url) qualification_package_transport_url="${2:-}"; shift 2 ;;
    --manage-origin) manage_origin="${2:-}"; shift 2 ;;
    --token-file) token_file="${2:-}"; shift 2 ;;
    --server-device-id) server_device_id="${2:-}"; shift 2 ;;
    --output) output="${2:-}"; shift 2 ;;
    *) usage ;;
  esac
done

test -f "$predecessor_evidence" && test ! -L "$predecessor_evidence"
test -f "$candidate_manifest" && test ! -L "$candidate_manifest"
test -f "$token_file" && test ! -L "$token_file"
test -n "$server_device_id" && test -n "$output"
[[ "$server_device_id" =~ ^[0-9A-Za-z][0-9A-Za-z._:-]{0,255}$ ]]
for command_name in base64 curl date jq python3 sha256sum; do
  command -v "$command_name" >/dev/null || {
    echo "error: missing $command_name" >&2
    exit 1
  }
done

poll_seconds="${CYBEX_UPDATE_QUALIFICATION_POLL_SECONDS:-5}"
maximum_polls="${CYBEX_UPDATE_QUALIFICATION_MAX_POLLS:-1440}"
qualification_ttl_seconds="${CYBEX_UPDATE_QUALIFICATION_TTL_SECONDS:-900}"
[[ "$poll_seconds" =~ ^[0-9]+$ ]] && ((poll_seconds <= 60))
[[ "$maximum_polls" =~ ^[1-9][0-9]{0,4}$ ]] && ((maximum_polls <= 10000))
[[ "$qualification_ttl_seconds" =~ ^[1-9][0-9]{0,3}$ ]]
((qualification_ttl_seconds >= 300 && qualification_ttl_seconds <= 3600))

python3 -B "$repository_root/tools/james-release.py" validate-manage-origin \
  --expected-manage-origin "$manage_origin" >/dev/null
test "$(jq -er '.installer_iso_template_v2.manage_origin' "$candidate_manifest")" = \
  "$manage_origin"

test "$(jq -er '.schema' "$predecessor_evidence")" = \
  cybex.james.ubuntu-appliance-qualification.v1
test "$(jq -er '.ok' "$predecessor_evidence")" = true
test "$(jq -er '.final_state' "$predecessor_evidence")" = ready
test "$(jq -er '.secure_boot' "$predecessor_evidence")" = true
test "$(jq -er '.appliance_projection_healthy' "$predecessor_evidence")" = true
test "$(jq -er '.two_phase_network_acknowledged' "$predecessor_evidence")" = true
test "$(jq -er '.root_generation | tostring' "$predecessor_evidence")" = 0

predecessor_release="$(jq -er '.release_version' "$predecessor_evidence")"
predecessor_snapshot="$(jq -er '.ubuntu_snapshot_id' "$predecessor_evidence")"
candidate_release="$(jq -er '.version' "$candidate_manifest")"
candidate_release_url="$(jq -er '.release_url' "$candidate_manifest")"
candidate_snapshot="$(jq -er '.appliance_release_v1.ubuntu_snapshot_id' "$candidate_manifest")"
candidate_package_url="$(jq -er '.appliance_release_v1.cybex_repository_snapshot.url' "$candidate_manifest")"
candidate_package_sha256="$(jq -er '.appliance_release_v1.cybex_repository_snapshot.sha256' "$candidate_manifest")"
candidate_package_size="$(jq -er '.appliance_release_v1.cybex_repository_snapshot.size_bytes' "$candidate_manifest")"
candidate_runtime_version="$(jq -er '.workstation_netboot.runtime_version' "$candidate_manifest")"
candidate_runtime_sha256="$(jq -er '.workstation_netboot.sha256' "$candidate_manifest")"
candidate_manage_revision="$(jq -er '.workstation_netboot.manage_source_revision' "$candidate_manifest")"
candidate_runtime_architecture="$(jq -er '.workstation_netboot.architecture' "$candidate_manifest")"

test "$(jq -er '.schema' "$candidate_manifest")" = cybex.james.release.v1
test "$(jq -er '.appliance_release_v1.schema' "$candidate_manifest")" = \
  cybex.james.appliance-release.v1
test "$(jq -er '.appliance_release_v1.release_id' "$candidate_manifest")" = \
  "$candidate_release"
test "$(jq -er '.appliance_release_v1.minimum_protocol' "$candidate_manifest")" = 4
test "$(jq -er '.appliance_release_v1.minimum_state_schema' "$candidate_manifest")" = 2
test "$(jq -er '.appliance_release_v1.rollback_compatible' "$candidate_manifest")" = true
test "$(jq -er '.workstation_netboot.schema' "$candidate_manifest")" = \
  cybex.james.workstation-netboot.v1
test "$candidate_runtime_architecture" = x86_64-linux
[[ "$candidate_package_sha256" =~ ^[0-9a-f]{64}$ ]]
[[ "$candidate_runtime_sha256" =~ ^[0-9a-f]{64}$ ]]
[[ "$candidate_manage_revision" =~ ^[0-9a-f]{40}$ ]]
[[ "$candidate_package_size" =~ ^[1-9][0-9]*$ ]]
test "${candidate_package_url##*/}" = \
  "cybex-james-appliance-packages-$candidate_release-x86_64-linux.tar.zst"
qualification_transport_override_supplied=false
if [[ -z "$qualification_package_transport_url" ]]; then
  # Frozen legacy predecessors deserialize only the original three update
  # fields. Omitting this option keeps their wire payload unchanged and makes
  # the signed canonical HTTPS URL the only transport they can consume.
  qualification_package_transport_url="$candidate_package_url"
fi
transport_kind="$(python3 - "$qualification_package_transport_url" \
  "$candidate_package_url" <<'PY'
import ipaddress
import sys
import urllib.parse

value, canonical_url = sys.argv[1:]
if value == canonical_url:
    parsed = urllib.parse.urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or urllib.parse.urlunsplit(parsed) != value
    ):
        raise SystemExit("signed canonical package URL is not canonical HTTPS")
    print("signed_canonical_https")
    raise SystemExit(0)

expected_filename = urllib.parse.urlsplit(canonical_url).path.rsplit("/", 1)[-1]
parsed = urllib.parse.urlsplit(value)
try:
    address = ipaddress.ip_address(parsed.hostname or "")
    port = parsed.port
except ValueError as error:
    raise SystemExit("qualification package transport URL is invalid") from error
allowed_networks = tuple(
    ipaddress.ip_network(value)
    for value in ("10.0.0.0/8", "127.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "::1/128", "fc00::/7")
)
if (
    parsed.scheme != "http"
    or not any(address in network for network in allowed_networks)
    or port is None
    or parsed.username is not None
    or parsed.password is not None
    or parsed.query
    or parsed.fragment
    or parsed.path.rsplit("/", 1)[-1] != expected_filename
    or urllib.parse.urlunsplit(parsed) != value
):
    raise SystemExit(
        "qualification package transport must be canonical private IP-literal HTTP "
        "with an explicit port and the signed archive filename"
    )
print("private_ip_literal_http_override")
PY
)"
[[ "$transport_kind" = signed_canonical_https \
  || "$transport_kind" = private_ip_literal_http_override ]]
if [[ "$transport_kind" = private_ip_literal_http_override ]]; then
  qualification_transport_override_supplied=true
fi
for package_name in cybex-james cybex-james-appliance cybex-james-bootstrap; do
  test -n "$(jq -er --arg package "$package_name" \
    '.appliance_release_v1.required_package_versions[$package]' \
    "$candidate_manifest")"
done

[[ "$predecessor_snapshot" =~ ^[0-9]{8}T[0-9]{6}Z$ ]]
[[ "$candidate_snapshot" =~ ^[0-9]{8}T[0-9]{6}Z$ ]]
[[ "$candidate_snapshot" > "$predecessor_snapshot" ]]
python3 - "$predecessor_release" "$candidate_release" <<'PY'
import re
import sys

pattern = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$"
)

def parse(value):
    match = pattern.fullmatch(value)
    if match is None:
        raise SystemExit("release version is not canonical SemVer")
    prerelease = match.group(4)
    identifiers = [] if prerelease is None else prerelease.split(".")
    return tuple(map(int, match.group(1, 2, 3))), identifiers

def compare(left, right):
    if left[0] != right[0]:
        return (left[0] > right[0]) - (left[0] < right[0])
    a, b = left[1], right[1]
    if not a or not b:
        return (not a) - (not b)
    for x, y in zip(a, b):
        if x == y:
            continue
        if x.isdigit() and y.isdigit():
            return (int(x) > int(y)) - (int(x) < int(y))
        if x.isdigit() != y.isdigit():
            return -1 if x.isdigit() else 1
        return (x > y) - (x < y)
    return (len(a) > len(b)) - (len(a) < len(b))

if compare(parse(sys.argv[2]), parse(sys.argv[1])) <= 0:
    raise SystemExit("candidate release is not newer than installed predecessor")
PY

token="$(tr -d '\r\n' < "$token_file")"
test -n "$token"
work_dir="$(mktemp -d)"
cleanup() { rm -rf -- "$work_dir"; }
trap cleanup EXIT

api() {
  local method="$1" path="$2" body="${3:-}"
  if [[ -n "$body" ]]; then
    curl --fail --silent --show-error --proto '=https' --tlsv1.2 \
      --request "$method" --header "Authorization: Bearer $token" \
      --header 'Content-Type: application/json' --data-binary "$body" \
      "$manage_origin$path"
  else
    curl --fail --silent --show-error --proto '=https' --tlsv1.2 \
      --request "$method" --header "Authorization: Bearer $token" \
      "$manage_origin$path"
  fi
}

probe_candidate_package_transport() {
  local headers="$work_dir/package-transport-headers.txt" protocol observed_sha256
  if [[ "$transport_kind" = signed_canonical_https ]]; then
    protocol='=https'
  else
    protocol='=http'
  fi
  if ! curl --fail --silent --show-error --noproxy '*' --proto "$protocol" \
    --head --dump-header "$headers" --output /dev/null \
    "$qualification_package_transport_url"; then
    return 1
  fi
  if ! python3 - "$headers" "$candidate_package_size" <<'PY'
import sys

path, expected_text = sys.argv[1:]
expected = int(expected_text)
with open(path, "rb") as stream:
    body = stream.read(64 * 1024 + 1)
if len(body) > 64 * 1024:
    raise SystemExit("package transport response headers exceed the qualification bound")
blocks = [block for block in body.replace(b"\r\n", b"\n").split(b"\n\n") if block]
if len(blocks) != 1:
    raise SystemExit("package transport preflight returned an unexpected response chain")
lines = blocks[0].split(b"\n")
if not lines or not lines[0].startswith(b"HTTP/"):
    raise SystemExit("package transport preflight did not return HTTP headers")
content_lengths = [
    line.split(b":", 1)[1].strip()
    for line in lines[1:]
    if line.lower().startswith(b"content-length:")
]
if len(content_lengths) != 1:
    raise SystemExit("package transport preflight requires one Content-Length")
try:
    observed = int(content_lengths[0])
except ValueError as error:
    raise SystemExit("package transport Content-Length is invalid") from error
if observed != expected:
    raise SystemExit("package transport Content-Length does not match signed size")
PY
  then
    return 1
  fi
  if ! observed_sha256="$(
    curl --fail --silent --show-error --noproxy '*' --proto "$protocol" \
      --max-filesize "$candidate_package_size" \
      "$qualification_package_transport_url" \
      | sha256sum | awk '{print $1}'
  )"; then
    return 1
  fi
  if [[ "$observed_sha256" != "$candidate_package_sha256" ]]; then
    echo 'error: package transport bytes do not match the signed candidate SHA-256' >&2
    return 1
  fi
  printf '%s\n' "$candidate_package_size"
}

fetch_runtime() {
  local destination="$1"
  api GET "/v1/james/nodes/$server_device_id/workstation-netboot" > "$destination"
  test "$(jq -er '.server_device_id' "$destination")" = "$server_device_id"
}

runtime_identity() {
  local source="$1" projection="$2"
  jq -ceS --arg projection "$projection" '
    .[$projection]
    | select(type == "object")
    | {
        compatibility_epoch,
        runtime_version,
        bundle_sha256,
        architecture,
        manage_source_revision
      }
    | select(
        (.compatibility_epoch | type == "number" and . > 0)
        and (.runtime_version | type == "string" and length > 0)
        and (.bundle_sha256 | test("^[0-9a-f]{64}$"))
        and (.architecture == "x86_64-linux")
        and (.manage_source_revision | test("^[0-9a-f]{40}$")))' "$source"
}

fetch_node() {
  local destination="$1"
  if ! api GET "/v1/james/nodes/$server_device_id" > "$work_dir/node-detail.json"; then
    return 1
  fi
  jq -e --arg device "$server_device_id" \
    '.node | select(.device_id == $device)' \
    "$work_dir/node-detail.json" > "$destination"
}

# Keep exact-candidate admission behind one seam. This endpoint is permitted
# to override package transport for one signed descriptor and one node only;
# it must never advance the global release or workstation-runtime selection.
request_candidate_update() {
  local body="$1" destination="$2"
  api POST "/v1/james/nodes/$server_device_id/qualification-updates" \
    "$body" > "$destination"
}

canonical_network() {
  jq -cS '
    {
      managed_interface_id:(.appliance_network.managed_interface_id // ""),
      fallback_active:(.network_fallback_active // true),
      interfaces:([
        (.appliance_network.interfaces // [])[]
        | select((.ifname // "") != "lo")
        | {
            ifname:(.ifname // ""),
            mac:((.address // "") | ascii_downcase),
            ipv4:([(.addr_info // [])[]
              | select(.family == "inet" and .scope == "global")
              | {address:.local,prefix_length:.prefixlen}]
              | sort_by(.address,.prefix_length))
          }
      ] | sort_by(.ifname,.mac))
    }' "$1"
}

assert_healthy_node() {
  local node="$1"
  test "$(jq -er '.connectivity_status' "$node")" = connected
  test "$(jq -er '.appliance_base_os' "$node")" = ubuntu
  test "$(jq -er '.appliance_base_os_version' "$node")" = 26.04
  test "$(jq -er '.at_rest_protection' "$node")" = none
  test "$(jq -er '.appliance_boot_mode | ascii_downcase' "$node")" = uefi
  test "$(jq -er '.appliance_secure_boot' "$node")" = true
  test "$(jq -er '.appliance_local_health.status' "$node")" = healthy
  test "$(jq -er '
    .appliance_local_health.checks
    | type == "object" and length > 0
      and all(.[]; . == true)' "$node")" = true
  test "$(jq -er '.network_fallback_active' "$node")" = false
  test "$(jq -er '.appliance_network.network_fallback_active' "$node")" = false
  test "$(jq -er '.cache_status | ascii_downcase' "$node")" = ready
  test -z "$(jq -er '.cache_error // ""' "$node")"
  [[ "$(jq -er '.cache_public_key_fingerprint' "$node")" =~ ^[0-9a-f]{64}$ ]]
  test -n "$(jq -er '.cache_base_url' "$node")"
  test -n "$(jq -er '.james_reported_at' "$node")"
}

before="$work_dir/before.json"
fetch_node "$before"
assert_healthy_node "$before"
transport_content_length="$(probe_candidate_package_transport)"
test "$transport_content_length" = "$candidate_package_size"
test "$(jq -er '.appliance_release' "$before")" = "$predecessor_release"
test "$(jq -er '.ubuntu_snapshot_id' "$before")" = "$predecessor_snapshot"
test "$(jq -er '.root_generation | tostring' "$before")" = 0
test "$(jq -er '.update_supported' "$before")" = true || {
  echo 'error: predecessor does not advertise the protected appliance update contract; qualify the legacy bridge first' >&2
  exit 1
}
test "$(jq -er '.update_active' "$before")" = false
test "$(jq -er '.update_hold' "$before")" = false
test "$(jq -er '.maintenance_hold' "$before")" = false
test "$(jq -er '.appliance_network.network_change.status' "$before")" = acknowledged
api GET "/v1/james/nodes/$server_device_id/qualification-updates" \
  > "$work_dir/qualification-preflight.json"
device_incarnation_id="$(jq -er '.device_incarnation_id' \
  "$work_dir/qualification-preflight.json")"
[[ "$device_incarnation_id" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]
test "$(jq -er '.current_release' "$work_dir/qualification-preflight.json")" = \
  "$predecessor_release"
test "$(jq -er '.ubuntu_snapshot_id' \
  "$work_dir/qualification-preflight.json")" = "$predecessor_snapshot"
test "$(jq -er '.root_generation | tostring' \
  "$work_dir/qualification-preflight.json")" = 0
selected_release_before="$(jq -er '.available_update_version' "$before")"
selected_release_url_before="$(jq -er '.available_update_release_url' "$before")"
test -n "$selected_release_before"
test -n "$selected_release_url_before"
test "$selected_release_before" != "$candidate_release"

# An unpublished appliance candidate must not advance the organization-wide
# workstation runtime watermark. Capture the authenticated published LKG
# before admission and require that exact identity after candidate activation.
fetch_runtime "$work_dir/runtime-before.json"
test "$(jq -er '.state' "$work_dir/runtime-before.json")" = ready
test "$(jq -er '.progress_percent' "$work_dir/runtime-before.json")" = 100
test "$(jq -er '.failure_code == null and .warning_code == null' \
  "$work_dir/runtime-before.json")" = true
test -n "$(jq -er '.last_verified_at' "$work_dir/runtime-before.json")"
test -n "$(jq -er '.last_reported_at' "$work_dir/runtime-before.json")"
runtime_identity "$work_dir/runtime-before.json" active > "$work_dir/runtime-lkg.json"
runtime_identity "$work_dir/runtime-before.json" desired > "$work_dir/runtime-desired-before.json"
cmp --silent -- "$work_dir/runtime-lkg.json" "$work_dir/runtime-desired-before.json"

before_network="$work_dir/before-network.json"
canonical_network "$before" > "$before_network"
test "$(jq -er '.managed_interface_id | length > 0' "$before_network")" = true
test "$(jq -er '
  [.interfaces[] | select(
    (.mac | test("^[0-9a-f]{2}(:[0-9a-f]{2}){5}$"))
    and (.ipv4 | length > 0))] | length > 0' "$before_network")" = true

before_identity="$work_dir/before-identity.json"
jq -cS --argjson network "$(<"$before_network")" '
  {
    device_id,
    hostname,
    public_base_url,
    cache_public_key_fingerprint,
    cache_base_url,
    managed_interface_id:$network.managed_interface_id,
    interface_macs:([$network.interfaces[].mac] | sort)
  }' "$before" > "$before_identity"
test -n "$(jq -er '.hostname' "$before_identity")"
test -n "$(jq -er '.public_base_url' "$before_identity")"

observations="$work_dir/update-observations.jsonl"
last_observation_key=""
record_observation() {
  local node="$1" source="$2" observation key
  observation="$(jq -c \
    --arg observed_at "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
    --arg source "$source" \
    '{observed_at:$observed_at,source:$source,
      update_status,update_stage,update_progress_percent,
      update_attempt_id,update_target_version,update_current_version,
      root_generation,connectivity_status,
      package_status:(.appliance_package_update.status // "idle"),
      package_stage:(.appliance_package_update.stage // "idle")}' "$node")"
  key="$(jq -r '[.update_status,.update_stage,(.update_progress_percent|tostring),
    .root_generation,.connectivity_status,.package_status,.package_stage] | join("|")' \
    <<<"$observation")"
  if [[ "$key" != "$last_observation_key" ]]; then
    printf '%s\n' "$observation" >> "$observations"
    last_observation_key="$key"
  fi
}

request_id="$(tr 'A-F' 'a-f' < /proc/sys/kernel/random/uuid)"
[[ "$request_id" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]
expires_at="$(date -u -d "+$qualification_ttl_seconds seconds" +'%Y-%m-%dT%H:%M:%SZ')"
candidate_manifest_sha256="$(sha256sum "$candidate_manifest" | awk '{print $1}')"
candidate_manifest_json_b64="$(base64 --wrap=0 "$candidate_manifest")"
qualification_package_transport_url_sha256="$(
  printf '%s' "$qualification_package_transport_url" | sha256sum | awk '{print $1}'
)"
request="$(jq -cn \
  --arg request_id "$request_id" \
  --arg expires_at "$expires_at" \
  --arg device_incarnation_id "$device_incarnation_id" \
  --arg current_release "$predecessor_release" \
  --arg ubuntu_snapshot_id "$predecessor_snapshot" \
  --arg root_generation '0' \
  --arg release_manifest_json_b64 "$candidate_manifest_json_b64" \
  --arg release_manifest_sha256 "$candidate_manifest_sha256" \
  --arg package_transport_url "$qualification_package_transport_url" \
  --argjson qualification_transport_override_supplied \
    "$qualification_transport_override_supplied" \
  '{request_id:$request_id,expires_at:$expires_at,
    expected:{device_incarnation_id:$device_incarnation_id,
      current_release:$current_release,ubuntu_snapshot_id:$ubuntu_snapshot_id,
      root_generation:$root_generation},
    candidate:({release_manifest_json_b64:$release_manifest_json_b64,
      release_manifest_sha256:$release_manifest_sha256}
      + (if $qualification_transport_override_supplied
         then {package_transport_url:$package_transport_url}
         else {} end))}')"
request_candidate_update "$request" "$work_dir/admission.json"
attempt_id="$(jq -er '.attempt_id' "$work_dir/admission.json")"
[[ "$attempt_id" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]
test "$(jq -er '.request_id' "$work_dir/admission.json")" = "$request_id"
test "$(jq -er '.release_version' "$work_dir/admission.json")" = "$candidate_release"
test "$(jq -er '.manifest_sha256' "$work_dir/admission.json")" = "$candidate_manifest_sha256"
test "$(jq -er '.package_snapshot_sha256' "$work_dir/admission.json")" = "$candidate_package_sha256"
test "$(jq -er '.package_transport_url_sha256' "$work_dir/admission.json")" = \
  "$qualification_package_transport_url_sha256"
test "$(jq -er '.expires_at' "$work_dir/admission.json")" = "$expires_at"
jq -e '.node' "$work_dir/admission.json" > "$work_dir/requested.json"
test "$(jq -er '.device_id' "$work_dir/requested.json")" = "$server_device_id"
test "$(jq -er '.update_status' "$work_dir/requested.json")" = requested
test "$(jq -er '.update_stage' "$work_dir/requested.json")" = queued
test "$(jq -er '.update_progress_percent' "$work_dir/requested.json")" = 0
test "$(jq -er '.update_target_version' "$work_dir/requested.json")" = "$candidate_release"
test "$(jq -er '.update_current_version' "$work_dir/requested.json")" = "$predecessor_release"
test "$(jq -er '.desired_update_version' "$work_dir/requested.json")" = "$candidate_release"
requested_at="$(jq -er '.desired_update_requested_at' "$work_dir/requested.json")"
record_observation "$work_dir/requested.json" admission

succeeded=false
api_unavailable_observed=false
consecutive_api_failures=0
restarting_stage_observed=false
intermediate_state_observed=false
for ((_poll = 1; _poll <= maximum_polls; _poll++)); do
  if ! fetch_node "$work_dir/node.json"; then
    api_unavailable_observed=true
    consecutive_api_failures=$((consecutive_api_failures + 1))
    if ((consecutive_api_failures > 12)); then
      echo 'error: Manage API remained unavailable during appliance update qualification' >&2
      exit 1
    fi
    sleep "$poll_seconds"
    continue
  fi
  consecutive_api_failures=0
  test "$(jq -er '.device_id' "$work_dir/node.json")" = "$server_device_id"
  test "$(jq -er '.update_attempt_id' "$work_dir/node.json")" = "$attempt_id"
  test "$(jq -er '.update_target_version' "$work_dir/node.json")" = "$candidate_release"
  current_projection="$(jq -er '.update_current_version' "$work_dir/node.json")"
  [[ "$current_projection" = "$predecessor_release" || "$current_projection" = "$candidate_release" ]]
  status="$(jq -er '.update_status' "$work_dir/node.json")"
  stage="$(jq -er '.update_stage' "$work_dir/node.json")"
  record_observation "$work_dir/node.json" poll
  case "$status" in
    requested|waiting)
      ;;
    preflight|applying|restarting|health_checking)
      intermediate_state_observed=true
      [[ "$status" != restarting ]] || restarting_stage_observed=true
      ;;
    succeeded)
      succeeded=true
      break
      ;;
    failed|rolled_back|unsupported)
      jq '{update_status,update_stage,update_error,update_attempt_id,
        appliance_release,ubuntu_snapshot_id,root_generation,
        appliance_package_update,appliance_local_health}' \
        "$work_dir/node.json" >&2
      exit 1
      ;;
    *)
      echo "error: unexpected appliance update state: $status/$stage" >&2
      exit 1
      ;;
  esac
  sleep "$poll_seconds"
done
test "$succeeded" = true
test "$intermediate_state_observed" = true

final="$work_dir/node.json"
assert_healthy_node "$final"
test "$(jq -er '.appliance_release' "$final")" = "$candidate_release"
test "$(jq -er '.ubuntu_snapshot_id' "$final")" = "$candidate_snapshot"
test "$(jq -er '.reported_version' "$final")" = "$candidate_release"
test "$(jq -er '.root_generation | tostring' "$final")" = 1
test "$(jq -er '.update_current_version' "$final")" = "$candidate_release"
test "$(jq -er '.update_status' "$final")" = succeeded
test "$(jq -er '.update_stage' "$final")" = committed
test "$(jq -er '.update_progress_percent' "$final")" = 100
test "$(jq -er '.update_active' "$final")" = false
test -z "$(jq -er '.update_error // ""' "$final")"
test -z "$(jq -er '.desired_update_version // ""' "$final")"
test "$(jq -er '.appliance_package_update.status' "$final")" = succeeded
test "$(jq -er '.appliance_package_update.stage' "$final")" = committed
test "$(jq -er '.appliance_package_update.progress_percent' "$final")" = 100
test "$(jq -er '.appliance_package_update.attempt_id' "$final")" = "$attempt_id"
test "$(jq -er '.appliance_package_update.target_release' "$final")" = "$candidate_release"
test "$(jq -er '.appliance_package_update.candidate_root_generation' "$final")" = 1
test "$(jq -er '.appliance_package_update.resulting_root_generation' "$final")" = 1
test -z "$(jq -er '.appliance_package_update.rollback_reason // ""' "$final")"
committed_candidate_receipt_observed="$(jq -er --arg attempt_id "$attempt_id" \
  --arg candidate_release "$candidate_release" '
    (.root_generation == "1")
    and (.appliance_package_update.status == "succeeded")
    and (.appliance_package_update.stage == "committed")
    and (.appliance_package_update.attempt_id == $attempt_id)
    and (.appliance_package_update.target_release == $candidate_release)
    and (.appliance_package_update.resulting_root_generation == "1")' "$final")"
test "$committed_candidate_receipt_observed" = true

final_network="$work_dir/final-network.json"
canonical_network "$final" > "$final_network"
cmp --silent -- "$before_network" "$final_network"
final_identity="$work_dir/final-identity.json"
jq -cS --argjson network "$(<"$final_network")" '
  {
    device_id,
    hostname,
    public_base_url,
    cache_public_key_fingerprint,
    cache_base_url,
    managed_interface_id:$network.managed_interface_id,
    interface_macs:([$network.interfaces[].mac] | sort)
  }' "$final" > "$final_identity"
cmp --silent -- "$before_identity" "$final_identity"
test "$(jq -er '.appliance_network.network_change.status' "$final")" = acknowledged
test "$(jq -er '.available_update_version' "$final")" = "$selected_release_before"
test "$(jq -er '.available_update_release_url' "$final")" = "$selected_release_url_before"
api GET "/v1/james/nodes/$server_device_id/qualification-updates" \
  > "$work_dir/qualification-postflight.json"
test "$(jq -er '.device_incarnation_id' \
  "$work_dir/qualification-postflight.json")" = "$device_incarnation_id"
test "$(jq -er '.current_release' "$work_dir/qualification-postflight.json")" = \
  "$candidate_release"
test "$(jq -er '.ubuntu_snapshot_id' \
  "$work_dir/qualification-postflight.json")" = "$candidate_snapshot"
test "$(jq -er '.root_generation | tostring' \
  "$work_dir/qualification-postflight.json")" = 1

before_reported_at="$(jq -er '.james_reported_at' "$before")"
final_reported_at="$(jq -er '.james_reported_at' "$final")"
[[ "$final_reported_at" > "$before_reported_at" ]]
started_at="$(jq -er '.update_started_at' "$final")"
completed_at="$(jq -er '.update_completed_at' "$final")"
python3 - "$requested_at" "$started_at" "$completed_at" <<'PY'
from datetime import datetime
import sys

def parse(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))

requested, started, completed = map(parse, sys.argv[1:])
if not requested <= started <= completed:
    raise SystemExit("update attempt timestamps are not chronological")
PY

stage_history="$work_dir/stage-history.json"
jq -s '.' "$observations" > "$stage_history"
python3 - "$stage_history" "$attempt_id" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    history = json.load(stream)
if not history or history[0]["update_status"] != "requested":
    raise SystemExit("update history does not begin with admission")
if history[-1]["update_status"] != "succeeded":
    raise SystemExit("update history does not end in success")
if any(item["update_attempt_id"] != sys.argv[2] for item in history):
    raise SystemExit("update history crossed attempt identities")
if any(item["update_status"] in {"failed", "rolled_back", "unsupported"} for item in history):
    raise SystemExit("update history contains a terminal failure")
PY

runtime_lkg_preserved=false
runtime_api_unavailable_observed=false
for ((_poll = 1; _poll <= maximum_polls; _poll++)); do
  if ! fetch_runtime "$work_dir/runtime.json"; then
    runtime_api_unavailable_observed=true
    sleep "$poll_seconds"
    continue
  fi
  runtime_state="$(jq -er '.state' "$work_dir/runtime.json")"
  if [[ "$runtime_state" = failed ]]; then
    jq '{state,failure_code,failure_kind,failure_message,desired,active}' \
      "$work_dir/runtime.json" >&2
    exit 1
  fi
  if [[ "$runtime_state" = ready ]]; then
    if runtime_identity "$work_dir/runtime.json" active > "$work_dir/runtime-active-after.json" \
      && cmp --silent -- "$work_dir/runtime-lkg.json" "$work_dir/runtime-active-after.json"; then
      runtime_lkg_preserved=true
      break
    fi
  fi
  sleep "$poll_seconds"
done
test "$runtime_lkg_preserved" = true
test -n "$(jq -er '.last_verified_at' "$work_dir/runtime.json")"
test -n "$(jq -er '.last_reported_at' "$work_dir/runtime.json")"
test "$(jq -er '.progress_percent' "$work_dir/runtime.json")" = 100
test "$(jq -er '.failure_code == null and .warning_code == null' "$work_dir/runtime.json")" = true

predecessor_evidence_sha256="$(sha256sum "$predecessor_evidence" | awk '{print $1}')"
candidate_manifest_sha256="$(sha256sum "$candidate_manifest" | awk '{print $1}')"
before_identity_sha256="$(sha256sum "$before_identity" | awk '{print $1}')"
final_identity_sha256="$(sha256sum "$final_identity" | awk '{print $1}')"
network_projection_sha256="$(sha256sum "$final_network" | awk '{print $1}')"
runtime_lkg_sha256="$(sha256sum "$work_dir/runtime-lkg.json" | awk '{print $1}')"
before_uptime="$(jq -er '.host_uptime_seconds' "$before")"
final_uptime="$(jq -er '.host_uptime_seconds' "$final")"
host_uptime_reset_observed=false
if [[ "$before_uptime" =~ ^[0-9]+$ && "$final_uptime" =~ ^[0-9]+$ ]] \
  && ((final_uptime < before_uptime)); then
  host_uptime_reset_observed=true
fi
test "$host_uptime_reset_observed" = true
reboot_observed=false
if [[ "$committed_candidate_receipt_observed" = true \
  && "$host_uptime_reset_observed" = true ]]; then
  reboot_observed=true
fi
test "$reboot_observed" = true

output_parent="$(dirname -- "$output")"
test -d "$output_parent"
test ! -L "$output_parent"
temporary_output="$(mktemp "$output_parent/.update-qualification.XXXXXX")"
jq -n \
  --arg schema 'cybex.james.ubuntu-appliance-update-qualification.v1' \
  --arg candidate_delivery_precondition 'isolated_exact_signed_appliance_candidate_without_global_selection' \
  --arg server_device_id "$server_device_id" \
  --arg predecessor_release "$predecessor_release" \
  --arg candidate_release "$candidate_release" \
  --arg predecessor_snapshot "$predecessor_snapshot" \
  --arg candidate_snapshot "$candidate_snapshot" \
  --arg candidate_release_url "$candidate_release_url" \
  --arg predecessor_evidence_sha256 "$predecessor_evidence_sha256" \
  --arg candidate_manifest_sha256 "$candidate_manifest_sha256" \
  --arg candidate_package_sha256 "$candidate_package_sha256" \
  --arg candidate_package_url "$candidate_package_url" \
  --arg transport_kind "$transport_kind" \
  --argjson qualification_transport_override_supplied "$qualification_transport_override_supplied" \
  --arg qualification_package_transport_url_sha256 "$qualification_package_transport_url_sha256" \
  --arg candidate_runtime_version "$candidate_runtime_version" \
  --arg candidate_runtime_sha256 "$candidate_runtime_sha256" \
  --arg candidate_manage_revision "$candidate_manage_revision" \
  --arg selected_release "$selected_release_before" \
  --arg selected_release_url "$selected_release_url_before" \
  --argjson runtime_lkg "$(<"$work_dir/runtime-lkg.json")" \
  --arg runtime_lkg_sha256 "$runtime_lkg_sha256" \
  --arg attempt_id "$attempt_id" \
  --arg request_id "$request_id" \
  --arg qualification_expires_at "$expires_at" \
  --arg device_incarnation_id "$device_incarnation_id" \
  --arg requested_at "$requested_at" \
  --arg started_at "$started_at" \
  --arg completed_at "$completed_at" \
  --arg before_identity_sha256 "$before_identity_sha256" \
  --arg final_identity_sha256 "$final_identity_sha256" \
  --arg network_projection_sha256 "$network_projection_sha256" \
  --arg completed_evidence_at "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
  --argjson candidate_package_size "$candidate_package_size" \
  --argjson stage_history "$(<"$stage_history")" \
  --argjson api_unavailable_observed "$api_unavailable_observed" \
  --argjson runtime_api_unavailable_observed "$runtime_api_unavailable_observed" \
  --argjson restarting_stage_observed "$restarting_stage_observed" \
  --argjson host_uptime_reset_observed "$host_uptime_reset_observed" \
  --argjson reboot_observed "$reboot_observed" \
  '{schema:$schema,ok:true,
    candidate_delivery_precondition:$candidate_delivery_precondition,
    server_device_id:$server_device_id,
    predecessor_release:$predecessor_release,
    candidate_release:$candidate_release,
    predecessor_ubuntu_snapshot_id:$predecessor_snapshot,
    candidate_ubuntu_snapshot_id:$candidate_snapshot,
    predecessor_evidence_sha256:$predecessor_evidence_sha256,
    candidate_manifest_sha256:$candidate_manifest_sha256,
    candidate_release_url:$candidate_release_url,
    candidate_package_snapshot:{url:$candidate_package_url,
      sha256:$candidate_package_sha256,size_bytes:$candidate_package_size},
    candidate_binding:{isolated_appliance_candidate_admitted:true,
      global_release_selection_unchanged:true,
      signed_appliance_tuple_observed:true,
      terminal_package_receipt_bound_to_attempt:true,
      request_id:$request_id,expires_at:$qualification_expires_at,
      package_transport:{kind:$transport_kind,
        override_supplied:$qualification_transport_override_supplied,
        url_sha256:$qualification_package_transport_url_sha256,
        content_length:$candidate_package_size,
        availability_checked_before_admission:true,
        signed_sha256_verified_before_admission:true,
        signed_sha256_verified_by_terminal_james_receipt:true}},
    candidate_runtime_deferred_until_publication:{runtime_version:$candidate_runtime_version,
      bundle_sha256:$candidate_runtime_sha256,
      manage_source_revision:$candidate_manage_revision,
      not_selected:true,not_projected:true},
    published_lkg_runtime_preserved:{identity:$runtime_lkg,
      identity_sha256:$runtime_lkg_sha256,active_exact_before_and_after:true},
    global_release_selection:{version:$selected_release,
      release_url:$selected_release_url,unchanged:true},
    attempt:{id:$attempt_id,requested_at:$requested_at,started_at:$started_at,
      completed_at:$completed_at,stage_history:$stage_history,
      api_unavailable_observed:$api_unavailable_observed},
    resulting_root_generation:"1",generation_transition:{source:"0",target:"1",
      exact_successor:true,committed_candidate_receipt:true},
    identity_continuity:{same_managed_node:true,
      device_incarnation_id:$device_incarnation_id,
      exact_device_incarnation_preserved:true,
      before_sha256:$before_identity_sha256,after_sha256:$final_identity_sha256,
      exact_public_projection:true},
    network_continuity:{static_ipv4_projection_preserved:true,
      projection_sha256:$network_projection_sha256,fallback_active:false,
      acknowledgement_preserved:true},
    cache_continuity:{ready_before_and_after:true,key_identity_preserved:true,
      base_url_preserved:true,error_free:true},
    reboot_evidence:{root_generation_transition:true,
      committed_candidate_receipt:true,
      restarting_stage_observed:$restarting_stage_observed,
      host_uptime_reset_observed:$host_uptime_reset_observed},
    runtime_api_unavailable_observed:$runtime_api_unavailable_observed,
    real_update:true,reboot_observed:$reboot_observed,release_activated:true,
    candidate_runtime_activated:false,published_lkg_runtime_continuity:true,
    appliance_projection_healthy:true,secure_boot:true,final_state:"ready",
    claims_not_made:["cache_poison_recovery_injected","manage_restart_injected",
      "james_service_restart_injected"],
    completed_at:$completed_evidence_at}' > "$temporary_output"
chmod 0644 "$temporary_output"
mv -f -- "$temporary_output" "$output"
