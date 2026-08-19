import json
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
HARNESS = (
    REPOSITORY_ROOT
    / "ubuntu-appliance"
    / "qualification"
    / "run-update-lifecycle.sh"
)

DEVICE_ID = "james_contract_test"
PREDECESSOR_RELEASE = "0.2.1-dev.11"
CANDIDATE_RELEASE = "0.2.1-dev.13"
PREDECESSOR_SNAPSHOT = "20260805T000000Z"
CANDIDATE_SNAPSHOT = "20260812T000000Z"
RELEASE_URL = "https://manage.example/james"
PUBLISHED_RELEASE = "0.2.1-dev.12"
PACKAGE_BYTES = b"exact signed candidate package bytes\n"
PACKAGE_SHA256 = hashlib.sha256(PACKAGE_BYTES).hexdigest()
PACKAGE_SIZE = len(PACKAGE_BYTES)
RUNTIME_SHA256 = "b" * 64
MANAGE_REVISION = "c" * 40
ATTEMPT_ID = "11111111-2222-4333-8444-555555555555"
CACHE_FINGERPRINT = "d" * 64
DEVICE_INCARNATION_ID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
PACKAGE_TRANSPORT_URL = (
    "http://10.0.2.2:18080/"
    f"cybex-james-appliance-packages-{CANDIDATE_RELEASE}-x86_64-linux.tar.zst"
)


def candidate_manifest():
    return {
        "schema": "cybex.james.release.v1",
        "version": CANDIDATE_RELEASE,
        "release_url": RELEASE_URL,
        "installer_iso_template_v2": {
            "manage_origin": "https://manage.example",
        },
        "appliance_release_v1": {
            "schema": "cybex.james.appliance-release.v1",
            "release_id": CANDIDATE_RELEASE,
            "ubuntu_snapshot_id": CANDIDATE_SNAPSHOT,
            "cybex_repository_snapshot": {
                "url": (
                    "https://manage.example/artifacts/"
                    f"cybex-james-appliance-packages-{CANDIDATE_RELEASE}-"
                    "x86_64-linux.tar.zst"
                ),
                "sha256": PACKAGE_SHA256,
                "size_bytes": PACKAGE_SIZE,
            },
            "required_package_versions": {
                "cybex-james": f"{CANDIDATE_RELEASE}-1",
                "cybex-james-appliance": f"{CANDIDATE_RELEASE}-1",
                "cybex-james-bootstrap": f"{CANDIDATE_RELEASE}-1",
            },
            "minimum_protocol": 4,
            "minimum_state_schema": 2,
            "rollback_compatible": True,
        },
        "workstation_netboot": {
            "schema": "cybex.james.workstation-netboot.v1",
            "runtime_version": "1.0.18",
            "sha256": RUNTIME_SHA256,
            "manage_source_revision": MANAGE_REVISION,
            "architecture": "x86_64-linux",
        },
    }


def predecessor_evidence():
    return {
        "schema": "cybex.james.ubuntu-appliance-qualification.v1",
        "ok": True,
        "final_state": "ready",
        "secure_boot": True,
        "appliance_projection_healthy": True,
        "two_phase_network_acknowledged": True,
        "root_generation": "0",
        "release_version": PREDECESSOR_RELEASE,
        "ubuntu_snapshot_id": PREDECESSOR_SNAPSHOT,
    }


def node(state):
    candidate = state == "succeeded"
    update_started_at = None if state in {"idle", "requested"} else "2026-08-12T10:01:00Z"
    update_completed_at = "2026-08-12T10:03:00Z" if candidate else None
    status = {
        "idle": ("idle", "idle", None),
        "requested": ("requested", "queued", 0),
        "applying": ("applying", "packages", 60),
        "succeeded": ("succeeded", "committed", 100),
    }[state]
    package_update = {"status": "idle"}
    if state == "applying":
        package_update = {
            "status": "applying",
            "stage": "packages",
            "progress_percent": 60,
            "attempt_id": ATTEMPT_ID,
            "target_release": CANDIDATE_RELEASE,
            "candidate_root_generation": "1",
            "resulting_root_generation": "",
            "rollback_reason": "",
        }
    elif state == "succeeded":
        package_update = {
            "status": "succeeded",
            "stage": "committed",
            "progress_percent": 100,
            "attempt_id": ATTEMPT_ID,
            "target_release": CANDIDATE_RELEASE,
            "candidate_root_generation": "1",
            "resulting_root_generation": "1",
            "rollback_reason": "",
        }
    return {
        "device_id": DEVICE_ID,
        "hostname": "james-test",
        "public_base_url": "http://192.0.2.10:8080",
        "connectivity_status": "connected",
        "reported_version": CANDIDATE_RELEASE if candidate else PREDECESSOR_RELEASE,
        "james_reported_at": (
            "2026-08-12T10:03:01Z" if candidate else "2026-08-12T10:00:00Z"
        ),
        "host_uptime_seconds": 90 if candidate else 7200,
        "appliance_base_os": "ubuntu",
        "appliance_base_os_version": "26.04",
        "at_rest_protection": "none",
        "appliance_boot_mode": "uefi",
        "appliance_secure_boot": True,
        "appliance_local_health": {
            "status": "healthy",
            "checks": {"nginx": True, "nix-daemon": True, "tftpd-hpa": True},
        },
        "appliance_release": CANDIDATE_RELEASE if candidate else PREDECESSOR_RELEASE,
        "ubuntu_snapshot_id": CANDIDATE_SNAPSHOT if candidate else PREDECESSOR_SNAPSHOT,
        "root_generation": "1" if candidate else "0",
        "appliance_network": {
            "managed_interface_id": "pci-0000:00:03.0",
            "network_fallback_active": False,
            "network_change": {"status": "acknowledged"},
            "interfaces": [
                {
                    "ifname": "ens3",
                    "address": "52:54:00:12:34:56",
                    "addr_info": [
                        {
                            "family": "inet",
                            "local": "192.0.2.10",
                            "prefixlen": 24,
                            "scope": "global",
                            "valid_life_time": 999,
                        }
                    ],
                }
            ],
        },
        "network_fallback_active": False,
        "cache_status": "ready",
        "cache_public_key_fingerprint": CACHE_FINGERPRINT,
        "cache_base_url": "http://192.0.2.10:8080/cache",
        "cache_error": "",
        "update_supported": True,
        "update_active": state in {"requested", "applying"},
        "update_hold": False,
        "maintenance_hold": False,
        "update_available": not candidate,
        "available_update_version": PUBLISHED_RELEASE,
        "available_update_release_url": RELEASE_URL,
        "desired_update_version": (
            CANDIDATE_RELEASE if state in {"requested", "applying"} else ""
        ),
        "desired_update_requested_at": (
            "2026-08-12T10:00:30Z"
            if state in {"requested", "applying"}
            else None
        ),
        "update_status": status[0],
        "update_stage": status[1],
        "update_progress_percent": status[2],
        "update_error": "",
        "update_target_version": "" if state == "idle" else CANDIDATE_RELEASE,
        "update_current_version": (
            CANDIDATE_RELEASE
            if candidate
            else ("" if state == "idle" else PREDECESSOR_RELEASE)
        ),
        "update_attempt_id": "" if state == "idle" else ATTEMPT_ID,
        "update_started_at": update_started_at,
        "update_completed_at": update_completed_at,
        "appliance_package_update": package_update,
    }


def runtime_status():
    identity = {
        "compatibility_epoch": 1,
        "runtime_version": "1.0.17",
        "bundle_sha256": "e" * 64,
        "manage_source_revision": "f" * 40,
        "architecture": "x86_64-linux",
    }
    return {
        "server_device_id": DEVICE_ID,
        "state": "ready",
        "progress_percent": 100,
        "desired": identity,
        "active": identity,
        "failure_code": None,
        "warning_code": None,
        "last_verified_at": "2026-08-12T10:03:02Z",
        "last_reported_at": "2026-08-12T10:03:02Z",
    }


class UpdateLifecycleContractTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self._write_json("predecessor.json", predecessor_evidence())
        self._write_json("candidate.json", candidate_manifest())
        self._write_json("before.json", {"node": node("idle")})
        self._write_json("requested.json", node("requested"))
        self._write_json("applying.json", {"node": node("applying")})
        self._write_json("final.json", {"node": node("succeeded")})
        self._write_json("runtime.json", runtime_status())
        (self.root / "package.bin").write_bytes(PACKAGE_BYTES)
        (self.root / "token").write_text("test-token\n", encoding="utf-8")
        self.curl_log = self.root / "curl.log"
        self.request_body = self.root / "request-body.json"
        self.node_counter = self.root / "node-counter"
        self.package_content_length = PACKAGE_SIZE
        self.preflight_snapshot = PREDECESSOR_SNAPSHOT
        self.postflight_snapshot = CANDIDATE_SNAPSHOT
        mock_curl = self.bin / "curl"
        mock_curl.write_text(
            """#!/usr/bin/env bash
set -Eeuo pipefail
method=GET
url=""
body=""
head_request=false
headers=""
while (($#)); do
  case "$1" in
    --request) method="$2"; shift 2 ;;
    --data-binary) body="$2"; shift 2 ;;
    --header|--proto|--output|--max-filesize|--noproxy) shift 2 ;;
    --dump-header) headers="$2"; shift 2 ;;
    --head) head_request=true; shift ;;
    --fail|--silent|--show-error|--tlsv1.2) shift ;;
    *) url="$1"; shift ;;
  esac
done
printf '%s %s\\n' "$method" "$url" >> "$MOCK_CURL_LOG"
if [[ "$head_request" = true ]]; then
  printf 'HTTP/1.1 200 OK\\r\\nContent-Length: %s\\r\\n\\r\\n' \
    "$MOCK_PACKAGE_CONTENT_LENGTH" > "$headers"
  exit 0
fi
if [[ "$url" = "$MOCK_PACKAGE_URL" ]]; then
  exec cat "$MOCK_PACKAGE_BODY"
fi
case "$method:$url" in
  POST:*/v1/james/nodes/*/qualification-updates)
    printf '%s' "$body" > "$MOCK_REQUEST_BODY"
    jq -cn \
      --arg attempt_id "$MOCK_ATTEMPT_ID" \
      --arg request_id "$(jq -er '.request_id' <<<"$body")" \
      --arg release_version "$MOCK_CANDIDATE_RELEASE" \
      --arg manifest_sha256 "$MOCK_MANIFEST_SHA256" \
      --arg package_snapshot_sha256 "$MOCK_PACKAGE_SHA256" \
      --arg package_transport_url_sha256 "$MOCK_TRANSPORT_SHA256" \
      --arg expires_at "$(jq -er '.expires_at' <<<"$body")" \
      --argjson node "$(cat "$MOCK_REQUESTED")" \
      '{attempt_id:$attempt_id,request_id:$request_id,
        release_version:$release_version,manifest_sha256:$manifest_sha256,
        package_snapshot_sha256:$package_snapshot_sha256,
        package_transport_url_sha256:$package_transport_url_sha256,
        expires_at:$expires_at,node:$node}'
    ;;
  GET:*/workstation-netboot)
    exec cat "$MOCK_RUNTIME"
    ;;
  GET:*/v1/james/nodes/*/qualification-updates)
    count=0
    [[ ! -f "$MOCK_NODE_COUNTER" ]] || read -r count < "$MOCK_NODE_COUNTER"
    if ((count >= 3)); then
      current_release="$MOCK_CANDIDATE_RELEASE"
      ubuntu_snapshot_id_json="$MOCK_POSTFLIGHT_SNAPSHOT_JSON"
      root_generation=1
    else
      current_release="$MOCK_PREDECESSOR_RELEASE"
      ubuntu_snapshot_id_json="$MOCK_PREFLIGHT_SNAPSHOT_JSON"
      root_generation=0
    fi
    jq -cn --arg device_incarnation_id "$MOCK_DEVICE_INCARNATION_ID" \
      --arg current_release "$current_release" \
      --argjson ubuntu_snapshot_id "$ubuntu_snapshot_id_json" \
      --arg root_generation "$root_generation" \
      '({device_incarnation_id:$device_incarnation_id,
        current_release:$current_release,root_generation:$root_generation}
        + (if $ubuntu_snapshot_id == null then {}
           else {ubuntu_snapshot_id:$ubuntu_snapshot_id} end))'
    ;;
  GET:*/v1/james/nodes/*)
    count=0
    [[ ! -f "$MOCK_NODE_COUNTER" ]] || read -r count < "$MOCK_NODE_COUNTER"
    count=$((count + 1))
    printf '%s\\n' "$count" > "$MOCK_NODE_COUNTER"
    if ((count == 1)); then
      exec cat "$MOCK_BEFORE"
    elif ((count == 2)); then
      exec cat "$MOCK_APPLYING"
    else
      exec cat "$MOCK_FINAL"
    fi
    ;;
  *)
    echo "unexpected mock request: $method $url" >&2
    exit 22
    ;;
esac
""",
            encoding="utf-8",
        )
        mock_curl.chmod(0o755)

    def tearDown(self):
        self.temporary.cleanup()

    def _write_json(self, name, value):
        (self.root / name).write_text(
            json.dumps(value, sort_keys=True), encoding="utf-8"
        )

    def _run(self, transport_url=PACKAGE_TRANSPORT_URL):
        environment = os.environ.copy()
        effective_transport_url = transport_url
        if effective_transport_url is None:
            effective_transport_url = candidate_manifest()["appliance_release_v1"][
                "cybex_repository_snapshot"
            ]["url"]
        manifest_sha256 = hashlib.sha256(
            (self.root / "candidate.json").read_bytes()
        ).hexdigest()
        transport_sha256 = hashlib.sha256(effective_transport_url.encode()).hexdigest()
        environment.update(
            {
                "PATH": f"{self.bin}:{environment['PATH']}",
                "CYBEX_UPDATE_QUALIFICATION_POLL_SECONDS": "0",
                "CYBEX_UPDATE_QUALIFICATION_MAX_POLLS": "5",
                "MOCK_CURL_LOG": str(self.curl_log),
                "MOCK_REQUEST_BODY": str(self.request_body),
                "MOCK_NODE_COUNTER": str(self.node_counter),
                "MOCK_BEFORE": str(self.root / "before.json"),
                "MOCK_REQUESTED": str(self.root / "requested.json"),
                "MOCK_APPLYING": str(self.root / "applying.json"),
                "MOCK_FINAL": str(self.root / "final.json"),
                "MOCK_RUNTIME": str(self.root / "runtime.json"),
                "MOCK_ATTEMPT_ID": ATTEMPT_ID,
                "MOCK_CANDIDATE_RELEASE": CANDIDATE_RELEASE,
                "MOCK_MANIFEST_SHA256": manifest_sha256,
                "MOCK_PACKAGE_SHA256": PACKAGE_SHA256,
                "MOCK_TRANSPORT_SHA256": transport_sha256,
                "MOCK_DEVICE_INCARNATION_ID": DEVICE_INCARNATION_ID,
                "MOCK_PREDECESSOR_RELEASE": PREDECESSOR_RELEASE,
                "MOCK_PREFLIGHT_SNAPSHOT_JSON": json.dumps(
                    self.preflight_snapshot
                ),
                "MOCK_POSTFLIGHT_SNAPSHOT_JSON": json.dumps(
                    self.postflight_snapshot
                ),
                "MOCK_PACKAGE_URL": effective_transport_url,
                "MOCK_PACKAGE_BODY": str(self.root / "package.bin"),
                "MOCK_PACKAGE_CONTENT_LENGTH": str(self.package_content_length),
            }
        )
        arguments = [
                str(HARNESS),
                "--predecessor-evidence",
                str(self.root / "predecessor.json"),
                "--candidate-manifest",
                str(self.root / "candidate.json"),
                "--manage-origin",
                "https://manage.example",
                "--token-file",
                str(self.root / "token"),
                "--server-device-id",
                DEVICE_ID,
                "--output",
                str(self.root / "evidence.json"),
            ]
        if transport_url is not None:
            arguments[5:5] = [
                "--qualification-package-transport-url",
                transport_url,
            ]
        return subprocess.run(
            arguments,
            cwd=REPOSITORY_ROOT,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def test_exact_successor_emits_only_observed_evidence(self):
        result = self._run()
        self.assertEqual(result.returncode, 0, result.stderr)
        evidence = json.loads((self.root / "evidence.json").read_text())
        self.assertTrue(evidence["ok"])
        self.assertEqual(
            evidence["candidate_delivery_precondition"],
            "isolated_exact_signed_appliance_candidate_without_global_selection",
        )
        self.assertEqual(
            evidence["candidate_package_snapshot"]["sha256"], PACKAGE_SHA256
        )
        self.assertEqual(
            evidence["candidate_runtime_deferred_until_publication"]["bundle_sha256"],
            RUNTIME_SHA256,
        )
        self.assertTrue(
            evidence["candidate_runtime_deferred_until_publication"]["not_projected"]
        )
        self.assertEqual(
            evidence["published_lkg_runtime_preserved"]["identity"]["runtime_version"],
            "1.0.17",
        )
        self.assertEqual(evidence["attempt"]["id"], ATTEMPT_ID)
        self.assertEqual(
            evidence["identity_continuity"]["device_incarnation_id"],
            DEVICE_INCARNATION_ID,
        )
        self.assertEqual(
            [entry["update_status"] for entry in evidence["attempt"]["stage_history"]],
            ["requested", "applying", "succeeded"],
        )
        self.assertTrue(evidence["reboot_evidence"]["root_generation_transition"])
        self.assertTrue(evidence["reboot_evidence"]["committed_candidate_receipt"])
        self.assertTrue(evidence["reboot_evidence"]["host_uptime_reset_observed"])
        self.assertFalse(evidence["reboot_evidence"]["restarting_stage_observed"])
        self.assertIn("cache_poison_recovery_injected", evidence["claims_not_made"])
        request = json.loads(self.request_body.read_text(encoding="utf-8"))
        self.assertEqual(
            request["expected"],
            {
                "device_incarnation_id": DEVICE_INCARNATION_ID,
                "current_release": PREDECESSOR_RELEASE,
                "ubuntu_snapshot_id": PREDECESSOR_SNAPSHOT,
                "root_generation": "0",
            },
        )
        self.assertEqual(
            hashlib.sha256(
                __import__("base64").b64decode(
                    request["candidate"]["release_manifest_json_b64"],
                    validate=True,
                )
            ).hexdigest(),
            request["candidate"]["release_manifest_sha256"],
        )

    def test_mismatched_admission_target_is_rejected(self):
        requested = json.loads((self.root / "requested.json").read_text())
        requested["update_target_version"] = "0.2.1-dev.12"
        self._write_json("requested.json", requested)
        result = self._run()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "evidence.json").exists())
        self.assertIn("POST ", self.curl_log.read_text(encoding="utf-8"))

    def test_missing_preflight_snapshot_fails_before_admission(self):
        self.preflight_snapshot = None
        result = self._run()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "evidence.json").exists())
        self.assertNotIn("POST ", self.curl_log.read_text(encoding="utf-8"))

    def test_mismatched_preflight_snapshot_fails_before_admission(self):
        self.preflight_snapshot = CANDIDATE_SNAPSHOT
        result = self._run()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "evidence.json").exists())
        self.assertNotIn("POST ", self.curl_log.read_text(encoding="utf-8"))

    def test_missing_postflight_snapshot_is_rejected(self):
        self.postflight_snapshot = None
        result = self._run()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "evidence.json").exists())
        self.assertIn("POST ", self.curl_log.read_text(encoding="utf-8"))

    def test_mismatched_postflight_snapshot_is_rejected(self):
        self.postflight_snapshot = PREDECESSOR_SNAPSHOT
        result = self._run()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "evidence.json").exists())
        self.assertIn("POST ", self.curl_log.read_text(encoding="utf-8"))

    def test_terminal_receipt_without_generation_transition_is_rejected(self):
        final = json.loads((self.root / "final.json").read_text())
        final["node"]["root_generation"] = "0"
        self._write_json("final.json", final)
        result = self._run()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "evidence.json").exists())

    def test_terminal_receipt_without_observed_uptime_reset_is_rejected(self):
        final = json.loads((self.root / "final.json").read_text())
        final["node"]["host_uptime_seconds"] = 7201
        self._write_json("final.json", final)
        result = self._run()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "evidence.json").exists())

    def test_canonical_https_transport_is_accepted_for_legacy_bridge(self):
        result = self._run(transport_url=None)
        self.assertEqual(result.returncode, 0, result.stderr)
        evidence = json.loads((self.root / "evidence.json").read_text())
        self.assertEqual(
            evidence["candidate_binding"]["package_transport"]["kind"],
            "signed_canonical_https",
        )
        self.assertFalse(
            evidence["candidate_binding"]["package_transport"]["override_supplied"]
        )
        request = json.loads(self.request_body.read_text(encoding="utf-8"))
        self.assertNotIn("package_transport_url", request["candidate"])

    def test_explicit_canonical_https_transport_uses_legacy_three_field_wire(self):
        canonical_url = candidate_manifest()["appliance_release_v1"][
            "cybex_repository_snapshot"
        ]["url"]
        result = self._run(transport_url=canonical_url)
        self.assertEqual(result.returncode, 0, result.stderr)
        evidence = json.loads((self.root / "evidence.json").read_text())
        self.assertEqual(
            evidence["candidate_binding"]["package_transport"]["kind"],
            "signed_canonical_https",
        )
        self.assertFalse(
            evidence["candidate_binding"]["package_transport"]["override_supplied"]
        )
        request = json.loads(self.request_body.read_text(encoding="utf-8"))
        self.assertNotIn("package_transport_url", request["candidate"])

    def test_package_transport_size_mismatch_fails_before_admission(self):
        self.package_content_length = PACKAGE_SIZE + 1
        result = self._run()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "evidence.json").exists())
        self.assertNotIn("POST ", self.curl_log.read_text(encoding="utf-8"))

    def test_package_transport_hash_mismatch_fails_before_admission(self):
        (self.root / "package.bin").write_bytes(b"x" * PACKAGE_SIZE)
        result = self._run()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "evidence.json").exists())
        self.assertNotIn("POST ", self.curl_log.read_text(encoding="utf-8"))

    def test_source_does_not_hardcode_fabricated_reboot_claim(self):
        source = HARNESS.read_text(encoding="utf-8")
        self.assertNotIn("reboot_observed:true", source)
        self.assertIn("committed_candidate_receipt", source)
        self.assertIn("request_candidate_update()", source)


if __name__ == "__main__":
    unittest.main()
