from pathlib import Path
import re
import subprocess
import unittest


REPOSITORY = Path(__file__).resolve().parents[2]
READINESS = (REPOSITORY / "src" / "readiness.rs").read_text(encoding="utf-8")
ROUTES = (REPOSITORY / "src" / "routes" / "mod.rs").read_text(encoding="utf-8")
MAIN = (REPOSITORY / "src" / "main.rs").read_text(encoding="utf-8")
GENERATION_COMMIT = (
    REPOSITORY
    / "ubuntu-appliance"
    / "rootfs"
    / "usr"
    / "lib"
    / "cybex-james"
    / "cybex-james-generation-commit"
).read_text(encoding="utf-8")
GENERATION_COMMIT_SERVICE = (
    REPOSITORY
    / "ubuntu-appliance"
    / "rootfs"
    / "etc"
    / "systemd"
    / "system"
    / "cybex-james-generation-commit.service"
).read_text(encoding="utf-8")


def shell_integer(name: str) -> int:
    match = re.search(rf"^{re.escape(name)}=([0-9]+)$", GENERATION_COMMIT, re.MULTILINE)
    if match is None:
        raise AssertionError(f"missing integer shell assignment: {name}")
    return int(match.group(1))


class ReadinessRecoveryContractTests(unittest.TestCase):
    def test_public_self_probe_arrives_as_a_loopback_checker(self) -> None:
        self.assertIn(
            ".local_address(IpAddr::V4(Ipv4Addr::LOCALHOST))", READINESS
        )
        self.assertIn('base.join("boot.ipxe?cybex_check=1")', READINESS)
        self.assertIn(
            "trusted_loopback_self_probe_does_not_record_a_boot_event", ROUTES
        )

    def test_background_workers_start_only_after_the_http_socket_is_bound(self) -> None:
        bind = MAIN.index("let listener = TcpListener::bind(listen_addr)")
        manage = MAIN.index("cybex_james::manage::spawn(state.clone())")
        self.assertLess(bind, manage)

    def test_candidate_commit_uses_three_uncached_successes_and_resets_on_failure(
        self,
    ) -> None:
        self.assertEqual(shell_integer("health_required_successes"), 3)
        self.assertIn(
            "'http://127.0.0.1:8080/healthz?cybex_fresh=1'", GENERATION_COMMIT
        )
        self.assertIn("consecutive_successes=$((consecutive_successes + 1))", GENERATION_COMMIT)
        self.assertIn("consecutive_successes=0\n      sleep", GENERATION_COMMIT)
        self.assertIn("crate::readiness::probe_fresh(&state).await", ROUTES)
        self.assertIn("!headers.contains_key(\"x-forwarded-for\")", ROUTES)
        self.assertIn("!headers.contains_key(\"forwarded\")", ROUTES)

    def test_stabilizer_survives_startup_failure_and_requires_consecutive_successes(
        self,
    ) -> None:
        function_start = GENERATION_COMMIT.index("wait_for_stable_readiness() {")
        function_end = GENERATION_COMMIT.index(
            "\n}\n\nwait_for_stable_readiness", function_start
        ) + 2
        function = GENERATION_COMMIT[function_start:function_end]
        harness = f"""
set -Eeuo pipefail
health_deadline_seconds={shell_integer("health_deadline_seconds")}
health_retry_seconds=0
health_stable_interval_seconds=0
health_required_successes={shell_integer("health_required_successes")}
attempts=0
candidate_ready() {{
  attempts=$((attempts + 1))
  case "$attempts" in
    1|4) return 1 ;;
    *) return 0 ;;
  esac
}}
sleep() {{ :; }}
{function}
wait_for_stable_readiness
printf '%s\n' "$attempts"
"""
        result = subprocess.run(
            ["bash", "-c", harness],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "7\n")

    def test_stabilization_is_bounded_below_the_systemd_five_minute_limit(self) -> None:
        deadline = shell_integer("health_deadline_seconds")
        unit_timeout = shell_integer("health_unit_timeout_seconds")
        http_timeout = shell_integer("health_http_timeout_seconds")
        retry = shell_integer("health_retry_seconds")
        stable_interval = shell_integer("health_stable_interval_seconds")
        self.assertEqual(GENERATION_COMMIT_SERVICE.count("TimeoutStartSec=5min"), 1)
        self.assertIn("local deadline=$health_deadline_seconds", GENERATION_COMMIT)
        self.assertNotIn("SECONDS + health_deadline_seconds", GENERATION_COMMIT)

        # One attempt may begin immediately before the internal deadline. Each
        # of four units has a one-second SIGKILL grace, followed by bounded HTTP.
        max_final_attempt = 4 * (unit_timeout + 1) + http_timeout
        self.assertLess(deadline + max_final_attempt, 5 * 60)
        self.assertLess(retry, deadline)
        self.assertLess(stable_interval * 2, deadline)


if __name__ == "__main__":
    unittest.main()
