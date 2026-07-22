from __future__ import annotations

import base64
from pathlib import Path
import subprocess
import unittest


REPOSITORY = Path(__file__).resolve().parents[2]
INSTALLERS = (
    REPOSITORY / "install" / "proxmox-host-lxc.sh",
    REPOSITORY / "install" / "cybex-forge-lxc-install.sh",
)


def extract_function(path: Path, function_name: str) -> str:
    lines = path.read_text(encoding="utf-8").splitlines()
    start = lines.index(f"{function_name}() {{")
    for end in range(start + 1, len(lines)):
        if lines[end] == "}":
            return "\n".join(lines[start : end + 1])
    raise AssertionError(f"unterminated function {function_name} in {path}")


class InstallerUpdateKeyTests(unittest.TestCase):
    def run_validator(self, installer: Path, value: str) -> subprocess.CompletedProcess[bytes]:
        validator = extract_function(installer, "validate_update_trusted_public_key")
        script = f"""
set -euo pipefail
die() {{ printf 'ERROR: %s\\n' "$1" >&2; exit 2; }}
require_command() {{ command -v "$1" >/dev/null 2>&1 || exit 1; }}
{validator}
update_trusted_public_key="$1"
validate_update_trusted_public_key
"""
        return subprocess.run(
            ["bash", "-c", script, "bash", value],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )

    def test_validators_accept_only_canonical_standard_base64_raw_32_byte_keys(self) -> None:
        canonical = base64.b64encode(bytes(range(32))).decode()
        wrong_size = base64.b64encode(bytes(range(31))).decode()
        noncanonical = base64.b64encode(bytes(32)).decode()
        noncanonical = noncanonical[:-2] + "B="
        invalid_values = (
            wrong_size,
            noncanonical,
            canonical.rstrip("="),
            base64.urlsafe_b64encode(b"\xff" * 32).decode(),
            canonical + "\n",
        )
        for installer in INSTALLERS:
            with self.subTest(installer=installer.name, kind="valid"):
                accepted = self.run_validator(installer, canonical)
                self.assertEqual(accepted.returncode, 0, accepted.stderr.decode())
            with self.subTest(installer=installer.name, kind="empty"):
                accepted = self.run_validator(installer, "")
                self.assertEqual(accepted.returncode, 0, accepted.stderr.decode())
            for invalid in invalid_values:
                with self.subTest(installer=installer.name, kind="invalid", value=repr(invalid)):
                    rejected = self.run_validator(installer, invalid)
                    self.assertEqual(rejected.returncode, 2, rejected.stderr.decode())

    def test_host_helper_propagates_only_the_public_key_option(self) -> None:
        host = INSTALLERS[0].read_text(encoding="utf-8")
        lxc = INSTALLERS[1].read_text(encoding="utf-8")
        self.assertIn('update_trusted_public_key="${CYBEX_FORGE_UPDATE_TRUSTED_PUBLIC_KEY:-}"', host)
        self.assertIn('--update-trusted-public-key "$update_trusted_public_key"', host)
        self.assertIn('update_trusted_public_key="${CYBEX_FORGE_UPDATE_TRUSTED_PUBLIC_KEY:-}"', lxc)
        self.assertIn('trusted_public_key = "$update_trusted_public_key"', lxc)
        self.assertNotIn("UPDATE_PRIVATE", host)
        self.assertNotIn("UPDATE_PRIVATE", lxc)


if __name__ == "__main__":
    unittest.main()
