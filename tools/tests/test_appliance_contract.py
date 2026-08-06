from pathlib import Path
import unittest


REPOSITORY = Path(__file__).resolve().parents[2]
FIRST_BOOT = (
    REPOSITORY
    / "ubuntu-appliance"
    / "rootfs"
    / "usr"
    / "lib"
    / "cybex-forge"
    / "cybex-forge-first-boot"
)
SERVICE = (
    REPOSITORY
    / "ubuntu-appliance"
    / "rootfs"
    / "etc"
    / "systemd"
    / "system"
    / "cybex-forge.service"
)


class ApplianceFirstBootContractTests(unittest.TestCase):
    def test_nix_store_directories_are_checked_individually(self) -> None:
        script = FIRST_BOOT.read_text(encoding="utf-8")
        self.assertIn("test -d /nix/store\n", script)
        self.assertIn("test -d /nix/var/nix/db\n", script)
        self.assertNotIn("test -d /nix/store /nix/var/nix/db", script)

    def test_service_can_read_config_only_after_first_boot_succeeds(self) -> None:
        script = FIRST_BOOT.read_text(encoding="utf-8")
        self.assertIn(
            "chown root:cybex-forge /etc/cybex-forge/config.toml\n"
            "chmod 0640 /etc/cybex-forge/config.toml\n",
            script,
        )

        service = SERVICE.read_text(encoding="utf-8")
        self.assertIn("Requires=cybex-forge-first-boot.service\n", service)
        self.assertIn("After=network-online.target nix-daemon.service "
                      "cybex-forge-first-boot.service\n", service)


if __name__ == "__main__":
    unittest.main()
