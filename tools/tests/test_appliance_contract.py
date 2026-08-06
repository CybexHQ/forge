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
QUALIFICATION_LIFECYCLE = (
    REPOSITORY / "ubuntu-appliance" / "qualification" / "run-lifecycle.sh"
)
NETWORK_CHANGE = (
    REPOSITORY
    / "ubuntu-appliance"
    / "rootfs"
    / "usr"
    / "lib"
    / "cybex-forge"
    / "cybex-forge-network-change"
)
NETPLAN_APPLY = (
    REPOSITORY
    / "ubuntu-appliance"
    / "rootfs"
    / "usr"
    / "lib"
    / "cybex-forge"
    / "cybex-forge-netplan-apply"
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

    def test_first_boot_does_not_wait_for_units_ordered_after_it(self) -> None:
        script = FIRST_BOOT.read_text(encoding="utf-8")
        self.assertNotIn("systemctl enable --now", script)
        self.assertIn(
            "systemctl enable nix-daemon nginx tftpd-hpa "
            "cybex-forge-firewall ssh\n",
            script,
        )

    def test_qualification_cold_starts_a_stalled_installed_disk_once(self) -> None:
        script = QUALIFICATION_LIFECYCLE.read_text(encoding="utf-8")
        self.assertIn(
            'installer) boot_arguments=(-boot "once=d,menu=off")', script
        )
        self.assertIn(
            'installed) boot_arguments=(-boot "order=c,menu=off")', script
        )
        self.assertIn("qemu_restart_count=0\n", script)
        self.assertIn("qemu_restart_count=1\n", script)
        self.assertIn("cold_restart_deadline=$((SECONDS + 300))\n", script)
        self.assertIn("-m 32768", script)

    def test_root_network_helper_shares_handshake_files_with_forge(self) -> None:
        change_script = NETWORK_CHANGE.read_text(encoding="utf-8")
        self.assertIn('chown root:cybex-forge "$status.tmp"\n', change_script)
        self.assertIn('chmod 0640 "$status.tmp"\n', change_script)

        apply_script = NETPLAN_APPLY.read_text(encoding="utf-8")
        self.assertIn('chown root:cybex-forge "$pending"\n', apply_script)
        self.assertIn('chmod 0640 "$pending"\n', apply_script)


if __name__ == "__main__":
    unittest.main()
