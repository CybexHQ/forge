# Cybex Forge

Cybex Forge is a managed Ubuntu 26.04 appliance that builds and serves Cybex
workstation netboot releases. The only supported installation route is a
personalized Forge appliance ISO created by Cybex Manage provisioning V2.

## Installation

In Cybex Manage, open Forge and create a provisioning session. Select the
target disk and network configuration, approve the plan, then download the
personalized ISO. Boot the target appliance from that ISO.

The media contains a signed, single-use provisioning envelope. The bootstrap
verifies the envelope before installation, activates the reserved device
identity, installs Ubuntu 26.04 from the offline repository, and writes the
activated device key and ID into the installed state partition. There is no
install-code, pairing-code, generic ISO, NixOS appliance, or Proxmox/LXC path.

If provisioning V2 is unavailable in Manage, installation is unavailable. No
fallback installer is supported.

## Development

```sh
cargo fmt --all --check
cargo test --locked
cargo build --release --locked
python3 -B -m unittest discover -s tools/tests -v
bash -n ubuntu-appliance/*.sh \
  ubuntu-appliance/qualification/run-lifecycle.sh \
  ubuntu-appliance/rootfs/usr/lib/cybex-forge/* \
  ubuntu-appliance/rootfs/etc/grub.d/09_cybex_generations
```

The installed service uses `/etc/cybex-forge/config.toml` and the V2-activated
identity at `/var/lib/cybex-forge/state/manage-state.json`. It reports
`appliance_update_v1` and accepts only signed Ubuntu appliance updates from
Manage. Workstation-netboot publication and appliance maintenance coordinate
through a shared lock so runtime promotion cannot race an appliance update.
Runtime compatibility is the explicit epoch in `protocol/compatibility.json`,
not equality between the running Manage revision and the descriptor's signed
`manage_source_revision`. That SHA remains provenance for reproduction and
audit. Compatible desired runtimes reconcile automatically in a single-flight
background task, so downloads and import failures do not delay Build, Cache,
appliance reporting, or managed heartbeats.

## Ubuntu appliance

The active implementation is under [`ubuntu-appliance/`](ubuntu-appliance/).
It provides:

- immutable personalized ISO templates with an 8192-byte provisioning slot;
- offline Ubuntu and Cybex package repositories;
- resumable first-boot installation and activation;
- Btrfs root generations and rollback;
- signed appliance updates and two-phase network changes;
- Secure Boot, firewall, SSH CA, and appliance qualification contracts.

See [`ubuntu-appliance/README.md`](ubuntu-appliance/README.md) for build and
qualification details.

## Release format

`tools/forge-release.py manifest` emits `cybex.forge.release.v1` with
`installer_iso_template_v2` as the sole Forge installation-media entry. The
thin USB template declares `package_delivery: network-snapshot-v1`; the
manifest also carries the core binary, the separately delivered signed Ubuntu
appliance package snapshot, and the workstation netboot bundle. `installer_iso`
is rejected. Releases also publish the separate, canonical
`cybex-forge-release-compatibility.json` asset. Its domain-separated Ed25519
signature binds the complete component compatibility contract, the exact main
manifest bytes, and every available binary, appliance, package-snapshot, and
workstation-runtime identity without adding a compatibility field to the
legacy main manifest's strict top-level schema.

See [`RELEASES.md`](RELEASES.md) for the release procedure and
[`SECURITY.md`](SECURITY.md) for trust boundaries.
