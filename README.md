# Cybex James

Cybex James is a managed Ubuntu 26.04 appliance that builds and serves Cybex
workstation netboot releases. The only supported installation route is a
personalized James appliance ISO created by Cybex Manage provisioning V2.

## Installation

In Cybex Manage, open James and start a new James setup. Download the
personalized ISO and boot the target appliance from it. When the appliance
appears in Manage, select its target disk and network configuration, review
the destructive installation warning, and approve the installation there.

The media contains a signed, single-use provisioning envelope. The bootstrap
verifies the envelope before installation, activates the reserved device
identity, installs Ubuntu 26.04 from the offline repository, and writes the
activated device key and ID into the installed state partition. The signed
install plan also binds the canonical organization UUID and slug; both are
validated and written to the installed managed configuration so James can
issue organization-scoped workstation boot grants immediately. There is no
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
  ubuntu-appliance/rootfs/usr/lib/cybex-james/* \
  ubuntu-appliance/rootfs/etc/grub.d/09_cybex_generations
```

The installed service uses `/etc/cybex-james/config.toml` and the V2-activated
identity at `/var/lib/cybex-james/state/manage-state.json`. It reports
`appliance_update_v1` and accepts only signed Ubuntu appliance updates from
Manage. Workstation-netboot publication and appliance maintenance coordinate
through a shared lock so runtime promotion cannot race an appliance update.
Runtime compatibility is the explicit epoch in `protocol/compatibility.json`,
not equality between the running Manage revision and the descriptor's signed
`manage_source_revision`. That SHA remains provenance for reproduction and
audit, and selects the exact root-owned offline Manage source archive used by
installer-target builds. Compatible desired runtimes reconcile automatically in a single-flight
background task, so downloads and import failures do not delay Build, Cache,
appliance reporting, or managed heartbeats. James keeps serving its verified
active runtime while a newer candidate is retried; the candidate import state
and current service availability are intentionally separate signals in Manage.

Source-free Blueprint preparation classifies the exact evaluated derivation
graph in an isolated store. Deterministic NixOS composition outputs and their
qualified tool providers are admitted by strict fingerprints, while an
unrecognized source-producing derivation remains blocked and is reported in
bounded `source_build_candidates` diagnostics.

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

`tools/james-release.py manifest` emits `cybex.james.release.v1` with
`installer_iso_template_v2` as the sole James installation-media entry. The
thin USB template declares `package_delivery: network-snapshot-v1`; the
descriptor also signs its canonical `manage_origin`, and the manifest carries
the core binary, the separately delivered signed Ubuntu
appliance package snapshot, and the workstation netboot bundle. `installer_iso`
is rejected. Releases also publish the separate, canonical
`cybex-james-release-compatibility.json` asset. Its domain-separated Ed25519
signature binds the complete component compatibility contract, the exact main
manifest bytes, and every available binary, appliance, package-snapshot, and
workstation-runtime identity without adding a compatibility field to the
legacy main manifest's strict top-level schema.

See [`RELEASES.md`](RELEASES.md) for the release procedure and
[`SECURITY.md`](SECURITY.md) for trust boundaries.
