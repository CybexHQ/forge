# Forge releases

Forge releases support one appliance platform: Ubuntu 26.04 installed from a
Manage-personalized V2 ISO.

The signed `cybex.forge.release.v1` manifest contains:

- `artifact`: the Forge service binary;
- `installer_iso_template_v2`: the immutable Ubuntu/x86-64 ISO template,
  personalization slot, `network-snapshot-v1` delivery contract, accepted
  provisioning keys, and signature;
- `appliance_release_v1`: the separately delivered APT repository snapshot, required
  package versions, kernel, rollback contract, and signature;
- `workstation_netboot`: the signed workstation kernel, bootstrap initrd, and
  Nix store squashfs bundle.

The companion `cybex-forge-release-compatibility.json` asset uses the exact
`cybex.forge.release-compatibility.v1` schema. It contains the complete shared
compatibility contract and its canonical SHA-256, the immutable URL and SHA-256
of `cybex-forge-release.json`, and fixed identity slots for the Forge binary,
ISO template, appliance package snapshot, and workstation runtime. Optional
identities are explicit JSON `null`. The asset is canonical compact sorted JSON
encoded as UTF-8 with one final LF; the contract digest uses the same encoding.
It is signed with the offline release key. The signature message is the ASCII
domain line
`CYBEX-FORGE-RELEASE-COMPATIBILITY-V1`, one LF, then the canonical unsigned
asset bytes. The compatibility asset adds no top-level field to the existing
main manifest, so older Manage rollbacks retain their strict parser
compatibility.

`installer_iso` is not a valid manifest field. The old generic NixOS appliance
ISO and executable-only updater are not release artifacts.

## Build and verify

The release workflow:

1. formats, tests, lints, and release-builds the Rust binaries;
2. validates Ubuntu appliance scripts and the pinned Ubuntu 26.04 base ISO;
3. builds the package snapshot separately from the thin immutable USB ISO
   template;
4. builds the workstation netboot bundle from pinned Manage and nixpkgs
   revisions;
5. signs the binary, template, appliance release, netboot descriptor, and
   canonical compatibility asset;
6. independently verifies the exact artifacts, main manifest, full
   compatibility contract, and cross-manifest identities;
7. boots a personalized template through the V2 lifecycle qualification;
8. attests and publishes only the qualified artifacts.

The pinned Manage and nixpkgs revisions in the workstation descriptor are
signed publication provenance. Deployment compatibility is instead the shared
workstation-runtime epoch and its signed descriptor/manifest target tuple in
`protocol/compatibility.json`. The release workflow requires Forge and its
pinned Manage source to agree on that contract; deployed source SHAs may differ
when both releases support the same epoch.

Local release-tool verification:

```sh
python3 -B -m unittest discover -s tools/tests -v
python3 tools/forge-release.py verify \
  --manifest dist/cybex-forge-release.json \
  --artifact dist/cybex-forge-x86_64-linux \
  --installer-iso-template dist/cybex-forge-appliance-template-VERSION-x86_64-linux.iso \
  --appliance-package-snapshot dist/cybex-forge-appliance-packages-VERSION-x86_64-linux.tar.zst \
  --trusted-public-key "$CYBEX_FORGE_UPDATE_TRUSTED_PUBLIC_KEY"
python3 tools/forge-release.py verify-compatibility \
  --asset dist/cybex-forge-release-compatibility.json \
  --manifest dist/cybex-forge-release.json \
  --manifest-url https://github.com/CybexHQ/forge/releases/download/vVERSION/cybex-forge-release.json \
  --compatibility protocol/compatibility.json \
  --trusted-public-key "$CYBEX_FORGE_UPDATE_TRUSTED_PUBLIC_KEY"
```

Qualification must prove Secure Boot, approval before disk mutation, identity
activation, installation resumability, an installed-media reboot, healthy
appliance reporting, signed updates, network acknowledgement, and exact SSH
certificate principals.
