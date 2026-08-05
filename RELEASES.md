# Forge releases

Forge releases support one appliance platform: Ubuntu 26.04 installed from a
Manage-personalized V2 ISO.

The signed `cybex.forge.release.v1` manifest contains:

- `artifact`: the Forge service binary;
- `installer_iso_template_v2`: the immutable Ubuntu/x86-64 ISO template,
  personalization slot, accepted provisioning keys, and signature;
- `appliance_release_v1`: the offline APT repository snapshot, required
  package versions, kernel, rollback contract, and signature;
- `workstation_netboot`: the signed workstation kernel, bootstrap initrd, and
  Nix store squashfs bundle.

`installer_iso` is not a valid manifest field. The old generic NixOS appliance
ISO and executable-only updater are not release artifacts.

## Build and verify

The release workflow:

1. formats, tests, lints, and release-builds the Rust binaries;
2. validates Ubuntu appliance scripts and the pinned Ubuntu 26.04 base ISO;
3. builds the offline package repository and immutable ISO template;
4. builds the workstation netboot bundle from pinned Manage and nixpkgs
   revisions;
5. signs the binary, template, appliance release, and netboot descriptors;
6. independently verifies the exact artifacts;
7. boots a personalized template through the V2 lifecycle qualification;
8. attests and publishes only the qualified artifacts.

Local release-tool verification:

```sh
python3 -B -m unittest discover -s tools/tests -v
python3 tools/forge-release.py verify \
  --manifest dist/cybex-forge-release.json \
  --artifact dist/cybex-forge-x86_64-linux \
  --installer-iso-template dist/cybex-forge-appliance-template-VERSION-x86_64-linux.iso \
  --appliance-package-snapshot dist/cybex-forge-appliance-packages-VERSION-x86_64-linux.tar.zst \
  --trusted-public-key "$CYBEX_FORGE_UPDATE_TRUSTED_PUBLIC_KEY"
```

Qualification must prove Secure Boot, approval before disk mutation, identity
activation, installation resumability, an installed-media reboot, healthy
appliance reporting, signed updates, network acknowledgement, and exact SSH
certificate principals.
