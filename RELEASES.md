# Release Notes

Use one section per production tag.

## v0.1.0

Status: public-source ready; production tag pending.

Release checklist:

- CI is green for formatting, tests, clippy, installer script syntax,
  shellcheck, and dependency audit.
- The tag exists on the remote Forge repository.
- The GitHub release contains the `cybex-forge` binary artifact for the
  supported Linux target and a `cybex-forge-release.json` manifest using schema
  `cybex.forge.release.v1`.
- The release manifest `version` matches the tag, `artifact.url` points at the
  release binary, `artifact.sha256` matches the uploaded bytes, and `signature`
  is filled when production Forge config sets `update.trusted_public_key`.
- The Cybex Manage deployment that generated production commands is configured
  with `CYBEX_FORGE_INSTALL_REF=v0.1.0` or the selected production tag.
- The Cybex Manage deployment used for updates is configured with
  `CYBEX_FORGE_RELEASE_GITHUB_REPOSITORY=CybexHQ/forge` and the release asset
  name expected by `CYBEX_FORGE_RELEASE_MANIFEST_ASSET` or an equivalent
  `CYBEX_FORGE_RELEASE_MANIFEST_URL`.
- A disposable Proxmox host/LXC install has verified that the generated command
  clones Forge into `/root/forge`, builds and starts Cybex Forge, submits the
  one-time enrollment, and appears as pending `cybex-forge` in Manage.
- The pending enrollment has been adopted and Boot health, nginx, TFTP,
  runtime apply services, and installer ISO/source serving have been verified.
- An adopted Forge node advertising `updater_v1` shows `Update available` in
  Cybex Manage when pointed at the release manifest, and a staged update reports
  progress through to `succeeded` or rolls back cleanly on a forced health-check
  failure.
- Install output has been captured with one-time auth codes and other secrets
  redacted.
