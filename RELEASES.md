# Release Notes

Use one section per production tag.

## v0.1.1

Status: release qualification pending; production tag pending.

Release checklist:

- CI is green for formatting, tests, clippy, installer script syntax,
  shellcheck, and dependency audit.
- `Cargo.toml`, `Cargo.lock`, and the running binary report the exact canonical
  version `0.1.1`; the corresponding Git tag is `v0.1.1`.
- The `v0.1.1` tag exists on the remote Forge repository.
- The GitHub release contains the `cybex-forge` binary artifact for the
  supported Linux target and a `cybex-forge-release.json` manifest using schema
  `cybex.forge.release.v1`.
- `tools/forge-release.py manifest` generated the manifest from the final
  artifact and a mode-0600 Ed25519 private key. Re-running it with the same
  arguments produces identical bytes.
- The release manifest `version` is exact Cargo SemVer `0.1.1` (not the
  `v0.1.1` tag), `artifact.url` points at the release binary,
  `artifact.sha256` matches the uploaded bytes, and `signature` is a
  self-verified standard-Base64 Ed25519 signature.
- Only the standard-Base64 raw 32-byte public key from
  `tools/forge-release.py public-key` is provisioned through
  `CYBEX_FORGE_UPDATE_TRUSTED_PUBLIC_KEY`/`--update-trusted-public-key`. The
  private key is absent from Git, Manage, Forge nodes, commands, logs, CI
  artifacts, and test evidence.
- The Cybex Manage deployment that generated production commands is configured
  with `CYBEX_FORGE_INSTALL_REF=v0.1.1` or the selected production tag.
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
  progress through to `succeeded`. A forced post-activation failure reports
  `rolled_back` only after the previous binary is restored and its service
  restart succeeds. Restore/restart failures report `rollback_failed:` and
  preserve durable recovery state rather than claiming rollback.
- Install output has been captured with one-time auth codes and other secrets
  redacted.
