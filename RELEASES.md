# Release Notes

Use one section per production tag.

## v0.1.2

Status: release qualification pending; production tag pending.

This is the governed update qualification target. The testbench builds the
exact `d396131f9c170f9b3cd27f5c3db8764cedccb00d` source as Bookworm-compatible
`0.1.1` bootstrap release A, builds this revision as `0.1.2` release B in the
same pinned environment, verifies both binary identities, signs both immutable
artifacts, and exercises rollback plus successful promotion on an owned Forge
node. Neither candidate is a production release until that evidence and the
remaining checklist below are complete.

Release checklist:

- Cargo metadata, the lockfile, and `cybex-forge --version` all report exact
  canonical version `0.1.2`.
- The governed Forge update qualification proves signature rejection,
  restart/health failure rollback, durable interrupted-apply recovery, stale
  lock recovery, and successful `0.1.1` to `0.1.2` activation.
- Artifacts are built in the pinned Debian Bookworm environment used by Forge;
  a host binary linked against a newer glibc is never deployed to the node.
- The `v0.1.1` checklist below remains the release signing, installer,
  enrollment, and production-readiness checklist for `v0.1.2` as well, with
  versions and URLs advanced consistently.

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
