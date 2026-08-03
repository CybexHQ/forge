# Release Notes

Use one section per production tag.

## Appliance release gate

Every production Forge release includes the static `package` output and, when
shipping appliance media, the matching
`cybex-forge-appliance-<version>-x86_64-linux.iso`. The additive
`installer_iso` manifest object binds the ISO URL, SHA-256, byte length,
architecture, version, and `CYBEX-FORGE-INSTALLER-ISO-V1` signature while the
existing binary signature bytes remain unchanged.

Production tags pass the ordinary installer/release contract suite, pinned
Rust 1.85 formatting, test, and clippy checks, and the pinned Nix appliance
parse, evaluation, and build checks. The protected build job depends on those
three gates, builds and signs the binary and ISO once, and uploads one internal
candidate artifact retained for 30 days. A rerun reuses that exact candidate by
Actions artifact ID and digest and fails closed if it is absent or expired.

The protected publisher depends only on the completed build. It independently
downloads the original candidate by artifact ID, verifies the workflow run,
head SHA, Actions digest, checksums, manifest, signatures, embedded version,
and approved public key, then attests and publishes exactly four assets: the
binary, installer ISO, release descriptor, and `SHA256SUMS`. The release is
created as a draft, every remote name, size, and digest is polled and verified,
and only then is the immutable release published.

The `production-release` environment must provide the approved public trust
root as `CYBEX_FORGE_UPDATE_TRUSTED_PUBLIC_KEY`, the matching governed Ed25519
PEM as `CYBEX_FORGE_RELEASE_PRIVATE_KEY_B64`, and the read-only repository
policy credential `CYBEX_FORGE_RELEASE_POLICY_TOKEN`. The workflow verifies
that immutable releases are enabled but never changes that repository policy.
It destroys its temporary private-key file before upload.

The shared `trust/ed25519-weak-public-keys.txt` deny set covers all byte
encodings accepted for the eight small-order points. Release verification, Nix
evaluation, and the deployed updater/cache verification reject these weak keys.
Repository rules must protect `v*` tag creation, update, and deletion and limit
bypass to the governed release role.

## v0.1.2

Status: release verification pending; production tag pending.

This release advances the governed updater contract from the exact
`3479528d8e05036d70780d93207c3e835f3006be` Bookworm-compatible `0.1.1`
bootstrap to `0.1.2`. Neither candidate is a production release until the
ordinary contract, Rust, Nix, signing, and publication checks below complete.

Release checklist:

- Cargo metadata, the lockfile, and `cybex-forge --version` all report exact
  canonical version `0.1.2`.
- The Forge updater contract tests prove signature rejection,
  restart/health failure rollback, durable interrupted-apply recovery, stale
  lock recovery, and successful `0.1.1` to `0.1.2` activation.
- Artifacts are built in the pinned Debian Bookworm environment used by Forge;
  a host binary linked against a newer glibc is never deployed to the node.
- The `v0.1.1` checklist below remains the release signing, installer,
  enrollment, and production-readiness checklist for `v0.1.2` as well, with
  versions and URLs advanced consistently.
- Managed update targets are canonical SemVer strictly newer than the running
  binary. Equal or older targets report durable `unsupported` status without a
  download, and the staged executable must report the exact signed version.
- Rollback and interrupted-apply recovery must report the restored executable's
  exact on-disk `--version`, never the newer recovery process's compile-time
  version. An unprovable restored identity remains a failed unknown state.
- Rust unit tests and shell/C contract tests prove that missing/non-executable
  binary recovery is journaled before restoration, older media is rejected
  before mutation, corrupt root config is never promoted over protected state,
  and both media-rebase interruption boundaries replay without losing evidence.
- The same contract suites prove installer children inherit no enrollment-code
  descriptor and protected install-state replacement uses the required
  file/directory durability ordering. These are fault-injection/ordering
  proofs, not claims that those four faults were physically injected by the
  disposable VM lifecycle.

## v0.1.1

Status: release verification pending; production tag pending.

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
  with `CYBEX_FORGE_INSTALL_REF` set to the exact compatible 40-hex Forge
  commit; a moving branch or tag is not a production provisioning input.
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
