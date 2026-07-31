# Release Notes

Use one section per production tag.

## Appliance release gate

Every production Forge release includes the static `package` output and, when
shipping appliance media, the matching
`cybex-forge-appliance-<version>-x86_64-linux.iso`. The additive
`installer_iso` manifest object binds the ISO URL, SHA-256, byte length,
architecture, version, and `CYBEX-FORGE-INSTALLER-ISO-V1` signature while the
existing binary signature bytes remain unchanged.

The signing key must remain effective-user-owned, single-linked, private, and
metadata-stable while OpenSSL derives/signs. Appliance qualification also
requires descriptor-bound seed input handling and sequence-ordered media
reconciliation across a deliberately backward guest clock.

The shared `trust/ed25519-weak-public-keys.txt` deny set covers all fourteen
byte encodings Dalek accepts for the eight small-order points, including
alternate sign and non-canonical field encodings. Release verification and
Nix evaluation reject them, while deployed updater/cache verification also
uses the Rust library's strict weak-key and signature checks.

Production tags first pass a pinned Rust 1.85 formatting, test, and clippy gate,
then use three ordered release jobs. The protected build job waits for that gate
and the exact-source disposable lifecycle, builds the binary and ISO once,
signs them, and uploads one immutable internal candidate artifact retained for
30 days. The first workflow attempt is the only attempt allowed to build or
sign: later attempts reuse that candidate by its Actions artifact ID and digest,
and fail closed if it is absent or expired. Re-run only failed/specific jobs;
GitHub full-workflow reruns may clear the run's artifacts and will therefore be
refused rather than silently producing a second candidate. A self-hosted
`cybex-proxmox` job downloads that candidate read-only, independently verifies
the descriptor, hashes, and signatures, boots the exact supplied ISO, and
checks its embedded version, production public key, and guided installer
service and exact embedded binary digest. It uploads bounded evidence only;
release bytes never round-trip through the self-hosted runner. The publisher
independently downloads both original Actions artifacts by ID, verifies their
run/head SHA and Actions digests, validates the bounded evidence against the
candidate hashes, source revisions, and cleanup results, then attests the four
candidate files plus `cybex-forge-appliance-qualification.json`. It creates a
draft, attaches and polls all five remote name/size/SHA-256 tuples, and only
then publishes the immutable release. `SHA256SUMS` records portable asset
basenames so it verifies in a flat release download. A retry may delete only a
mutable draft with the exact workflow title and marker-only body for this run
and candidate, and only when its assets are a unique subset of the five allowed
release names; it never replaces a modified, human-owned, published, or
immutable release.

The published qualification document is rebuilt from a closed allowlist; it
contains only exact source revisions, candidate hashes and size, the eight
required named physical checks, and VM/private-state cleanup booleans. Unknown
or extra evidence fields are rejected and raw testbench evidence is never
copied into a release asset.

The protected `production-release` environment must provide the approved
public trust root as `CYBEX_FORGE_UPDATE_TRUSTED_PUBLIC_KEY` and the matching
governed Ed25519 PEM as the base64-encoded
`CYBEX_FORGE_RELEASE_PRIVATE_KEY_B64` secret. The tag job
requires repository immutable releases to already be enabled. The environment
must also provide `CYBEX_FORGE_RELEASE_POLICY_TOKEN`, a fine-grained read-only
credential with repository Administration read permission; the workflow uses
it only to `GET /repos/$GITHUB_REPOSITORY/immutable-releases` and requires
`enabled: true`. It never enables or changes that policy. The tag job fails
closed when policy or trust inputs are absent or mismatched, embeds only the
public key, signs and self-verifies the exact binary/ISO manifest, and destroys
its temporary private-key file before upload. The production signing key is
not referenced by the self-hosted smoke or publisher. Dummy trust material is
restricted to expression evaluation and source-lifecycle contracts.

Forge CI invokes the Manage-owned appliance controller from a sibling checkout
before any pushed commit or tag can publish. Pull requests run hosted contracts
and Nix checks only because the self-hosted lifecycle receives live
qualification credentials. Both source-built qualification and exact-candidate
smoke run behind a dedicated protected `forge-appliance-qualification`
environment. Require reviewer approval and restrict that environment's
deployment policy to protected `main` and governed `v*` tags. Store
`CYBEX_GOLDEN_ISO_API_TOKEN` (or `CYBEX_API_TOKEN`) and the optional
`CYBEX_MANAGE_REPO_TOKEN` only as environment secrets; remove repository-scoped
duplicates so an unapproved job cannot receive them. Configure
`CYBEX_E2E_MANAGE_REF` as an immutable
40-hex Manage commit, `CYBEX_API_URL` as the HTTPS qualification API, and
`CYBEX_FORGE_UPDATE_TRUSTED_PUBLIC_KEY` as the same approved public key used by
the release environment, plus the dedicated API token named above. For a
private Manage repository, give the
environment's repository token read access; otherwise the workflow falls back
to `github.token`. A runner labelled `self-hosted` and `cybex-proxmox` must
provide the authorized Incus testbench dependencies and configuration. The
source-lifecycle gate verifies that the Forge event SHA and coordinated Manage
SHA are exact, clean, and reachable from each repository's `origin/main`, then
runs controller contracts, Manage/web builds, lab
preparation, the complete appliance lifecycle, interruption recovery, and
bounded evidence export. It uses an ephemeral qualification key and synthetic
successor versions derived from the same exact source; those are test fixtures,
not production release assets. Manage is checked out at `.cybex-manage`,
beside—not inside—the exact `.cybex-forge` source consumed by Nix.

Coordinate the cross-repository rollout in dependency order. First land and
push a Forge revision whose Proxmox host helper implements the hidden
file-backed enrollment prompt; it must be remotely reachable before Manage can
generate a compatible command. Pin the Manage production
`CYBEX_FORGE_INSTALL_REF` and Manage qualification `CYBEX_E2E_FORGE_REF` to
that exact 40-hex Forge commit, and pin Forge qualification
`CYBEX_E2E_MANAGE_REF` to the exact compatible 40-hex Manage commit. Qualify
those exact revisions before deploying Manage. Never deploy a Manage command
template that relies on a helper revision which is not yet available from the
configured Forge repository.

Because a tag selects the workflow source that evaluates it, repository rules
must also protect `v*` tag creation, update, and deletion and limit bypass to
the governed release role. The privileged job's full-history ancestry checks
are defense in depth, not a substitute for the tag ruleset and required
environment review.

Before publishing, disposable Incus qualification must prove UEFI/serial boot,
strict seed install on a 128 GiB disk, first-boot pairing/fingerprint identity,
one-time credential scrub, adoption, HTTP/TFTP health, forward-only signed
update, interrupted-update rollback, identity-preserving repair, root/EFI
recovery with state/cache preservation, and safe unattended poweroff/detach.
Destroy the secret-bearing seed ISO after collecting redacted evidence.
The later exact-candidate smoke deliberately does not repeat destructive
installation: it proves the already-signed production ISO bytes boot to the
guided installer with the expected embedded version and production trust root.

## v0.1.2

Status: release qualification pending; production tag pending.

This is the governed update qualification target. The testbench builds the
exact `3479528d8e05036d70780d93207c3e835f3006be` source as Bookworm-compatible
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
