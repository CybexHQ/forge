# Cybex Forge

Cybex Forge is the local companion appliance for [Cybex](https://cybex.net).
It runs inside customer infrastructure and provides local services that Cybex
Manage can orchestrate without moving customer-specific heavy work into the
SaaS control plane.

## Capabilities

Cybex Forge currently provides four managed local capabilities:

- Forge Boot (`boot_v1`): serves PXE/iPXE boot flows, installer ISOs, boot
  profiles, known clients, boot assets, and boot events.
- Forge Build (`builder_v1`): runs local Nix builds that Cybex Manage queues
  for configured and allowed targets.
- Forge Cache (`cache_v1`): publishes successful build outputs through a signed
  local Nix binary cache and reports cache metadata back to Cybex Manage.
- Forge updater (`updater_v1`): applies Manage-approved release updates locally
  with artifact verification, service restart, health check, and rollback.

Cybex Forge is not a standalone infrastructure management product. It is
designed to work only with the Cybex commercial SaaS platform, including Cybex
Manage at [manage.cybex.net](https://manage.cybex.net). Profiles, device
enrollment, runtime settings, desired Build jobs, artifact metadata, and
reporting are controlled by Cybex Manage.

Default PXE requests render a non-timed iPXE menu because `menu_timeout_ms`
defaults to `0`. The first entry boots the local disk, and the server default
profile, normally `Default Enrollment`, is listed next. Explicit per-client
one-time or default profile assignments still bypass the menu and boot the
assigned profile directly.

After each atomic managed-config transaction, Boot reports the Manage client
UUID and the exact managed default/one-time profile UUIDs resolved from its
committed SQLite rows. These optional protocol-v3 fields let Manage prove that
a destructive network-reinstall assignment was locally applied before it
queues a reboot. The fields are additive: older Manage releases ignore them,
while newer Manage releases safely leave destructive requests armed when an
older Forge omits them.

Forge also signs the exact JSON bytes of its initial enrollment request with
its generated Ed25519 key. The request uses the same timestamp, request ID,
body hash, and signature contract as managed agent calls, but omits a device ID
because Manage has not assigned one yet. This proof lets Manage retry a lost
enrollment response without allowing an anonymous public-key replay to replace
the pending polling secret or reported identity. Pending status polls prove the
same key with a signed, empty-body `GET` over the exact enrollment status path;
they omit the not-yet-assigned device ID and retain the polling token only for
compatibility with older Manage releases. Forge creates and exclusively locks
`<state_path>.lock` before loading enrollment state, so the service and one-shot
commands cannot race key creation, credential rotation, or adoption persistence.
On Unix the lock is opened without following symlinks, verified as a regular
file, and secured through the opened file descriptor before it is locked.

## Installation

Installation is currently supported only through the Proxmox installer generated
inside Cybex Manage:

1. Sign in to [manage.cybex.net](https://manage.cybex.net).
2. Open the Forge installer flow.
3. Choose the Proxmox installer.
4. Run the generated command on your Proxmox host.

The installer creates and configures the Cybex Forge service, installs the
local Nix toolchain used by Forge Build/Cache and installer ISO builds, grants
the service account Nix daemon access, auto-detects the LXC LAN address for the
initial Boot URL, enrolls it with Cybex Manage, and keeps the local Forge node
managed by Cybex.
The installer uses Debian's Nix package to bootstrap `/nix/var/nix/profiles/default/bin/nix`
to a current Nix release, and Forge Build uses that profile binary for managed
flake builds.

The generated Proxmox helper and the in-LXC installer accept
`--update-trusted-public-key` (or
`CYBEX_FORGE_UPDATE_TRUSTED_PUBLIC_KEY`) for the canonical standard-Base64
encoding of a raw 32-byte Ed25519 public key. This value is public material and
is written to `update.trusted_public_key`; the corresponding private release key
must never be copied to Manage, a Forge node, an installer command, or test
evidence. Omitting the public key is supported, but the updater then fails
closed and Forge refuses every managed update.

Proxmox LXC is supported for Forge Boot and Build/Cache. Build/Cache requires at
least **16 GiB of memory**, 4 CPU cores, and 8 GiB of emergency swap; use 32 GiB
for heavy developer Blueprints. The default installer enforces those capacity
minimums, limits individual Nix derivations to four cores, and creates a narrow
generated Blueprint closure target in `[[build.targets]]`. Blueprint targets
must use an immutable 40-character nixpkgs commit, and Forge rejects a managed
build request whose `nixpkgs_commit` differs from that configured target. The
installer validates the pin and representative heavy browser outputs against `cache.nixos.org` before
starting Forge. Jobs and cache artifacts record the exact pin used, and capacity,
OOM, disk, timeout, and package failures are reported as distinct operator-facing
states. Capacity detection supports finite cgroup limits, `/proc/meminfo`, and
the LXC-virtualized `sysinfo(2)` fallback used when hardened systemd services
hide non-process procfs files. Add further targets deliberately instead of using a broad build
allowlist. Manual standalone installation is not currently supported.

When a Blueprint disables source builds, Forge evaluates its closure in a
fresh isolated local Nix store before the real build. Every advertised local
derivation must either be a plain fixed-output fetch or match reviewed native
NixOS materialization bytes executed by the pinned stdenv/default builder;
the exact Bash provider and each allowed generator tool/output are pinned.
Forge carries the complete dry-run derivation set into this decision, so a
locally built shell, compiler, hook, or same-named replacement tool cannot hide
inside otherwise reviewed glue. Configuration-only derivations are admitted in
a bounded dependency fixed point, so reviewed glue may consume already proven
glue while dependency cycles and source-building leaves remain rejected.
Source-disabled preflight and real builds also reject flake-provided Nix config
and disable import from derivation at command-line precedence, so evaluation
cannot re-enable or realize hidden work before the advertised derivation set is
classified.
Unknown output, malformed structured attrs,
truncated listings, extra tools/hooks, traversal paths, and executable
environment injection fail closed. Subprocess output is captured concurrently
with byte and time limits enforced while it is read. This prevents an output
already present in Forge's normal store from hiding a source requirement.
Prefer a cache-backed native nixpkgs package or a native NixOS option first;
enable source builds only as an explicit Blueprint fallback when no source-free
replacement exists. A nixpkgs pin refresh must include review and deliberate
refresh of materializer, executable-path, and tool-provider fingerprints—names
such as `runCommand` or `preferLocalBuild` are not provenance.

## Availability and self-healing

Forge keeps PXE availability on a latency-sensitive systemd slice while Nix
build/cache work runs in a separately throttled slice. The Forge process uses
systemd readiness notification and a 30-second watchdog; Forge, nginx, TFTP,
Nix, and `systemd-resolved` have unlimited restart attempts rather than a
permanent start-limit failure. A hardened sentinel runs every 30 seconds,
checks DNS, Manage reachability, the local backend, nginx PXE, and TFTP, and
repairs failed local services. Manage outages are recorded but do not cause
cached local PXE assets to be removed or disabled.

The sentinel atomically persists a bounded, non-secret incident summary at
`/var/lib/cybex-forge/reliability-state.json`. Managed reports expose that
summary to Cybex Manage, including the failing component, consecutive failures,
repair count, and recovery timestamp. The hourly comprehensive checker remains
independent and verifies deeper security, configuration, HTTP, and TFTP
invariants without requiring fixed operator-selected build capacity values.

Managed runtime settings are serialized with a root-only lock. Forge backs up
all managed configuration files, installs changes atomically, validates nginx,
restarts and verifies all local boot services, probes cached PXE, and restores
the previous files and services if any stage fails.

Managed ISO synchronization runs in a durable worker separate from the control
and report loop. Each desired profile carries a generation and operation UUID;
local state transitions and reports use both values, so a late completion can
never overwrite a newer request. The worker recovers interrupted `syncing`
state, retries temporary failures with bounded backoff, resumes a stable partial
file with HTTP Range, verifies the expected size and SHA-256, fsyncs it, and
atomically promotes a content-addressed filename before updating Boot config.
Control-plane heartbeats continue while a multi-gigabyte ISO is downloading.

Manage and Forge exchange protocol compatibility version 3 in both config and
reports. Forge validates the allowed version range before applying desired
state, while Manage records and rejects incompatible reports. The checked-in
`protocol/compatibility.json` manifest is the release contract and is tested
against runtime constants in both repositories.

Forge reports a persistent cache-inventory instance and mutation generation,
and marks a snapshot complete only when every artifact fits in the signed
report. Manage returns protected current-Blueprint keys, so local retention
cannot evict rollout-critical artifacts. Bounded cache scrubs remove invalid
NAR/NARInfo rows for automatic rebuild. Cache export, inventory publication,
deletion, retention, and scrubbing share one cross-process mutation lock, so a
sync sweep cannot remove an export before its SQLite row is committed.
Retention evicts unprotected artifacts oldest-first, preferring recent completed
builds until capacity requires them; active builds and Manage-desired artifacts
remain hard-protected and produce an explicit warning if they alone exceed the
configured capacity. Managed Organization ISOs retry
transient failures with capped backoff, periodically reverify ready bytes, and
garbage-collect only unreferenced content-addressed files after a grace period.
Boot asset inventory scans persist each ISO's device, inode, size, modification
time, change time, and last checksum-verification time. New, replaced, or
modified media is SHA-256 hashed immediately; unchanged media reuses its durable
checksum, with periodic full verification bounded to one unchanged ISO per
inventory pass. Reports include the exact normalized absolute path and the
Forge-local first-discovery time for each ISO so Manage can present copyable
filesystem identity without treating its own receipt time as file creation.
This keeps the 30-second control heartbeat lightweight even
while multiple multi-gigabyte ISO generations are inside the garbage-collection
grace period.

The self-healing units, slices, resolver/service drop-ins, and sentinel script
are embedded in the Forge binary's privileged runtime apply plan. Existing
managed nodes therefore adopt the same availability baseline after a verified
binary update; reliability is not limited to newly provisioned appliances.

## Managed Updates

Managed installs enable `[update]` by default. A node advertises `updater_v1`
only when it also has a valid trusted Ed25519 public key. Cybex Manage discovers
the latest release manifest, shows an `Update available` badge for eligible
adopted Forge nodes, and sends the selected update through the signed managed
config endpoint. Forge stores the request, reports progress back to Manage, and
the root `cybex-forge-runtime-apply.timer` performs the privileged apply.

The release manifest asset is JSON:

```json
{
  "schema": "cybex.forge.release.v1",
  "version": "0.1.1",
  "release_url": "https://github.com/CybexHQ/forge/releases/tag/v0.1.1",
  "notes_url": "https://github.com/CybexHQ/forge/releases/tag/v0.1.1",
  "published_at": "2026-07-23T12:00:00Z",
  "artifact": {
    "url": "https://github.com/CybexHQ/forge/releases/download/v0.1.1/cybex-forge-x86_64-linux",
    "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  },
  "signature": "replace-with-standard-base64-ed25519-signature"
}
```

Manifest `version` is the exact canonical Cargo SemVer reported by the binary,
without the Git tag's leading `v`. Build manifests with the checked-in tool; it
hashes the already-built artifact, signs the exact update message, self-verifies
the Ed25519 signature, and atomically writes deterministic JSON. It refuses
symlinked input, a non-Ed25519 key, or a private key that grants group/other
access. `--published-at` is deliberately explicit so identical inputs produce
identical output.

```bash
install -d -m 0700 /secure/operator-owned/forge-release
umask 077
openssl genpkey -algorithm ED25519 \
  -out /secure/operator-owned/forge-release/release-key.pem

tools/forge-release.py public-key \
  --private-key /secure/operator-owned/forge-release/release-key.pem

tools/forge-release.py manifest \
  --artifact dist/cybex-forge-x86_64-linux \
  --artifact-url https://github.com/CybexHQ/forge/releases/download/v0.1.1/cybex-forge-x86_64-linux \
  --version 0.1.1 \
  --private-key /secure/operator-owned/forge-release/release-key.pem \
  --output dist/cybex-forge-release.json \
  --release-url https://github.com/CybexHQ/forge/releases/tag/v0.1.1 \
  --notes-url https://github.com/CybexHQ/forge/releases/tag/v0.1.1 \
  --published-at 2026-07-23T12:00:00Z
```

The example key directory is illustrative. Use the approved release-key store
in each environment, retain it outside the repository and release artifacts,
and provision only the `public-key` command's output into installers.

Forge first verifies the request's Ed25519 signature against
`update.trusted_public_key` (the signature covers version, sha256, and artifact
URL, so nothing is downloaded for an unsigned request; an empty
`trusted_public_key` refuses updates outright), then downloads to
`update.work_dir` after a free-disk preflight, enforces
`max_artifact_size_bytes`, verifies the SHA-256, stages the binary under
`releases_dir`, smoke tests it with `--config <config_path> print-config`,
atomically replaces `binary_path`, restarts `service_name`, and waits for
`health_url`. Leave `health_url` empty in config to derive it from
`server.listen_addr`; managed config rendering keeps it aligned with
Manage-owned listener changes. Any failure after candidate activation begins
causes Forge to restore the previous binary and restart the restored service.
Forge reports `rolled_back` only after both restoration and that restart
succeed. A restoration or restored-binary restart failure is reported as a
terminal failure whose reason starts with `rollback_failed:`; durable apply
state and its backup remain for explicit recovery and must not be interpreted as
a successful rollback. Backups and staged binaries from earlier completed
attempts are pruned after each apply.

When signing is enabled, sign this exact message:

```text
version + "\n" + sha256 + "\n" + artifact_url + "\n"
```

## Source And License

The source code is published as source-available for transparency,
auditability, and trust.

Cybex is a commercial SaaS product. This repository is not licensed under MIT or
another permissive open-source license. Use, modification, and deployment are
limited to Cybex-connected installations under the terms in [LICENSE](LICENSE).
