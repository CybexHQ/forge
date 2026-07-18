# Cybex Forge

Cybex Forge is the local companion appliance for [Cybex](https://cybex.net).
It runs inside customer infrastructure and provides local services that Cybex
Manage can orchestrate without moving customer-specific heavy work into the
SaaS control plane.

## Capabilities

Cybex Forge currently provides five managed local capabilities:

- Forge Boot (`boot_v1`): serves PXE/iPXE boot flows, installer ISOs, boot
  profiles, known clients, boot assets, and boot events.
- Forge Build (`builder_v1`): runs local Nix builds that Cybex Manage queues
  for configured and allowed targets.
- Forge Cache (`cache_v1`): publishes successful build outputs through a signed
  local Nix binary cache and reports cache metadata back to Cybex Manage.
- Verified System Release builder (`system_release_builder_v3`): compiles a
  protocol-5, server-fenced Blueprint and managed hardware baseline into an
  exact pinned NixOS generation, publishes its complete canonical closure
  graph, and signs observed build provenance with a dedicated Forge
  attestation key. This capability is fail-closed and is not advertised until
  the operator-pinned agent bundle, Nix, managed identity, cache signing key,
  and attestation key all validate.
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

Proxmox LXC is supported for Forge Boot and Build/Cache. Build/Cache requires at
least **16 GiB of memory**, 4 CPU cores, and 8 GiB of emergency swap; use 32 GiB
for heavy developer Blueprints. The default installer enforces those capacity
minimums, limits individual Nix derivations to four cores, and creates a narrow
generated Blueprint closure target in `[[build.targets]]`. Blueprint targets
must use an immutable 40-character nixpkgs commit. The installer validates the
pin and representative heavy browser outputs against `cache.nixos.org` before
starting Forge. Jobs and cache artifacts record the exact pin used, and capacity,
OOM, disk, timeout, and package failures are reported as distinct operator-facing
states. Capacity detection supports finite cgroup limits, `/proc/meminfo`, and
the LXC-virtualized `sysinfo(2)` fallback used when hardened systemd services
hide non-process procfs files. Add further targets deliberately instead of using a broad build
allowlist. Manual standalone installation is not currently supported.
Ordinary Blueprint jobs preserve immutable expected-state v1, v2, and v3
artifacts as bounded build metadata so an older revision remains cacheable;
the Verified System Release path is separate and accepts only the strict
compiler-v3 projection and BuildSpec v3 contract.

That installer/default-target pin is Forge infrastructure configuration. A
Verified System Release pin is separate release identity supplied in its strict
BuildSpec after Manage accepts it from the supported-pin catalog; Forge never
substitutes the infrastructure pin for that value. The current infrastructure
pin is intentionally aligned with the initial supported System Release fixture,
`8eeec934ae0dbeca3d7868c059568a65c08b2fc3`, so provisioning checks and the
initial release line exercise compatible package outputs. Future changes still
require the two identities to be reviewed independently.

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

Manage and Forge support protocol compatibility through version 5. Forge stays
on protocol 3 for legacy Boot/Build/Cache operation unless the complete
Verified System Release builder is enabled and ready. A ready Forge advertises
protocol 5, `system_release_builder_v3`, and its Ed25519 attestation identity as
one consistent readiness snapshot. Forge validates the allowed version range
before applying desired state, while Manage records and rejects incompatible
reports. The checked-in `protocol/compatibility.json` manifest is the release
contract and is tested against runtime constants in both repositories.

Verified System Release jobs accept only strict BuildSpec v3 input. Forge does
not execute Manage-supplied Nix: it renders a private Forge-owned flake from
bounded typed Blueprint data and `cybex.managed-baseline.v1`, pins the exact
nixpkgs commit and target system, and independently verifies the configured
managed-agent package, module, transition helper, and watchdog digests. Build
inputs are owner-only and removed after the job. Successful builds publish an
immutable, sorted closure manifest containing every recursively reachable store
path, NAR identity, size, and reference, plus a canonical signed provenance
envelope. Cache retention follows the full NARInfo reference graph and retains
the closure and evidence files together. Before reporting a `system_generation`
inventory row, Forge uploads the exact canonical closure to Manage over the
signed agent channel using a dedicated 16 MiB endpoint. The ordinary 3 MiB
report remains URL/hash-only. Forge durably records Manage's identity-bound ACK,
uploads at most four new closures per report cycle, and clears only the matching
ACKs for exact retry when Manage returns `428 Precondition Required`.

The compiler-v3 Forge Blueprint renderer is deliberately fail-closed on shape,
bounds, provenance, secrets, and unknown fields while supporting every current
Blueprint editor path. Manage publishes an immutable compatibility proof with
canonical source/typed digests, the exact compiled NixOS module, expected
state, captured-asset and governed-extension manifests, and sorted coverage.
Forge independently derives the projection and rejects any mismatch. Any
syntactically safe nixpkgs `package_ref` may select application content, so the
contract does not delete Docker, Hyprland, or non-Standard package choices.
`cybex-agent` remains a required non-nixpkgs sentinel.

For an admitted BuildSpec v3 job, Forge downloads only the compiled module,
assets, and approved extension bytes named by their exact digests through the
signed material endpoint. It refuses redirects, bounds each response, rehashes
all bytes, rechecks extension safety, renders captured desktop state into the
closure, and composes those inputs with the locally pinned generic Blueprint
runtime and managed baseline. Governed modules receive the same `byId`,
`byName`, and `byNameVersion` public parameter maps used by ordinary Manage
Blueprint application; duplicate names and aggregate extension material above
8 MiB fail closed. Its semantic-input digest excludes replica transport and
artifact identity and is bound by the release marker, while the full BuildSpec
digest remains in signed provenance.

Before enabling `[system_release]`, install the trusted agent package in the
Nix store and the three Forge-controlled support files, then configure their
exact version and SHA-256 values along with explicit attestation key paths. On
first enabled startup Forge creates the dedicated key pair only when both files
are absent; partial, incorrectly owned, or incorrectly permissioned key pairs
leave protocol 5 disabled.

Managed Forge must use an `https://` Manage API URL before System Releases can
be enabled. The signed device request authenticates Forge to Manage; TLS
authenticates the desired-state and acknowledgement responses back to Forge.
Forge never follows redirects on managed control, reporting, enrollment, or ISO
download requests and rejects a response whose final endpoint differs from the
exact configured URL. Legacy managed mode may still use an explicit HTTP URL
while System Releases remain disabled.

The LXC installer provides a reproducible provisioning surface for this bundle.
Pass `--enable-system-releases` together with `--agent-version`,
`--agent-package`, `--agent-package-sha256`, `--agent-module`,
`--agent-module-sha256`, `--transition-helper`,
`--transition-helper-sha256`, `--release-watchdog`, and
`--release-watchdog-sha256` (matching `CYBEX_FORGE_*` environment variables are
also supported). It verifies every digest, installs the module and helpers as
root-owned read-only files under `/etc/cybex-forge/system-release`, and creates
a Nix GC root for the exact agent package. The package digest is the lowercase
output of:

```sh
nix hash path --type sha256 --base16 /nix/store/<hash>-cybex-agent
```

The module and helper digests are ordinary raw-file `sha256sum` values. Cybex
Manage must be configured with the same version and four digests; a mismatch
fails the job and keeps Forge from advertising protocol 5. The trusted paths
are local operator configuration and are never accepted from a BuildSpec.

Protocol-5 peers negotiate `cybex.forge-reporting.v1` without changing the
component protocol. Forge reports its persistent cache-inventory instance and
mutation generation in pages of at most 500 under a 3 MiB envelope, advances
the cursor only from Manage's committed ACK, and never marks a truncated page
complete. All active jobs remain in the report; safe logs and lower-priority
unacknowledged terminal history are trimmed before new System Release terminal
evidence, and acknowledged terminal jobs become eligible for local pruning only
after their durable SQLite ACK. Cache artifacts are producer-bounded so one
oversized identity/provenance object is rejected rather than silently omitted.

Manage returns protected current-Blueprint and System Release keys in matching
snapshot-fenced pages. Forge stages them durably, atomically replaces the
authoritative protection set only after the exact final page, and inhibits
retention or management-requested deletion while a page sequence is partial,
restarted, or out of order. Bounded cache scrubs remove invalid
NAR/NARInfo rows for automatic rebuild. Managed Organization ISOs retry
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

Managed installs enable `[update]` by default. Cybex Manage discovers the latest
release manifest, shows an `Update available` badge for adopted Forge nodes that
advertise `updater_v1`, and sends the selected update through the signed managed
config endpoint. Forge stores the request, reports progress back to Manage, and
the root `cybex-forge-runtime-apply.timer` performs the privileged apply.

The release manifest asset is JSON:

```json
{
  "schema": "cybex.forge.release.v1",
  "version": "v0.1.0",
  "release_url": "https://github.com/CybexHQ/forge/releases/tag/v0.1.0",
  "notes_url": "https://github.com/CybexHQ/forge/releases/tag/v0.1.0",
  "published_at": "2026-07-06T00:00:00Z",
  "artifact": {
    "url": "https://github.com/CybexHQ/forge/releases/download/v0.1.0/cybex-forge-x86_64-linux",
    "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  },
  "signature": ""
}
```

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
Manage-owned listener changes. On restart or health failure, Forge restores the
previous binary and reports `rolled_back`. Backups and staged binaries from
earlier attempts are pruned after each apply.

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
