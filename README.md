# Cybex Boot

Cybex Boot is a UEFI-only PXE/iPXE boot control service. It does not run DHCP and does not implement a TFTP server. UniFi DHCP points clients at an external TFTP root for the first-stage UEFI iPXE loader, then iPXE chains to this Rust HTTP service for dynamic boot scripts.

## Architecture

- UniFi DHCP Option 66: Cybex Boot server IP or DNS name.
- UniFi DHCP Option 67: UEFI iPXE loader filename, for example `snponly.efi` or `ipxe.efi`.
- TFTP root: `/srv/cybex-boot/tftp`, serving only the first-stage UEFI loader.
- nginx public HTTP entrypoint on port 80, proxying boot endpoints to the local Rust service.
- Cybex Boot HTTP service on `127.0.0.1:8080`: dynamic iPXE scripts, health checks, and safe boot-asset file serving. Local admin UI/API routes are not exposed.
- SQLite database: `/var/lib/cybex-boot/cybex-boot.sqlite`.
- Boot assets: `/srv/cybex-boot/www`; ISOs are registered from `/srv/cybex-boot/www/isos`.
- Boot asset HTTP responses support single byte ranges for large kernels, initrds, and ISO-derived files.

Main boot endpoints:

- `GET /boot`
- `GET /boot.ipxe`
- `GET /boot/:mac`
- `GET /boot/by-serial/:serial`
- `GET /boot/select/:profile_id`

The recommended chain command from iPXE is:

```ipxe
chain http://CYBEX_BOOT_IP/boot.ipxe
```

Generated iPXE scripts are served with no-store headers so PXE clients and
intermediate proxies fetch current menu/profile state on each boot.
Unknown-device interactive menus use an iPXE text-mode Cybex theme that mirrors
the installer ISO bootloader palette: dark canvas, CYBEX title, muted metadata,
orange highlighted selection, and a timeout hint.
In nginx-fronted deployments, proxy `/boot.ipxe` as-is so query parameters such
as `mac` and `serial` survive to the Rust route.
Boot event metadata from public boot endpoints is bounded before storage or
reporting: serial query values are capped at 128 characters, user agents at
256 characters, control characters are replaced, and `X-Forwarded-For` is
trusted only from the loopback nginx proxy using the last valid forwarded IP.
Boot event storage is a rolling window capped at the newest 10000 events so
public boot probes cannot grow the SQLite database indefinitely.
Auto-discovered unmanaged PXE clients are also capped at the newest 2000 rows
that were observed through boot requests and remain uncurated. Managed clients,
manual rows, and locally curated rows with hostname, notes, tags, or profile
assignments are preserved.
Client metadata is bounded on managed paths: hostnames at 253
characters, serial numbers at 128 characters, notes at 2000 characters, and up
to 50 tags of 64 characters each.
Managed profile sync prunes the original unreferenced migration-seeded `Local
disk` fallback after a managed local-disk profile exists, so local profile lists
do not retain a duplicate fallback.
Profile descriptions are capped at 2000 characters and raw iPXE scripts at
64 KiB on managed profile paths.
Boot and file GET paths keep their route-specific caching behavior. Responses
include browser safety headers: `X-Content-Type-Options: nosniff`,
`X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, and a no-script
Content Security Policy.

## Build

```sh
cargo build --release
sudo install -m 0755 target/release/cybex-boot /usr/local/bin/cybex-boot
```

## Production Proxmox LXC Install

The production operator path starts in Cybex Manage. Open the Dashboard Forge
card, choose `Proxmox Host LXC`, enter the Boot server public base URL, keep or
adjust the LXC resource defaults, generate the one-time command, and run it as
root on the Proxmox host.

The generated command fetches `install/proxmox-host-lxc.sh` from the configured
Forge ref, creates a Debian/Ubuntu LXC, clones Forge into `/root/forge` inside
that LXC at the same ref, runs `install/cybex-boot-lxc-install.sh`, starts
Cybex Boot behind nginx/TFTP, submits the one-time Boot install authorization,
and leaves a pending `cybex-boot` enrollment in Manage. Adopt that pending
enrollment in Manage before treating the server as managed infrastructure.

Production installs should be pinned to a release tag such as `v0.1.0`, not to
the floating `main` branch. The Manage control plane controls this with
`CYBEX_FORGE_INSTALL_REF`; the generated command passes the value as
`--forge-ref`. Production install commands that reference a tag require the
Forge repository to be pushed and the referenced remote tag to exist.

Resource defaults are intentionally conservative for a small Boot server:

- root disk: `32 GiB`
- CPU cores: `2`
- memory: `4096 MiB`

The host helper needs root privileges on a Proxmox node and access to `pct`,
`pvesm`, `pveam`, `pvesh`, and `ip`. It chooses the next available VMID, the
first rootdir-capable storage, the first template-capable storage, `vmbr0` or
the first `vmbr*` bridge, and the newest cached/listed Debian 12 or Ubuntu
22.04/24.04 standard LXC template. Override those with `--vmid`, `--storage`,
`--template-storage`, `--bridge`, or `--template` when the defaults do not
match the host. The LXC uses DHCP on the selected bridge, so the network must
provide an address, a default route, and outbound HTTPS access to Manage,
GitHub, Debian/Ubuntu package mirrors, and rustup during install.

`--public-base-url` must be the URL PXE clients will use to reach the Boot LXC,
for example `http://10.10.0.239`. After adoption, configure DHCP option 66 to
the LXC IP or DNS name and option 67 to the configured bootloader filename
(`snponly.efi` by default). Cybex Boot does not run DHCP.

Custom `--tftp-root` and `--http-root` values must be separate,
non-overlapping paths below `/srv/cybex-boot`; this matches the managed runtime
apply boundary.

Both installers support non-mutating validation:

```sh
bash install/proxmox-host-lxc.sh --dry-run --api-url https://manage.example.com \
  --organization-id 550e8400-e29b-41d4-a716-446655440000 \
  --auth-code boot_redacted_one_time_code \
  --public-base-url http://10.10.0.239 \
  --forge-ref v0.1.0
```

The scripts do not print the one-time auth code in status output. It still
appears in the generated command and process arguments while installation is
running, so treat command transcripts as sensitive and redact secrets before
sharing evidence.

Useful post-install checks inside the LXC:

```sh
systemctl status cybex-boot nginx tftpd-hpa cybex-boot-runtime-apply.timer cybex-boot-check.timer
journalctl -u cybex-boot --no-pager -n 100
/usr/local/sbin/cybex-boot-check
cat /root/forge/.cybex-forge-revision
```

If the host wrapper fails after creating the LXC, it reports the partial VMID
and leaves it in place for inspection. Use `pct status <vmid>`,
`pct enter <vmid>`, and `pct exec <vmid> -- journalctl --no-pager -n 200` to
collect evidence before removing it with `pct destroy <vmid>`.

The Cybex Boot ISO method shown in Manage is a placeholder for a future
installer. It does not create supported production ISO media yet.

## Manual Service Install In A Proxmox LXC

Create a service user and directories:

```sh
sudo useradd --system --home /var/lib/cybex-boot --shell /usr/sbin/nologin cybex-boot
sudo mkdir -p /etc/cybex-boot /var/lib/cybex-boot /srv/cybex-boot/www/isos /srv/cybex-boot/www/assets /srv/cybex-boot/tftp
sudo chown -R cybex-boot:cybex-boot /var/lib/cybex-boot /srv/cybex-boot
sudo chmod 0700 /var/lib/cybex-boot
```

Install config and systemd unit:

```sh
sudo install -m 0640 -o root -g cybex-boot examples/config.toml /etc/cybex-boot/config.toml
sudo install -m 0644 systemd/cybex-boot.service /etc/systemd/system/cybex-boot.service
```

The packaged unit runs as the `cybex-boot` user with no Linux capabilities,
`NoNewPrivileges`, private devices/tmp, strict system protection,
kernel/control-group protections, namespace/realtime/SUID restrictions, native
syscall architecture, and write access limited to `/var/lib/cybex-boot` and
`/srv/cybex-boot`.
The private data/state/database directory is forced to owner-only `0700` on
startup, while public boot assets remain under `/srv/cybex-boot/www`.

Edit `/etc/cybex-boot/config.toml`:

- Set `server.public_base_url` to the nginx URL PXE clients use, for example `http://192.168.1.20`.
- Set `boot.bootloader_filename` to the file placed in `/srv/cybex-boot/tftp`.

Initialize and start:

```sh
sudo -u cybex-boot /usr/local/bin/cybex-boot --config /etc/cybex-boot/config.toml migrate
sudo systemctl daemon-reload
sudo systemctl enable --now cybex-boot
```

In the managed LXC deployment, nginx exposes only health, PXE, selection, and `/files/*` paths on port 80. Keep the Rust service bound to localhost. Do not serve arbitrary files from `/srv/cybex-boot/www` directly through nginx; boot assets should go through the Rust-controlled `/files/*` path. Direct `/login`, `/logout`, `/settings`, `/devices`, `/profiles`, `/isos`, and `/api/*` requests return `404`.

## Cybex Manage Enrollment

Cybex Boot enrolls into Cybex Manage as device kind `cybex-boot` with a one-time Boot install authorization. Create the authorization in Manage and run the generated Proxmox LXC command; it writes `[manage] organization_id` and `boot_install_code`, submits a pending enrollment, and then waits for normal adoption in Manage. After adoption, Manage becomes the source of truth for Boot profiles, known PXE clients, runtime settings, menu timeout, and reporting.

A managed config contains the organization UUID, not an organization slug:

```toml
[manage]
enabled = true
api_url = "https://manage.example.com"
organization_id = "550e8400-e29b-41d4-a716-446655440000"
boot_install_code = "boot_..."
state_path = "/var/lib/cybex-boot/manage-state.json"
sync_interval_seconds = 30
enrollment_poll_seconds = 10
http_timeout_seconds = 30
```

The long-running `serve` command submits and polls enrollment when managed mode is enabled. The root-owned `cybex-boot-runtime-apply.timer` runs `apply-runtime-config`, fetches signed desired runtime settings with the adopted Boot identity, rewrites root-owned nginx/TFTP/systemd/config files, rebuilds managed iPXE loader artifacts when needed, and restarts affected services. The Boot service itself remains unprivileged.

Pending enrollment uses `enrollment_poll_seconds`, and adopted servers use `sync_interval_seconds` for config/report cycles. After adoption it pulls `/v1/agent/devices/{device_id}/boot/config` and reports to `/v1/agent/devices/{device_id}/boot/report` with signed Ed25519 agent requests. Managed HTTP calls use `http_timeout_seconds` clamped to 1-300 seconds, so a stalled control-plane connection does not pin the sync loop indefinitely. Successful managed JSON responses are capped at 8 MiB before parsing. Managed settings reuse the local config validators for `public_base_url`, `listen_addr`, `tftp_root`, `http_root`, `bootloader_filename`, and `menu_timeout_ms`; unsafe listeners and paths are rejected, and configs above 500 profiles or 2000 clients are rejected. Managed profile/client config is validated before local mutation and committed through one SQLite transaction, so invalid references or duplicate IDs/MACs do not leave partially applied profiles or clients behind. Reports include `asset_scan_status`; if the local ISO scan fails, Cybex Boot reports `warning` with a bounded scan error while preserving the previous asset list. Boot event reports include the local SQLite event ID as `source_event_id` so Cybex Manage can deduplicate retried reports.
Managed state writes use owner-only temporary files in the private state
directory, sync the file contents before atomic rename, and sync the parent
directory after replacement.

Config loading validates `server.listen_addr` as an IP socket address, `server.public_base_url` and managed `api_url` as absolute HTTP(S) URLs with a host, no embedded credentials, and no query or fragment, `boot.bootloader_filename` as a simple filename, and `boot.menu_timeout_ms` as 1000-600000. Managed mode requires a valid `manage.api_url` and `manage.organization_id` for new Boot install-code enrollment; legacy `organization_slug` is accepted only as a compatibility fallback for already-adopted state.

## UniFi DHCP Setup

In the UniFi network DHCP options:

- Option 66: `CYBEX_BOOT_IP`
- Option 67: `snponly.efi` or `ipxe.efi`

Cybex Boot does not answer DHCP. Keep UniFi as the DHCP authority.

## TFTP Loader

Install and configure a TFTP daemon such as `tftpd-hpa` or `dnsmasq` TFTP mode with `/srv/cybex-boot/tftp` as the root, then place a UEFI iPXE loader there:

```sh
sudo install -m 0644 snponly.efi /srv/cybex-boot/tftp/snponly.efi
```

Option 67 must match that filename.

## Profiles

Profile types:

- `local_disk`: returns to UEFI firmware with `exit 0`.
- `linux_installer`: renders `kernel`, optional `initrd`, and `boot`.
- `iso_live`: tracks an ISO and can boot extracted netboot assets; direct UEFI ISO boot usually needs a raw iPXE override.
- `custom_ipxe`: serves the raw script override.

Paths such as `kernel_path`, `initrd_path`, and `iso_path` are relative to `/srv/cybex-boot/www`. Absolute paths and `..` traversal are rejected.
Profile names and `cmdline` must not contain control characters. `cmdline` is a single Linux kernel command line. Use `raw_script` only when an operator intentionally needs custom iPXE commands.

Unknown devices receive an interactive menu. A device’s first seen MAC is registered automatically, but that first request is still treated as unknown for boot selection. Known devices can use a default profile or a one-time profile. One-time profiles are marked consumed when the script is served.

## Local Management Surface

Cybex Boot managed installs do not expose a standalone admin UI or local JSON management API. Manage owns profiles, clients, assets, runtime settings, and adoption. Direct local `/login`, `/logout`, `/settings`, `/devices`, `/profiles`, `/isos`, and `/api/*` requests return `404`; `/healthz`, `/boot`, `/boot.ipxe`, `/boot/*`, `/boot/select/*`, and `/files/*` remain available.

`cybex-boot --config /etc/cybex-boot/config.toml print-config` emits redacted TOML on stdout without initializing runtime directories or mixing operational warnings into the output.

## Troubleshooting

- Client never downloads iPXE: check UniFi Option 66/67 and the external TFTP daemon.
- iPXE starts but scripts fail: run `chain http://CYBEX_BOOT_IP/boot.ipxe` from the iPXE shell.
- HTTP assets return 404: confirm files are under `/srv/cybex-boot/www` and profile paths are relative.
- One-time boot repeats: confirm the client is chaining through `/boot/${mac}` so Cybex Boot can identify the device.
- Local disk does not boot after `exit 0`: verify firmware boot order after PXE in the VM or physical host UEFI settings.
