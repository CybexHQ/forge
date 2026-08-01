{ config, lib, pkgs, forgePackage, updateTrustedPublicKey, version, ... }:

let
  forgeUid = 980;
  forgePath = with pkgs; [
    bash binutils coreutils curl findutils gawk git gnumake gnugrep gnused
    iproute2 ipxe mtools nginx openssl perl pkg-config shadow sqlite
    squashfsTools systemd tftp-hpa util-linux xorriso xz zstd gcc
  ];
in
{
  assertions = [{
    assertion = updateTrustedPublicKey != "";
    message = "Cybex Forge appliance requires embedded release update trust";
  }];

  nixpkgs.config.allowUnfree = true;
  system.stateVersion = "25.11";
  networking.hostName = "cybex-forge";
  networking.useDHCP = lib.mkDefault true;
  networking.firewall = {
    enable = true;
    allowedTCPPorts = [ 22 80 ];
    allowedUDPPorts = [ 69 ];
  };

  boot.loader.systemd-boot.enable = true;
  boot.loader.efi.canTouchEfiVariables = false;
  boot.kernelParams = [ "console=tty0" "console=ttyS0,115200n8" ];
  # The EFI partition must remain mountable after switch-root, including on
  # virtual hardware where the filesystem alias is not automatically resolved
  # before local-fs.target starts.  Load vfat in the initrd and retain the
  # module for the installed system rather than relying on late autoloading.
  boot.initrd.kernelModules = [ "nls_ascii" "nls_cp437" "vfat" ];
  boot.initrd.availableKernelModules = [
    "ahci" "ata_piix" "nvme" "sd_mod" "sr_mod"
    "virtio_blk" "virtio_pci" "virtio_scsi" "xhci_pci"
  ];

  fileSystems."/" = {
    device = "/dev/disk/by-label/CYBEX_ROOT";
    fsType = "ext4";
  };
  fileSystems."/boot" = {
    device = "/dev/disk/by-label/CYBEX_EFI";
    fsType = "vfat";
    options = [ "fmask=0077" "dmask=0077" ];
  };
  fileSystems."/var/lib/cybex-forge" = {
    device = "/dev/disk/by-label/CYBEX_STATE";
    fsType = "ext4";
    options = [ "nodev" "nosuid" ];
  };
  fileSystems."/srv/cybex-forge" = {
    device = "/dev/disk/by-label/CYBEX_CACHE";
    fsType = "ext4";
    options = [ "nodev" "nosuid" ];
  };

  # If an operator reaches emergency mode, emit only bounded storage-unit
  # diagnostics on the serial console.  This intentionally excludes the Forge
  # service and configuration so enrollment material cannot enter the boot
  # transcript captured by remote consoles or qualification tooling.
  systemd.services.cybex-forge-boot-diagnostics = {
    description = "Cybex Forge boot storage diagnostics";
    wantedBy = [ "emergency.target" ];
    before = [ "emergency.service" ];
    unitConfig.DefaultDependencies = false;
    serviceConfig = {
      Type = "oneshot";
      StandardOutput = "tty";
      StandardError = "tty";
      TTYPath = "/dev/ttyS0";
      ExecStart = pkgs.writeShellScript "cybex-forge-boot-diagnostics" ''
        set -eu
        echo "CYBEX_FORGE_BOOT_DIAGNOSTIC status=storage-failure"
        ${pkgs.systemd}/bin/systemctl --no-pager --full status boot.mount || true
        ${pkgs.systemd}/bin/journalctl --no-pager --quiet -b -n 20 \
          -u boot.mount -u systemd-fsck@dev-disk-by\\x2dlabel-CYBEX_EFI.service || true
        ${pkgs.util-linux}/bin/dmesg --level=err,warn \
          | ${pkgs.coreutils}/bin/tail -n 20 || true
        ${pkgs.dosfstools}/bin/fsck.vfat -n \
          /dev/disk/by-label/CYBEX_EFI || true
      '';
    };
  };

  users.groups.cybex-forge.gid = forgeUid;
  users.groups.nix-users = { };
  users.users.cybex-forge = {
    isSystemUser = true;
    uid = forgeUid;
    group = "cybex-forge";
    home = "/var/lib/cybex-forge";
    createHome = false;
    extraGroups = [ "nix-users" ];
  };

  nix.settings = {
    auto-optimise-store = true;
    experimental-features = [ "nix-command" "flakes" ];
    allowed-users = [ "root" "cybex-forge" ];
    trusted-users = [ "root" ];
  };
  nix.gc = {
    automatic = true;
    dates = "daily";
    options = "--delete-older-than 7d";
  };

  # Build admission requires emergency swap headroom independently of RAM.
  # Keep it on the private state filesystem rather than the public cache.
  swapDevices = [{
    device = "/var/lib/cybex-forge/swapfile";
    size = 8192;
  }];

  environment.systemPackages = forgePath ++ [ forgePackage ];
  environment.etc."cybex-forge-appliance/update-trusted-public-key" = {
    text = updateTrustedPublicKey + "\n";
    mode = "0444";
  };
  environment.etc."cybex-forge-appliance/version" = {
    text = version + "\n";
    mode = "0444";
  };
  environment.etc."cybex-forge-appliance/package-path" = {
    text = toString forgePackage + "\n";
    mode = "0444";
  };

  system.activationScripts.cybexForgeMutableRuntime = lib.stringAfter [ "users" ] ''
    exact_single_line() {
      [ "$(wc -l < "$1" | tr -d '[:space:]')" = 1 ] \
        && [ "$(tail -c 1 -- "$1" | od -An -t u1 | tr -d '[:space:]')" = 10 ]
    }
    install -d -m 0750 -o root -g cybex-forge /etc/cybex-forge
    install -d -m 0700 -o cybex-forge -g cybex-forge \
      /var/lib/cybex-forge \
      /var/lib/cybex-forge/bootstrap /var/lib/cybex-forge/build \
      /var/lib/cybex-forge/build-outputs /var/lib/cybex-forge/cache \
      /var/lib/cybex-forge/updates
    if [ -L /var/lib/cybex-forge/appliance ] \
      || { [ -e /var/lib/cybex-forge/appliance ] \
        && [ ! -d /var/lib/cybex-forge/appliance ]; }; then
      echo "refusing unsafe Forge appliance recovery metadata path" >&2
      exit 1
    fi
    if [ -d /var/lib/cybex-forge/appliance ] \
      && [ "$(stat -c %u /var/lib/cybex-forge/appliance)" != 0 ]; then
      echo "refusing non-root-owned Forge appliance recovery metadata" >&2
      exit 1
    fi
    install -d -m 0700 -o root -g root /var/lib/cybex-forge/appliance
    if [ -L /var/lib/cybex-forge/appliance/ssh ] \
      || { [ -e /var/lib/cybex-forge/appliance/ssh ] \
        && [ ! -d /var/lib/cybex-forge/appliance/ssh ]; }; then
      echo "refusing unsafe Forge SSH identity directory" >&2
      exit 1
    fi
    if [ -d /var/lib/cybex-forge/appliance/ssh ] \
      && [ "$(stat -c %u /var/lib/cybex-forge/appliance/ssh)" != 0 ]; then
      echo "refusing non-root-owned Forge SSH identity directory" >&2
      exit 1
    fi
    install -d -m 0700 -o root -g root /var/lib/cybex-forge/appliance/ssh
    machine_id_backup=/var/lib/cybex-forge/appliance/machine-id
    if [ -e "$machine_id_backup" ] || [ -L "$machine_id_backup" ]; then
      [ ! -L "$machine_id_backup" ] && [ -f "$machine_id_backup" ] \
        && [ "$(stat -c %u:%a:%h:%s "$machine_id_backup")" = 0:600:1:33 ] \
        && exact_single_line "$machine_id_backup" \
        || { echo "refusing unsafe Forge machine-id backup" >&2; exit 1; }
      grep -Eq '^[0-9a-f]{32}$' "$machine_id_backup" \
        || { echo "refusing invalid Forge machine-id backup" >&2; exit 1; }
      [ "$(cat "$machine_id_backup")" != 00000000000000000000000000000000 ] \
        || { echo "refusing uninitialized Forge machine-id backup" >&2; exit 1; }
      install -m 0444 -o root -g root "$machine_id_backup" /etc/machine-id
    fi
    media_sequence=/var/lib/cybex-forge/appliance/media-sequence
    [ ! -L "$media_sequence" ] && [ -f "$media_sequence" ] \
      && [ "$(stat -c %u:%a:%h "$media_sequence")" = 0:600:1 ] \
      && [ "$(stat -c %s "$media_sequence")" -le 20 ] \
      && exact_single_line "$media_sequence" \
      && grep -Eq '^(0|[1-9][0-9]{0,18})$' "$media_sequence" \
      && [ "$(cat "$media_sequence")" -le 9223372036854775807 ] \
      || { echo "refusing unsafe Forge media sequence" >&2; exit 1; }
    authorized_key_backup=/var/lib/cybex-forge/appliance/root-authorized_keys
    if [ -e "$authorized_key_backup" ] || [ -L "$authorized_key_backup" ]; then
      [ ! -L "$authorized_key_backup" ] && [ -f "$authorized_key_backup" ] \
        && [ "$(stat -c %u:%a:%h "$authorized_key_backup")" = 0:600:1 ] \
        && [ "$(stat -c %s "$authorized_key_backup")" -le 8193 ] \
        && exact_single_line "$authorized_key_backup" \
        && ${pkgs.openssh}/bin/ssh-keygen -l -f "$authorized_key_backup" >/dev/null \
        || { echo "refusing unsafe Forge root authorized-key backup" >&2; exit 1; }
      install -d -m 0700 -o root -g root /root/.ssh
      install -m 0600 -o root -g root "$authorized_key_backup" /root/.ssh/authorized_keys
    fi
    install -d -m 0755 -o root -g cybex-forge /srv/cybex-forge
    install -d -m 0755 -o cybex-forge -g cybex-forge \
      /srv/cybex-forge/www /srv/cybex-forge/www/isos \
      /srv/cybex-forge/www/assets /srv/cybex-forge/www/cache \
      /srv/cybex-forge/build-work /srv/cybex-forge/build-outputs
    install -d -m 0555 -o root -g root /srv/cybex-forge/tftp
    install -d -m 0755 -o root -g root /opt/cybex-forge/releases /usr/local/bin /usr/local/sbin
    if [ ! -f /usr/local/src/ipxe/.cybex-forge-pinned-source ] \
      || [ "$(cat /usr/local/src/ipxe/.cybex-forge-pinned-source 2>/dev/null || true)" != "${pkgs.ipxe.src}" ] \
      || [ ! -f /usr/local/src/ipxe/src/Makefile ]; then
      rm -rf -- /usr/local/src/ipxe
      install -d -m 0755 -o root -g root /usr/local/src/ipxe
      cp -a --no-preserve=ownership ${pkgs.ipxe.src}/. /usr/local/src/ipxe/
      chmod -R u+rwX,go+rX,go-w /usr/local/src/ipxe
      printf '%s\n' '${pkgs.ipxe.src}' > /usr/local/src/ipxe/.cybex-forge-pinned-source
      chmod 0444 /usr/local/src/ipxe/.cybex-forge-pinned-source
    fi
    binary_recovery=/var/lib/cybex-forge/appliance/binary-recovery.json
    if [ -e "$binary_recovery" ] || [ -L "$binary_recovery" ]; then
      [ ! -L "$binary_recovery" ] && [ -f "$binary_recovery" ] \
        && [ "$(stat -c %u:%a:%h "$binary_recovery")" = 0:600:1 ] \
        && [ "$(stat -c %s "$binary_recovery")" -le 4096 ] \
        && grep -Fx '{"schema":"cybex.forge.appliance.binary-recovery.v1","embedded_version":"${version}","reason":"missing_or_nonexecutable"}' "$binary_recovery" >/dev/null \
        || { echo "refusing unsafe Forge binary-recovery journal" >&2; exit 1; }
    fi
    binary_needs_recovery=0
    if [ -L /usr/local/bin/cybex-forge ] \
      || [ ! -f /usr/local/bin/cybex-forge ] \
      || [ ! -x /usr/local/bin/cybex-forge ]; then
      binary_needs_recovery=1
    elif [ "$(stat -c %u:%a:%h /usr/local/bin/cybex-forge)" != 0:755:1 ]; then
      binary_needs_recovery=1
    fi
    if [ "$binary_needs_recovery" -eq 1 ]; then
      if [ ! -e "$binary_recovery" ] && [ ! -L "$binary_recovery" ]; then
        binary_recovery_tmp="$(mktemp /var/lib/cybex-forge/appliance/.binary-recovery.XXXXXX)"
        printf '%s\n' '{"schema":"cybex.forge.appliance.binary-recovery.v1","embedded_version":"${version}","reason":"missing_or_nonexecutable"}' > "$binary_recovery_tmp"
        chown root:root "$binary_recovery_tmp"
        chmod 0600 "$binary_recovery_tmp"
        sync -f "$binary_recovery_tmp"
        mv -- "$binary_recovery_tmp" "$binary_recovery"
        sync -f /var/lib/cybex-forge/appliance
      fi
      binary_tmp="$(mktemp /usr/local/bin/.cybex-forge-recovery.XXXXXX)"
      install -m 0755 -o root -g root ${forgePackage}/bin/cybex-forge "$binary_tmp"
      sync -f "$binary_tmp"
      mv -T -- "$binary_tmp" /usr/local/bin/cybex-forge
      sync -f /usr/local/bin
    fi
    install -m 0755 -o root -g root ${forgePackage}/libexec/cybex-forge-appliance-check /usr/local/bin/cybex-forge-check
    install -m 0755 -o root -g root ${forgePackage}/libexec/cybex-forge-sentinel /usr/local/bin/cybex-forge-sentinel
    install -m 0755 -o root -g root ${forgePackage}/libexec/cybex-forge-sync-once /usr/local/sbin/cybex-forge-sync-once
    install -m 0755 -o root -g root ${forgePackage}/libexec/cybex-forge-appliance-rescue /usr/local/sbin/cybex-forge-appliance-rescue
    install -m 0644 -o cybex-forge -g cybex-forge ${forgePackage}/share/cybex-forge/pxe-menu.png \
      /srv/cybex-forge/www/assets/pxe-menu.png
  '';

  services.resolved.enable = true;
  services.timesyncd.enable = true;
  # Enrollment signatures and TLS need a sane clock, but a disconnected,
  # already-adopted appliance must still recover its cached PXE service.
  systemd.services.systemd-time-wait-sync.serviceConfig.TimeoutStartSec = "60s";
  services.openssh = {
    enable = true;
    hostKeys = [{
      path = "/var/lib/cybex-forge/appliance/ssh/ssh_host_ed25519_key";
      type = "ed25519";
    }];
    settings = {
      PasswordAuthentication = false;
      KbdInteractiveAuthentication = false;
      PermitRootLogin = "prohibit-password";
    };
  };
  virtualisation.incus.agent.enable = true;

  services.nginx = {
    enable = true;
    appendHttpConfig = ''
      include /etc/nginx/sites-available/*;
    '';
  };

  systemd.services.tftpd-hpa = {
    description = "Cybex Forge TFTP service";
    wantedBy = [ "multi-user.target" ];
    after = [ "network.target" ];
    serviceConfig = {
      Type = "simple";
      Restart = "always";
      RestartSec = "2s";
      User = "cybex-forge";
      Group = "cybex-forge";
      AmbientCapabilities = [ "CAP_NET_BIND_SERVICE" "CAP_SYS_CHROOT" ];
      CapabilityBoundingSet = [ "CAP_NET_BIND_SERVICE" "CAP_SYS_CHROOT" ];
      NoNewPrivileges = true;
      ExecStart = "${pkgs.tftp-hpa}/bin/in.tftpd --foreground --ipv4 --secure --address 0.0.0.0:69 /srv/cybex-forge/tftp";
    };
  };

  systemd.slices.cybex-forge-control = {
    description = "Cybex Forge latency-sensitive services";
    sliceConfig = {
      CPUWeight = 1000;
      IOWeight = 1000;
    };
  };
  systemd.slices.cybex-forge-build = {
    description = "Cybex Forge resource-intensive build and cache work";
    sliceConfig = {
      CPUWeight = 25;
      IOWeight = 25;
      MemoryHigh = "80%";
      MemoryMax = "90%";
    };
  };
  systemd.services.nix-daemon.serviceConfig = {
    Slice = "cybex-forge-build.slice";
    CPUWeight = 25;
    IOWeight = 25;
    OOMScoreAdjust = 250;
  };

  systemd.services.cybex-forge-appliance-reconcile = {
    description = "Replay durable Cybex Forge appliance recovery journals";
    wantedBy = [ "multi-user.target" ];
    before = [ "cybex-forge.service" ];
    after = [ "local-fs.target" ];
    path = forgePath;
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
      # Activation restores the mutable executable and journals that recovery
      # before services start. Reconcile through that exact restored path so
      # the durable projection is tied to the binary that will actually run.
      ExecStart = "/usr/local/bin/cybex-forge --config /etc/cybex-forge/config.toml reconcile-appliance";
      UMask = "0077";
      StandardOutput = "journal+console";
      StandardError = "journal+console";
      CapabilityBoundingSet = [ "CAP_CHOWN" "CAP_DAC_OVERRIDE" "CAP_FOWNER" ];
      NoNewPrivileges = true;
      PrivateDevices = true;
      PrivateTmp = true;
      ProtectHome = true;
      ProtectSystem = "strict";
      ReadWritePaths = [ "/opt/cybex-forge" "/var/lib/cybex-forge" ];
      RestrictAddressFamilies = [ "AF_UNIX" ];
      RestrictNamespaces = true;
      RestrictRealtime = true;
      RestrictSUIDSGID = true;
      LockPersonality = true;
      MemoryDenyWriteExecute = true;
      SystemCallArchitectures = "native";
    };
  };

  systemd.services.cybex-forge = {
    description = "Cybex Forge appliance control service";
    wantedBy = [ "multi-user.target" ];
    requires = [ "cybex-forge-appliance-reconcile.service" ];
    after = [
      "cybex-forge-appliance-reconcile.service"
      "network-online.target" "time-sync.target" "nix-daemon.socket"
    ];
    wants = [ "network-online.target" "time-sync.target" "nix-daemon.socket" ];
    path = forgePath;
    environment.RUST_LOG = "cybex_forge=info,tower_http=warn";
    preStart = ''
      test -s /etc/cybex-forge/config.toml
      /usr/local/bin/cybex-forge --config /etc/cybex-forge/config.toml migrate
    '';
    serviceConfig = {
      Type = "notify";
      NotifyAccess = "all";
      WatchdogSec = "30s";
      User = "cybex-forge";
      Group = "cybex-forge";
      SupplementaryGroups = [ "nix-users" ];
      ExecStart = "/usr/local/bin/cybex-forge --config /etc/cybex-forge/config.toml serve";
      WorkingDirectory = "/var/lib/cybex-forge";
      Restart = "always";
      RestartSec = "3s";
      Slice = "cybex-forge-control.slice";
      CPUWeight = 1000;
      IOWeight = 1000;
      OOMScoreAdjust = -500;
      UMask = "0077";
      StandardOutput = "journal+console";
      StandardError = "journal+console";
      CapabilityBoundingSet = "";
      AmbientCapabilities = "";
      NoNewPrivileges = true;
      PrivateDevices = true;
      PrivateTmp = true;
      ProtectHome = true;
      ProtectSystem = "strict";
      ProtectClock = true;
      ProtectControlGroups = true;
      ProtectHostname = true;
      ProtectKernelLogs = true;
      ProtectKernelModules = true;
      ProtectKernelTunables = true;
      RemoveIPC = true;
      ReadWritePaths = [ "/var/lib/cybex-forge" "/srv/cybex-forge" ];
      RestrictAddressFamilies = [ "AF_UNIX" "AF_INET" "AF_INET6" "AF_NETLINK" ];
      RestrictNamespaces = true;
      RestrictRealtime = true;
      RestrictSUIDSGID = true;
      LockPersonality = true;
      MemoryDenyWriteExecute = true;
      SystemCallArchitectures = "native";
    };
  };

  systemd.services.cybex-forge-runtime-apply = {
    description = "Apply Cybex Forge managed runtime configuration";
    after = [ "network-online.target" "time-sync.target" ];
    wants = [ "network-online.target" "time-sync.target" ];
    path = forgePath;
    environment.CYBEX_FORGE_REQUIRE_PINNED_IPXE_SOURCE = "1";
    serviceConfig = {
      Type = "oneshot";
      ExecStart = "/usr/local/bin/cybex-forge --config /etc/cybex-forge/config.toml apply-runtime-config";
      WorkingDirectory = "/var/lib/cybex-forge";
      UMask = "0077";
      StandardOutput = "journal+console";
      StandardError = "journal+console";
      CapabilityBoundingSet = [
        "CAP_CHOWN" "CAP_DAC_OVERRIDE" "CAP_FOWNER" "CAP_NET_BIND_SERVICE"
        "CAP_SETGID" "CAP_SETUID" "CAP_SYS_ADMIN"
      ];
      NoNewPrivileges = true;
      PrivateDevices = true;
      PrivateTmp = true;
      ProtectHome = true;
      ProtectSystem = "full";
      ReadWritePaths = [
        "/etc/cybex-forge" "/etc/default" "/etc/nginx" "/etc/systemd/system"
        "/opt/cybex-forge" "/srv/cybex-forge" "/usr/local/bin"
        "/usr/local/src" "/var/lib/cybex-forge" "/run" "/tmp"
      ];
      RestrictAddressFamilies = [ "AF_INET" "AF_INET6" "AF_UNIX" ];
      RestrictNamespaces = true;
      RestrictRealtime = true;
      RestrictSUIDSGID = true;
      LockPersonality = true;
      SystemCallArchitectures = "native";
    };
  };
  systemd.timers.cybex-forge-runtime-apply = {
    wantedBy = [ "timers.target" ];
    timerConfig = {
      OnBootSec = "45s";
      OnUnitActiveSec = "60s";
      AccuracySec = "15s";
      Persistent = true;
    };
  };

  systemd.services.cybex-forge-sentinel = {
    description = "Cybex Forge self-healing availability sentinel";
    after = [ "cybex-forge.service" "nginx.service" "tftpd-hpa.service" ];
    path = forgePath;
    serviceConfig = {
      Type = "oneshot";
      ExecStart = "/usr/local/bin/cybex-forge-sentinel";
      UMask = "0077";
    };
  };
  systemd.timers.cybex-forge-sentinel = {
    wantedBy = [ "timers.target" ];
    timerConfig = {
      OnBootSec = "30s";
      OnUnitActiveSec = "30s";
      AccuracySec = "5s";
      Persistent = true;
    };
  };
}
