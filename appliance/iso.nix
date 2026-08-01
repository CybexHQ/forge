{ config, lib, pkgs, modulesPath, forgePackage, targetSystem
, updateTrustedPublicKey, version, ... }:

let
  secureInput = pkgs.stdenv.mkDerivation {
    pname = "cybex-forge-secure-input";
    inherit version;
    dontUnpack = true;
    strictDeps = true;
    buildPhase = ''
      $CC -std=c11 -O2 -Wall -Wextra -Werror \
        ${./cybex-forge-secure-input.c} -o cybex-forge-secure-input
    '';
    installPhase = ''
      install -Dm0755 cybex-forge-secure-input "$out/bin/cybex-forge-secure-input"
    '';
  };
  installerRuntime = with pkgs; [
    bash coreutils dosfstools e2fsprogs findutils gawk gnugrep gnused
    gptfdisk nix nixos-install-tools openssh systemd util-linux
  ] ++ [ secureInput ];
  installer = pkgs.writeShellApplication {
    name = "cybex-forge-appliance-install";
    runtimeInputs = installerRuntime;
    text = builtins.readFile ./cybex-forge-appliance-install;
  };
  rescue = pkgs.writeShellApplication {
    name = "cybex-forge-appliance-rescue";
    runtimeInputs = installerRuntime;
    text = builtins.readFile ./cybex-forge-appliance-rescue;
  };
  entrypoint = pkgs.writeShellApplication {
    name = "cybex-forge-appliance-entrypoint";
    runtimeInputs = installerRuntime;
    text = builtins.readFile ./cybex-forge-appliance-entrypoint;
  };
in
{
  imports = [ (modulesPath + "/installer/cd-dvd/installation-cd-minimal.nix") ];

  nixpkgs.hostPlatform = "x86_64-linux";
  nixpkgs.config.allowUnfree = true;
  # The ISO builder still derives its output name from image.baseName even
  # though image.fileName is the public option. Set the base explicitly so the
  # on-disk artifact and signed-release contract cannot diverge.
  image.baseName = lib.mkForce "cybex-forge-appliance-${version}-x86_64-linux";
  isoImage.volumeID = lib.mkForce "CYBEX_FORGE_${lib.replaceStrings [ "." ] [ "_" ] version}";
  isoImage.makeEfiBootable = true;
  isoImage.makeUsbBootable = true;

  boot.kernelParams = lib.mkAfter [ "console=tty0" "console=ttyS0,115200n8" ];
  boot.zfs.forceImportRoot = false;
  networking.useDHCP = lib.mkForce true;
  networking.hostName = "cybex-forge-installer";
  virtualisation.incus.agent.enable = true;
  # The guided installer is the sole tty1 owner; a concurrent getty can steal
  # keystrokes or interleave destructive confirmation prompts.
  systemd.services."getty@tty1".enable = false;
  systemd.services."autovt@tty1".enable = false;
  services.getty.helpLine = ''
    Cybex Forge Appliance ${version}
    Guided setup starts on tty1. Rescue: cybex-forge-appliance-rescue --help
  '';

  environment.systemPackages = installerRuntime ++ [ installer rescue entrypoint forgePackage ];
  environment.etc."cybex-forge-appliance/update-trusted-public-key" = {
    text = updateTrustedPublicKey + "\n";
    mode = "0444";
  };
  environment.etc."cybex-forge-appliance/version" = {
    text = version + "\n";
    mode = "0444";
  };
  environment.etc."cybex-forge-appliance/target-system" = {
    text = toString targetSystem + "\n";
    mode = "0444";
  };
  environment.etc."cybex-forge-appliance/package-path" = {
    text = toString forgePackage + "\n";
    mode = "0444";
  };

  systemd.services.cybex-forge-seed-install = {
    description = "Cybex Forge unattended seed installer";
    wantedBy = [ "multi-user.target" ];
    after = [ "systemd-udev-settle.service" "network-online.target" ];
    wants = [ "systemd-udev-settle.service" "network-online.target" ];
    path = installerRuntime ++ [ installer entrypoint ];
    serviceConfig = {
      Type = "oneshot";
      ExecStart = "${entrypoint}/bin/cybex-forge-appliance-entrypoint";
      StandardOutput = "journal+console";
      StandardError = "journal+console";
      TimeoutStartSec = "0";
    };
  };

  systemd.services.cybex-forge-guided-install = {
    description = "Cybex Forge guided appliance installer";
    wantedBy = [ "multi-user.target" ];
    after = [ "cybex-forge-seed-install.service" ];
    requires = [ "cybex-forge-seed-install.service" ];
    before = [ "getty@tty1.service" "autovt@tty1.service" ];
    conflicts = [ "getty@tty1.service" "autovt@tty1.service" ];
    path = installerRuntime ++ [ installer ];
    serviceConfig = {
      Type = "idle";
      ExecCondition = "${pkgs.bash}/bin/bash -c '! ${pkgs.util-linux}/bin/blkid -t LABEL=CYBEX_FORGE_SEED -o device | ${pkgs.gnugrep}/bin/grep -q .'";
      ExecStartPre = "${pkgs.kbd}/bin/chvt 1";
      ExecStart = "${installer}/bin/cybex-forge-appliance-install";
      StandardInput = "tty-force";
      StandardOutput = "tty";
      StandardError = "tty";
      TTYPath = "/dev/tty1";
      TTYReset = true;
      TTYVHangup = true;
      TimeoutStartSec = "0";
    };
  };
}
