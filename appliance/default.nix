{ system ? "x86_64-linux"
, nixpkgs ? builtins.fetchTarball {
    url = "https://github.com/NixOS/nixpkgs/archive/74cc63f702f7d60a557e152a57b40fb1fd0f72ac.tar.gz";
    sha256 = "102brk31m46v3p5n630zdl230ni0hjxrigc6n601k10rds8dqyfi";
  }
, updateTrustedPublicKey ? ""
}:

let
  pkgs = import nixpkgs { inherit system; };
  lib = pkgs.lib;
  cargo = builtins.fromTOML (builtins.readFile ../Cargo.toml);
  version = cargo.package.version;
  source = lib.cleanSourceWith {
    src = ../.;
    filter = path: type:
      let name = baseNameOf path;
      in !(name == ".git" || name == "target" || name == "result"
        || name == "__pycache__" || lib.hasSuffix ".pyc" name
        || lib.hasPrefix "result-" name || lib.hasPrefix ".env" name);
  };

  # Forge updates are a single signed executable, so produce a static binary.
  # The package is also retained by the appliance system as the recovery copy.
  package = pkgs.pkgsStatic.rustPlatform.buildRustPackage {
    pname = "cybex-forge";
    inherit version;
    src = source;
    cargoLock.lockFile = ../Cargo.lock;
    strictDeps = true;
    doCheck = false;
    postInstall = ''
      install -Dm0644 ${../LICENSE} "$out/share/licenses/cybex-forge/LICENSE"
      install -Dm0644 ${../assets/pxe-menu.png} "$out/share/cybex-forge/pxe-menu.png"
      install -Dm0755 ${../install/cybex-forge-check} "$out/libexec/cybex-forge-check"
      install -Dm0755 ${../install/cybex-forge-sentinel} "$out/libexec/cybex-forge-sentinel"
      install -Dm0755 ${../install/cybex-forge-sync-once} "$out/libexec/cybex-forge-sync-once"
      install -Dm0755 ${./cybex-forge-appliance-rescue} "$out/libexec/cybex-forge-appliance-rescue"
      install -Dm0755 ${./cybex-forge-appliance-check} "$out/libexec/cybex-forge-appliance-check"
    '';
    meta = {
      description = cargo.package.description;
      platforms = [ "x86_64-linux" ];
      mainProgram = "cybex-forge";
    };
  };

  evalNixos = modules: specialArgs: import (nixpkgs + "/nixos/lib/eval-config.nix") {
    inherit system modules specialArgs;
  };

  target = evalNixos [ ./module.nix ] {
      forgePackage = package;
      inherit updateTrustedPublicKey version;
  };

  installer = evalNixos [ ./iso.nix ] {
      forgePackage = package;
      targetSystem = target.config.system.build.toplevel;
      inherit updateTrustedPublicKey version;
  };

  trustedKeyLooksCanonical =
    builtins.stringLength updateTrustedPublicKey == 44
    && builtins.match "[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=" updateTrustedPublicKey != null;
  weakTrustedPublicKeys = lib.filter (value: value != "")
    (lib.splitString "\n" (builtins.readFile ../trust/ed25519-weak-public-keys.txt));
  trustedKeyIsStrong = !(builtins.elem updateTrustedPublicKey weakTrustedPublicKeys);
  trustedKeyAssertion = lib.assertMsg
    (trustedKeyLooksCanonical && trustedKeyIsStrong)
    "appliance requires canonical Base64 for a non-weak raw 32-byte Ed25519 update key";
in
{
  inherit package;
  applianceSystem = assert trustedKeyAssertion; target.config.system.build.toplevel;
  installerIso =
    assert trustedKeyAssertion;
    installer.config.system.build.isoImage;
}
