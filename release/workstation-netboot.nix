{ manageRepo
, system ? "x86_64-linux"
, sourceDateEpoch
}:

let
  sourcePin = builtins.fromJSON (builtins.readFile ./workstation-netboot-source.json);
  nixpkgsPin = import ./nixpkgs.nix;
  nixpkgs = builtins.fetchTarball {
    inherit (nixpkgsPin) url sha256;
  };
  runtimeVersion = builtins.replaceStrings [ "\n" ] [ "" ]
    (builtins.readFile (manageRepo + "/deploy/nixos/workstation-netboot-version"));
  sourceRevisionMatches = builtins.match "[0-9a-f]{40}" sourcePin.revision != null;
  nixpkgsRevisionMatches = builtins.match "[0-9a-f]{40}" nixpkgsPin.revision != null;
in
assert sourcePin.repository == "CybexHQ/manage";
assert sourceRevisionMatches;
assert nixpkgsRevisionMatches;
assert runtimeVersion == sourcePin.runtime_version;
import (manageRepo + "/deploy/nixos/cybex-installer-netboot.nix") {
  inherit nixpkgs system sourceDateEpoch;
  repoRoot = manageRepo;
  manageSourceRevision = sourcePin.revision;
  nixpkgsRevision = nixpkgsPin.revision;
}
