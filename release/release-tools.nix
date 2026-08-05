{ system ? builtins.currentSystem }:

let
  nixpkgsPin = import ./nixpkgs.nix;
  nixpkgs = builtins.fetchTarball {
    inherit (nixpkgsPin) url sha256;
  };
  pkgs = import nixpkgs { inherit system; };
in
pkgs.mkShellNoCC {
  packages = with pkgs; [
    dracut
    gnutar
    squashfsTools
    zstd
  ];
}
