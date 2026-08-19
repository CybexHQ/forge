use std::{env, fs, path::PathBuf};

fn main() {
    const PIN_FILE: &str = "release/nixpkgs.nix";
    println!("cargo:rerun-if-changed={PIN_FILE}");
    println!("cargo:rerun-if-env-changed=CYBEX_JAMES_BUILD_MANAGE_ORIGIN");
    let source = fs::read_to_string(
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("Cargo manifest directory"))
            .join(PIN_FILE),
    )
    .expect("read canonical release nixpkgs pin");
    let revisions = source
        .lines()
        .filter_map(|line| {
            line.trim()
                .strip_prefix("revision = \"")
                .and_then(|value| value.strip_suffix("\";"))
        })
        .collect::<Vec<_>>();
    assert_eq!(
        revisions.len(),
        1,
        "release/nixpkgs.nix must declare exactly one revision"
    );
    let revision = revisions[0];
    assert!(
        revision.len() == 40
            && revision
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
        "release/nixpkgs.nix revision must be a canonical lowercase 40-character commit"
    );
    assert!(
        source.contains(&format!(
            "url = \"https://github.com/NixOS/nixpkgs/archive/{revision}.tar.gz\";"
        )),
        "release nixpkgs URL must carry the exact declared revision"
    );
    println!("cargo:rustc-env=CYBEX_RELEASE_NIXPKGS_REVISION={revision}");
}
