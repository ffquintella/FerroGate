//! Bundle TPM vendor root CAs at compile time.
//!
//! For each vendor directory under `vendor-roots/`, concatenate every `*.pem`
//! file into a single `<vendor>.pem` in `OUT_DIR`. `vendor.rs` then embeds
//! those via `include_str!`, so dropping a root into `vendor-roots/<vendor>/`
//! and rebuilding is all it takes to trust it — no code change required.

use std::{env, fs, path::Path};

const VENDORS: [&str; 4] = ["infineon", "nuvoton", "st", "intel"];

fn main() {
    let out_dir = env::var("OUT_DIR").expect("OUT_DIR set by cargo");
    let roots = Path::new(env!("CARGO_MANIFEST_DIR")).join("vendor-roots");
    println!("cargo:rerun-if-changed=vendor-roots");

    for vendor in VENDORS {
        let dir = roots.join(vendor);
        let mut bundle = String::new();

        if dir.is_dir() {
            let mut pems: Vec<_> = fs::read_dir(&dir)
                .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
                .filter_map(Result::ok)
                .map(|e| e.path())
                .filter(|p| p.extension().is_some_and(|ext| ext == "pem"))
                .collect();
            pems.sort();
            for pem in pems {
                println!("cargo:rerun-if-changed={}", pem.display());
                let contents = fs::read_to_string(&pem)
                    .unwrap_or_else(|e| panic!("read {}: {e}", pem.display()));
                bundle.push_str(&contents);
                if !bundle.ends_with('\n') {
                    bundle.push('\n');
                }
            }
        }

        let out = Path::new(&out_dir).join(format!("{vendor}.pem"));
        fs::write(&out, bundle).unwrap_or_else(|e| panic!("write {}: {e}", out.display()));
    }
}
