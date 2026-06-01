//! F13 CLI integration: the `fleet-manifest` tool can derive a publisher key,
//! build a manifest, add/remove EK hashes, sign it, and the result both
//! verifies through the tool's `verify` subcommand and parses + authenticates
//! through the library types CMIS uses at load time.

use std::path::PathBuf;
use std::process::Command;

use cmis::fleet_manifest::SignedFleetManifest;
use ferro_attest::TrustedKeys;
use ferro_crypto::composite::CompositePublicKey;

/// Path to the freshly-built `fleet-manifest` binary under test.
fn bin() -> PathBuf {
    // `CARGO_BIN_EXE_<name>` is set by cargo for integration tests of a crate
    // that defines the binary.
    PathBuf::from(env!("CARGO_BIN_EXE_fleet-manifest"))
}

fn tmpdir(tag: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    p.push(format!("ferrogate-fleet-cli-{tag}-{nanos}"));
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn run(args: &[&str]) -> (bool, String, String) {
    let out = Command::new(bin()).args(args).output().unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn full_lifecycle_keygen_edit_sign_verify() {
    let dir = tmpdir("lifecycle");
    let manifest = dir.join("manifest.json");
    let signed = dir.join("signed.json");
    let manifest_s = manifest.to_str().unwrap();
    let signed_s = signed.to_str().unwrap();

    // A fixed seed makes the publisher key reproducible across runs.
    let seed = "1".repeat(64);
    let (ok, stdout, _) = run(&["keygen", "--seed", &seed]);
    assert!(ok, "keygen failed");
    let pubkey = stdout
        .lines()
        .find_map(|l| l.strip_prefix("pubkey "))
        .expect("keygen prints pubkey")
        .trim()
        .to_string();

    // Build an empty manifest, then add two EK hashes and remove one.
    let ek_a = hex::encode([0xAAu8; 48]);
    let ek_b = hex::encode([0xBBu8; 48]);
    assert!(
        run(&[
            "new",
            "--version",
            "7",
            "--trust-domain",
            "ferrogate.test",
            "--issued-at",
            "1700000000",
            "--out",
            manifest_s,
        ])
        .0
    );
    assert!(run(&["add", "--manifest", manifest_s, "--ek", &ek_a, "--ek", &ek_b]).0);
    assert!(run(&["remove", "--manifest", manifest_s, "--ek", &ek_b]).0);

    // Sign with the seed; emit the signed bundle.
    assert!(
        run(&[
            "sign",
            "--manifest",
            manifest_s,
            "--seed",
            &seed,
            "--kid",
            "fleet-pub-1",
            "--out",
            signed_s,
        ])
        .0,
        "sign failed"
    );

    // The tool's own verify accepts it under the matching kid + pubkey.
    let (ok, stdout, stderr) = run(&[
        "verify",
        "--signed",
        signed_s,
        "--kid",
        "fleet-pub-1",
        "--pub",
        &pubkey,
    ]);
    assert!(ok, "verify failed: {stderr}");
    assert!(stdout.contains("v7"), "verify reports version: {stdout}");

    // And the library path CMIS uses authenticates the same bundle.
    let bytes = std::fs::read(&signed).unwrap();
    let parsed = SignedFleetManifest::from_json(&bytes).unwrap();
    let pk = CompositePublicKey::from_concat_bytes(&hex::decode(&pubkey).unwrap()).unwrap();
    let mut trust = TrustedKeys::new();
    trust.add("fleet-pub-1", pk);
    let m = parsed.verify(&trust).expect("library verify");
    assert_eq!(m.version, 7);
    assert_eq!(m.enrolled_ek_sha384, vec![ek_a]); // ek_b was removed

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn verify_rejects_wrong_key() {
    let dir = tmpdir("wrongkey");
    let manifest = dir.join("m.json");
    let signed = dir.join("s.json");
    let m = manifest.to_str().unwrap();
    let s = signed.to_str().unwrap();

    let seed = "2".repeat(64);
    run(&["new", "--version", "1", "--trust-domain", "t", "--out", m]);
    run(&[
        "sign", "--manifest", m, "--seed", &seed, "--kid", "k", "--out", s,
    ]);

    // A pubkey from a *different* seed must fail verification.
    let (_, other_stdout, _) = run(&["keygen", "--seed", &"3".repeat(64)]);
    let other_pub = other_stdout
        .lines()
        .find_map(|l| l.strip_prefix("pubkey "))
        .unwrap()
        .trim()
        .to_string();

    let (ok, _, _) = run(&["verify", "--signed", s, "--kid", "k", "--pub", &other_pub]);
    assert!(!ok, "verify must reject a mismatched key");

    std::fs::remove_dir_all(&dir).ok();
}
