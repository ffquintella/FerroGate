//! F14 CLI integration: the `offline-signer` tool drives a full air-gapped
//! ceremony — derive roots, split into sealed media, cross-sign both
//! directions, build and sign minutes, publish a newer-preferred JWKS, and
//! destroy + verify the outgoing media — and the artefacts it emits parse and
//! verify through the same library types CMIS and the reference verifier use.

use std::path::PathBuf;
use std::process::Command;

use ferro_ceremony::{CrossSignBundle, SealedShare, SignedMinutes};
use ferro_svid::JwkSet;

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_offline-signer"))
}

fn tmpdir(tag: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    p.push(format!("ferrogate-signer-cli-{tag}-{nanos}"));
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

fn pubkey_for(seed: &str) -> String {
    let (ok, stdout, _) = run(&["pubkey", "--seed", seed]);
    assert!(ok, "pubkey failed");
    stdout
        .lines()
        .find_map(|l| l.strip_prefix("hex    "))
        .expect("pubkey prints hex")
        .trim()
        .to_string()
}

#[test]
fn dry_run_produces_all_verifiable_artefacts() {
    let dir = tmpdir("dryrun");
    let work = dir.join("ceremony");
    let work_s = work.to_str().unwrap();

    let (ok, stdout, stderr) = run(&["dry-run", "--work-dir", work_s, "--now", "1780000000"]);
    assert!(ok, "dry-run failed: {stderr}");
    assert!(stdout.contains("all F14 ceremony steps passed"));

    // Cross-sign bundle verifies both directions through the library.
    let bundle =
        CrossSignBundle::from_json(&std::fs::read(work.join("cross-sign.json")).unwrap()).unwrap();
    bundle.verify().unwrap();

    // Minutes verify: every listed participant signed.
    let minutes =
        SignedMinutes::from_json(&std::fs::read(work.join("minutes.json")).unwrap()).unwrap();
    minutes.verify_all().unwrap();
    assert_eq!(minutes.signed_count(), minutes.minutes.participants.len());

    // JWKS picks the newer (incoming) root as preferred.
    let jwks: JwkSet =
        serde_json::from_slice(&std::fs::read(work.join("jwks.json")).unwrap()).unwrap();
    assert_eq!(jwks.preferred().unwrap().kid, "root-2026");

    // Every outgoing-root medium is zeroized and no longer a usable share.
    for entry in std::fs::read_dir(work.join("old-shares")).unwrap() {
        let bytes = std::fs::read(entry.unwrap().path()).unwrap();
        assert!(bytes.iter().all(|&b| b == 0));
        assert!(SealedShare::from_json(&bytes).is_err());
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn split_combine_cross_sign_and_minutes_round_trip() {
    let dir = tmpdir("rt");
    let shares_dir = dir.join("shares");
    let shares_s = shares_dir.to_str().unwrap();

    let old_seed = "a".repeat(64);
    let new_seed = "b".repeat(64);

    // Split the new root 3-of-5 into sealed media.
    let (ok, _, stderr) = run(&[
        "split",
        "--seed",
        &new_seed,
        "--root-kid",
        "root-2026",
        "--holder",
        "alice",
        "--holder",
        "bob",
        "--holder",
        "carol",
        "--holder",
        "dave",
        "--holder",
        "erin",
        "--threshold",
        "3",
        "--created",
        "1780000000",
        "--out-dir",
        shares_s,
    ]);
    assert!(ok, "split failed: {stderr}");
    let files: Vec<_> = std::fs::read_dir(&shares_dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    assert_eq!(files.len(), 5);

    // Combine from the directory recovers the seed → matching pubkey.
    let (ok, stdout, _) = run(&["combine", "--in-dir", shares_s]);
    assert!(ok, "combine failed");
    let recovered_pub = stdout
        .lines()
        .find_map(|l| l.strip_prefix("pubkey "))
        .unwrap()
        .trim();
    assert_eq!(recovered_pub, pubkey_for(&new_seed));

    // Cross-sign old↔new and verify.
    let bundle_path = dir.join("bundle.json");
    let bundle_s = bundle_path.to_str().unwrap();
    let (ok, _, stderr) = run(&[
        "cross-sign",
        "--old-seed",
        &old_seed,
        "--old-kid",
        "root-2025",
        "--new-seed",
        &new_seed,
        "--new-kid",
        "root-2026",
        "--window-start",
        "1780000000",
        "--window-days",
        "90",
        "--out",
        bundle_s,
    ]);
    assert!(ok, "cross-sign failed: {stderr}");
    let (ok, stdout, _) = run(&["verify-cross", "--bundle", bundle_s]);
    assert!(ok, "verify-cross failed");
    assert!(stdout.contains("both directions verify"));

    // jwks emits a newer-preferred set parseable by the SVID library.
    let (ok, jwks_json, _) = run(&["jwks", "--bundle", bundle_s]);
    assert!(ok, "jwks failed");
    let jwks: JwkSet = serde_json::from_str(&jwks_json).unwrap();
    assert_eq!(jwks.preferred().unwrap().kid, "root-2026");

    // Build minutes with three participants, each signs, all must verify.
    let p1 = format!(
        "alice|share-holder|op-1|{}",
        pubkey_for("01".repeat(32).as_str())
    );
    let p2 = format!(
        "bob|share-holder|op-2|{}",
        pubkey_for("02".repeat(32).as_str())
    );
    let p3 = format!(
        "carol|witness|op-3|{}",
        pubkey_for("03".repeat(32).as_str())
    );
    let minutes_path = dir.join("minutes.json");
    let minutes_s = minutes_path.to_str().unwrap();
    let (ok, _, stderr) = run(&[
        "minutes-new",
        "--ceremony-id",
        "rotation-2026",
        "--kind",
        "rotation",
        "--location",
        "Faraday room",
        "--trust-domain",
        "ferrogate.prod",
        "--occurred-at",
        "1780000000",
        "--old-root-kid",
        "root-2025",
        "--new-root-kid",
        "root-2026",
        "--threshold",
        "3",
        "--total",
        "3",
        "--participant",
        &p1,
        "--participant",
        &p2,
        "--participant",
        &p3,
        "--out",
        minutes_s,
    ]);
    assert!(ok, "minutes-new failed: {stderr}");

    // Before all sign, verification fails.
    assert!(!run(&["minutes-verify", "--minutes", minutes_s]).0);

    for (kid, seed) in [("op-1", "01"), ("op-2", "02"), ("op-3", "03")] {
        let (ok, _, stderr) = run(&[
            "minutes-sign",
            "--minutes",
            minutes_s,
            "--kid",
            kid,
            "--seed",
            &seed.repeat(32),
        ]);
        assert!(ok, "minutes-sign {kid} failed: {stderr}");
    }
    let (ok, stdout, _) = run(&["minutes-verify", "--minutes", minutes_s]);
    assert!(ok, "minutes-verify failed");
    assert!(stdout.contains("all 3 participant(s) signed"));

    // Destroy a share and confirm the read-back.
    let victim = files[0].to_str().unwrap();
    let (ok, _, stderr) = run(&["destroy", "--share", victim, "--at", "1790000000"]);
    assert!(ok, "destroy failed: {stderr}");
    assert!(run(&["verify-destruction", "--share", victim]).0);
}
