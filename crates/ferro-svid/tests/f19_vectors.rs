//! F19 shared vectors.
//!
//! - `path_hash` / `sid_hash` over `ferro_appid::path_key` for every platform
//!   rule of F19 §4.2 (Linux `(deleted)` suffix, macOS, Windows case folding,
//!   UNC). MIA and CMIS must agree byte for byte; the expected values were
//!   cross-checked with an independent SHA-256 implementation.
//! - The v1 allowlist body encoding and context are pinned: ADR-0004 amends
//!   ADR-0002 without changing the v1 wire format.

use ferro_appid::path::{from_linux_link, from_macos_path, from_windows_final_path};
use ferro_appid::{path_key, Platform};
use ferro_svid::{
    path_hash, sid_hash, AllowEntry, AllowlistDoc, ALLOWLIST_SIGNING_CONTEXT,
    ALLOWLIST_V2_SIGNING_CONTEXT,
};

const HOST: &str = "5376139b-0117-8e2d-8049-1ab7b32e7d9a";

fn hash_of(platform: Platform, path: &str) -> String {
    hex::encode(path_hash(HOST, &path_key(platform, path).unwrap()))
}

#[test]
fn path_hash_vectors_per_platform() {
    // Linux: the kernel's ` (deleted)` suffix is stripped before hashing.
    let linux = from_linux_link(b"/usr/bin/tool (deleted)").unwrap();
    assert!(linux.deleted_on_disk);
    assert_eq!(
        hash_of(Platform::Linux, &linux.path),
        "a4a22dc7b69dadb7e135c13a3f8b27c42031d5ad7ddb3e4590ebc7b23a17fd2b"
    );
    // Linux is case-sensitive.
    assert_ne!(
        hash_of(Platform::Linux, "/usr/bin/Tool"),
        hash_of(Platform::Linux, "/usr/bin/tool")
    );

    // macOS: the data-volume firmlink prefix is stripped for the same file.
    let mac = from_macos_path(
        "/System/Volumes/Data/Applications/Tool.app/Contents/MacOS/Tool",
        |_| true,
    )
    .unwrap();
    assert_eq!(
        hash_of(Platform::MacOs, &mac.path),
        "a55e4223afa052e0253868ecaca31cd234fd2e89d5b7edd43c9d4465724a4a91"
    );

    // Windows: `\\?\` removed and simple upper-case folding.
    let win = from_windows_final_path(r"\\?\c:\Program Files\Tool\tool.exe").unwrap();
    assert_eq!(
        hash_of(Platform::Windows, &win.path),
        "25e8180b9e8c1ecf97a1f24d915508c1a39bab64817b442317e42db6d9691abb"
    );
    assert_eq!(
        hash_of(Platform::Windows, r"C:\PROGRAM FILES\TOOL\TOOL.EXE"),
        hash_of(Platform::Windows, &win.path)
    );

    // Windows UNC: `\\?\UNC\srv\share` becomes `\\srv\share`.
    let unc = from_windows_final_path(r"\\?\UNC\srv\Share\tool.exe").unwrap();
    assert_eq!(
        hash_of(Platform::Windows, &unc.path),
        "d7a47ae566db0c49122c83a4d923d86c248dba4f37f0573477008299ed0d7d6c"
    );
}

#[test]
fn sid_hash_vector() {
    let expected = "dc9d5bd301694692ac54e59fe6ed91d8f63aa6a24d7c848eaaff3a867d4a107b";
    assert_eq!(
        hex::encode(sid_hash(
            HOST,
            "S-1-5-21-3623811015-3361044348-30300820-1013"
        )),
        expected
    );
    assert_eq!(
        hex::encode(sid_hash(
            HOST,
            "s-1-5-21-3623811015-3361044348-30300820-1013"
        )),
        expected
    );
}

/// The v1 body bytes and context are exactly what they were before v2.
#[test]
fn v1_encoding_is_unchanged() {
    let doc = AllowlistDoc {
        trust_domain: "ferrogate.test".into(),
        issued_at: 1000,
        not_after: 4600,
        entries: vec![
            AllowEntry {
                uid: Some(1001),
                bin_sha: hex::encode([0xAA; 48]),
            },
            AllowEntry {
                uid: None,
                bin_sha: "*".into(),
            },
        ],
    };
    let mut body = Vec::new();
    ciborium::into_writer(&doc, &mut body).unwrap();
    // map(4) {trust_domain, issued_at, not_after, entries: [
    //   {uid: 1001, bin_sha: text(96) "aa…"}, {uid: null, bin_sha: "*"}]}
    let expected = format!(
        "{}{}{}",
        "a46c74727573745f646f6d61696e6e666572726f676174652e74657374696973737565645f61741903e8\
         696e6f745f61667465721911f867656e747269657382a2637569641903e96762696e5f7368617860",
        "61".repeat(96),
        "a263756964f66762696e5f736861612a"
    );
    assert_eq!(hex::encode(&body), expected);
    assert_eq!(ALLOWLIST_SIGNING_CONTEXT, b"ferrogate-allowlist-v1");
    assert_ne!(ALLOWLIST_SIGNING_CONTEXT, ALLOWLIST_V2_SIGNING_CONTEXT);
}

/// The bits a host may set agree with `ferro-appid`'s flag table.
#[test]
fn host_settable_flags_match_the_appid_table() {
    assert_eq!(
        ferro_svid::app_docs::HOST_SETTABLE_FLAGS,
        ferro_appid::RiskFlags::HOST_SETTABLE
    );
}

/// The issuer signs v2 for one host with its trust domain, verifiable only
/// under the v2 context.
#[test]
fn the_issuer_signs_v2_allowlists() {
    let issuer = ferro_svid::Issuer::from_seed(&[7u8; 32], "cmis-test", "ferrogate.test");
    let entry = ferro_svid::AllowEntryV2 {
        approval_id: [1; 16],
        bin_sha: hex::encode([0xcd; 48]),
        uid: None,
        user_sid_hash: Some(sid_hash(HOST, "S-1-5-21-1-2-3-1001")),
        path_hash: Some(path_hash(HOST, b"C:\\APP\\APP.EXE")),
        expires_at: None,
    };
    let signed = issuer
        .sign_allowlist_v2(HOST, 42, vec![entry.clone()], 1000, 2000)
        .unwrap();
    let doc = ferro_svid::allowlist_v2::verify_v2(&signed, issuer.public_key()).unwrap();
    assert_eq!(doc.trust_domain, "ferrogate.test");
    assert_eq!(doc.host_uuid, HOST);
    assert_eq!(doc.generation, 42);
    assert_eq!(doc.entries, vec![entry]);
    assert!(ferro_svid::allowlist::verify(&signed, issuer.public_key()).is_err());
}
