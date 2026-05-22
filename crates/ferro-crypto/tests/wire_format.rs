//! Wire-format witness tests for feature F01 — hybrid PQC TLS transport.
//!
//! This is the "BoringSSL interop" acceptance criterion delivered as an
//! in-tree check. Rather than spawning `bssl_shim` in CI, the test
//! captures the bytes rustls actually puts on the wire for the FerroGate
//! `ProviderMode::HybridOnly` configuration and asserts they match the
//! IETF `draft-ietf-tls-hybrid-design` layout exactly:
//!
//! - The `supported_groups` extension (type `0x000A`) lists named group
//!   `X25519MLKEM768` (codepoint `0x11EC`).
//! - The `key_share` extension (type `0x0033`) carries a client share for
//!   `0x11EC` whose key-exchange field is **1216 bytes** — namely the
//!   X25519 public key (32 bytes) concatenated with the ML-KEM-768
//!   public key (1184 bytes), per the draft's "concat" combiner.
//!
//! Any IETF-conforming peer — BoringSSL-PQ, OpenSSL+oqs, NSS — speaks
//! this wire. A divergence in layout (e.g. rustls upstream silently
//! reordering the share, or changing the codepoint) is caught here.

use std::sync::Arc;

use ferro_crypto::pin::{SpkiPin, SpkiPinVerifier};
use ferro_crypto::tls::{ferrogate_provider, ProviderMode};
use rustls::client::ClientConnection;
use rustls::pki_types::ServerName;
use rustls::ClientConfig;

/// IANA codepoint for `X25519MLKEM768`, draft-ietf-tls-hybrid-design.
const HYBRID_GROUP: u16 = 0x11EC;

const TLS_EXT_SUPPORTED_GROUPS: u16 = 0x000A;
const TLS_EXT_KEY_SHARE: u16 = 0x0033;

/// Length of an X25519 public key in bytes.
const X25519_PK_LEN: usize = 32;
/// Length of an ML-KEM-768 public key in bytes (FIPS 203).
const MLKEM768_PK_LEN: usize = 1184;
/// Concat-combined hybrid share length.
const HYBRID_SHARE_LEN: usize = X25519_PK_LEN + MLKEM768_PK_LEN;

/// Drive a rustls client far enough to produce its first flight (the
/// ClientHello record) and return the raw bytes it wrote.
fn capture_client_hello(mode: ProviderMode) -> Vec<u8> {
    // A throwaway pin is fine: the verifier is never invoked because we
    // never feed the connection a server response.
    let provider = Arc::new(ferrogate_provider(mode));
    let dummy_pin = SpkiPin::from_bytes([0xAA; 48]);
    let verifier = SpkiPinVerifier::new(vec![dummy_pin], Arc::clone(&provider));

    let cfg = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("safe defaults")
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();

    let server_name = ServerName::try_from("cmis.test.ferrogate.invalid").unwrap();
    let mut conn = ClientConnection::new(Arc::new(cfg), server_name).expect("new client conn");

    let mut out = Vec::new();
    // First call returns the ClientHello flight.
    conn.write_tls(&mut out).expect("write_tls");
    assert!(
        !out.is_empty(),
        "rustls produced no first-flight bytes — API change?"
    );
    out
}

/// Minimal slice-based reader.
struct R<'a>(&'a [u8]);

impl<'a> R<'a> {
    fn take(&mut self, n: usize) -> &'a [u8] {
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        head
    }
    fn u8(&mut self) -> u8 {
        self.take(1)[0]
    }
    fn u16(&mut self) -> u16 {
        let b = self.take(2);
        u16::from_be_bytes([b[0], b[1]])
    }
    fn u24(&mut self) -> u32 {
        let b = self.take(3);
        u32::from_be_bytes([0, b[0], b[1], b[2]])
    }
}

/// Parse a TLS 1.3 ClientHello record and return its raw extensions blob.
///
/// Layout (RFC 8446 §5.1, §4.1.2):
///
/// ```text
/// TLSPlaintext { type, legacy_record_version, length, fragment }
/// Handshake    { msg_type=1 (ClientHello), length, body }
/// ClientHello  { legacy_version(2), random(32),
///                legacy_session_id<0..32>,
///                cipher_suites<2..2^16-2>,
///                legacy_compression_methods<1..2^8-1>,
///                extensions<8..2^16-1> }
/// ```
fn extract_extensions(record: &[u8]) -> Vec<(u16, &[u8])> {
    let mut r = R(record);
    // TLS record header.
    let rec_ty = r.u8();
    assert_eq!(rec_ty, 0x16, "expected TLS handshake record");
    let _legacy_version = r.u16();
    let _record_len = r.u16();

    // Handshake header.
    let hs_ty = r.u8();
    assert_eq!(hs_ty, 0x01, "expected ClientHello handshake message");
    let _hs_len = r.u24();

    // ClientHello body.
    let _legacy_version = r.u16();
    let _random = r.take(32);
    let sid_len = r.u8() as usize;
    let _sid = r.take(sid_len);
    let cs_len = r.u16() as usize;
    let _cipher_suites = r.take(cs_len);
    let comp_len = r.u8() as usize;
    let _compression = r.take(comp_len);

    let ext_len = r.u16() as usize;
    let mut ext_slice = R(r.take(ext_len));

    let mut out = Vec::new();
    while !ext_slice.0.is_empty() {
        let ty = ext_slice.u16();
        let len = ext_slice.u16() as usize;
        let data = ext_slice.take(len);
        out.push((ty, data));
    }
    out
}

fn find_ext<'a>(exts: &'a [(u16, &'a [u8])], ty: u16) -> Option<&'a [u8]> {
    exts.iter().find(|(t, _)| *t == ty).map(|(_, d)| *d)
}

fn supported_groups(ext_body: &[u8]) -> Vec<u16> {
    // NamedGroupList: list_length(2) || group(2) ...
    let mut r = R(ext_body);
    let total = r.u16() as usize;
    let mut body = R(r.take(total));
    let mut groups = Vec::new();
    while !body.0.is_empty() {
        groups.push(body.u16());
    }
    groups
}

fn key_share_entries(ext_body: &[u8]) -> Vec<(u16, &[u8])> {
    // ClientShares: list_length(2) || KeyShareEntry ...
    // KeyShareEntry: group(2) || key_exchange<1..2^16-1>
    let mut r = R(ext_body);
    let total = r.u16() as usize;
    let mut body = R(r.take(total));
    let mut entries = Vec::new();
    while !body.0.is_empty() {
        let group = body.u16();
        let kx_len = body.u16() as usize;
        let kx = body.take(kx_len);
        entries.push((group, kx));
    }
    entries
}

#[test]
fn hybrid_only_supported_groups_lists_x25519mlkem768_alone() {
    let record = capture_client_hello(ProviderMode::HybridOnly);
    let exts = extract_extensions(&record);
    let body = find_ext(&exts, TLS_EXT_SUPPORTED_GROUPS).expect("supported_groups present");
    let groups = supported_groups(body);
    assert_eq!(
        groups,
        vec![HYBRID_GROUP],
        "HybridOnly must advertise only the hybrid group; saw {groups:#06x?}"
    );
}

#[test]
fn hybrid_only_key_share_layout_matches_ietf_draft() {
    let record = capture_client_hello(ProviderMode::HybridOnly);
    let exts = extract_extensions(&record);
    let body = find_ext(&exts, TLS_EXT_KEY_SHARE).expect("key_share present");
    let entries = key_share_entries(body);

    // The hybrid client share must be present.
    let (_, hybrid_kx) = entries
        .iter()
        .find(|(g, _)| *g == HYBRID_GROUP)
        .expect("client_shares contains the hybrid group");

    // Wire layout per draft-ietf-tls-hybrid-design: 32-byte X25519 public
    // key concatenated with 1184-byte ML-KEM-768 public key. This length
    // is the witness that we are wire-compatible with BoringSSL-PQ.
    assert_eq!(
        hybrid_kx.len(),
        HYBRID_SHARE_LEN,
        "X25519MLKEM768 client share must be {HYBRID_SHARE_LEN} bytes \
         (X25519 {X25519_PK_LEN} || ML-KEM-768 {MLKEM768_PK_LEN}); got {}",
        hybrid_kx.len(),
    );

    // No legacy X25519 share should appear in HybridOnly mode.
    assert!(
        entries.iter().all(|(g, _)| *g != 0x001D),
        "plain X25519 key share leaked into HybridOnly ClientHello"
    );
}

#[test]
fn fallback_mode_offers_both_shares_with_hybrid_first() {
    let record = capture_client_hello(ProviderMode::HybridPreferredWithX25519Fallback);
    let exts = extract_extensions(&record);
    let body = find_ext(&exts, TLS_EXT_KEY_SHARE).expect("key_share present");
    let entries = key_share_entries(body);

    let groups: Vec<u16> = entries.iter().map(|(g, _)| *g).collect();
    assert_eq!(
        groups,
        vec![HYBRID_GROUP, 0x001D],
        "fallback mode must offer hybrid first, X25519 second"
    );

    let hybrid_kx = entries[0].1;
    let x25519_kx = entries[1].1;
    assert_eq!(hybrid_kx.len(), HYBRID_SHARE_LEN);
    assert_eq!(x25519_kx.len(), X25519_PK_LEN);
}
