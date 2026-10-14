//! The signed caller allowlist, format **v2** (ADR-0004 §4, F19 §6).
//!
//! v2 is a per-host *compiled view* of a host's active approvals: bound to
//! one host UUID, carrying a monotonic generation, and with per-entry
//! constraints (uid, Windows SID, path, expiry). It is signed under its own
//! context, [`ALLOWLIST_V2_SIGNING_CONTEXT`], so a v1-only MIA rejects a v2
//! body as a bad signature (fail closed) and never mis-reads it as v1. The v1
//! format and its context ([`crate::allowlist`]) are unchanged.
//!
//! No personal data travels in the signed body: paths and SIDs appear only
//! as domain-separated SHA-256 hashes salted with the host UUID
//! ([`path_hash`], [`sid_hash`]). Both structs are `deny_unknown_fields`: a
//! constraint a verifier does not understand must make it fail closed, never
//! be ignored.

use ferro_crypto::composite::{CompositePublicKey, CompositeSecretKey, CompositeSignature};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha384};

use crate::allowlist::{SignedAllowlist, BIN_SHA_WILDCARD};
use crate::cbor_bytes::{fixed, opt_fixed};

/// Domain-separation context of the v2 allowlist signature. Distinct from
/// (and prefix-free with) every other FerroGate context, v1 included.
pub const ALLOWLIST_V2_SIGNING_CONTEXT: &[u8] = b"ferrogate-allowlist-v2";

/// The `format` value of a v2 body.
pub const ALLOWLIST_V2_FORMAT: u32 = 2;

/// Largest encoded v2 body accepted (about 40 000 entries).
pub const MAX_ALLOWLIST_V2_BYTES: usize = 8 * 1024 * 1024;

/// Domain-separation tag of [`path_hash`].
pub const PATH_HASH_TAG: &[u8] = b"ferrogate-path-v1";

/// Domain-separation tag of [`sid_hash`].
pub const SID_HASH_TAG: &[u8] = b"ferrogate-sid-v1";

/// One permitted caller constraint set (F19 §6.1). An entry admits a caller
/// when every constraint present matches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllowEntryV2 {
    /// UUID bytes of the approval (audit correlation); all zero for an entry
    /// compiled from a legacy body.
    #[serde(with = "fixed")]
    pub approval_id: [u8; 16],
    /// Lowercase hex SHA-384, or `"*"` for legacy imports only.
    pub bin_sha: String,
    /// Unix exact-user approvals (legacy imports keep their v1 uid).
    pub uid: Option<u32>,
    /// [`sid_hash`] of the Windows user (exact-user approvals).
    #[serde(with = "opt_fixed", default)]
    pub user_sid_hash: Option<[u8; 32]>,
    /// [`path_hash`] of the canonical path (exact-path approvals).
    #[serde(with = "opt_fixed", default)]
    pub path_hash: Option<[u8; 32]>,
    /// Unix seconds after which the entry admits nobody, enforced by MIA on
    /// every check, offline included.
    pub expires_at: Option<i64>,
}

/// The signed v2 body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllowlistDocV2 {
    /// [`ALLOWLIST_V2_FORMAT`].
    pub format: u32,
    /// Trust domain the allowlist was issued for.
    pub trust_domain: String,
    /// The only host that may use this body (MIA rejects `wrong_host`).
    pub host_uuid: String,
    /// Hybrid-logical generation (MIA rejects a lower one: `rollback`).
    pub generation: u64,
    /// Issuance time, Unix seconds.
    pub issued_at: i64,
    /// Hard expiry, Unix seconds.
    pub not_after: i64,
    /// Entries, sorted by `(bin_sha, approval_id)`.
    pub entries: Vec<AllowEntryV2>,
}

/// v2 encode, sign and verify failures. A verifier treats every variant as
/// "deny every caller" (fail closed).
#[derive(Debug, thiserror::Error)]
pub enum AllowlistV2Error {
    /// The CBOR was malformed or had an unknown field.
    #[error("cbor: {0}")]
    Cbor(String),
    /// The encoded body exceeds [`MAX_ALLOWLIST_V2_BYTES`].
    #[error("body too large ({0} bytes)")]
    TooLarge(usize),
    /// `format` is not [`ALLOWLIST_V2_FORMAT`].
    #[error("unsupported allowlist format {0}")]
    Format(u32),
    /// `host_uuid` is empty or longer than 64 bytes.
    #[error("bad host_uuid")]
    HostUuid,
    /// An entry's `bin_sha` is not 96 lowercase hex characters or `"*"`.
    #[error("malformed entry hash")]
    MalformedEntry,
    /// The signature bytes were not a composite signature.
    #[error("malformed signature")]
    MalformedSignature,
    /// The signature did not verify under the v2 context and trusted key.
    #[error("bad signature")]
    BadSignature,
}

/// Whether `s` is a lowercase-hex SHA-384 or the legacy wildcard.
fn valid_bin_sha(s: &str) -> bool {
    s == BIN_SHA_WILDCARD
        || (s.len() == 96 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
}

fn validate(doc: &AllowlistDocV2) -> Result<(), AllowlistV2Error> {
    if doc.format != ALLOWLIST_V2_FORMAT {
        return Err(AllowlistV2Error::Format(doc.format));
    }
    if doc.host_uuid.is_empty() || doc.host_uuid.len() > crate::host_call::MAX_HOST_UUID_LEN {
        return Err(AllowlistV2Error::HostUuid);
    }
    if !doc.entries.iter().all(|e| valid_bin_sha(&e.bin_sha)) {
        return Err(AllowlistV2Error::MalformedEntry);
    }
    Ok(())
}

/// Sort entries into the canonical order, `(bin_sha, approval_id)`.
pub fn sort_entries(entries: &mut [AllowEntryV2]) {
    entries.sort_by(|a, b| {
        a.bin_sha
            .cmp(&b.bin_sha)
            .then_with(|| a.approval_id.cmp(&b.approval_id))
    });
}

/// `entries_digest = SHA-384(canonical CBOR of the sorted entries)` (F19
/// §6.1). Equal entry sets give equal digests whatever their input order.
pub fn entries_digest(entries: &[AllowEntryV2]) -> Result<[u8; 48], AllowlistV2Error> {
    let mut sorted = entries.to_vec();
    sort_entries(&mut sorted);
    let mut cbor = Vec::with_capacity(64 * sorted.len() + 8);
    ciborium::into_writer(&sorted, &mut cbor).map_err(|e| AllowlistV2Error::Cbor(e.to_string()))?;
    let mut out = [0u8; 48];
    out.copy_from_slice(&Sha384::digest(&cbor));
    Ok(out)
}

/// Canonical CBOR of a v2 body (entries are sorted first).
pub fn encode_body_v2(doc: &AllowlistDocV2) -> Result<Vec<u8>, AllowlistV2Error> {
    validate(doc)?;
    let mut doc = doc.clone();
    sort_entries(&mut doc.entries);
    let mut body = Vec::with_capacity(128 + 160 * doc.entries.len());
    ciborium::into_writer(&doc, &mut body).map_err(|e| AllowlistV2Error::Cbor(e.to_string()))?;
    if body.len() > MAX_ALLOWLIST_V2_BYTES {
        return Err(AllowlistV2Error::TooLarge(body.len()));
    }
    Ok(body)
}

/// Parse and validate a v2 body. Does **not** verify a signature; use
/// [`verify_v2`] on anything received.
pub fn decode_body_v2(body: &[u8]) -> Result<AllowlistDocV2, AllowlistV2Error> {
    if body.len() > MAX_ALLOWLIST_V2_BYTES {
        return Err(AllowlistV2Error::TooLarge(body.len()));
    }
    let doc: AllowlistDocV2 =
        ciborium::from_reader(body).map_err(|e| AllowlistV2Error::Cbor(e.to_string()))?;
    validate(&doc)?;
    Ok(doc)
}

/// Encode and sign a v2 body with the CMIS issuer key, under
/// [`ALLOWLIST_V2_SIGNING_CONTEXT`]. The envelope is the same
/// [`SignedAllowlist`] shape as v1; only the context and body differ.
pub fn sign_v2(
    doc: &AllowlistDocV2,
    signer: &CompositeSecretKey,
) -> Result<SignedAllowlist, AllowlistV2Error> {
    let body = encode_body_v2(doc)?;
    let sig = signer
        .sign(ALLOWLIST_V2_SIGNING_CONTEXT, &body)
        .map_err(|_| AllowlistV2Error::BadSignature)?;
    Ok(SignedAllowlist {
        body,
        signature: sig.to_concat_bytes(),
    })
}

/// Verify `signed` under `trusted` and the v2 context, then parse and
/// validate its body. The caller layers host binding, generation and
/// freshness checks on top (F19 §6.2).
pub fn verify_v2(
    signed: &SignedAllowlist,
    trusted: &CompositePublicKey,
) -> Result<AllowlistDocV2, AllowlistV2Error> {
    if signed.body.len() > MAX_ALLOWLIST_V2_BYTES {
        return Err(AllowlistV2Error::TooLarge(signed.body.len()));
    }
    let sig = CompositeSignature::from_concat_bytes(&signed.signature)
        .map_err(|_| AllowlistV2Error::MalformedSignature)?;
    trusted
        .verify(ALLOWLIST_V2_SIGNING_CONTEXT, &signed.body, &sig)
        .map_err(|_| AllowlistV2Error::BadSignature)?;
    // Only parse the body after the signature checks out.
    decode_body_v2(&signed.body)
}

/// `SHA-256(tag ‖ 0x00 ‖ host_uuid ‖ 0x00 ‖ value)`.
fn tagged_hash(tag: &[u8], host_uuid: &str, value: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(tag);
    h.update([0]);
    h.update(host_uuid.as_bytes());
    h.update([0]);
    h.update(value);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

/// `path_hash = SHA-256("ferrogate-path-v1" ‖ 0x00 ‖ host_uuid ‖ 0x00 ‖
/// path_key)` (F19 §4.2), where `path_key` is `ferro_appid::path_key`.
#[must_use]
pub fn path_hash(host_uuid: &str, path_key: &[u8]) -> [u8; 32] {
    tagged_hash(PATH_HASH_TAG, host_uuid, path_key)
}

/// `sid_hash = SHA-256("ferrogate-sid-v1" ‖ 0x00 ‖ host_uuid ‖ 0x00 ‖
/// upper(SID))` (F19 §4.2). SIDs are ASCII (`S-1-5-21-…`), so the upper-case
/// form is the ASCII one.
#[must_use]
pub fn sid_hash(host_uuid: &str, sid: &str) -> [u8; 32] {
    tagged_hash(SID_HASH_TAG, host_uuid, sid.to_ascii_uppercase().as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::allowlist::{self, AllowEntry, AllowlistDoc, ALLOWLIST_SIGNING_CONTEXT};

    const HOST: &str = "5376139b-0117-8e2d-8049-1ab7b32e7d9a";

    fn entry(n: u8, id: u8) -> AllowEntryV2 {
        AllowEntryV2 {
            approval_id: [id; 16],
            bin_sha: hex::encode([n; 48]),
            uid: Some(1000),
            user_sid_hash: None,
            path_hash: Some(path_hash(HOST, b"/usr/bin/tool")),
            expires_at: Some(2_000_000_000),
        }
    }

    fn doc() -> AllowlistDocV2 {
        AllowlistDocV2 {
            format: ALLOWLIST_V2_FORMAT,
            trust_domain: "ferrogate.test".into(),
            host_uuid: HOST.into(),
            generation: 1_800_000_000_000,
            issued_at: 1000,
            not_after: 4600,
            entries: vec![entry(0xbb, 2), entry(0xaa, 9), entry(0xaa, 1)],
        }
    }

    #[test]
    fn sign_verify_roundtrip_sorts_entries() {
        let (sk, pk) = CompositeSecretKey::generate().unwrap();
        let signed = sign_v2(&doc(), &sk).unwrap();
        let back = verify_v2(
            &allowlist::decode(&allowlist::encode(&signed).unwrap()).unwrap(),
            &pk,
        )
        .unwrap();
        let order: Vec<_> = back
            .entries
            .iter()
            .map(|e| (e.bin_sha[..2].to_string(), e.approval_id[0]))
            .collect();
        assert_eq!(
            order,
            [("aa".into(), 1), ("aa".into(), 9), ("bb".into(), 2)]
        );
        assert_eq!(back.host_uuid, HOST);
        assert_eq!(back.generation, 1_800_000_000_000);
    }

    /// A v2 body never verifies under the v1 context, and a v1 body never
    /// under the v2 context (ADR-0004 §4: old agents fail closed).
    #[test]
    fn v1_and_v2_signatures_do_not_cross_verify() {
        let (sk, pk) = CompositeSecretKey::generate().unwrap();
        let v2 = sign_v2(&doc(), &sk).unwrap();
        assert!(matches!(
            allowlist::verify(&v2, &pk),
            Err(allowlist::AllowlistError::BadSignature)
        ));
        let v1 = allowlist::sign(
            &AllowlistDoc {
                trust_domain: "ferrogate.test".into(),
                issued_at: 1000,
                not_after: 4600,
                entries: vec![AllowEntry {
                    uid: Some(1000),
                    bin_sha: hex::encode([0xaa; 48]),
                }],
            },
            &sk,
        )
        .unwrap();
        assert!(matches!(
            verify_v2(&v1, &pk),
            Err(AllowlistV2Error::BadSignature)
        ));
        assert_ne!(ALLOWLIST_V2_SIGNING_CONTEXT, ALLOWLIST_SIGNING_CONTEXT);
    }

    #[test]
    fn unknown_fields_and_bad_values_are_rejected() {
        #[derive(Serialize)]
        struct DocPlus<'a> {
            #[serde(flatten)]
            doc: &'a AllowlistDocV2,
            extra: u8,
        }
        #[derive(Serialize)]
        struct EntryPlus {
            #[serde(with = "fixed")]
            approval_id: [u8; 16],
            bin_sha: String,
            uid: Option<u32>,
            user_sid_hash: Option<u8>,
            path_hash: Option<u8>,
            expires_at: Option<i64>,
            new_constraint: u8,
        }
        let mut cbor = Vec::new();
        ciborium::into_writer(
            &EntryPlus {
                approval_id: [0; 16],
                bin_sha: "*".into(),
                uid: None,
                user_sid_hash: None,
                path_hash: None,
                expires_at: None,
                new_constraint: 1,
            },
            &mut cbor,
        )
        .unwrap();
        assert!(ciborium::from_reader::<AllowEntryV2, _>(&cbor[..]).is_err());

        let mut d = doc();
        d.format = 3;
        assert!(matches!(
            encode_body_v2(&d),
            Err(AllowlistV2Error::Format(3))
        ));
        let mut d = doc();
        d.entries[0].bin_sha = "AA".repeat(48);
        assert!(matches!(
            encode_body_v2(&d),
            Err(AllowlistV2Error::MalformedEntry)
        ));
        let mut d = doc();
        d.host_uuid = String::new();
        assert!(matches!(
            encode_body_v2(&d),
            Err(AllowlistV2Error::HostUuid)
        ));
        assert!(matches!(
            decode_body_v2(&vec![0u8; MAX_ALLOWLIST_V2_BYTES + 1]),
            Err(AllowlistV2Error::TooLarge(_))
        ));
        assert!(decode_body_v2(&[0xff, 0x00]).is_err());

        // A body carrying an extra top-level field is rejected too.
        let mut cbor = Vec::new();
        ciborium::into_writer(
            &DocPlus {
                doc: &doc(),
                extra: 1,
            },
            &mut cbor,
        )
        .unwrap();
        assert!(matches!(
            decode_body_v2(&cbor),
            Err(AllowlistV2Error::Cbor(_))
        ));
    }

    #[test]
    fn optional_hashes_are_byte_strings_or_null() {
        let e = entry(0xaa, 1);
        let mut cbor = Vec::new();
        ciborium::into_writer(&e, &mut cbor).unwrap();
        // 0x58 0x20: a 32-byte byte string (the path hash).
        assert!(cbor.windows(2).any(|w| w == [0x58, 0x20]));
        assert_eq!(
            ciborium::from_reader::<AllowEntryV2, _>(&cbor[..]).unwrap(),
            e
        );
        let none = AllowEntryV2 {
            path_hash: None,
            ..e
        };
        let mut cbor = Vec::new();
        ciborium::into_writer(&none, &mut cbor).unwrap();
        assert_eq!(
            ciborium::from_reader::<AllowEntryV2, _>(&cbor[..]).unwrap(),
            none
        );
    }

    #[test]
    fn the_entries_digest_ignores_input_order() {
        let a = doc().entries;
        let mut b = a.clone();
        b.reverse();
        assert_eq!(entries_digest(&a).unwrap(), entries_digest(&b).unwrap());
        b.pop();
        assert_ne!(entries_digest(&a).unwrap(), entries_digest(&b).unwrap());
    }

    /// Shared vectors: MIA and CMIS must agree byte for byte (F19 §4.2).
    #[test]
    fn constraint_hash_vectors() {
        assert_eq!(
            hex::encode(path_hash(HOST, b"/usr/bin/tool")),
            hex::encode(Sha256::digest(
                [
                    PATH_HASH_TAG,
                    b"\0",
                    HOST.as_bytes(),
                    b"\0",
                    b"/usr/bin/tool"
                ]
                .concat()
            ))
        );
        assert_eq!(
            sid_hash(HOST, "s-1-5-21-1-2-3-1001"),
            sid_hash(HOST, "S-1-5-21-1-2-3-1001")
        );
        assert_ne!(path_hash(HOST, b"/a"), path_hash("other-host", b"/a"));
        assert_ne!(
            path_hash(HOST, b"S-1-5-21-1"),
            sid_hash(HOST, "S-1-5-21-1"),
            "the tags separate the domains"
        );
    }
}
