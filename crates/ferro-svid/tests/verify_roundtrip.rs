//! End-to-end: an SVID minted by `ferro-svid` validates under the independent
//! `ferro-svid-verify` reference verifier, and an expired one is refused.

use ferro_svid::{CrlBody, CrlEntry, IssueParams, Issuer, RevocationTarget};
use sha2::{Digest, Sha384};

fn issuer() -> Issuer {
    Issuer::generate("kid-test", "ferrogate.test").unwrap()
}

fn params() -> IssueParams {
    IssueParams {
        ek_cert_sha384: [0x11; 48],
        pcr_digest: [0x22; 48],
        policy_id: "rim-gen-5".to_string(),
        dpop_jkt: "dpop-thumb".to_string(),
        ttl_secs: 3600,
        tee_evidence_id: None,
    }
}

fn jwks_json(issuer: &Issuer) -> String {
    serde_json::to_string(&issuer.jwks()).unwrap()
}

/// JWKS JSON with a CRL (signed by `issuer`) containing `entries`, issued at
/// `now`.
fn jwks_json_with_crl(issuer: &Issuer, now: i64, entries: Vec<CrlEntry>) -> String {
    let mut set = issuer.jwks();
    set.crl = Some(
        issuer
            .sign_crl(CrlBody {
                issued_at: now,
                number: 1,
                entries,
            })
            .unwrap(),
    );
    serde_json::to_string(&set).unwrap()
}

fn cert_sha_hex(jws: &str) -> String {
    hex::encode(Sha384::digest(jws.as_bytes()))
}

#[test]
fn issued_svid_validates_against_published_jwks() {
    let issuer = issuer();
    let now = 1_700_000_000;
    let svid = issuer.issue(&params(), now).unwrap();

    let jwks = ferro_svid_verify::JwkSet::from_json(&jwks_json(&issuer)).unwrap();
    let verified = ferro_svid_verify::verify(&svid.jws, &jwks, now + 60, 0).unwrap();

    assert_eq!(verified.kid, "kid-test");
    assert_eq!(verified.claims.iss, "spiffe://ferrogate.test/cmis");
    assert_eq!(verified.claims.sub, svid.spiffe_id);
    assert_eq!(verified.claims.cnf.jkt, "dpop-thumb");
    assert_eq!(verified.claims.attest.policy_id, "rim-gen-5");
    assert_eq!(verified.claims.exp - verified.claims.iat, 3600);
}

#[test]
fn expired_svid_is_refused() {
    let issuer = issuer();
    let now = 1_700_000_000;
    let svid = issuer.issue(&params(), now).unwrap();
    let jwks = ferro_svid_verify::JwkSet::from_json(&jwks_json(&issuer)).unwrap();

    // One second past expiry, no leeway.
    let err = ferro_svid_verify::verify(&svid.jws, &jwks, now + 3601, 0).unwrap_err();
    assert_eq!(err, ferro_svid_verify::VerifyError::Expired);
}

#[test]
fn not_yet_valid_is_refused() {
    let issuer = issuer();
    let now = 1_700_000_000;
    let svid = issuer.issue(&params(), now).unwrap();
    let jwks = ferro_svid_verify::JwkSet::from_json(&jwks_json(&issuer)).unwrap();

    // Before nbf (iat - 60), no leeway.
    let err = ferro_svid_verify::verify(&svid.jws, &jwks, now - 120, 0).unwrap_err();
    assert_eq!(err, ferro_svid_verify::VerifyError::NotYetValid);
}

#[test]
fn tampered_payload_fails_signature() {
    let issuer = issuer();
    let now = 1_700_000_000;
    let svid = issuer.issue(&params(), now).unwrap();
    let jwks = ferro_svid_verify::JwkSet::from_json(&jwks_json(&issuer)).unwrap();

    // Flip a character in the payload segment.
    let mut parts: Vec<String> = svid.jws.split('.').map(str::to_string).collect();
    let payload = &mut parts[1];
    let last = payload.pop().unwrap();
    payload.push(if last == 'A' { 'B' } else { 'A' });
    let tampered = parts.join(".");

    let err = ferro_svid_verify::verify(&tampered, &jwks, now + 60, 0).unwrap_err();
    assert!(matches!(
        err,
        ferro_svid_verify::VerifyError::BadSignature | ferro_svid_verify::VerifyError::Malformed(_)
    ));
}

// ---- F11: revocation across the crate boundary -----------------------------

#[test]
fn unrevoked_svid_passes_with_fresh_clean_crl() {
    let issuer = issuer();
    let now = 1_700_000_000;
    let svid = issuer.issue(&params(), now).unwrap();
    let jwks =
        ferro_svid_verify::JwkSet::from_json(&jwks_json_with_crl(&issuer, now, vec![])).unwrap();

    let verified = ferro_svid_verify::verify_unrevoked(&svid.jws, &jwks, now + 60, 0).unwrap();
    assert_eq!(verified.claims.sub, svid.spiffe_id);
}

#[test]
fn revoked_by_cert_sha_is_rejected_by_reference_verifier() {
    let issuer = issuer();
    let now = 1_700_000_000;
    let svid = issuer.issue(&params(), now).unwrap();
    let entries = vec![CrlEntry::new(
        RevocationTarget::Svid {
            cert_sha: cert_sha_hex(&svid.jws),
        },
        "key-compromise",
        now,
    )];
    let jwks =
        ferro_svid_verify::JwkSet::from_json(&jwks_json_with_crl(&issuer, now, entries)).unwrap();

    let err = ferro_svid_verify::verify_unrevoked(&svid.jws, &jwks, now + 60, 0).unwrap_err();
    assert_eq!(err, ferro_svid_verify::VerifyError::Revoked);
}

#[test]
fn revoked_by_host_is_rejected_by_reference_verifier() {
    let issuer = issuer();
    let now = 1_700_000_000;
    let svid = issuer.issue(&params(), now).unwrap();
    let entries = vec![CrlEntry::new(
        RevocationTarget::Host {
            spiffe_id: svid.spiffe_id.clone(),
        },
        "decommissioned",
        now,
    )];
    let jwks =
        ferro_svid_verify::JwkSet::from_json(&jwks_json_with_crl(&issuer, now, entries)).unwrap();

    let err = ferro_svid_verify::verify_unrevoked(&svid.jws, &jwks, now + 60, 0).unwrap_err();
    assert_eq!(err, ferro_svid_verify::VerifyError::Revoked);
}

#[test]
fn stale_crl_fails_closed_in_reference_verifier() {
    let issuer = issuer();
    let now = 1_700_000_000;
    let svid = issuer.issue(&params(), now).unwrap();
    // CRL issued an hour ago — well past the 5-min freshness bound.
    let jwks =
        ferro_svid_verify::JwkSet::from_json(&jwks_json_with_crl(&issuer, now - 3600, vec![]))
            .unwrap();

    let err = ferro_svid_verify::verify_unrevoked(&svid.jws, &jwks, now, 0).unwrap_err();
    assert_eq!(err, ferro_svid_verify::VerifyError::CrlStale);
}

#[test]
fn absent_crl_fails_closed_in_reference_verifier() {
    let issuer = issuer();
    let now = 1_700_000_000;
    let svid = issuer.issue(&params(), now).unwrap();
    // Plain JWKS with no CRL extension.
    let jwks = ferro_svid_verify::JwkSet::from_json(&jwks_json(&issuer)).unwrap();

    let err = ferro_svid_verify::verify_unrevoked(&svid.jws, &jwks, now + 60, 0).unwrap_err();
    assert_eq!(err, ferro_svid_verify::VerifyError::CrlStale);
}

#[test]
fn tampered_crl_signature_is_rejected_by_reference_verifier() {
    let issuer = issuer();
    let now = 1_700_000_000;
    let svid = issuer.issue(&params(), now).unwrap();
    // Build a valid JWKS+CRL, then corrupt the CRL signature bytes.
    let json = jwks_json_with_crl(&issuer, now, vec![]);
    let mut value: serde_json::Value = serde_json::from_str(&json).unwrap();
    value["x-ferrogate-crl"]["signature_b64"] = serde_json::Value::String("AAAA".repeat(100));
    let jwks = ferro_svid_verify::JwkSet::from_json(&value.to_string()).unwrap();

    let err = ferro_svid_verify::verify_unrevoked(&svid.jws, &jwks, now + 60, 0).unwrap_err();
    assert!(matches!(err, ferro_svid_verify::VerifyError::CrlInvalid(_)));
}

#[test]
fn wrong_key_is_refused() {
    let issuer = issuer();
    let other = Issuer::generate("kid-test", "ferrogate.test").unwrap();
    let now = 1_700_000_000;
    let svid = issuer.issue(&params(), now).unwrap();

    // JWKS advertises a different key under the same kid.
    let jwks = ferro_svid_verify::JwkSet::from_json(&jwks_json(&other)).unwrap();
    let err = ferro_svid_verify::verify(&svid.jws, &jwks, now + 60, 0).unwrap_err();
    assert_eq!(err, ferro_svid_verify::VerifyError::BadSignature);
}
