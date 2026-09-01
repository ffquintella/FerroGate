//! End-to-end for the X.509-SVID profile: one attestation yields both
//! credentials, the certificate validates under the `ferro-svid-verify`
//! reference verifier, and — the point of the profile — a stack that knows
//! nothing about FerroGate can parse and verify the leaf too.

use ferro_crypto::composite::CompositeSecretKey;
use ferro_svid::{CrlBody, CrlEntry, IssueParams, Issuer, RevocationTarget};
use ferro_svid_verify::x509 as verify_x509;

const NOW: i64 = 1_700_000_000;

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
        subject_pub: Some(
            CompositeSecretKey::from_seed(&[0x5a; 32])
                .1
                .to_concat_bytes(),
        ),
    }
}

fn jwks(issuer: &Issuer) -> ferro_svid_verify::JwkSet {
    ferro_svid_verify::JwkSet::from_json(&serde_json::to_string(&issuer.jwks()).unwrap()).unwrap()
}

// --- reference verifier -----------------------------------------------------

#[test]
fn issued_certificate_validates_against_the_published_bundle() {
    let issuer = issuer();
    let svid = issuer.issue(&params(), NOW).unwrap();
    let leaf = svid
        .x509
        .expect("the X.509 profile is issued alongside the JWS");

    let verified =
        verify_x509::verify_x509(&leaf.leaf_der, issuer.x509_ca().unwrap(), NOW + 60, 0).unwrap();

    assert_eq!(verified.spiffe_id, svid.spiffe_id);
    assert_eq!(verified.trust_domain, "ferrogate.test");
    assert_eq!(verified.not_after, svid.exp);
    assert_eq!(
        verified.subject_pub.to_concat_bytes(),
        params().subject_pub.unwrap(),
        "the verified subject key is the host's CSR key"
    );
}

#[test]
fn both_profiles_verify_from_the_same_jwks_fetch() {
    let issuer = issuer();
    let svid = issuer.issue(&params(), NOW).unwrap();
    let set = jwks(&issuer);

    let from_jws = ferro_svid_verify::verify(&svid.jws, &set, NOW + 60, 0).unwrap();
    let bundle = set
        .x509_bundle_der()
        .unwrap()
        .expect("bundle in the JWK set");
    let from_cert =
        verify_x509::verify_x509(&svid.x509.unwrap().leaf_der, &bundle, NOW + 60, 0).unwrap();

    assert_eq!(from_jws.claims.sub, from_cert.spiffe_id);
}

#[test]
fn expired_certificate_is_refused() {
    let issuer = issuer();
    let svid = issuer.issue(&params(), NOW).unwrap();
    let err = verify_x509::verify_x509(
        &svid.x509.unwrap().leaf_der,
        issuer.x509_ca().unwrap(),
        NOW + 3601,
        0,
    )
    .unwrap_err();
    assert_eq!(err, ferro_svid_verify::VerifyError::Expired);
}

#[test]
fn certificate_not_yet_valid_is_refused() {
    let issuer = issuer();
    let svid = issuer.issue(&params(), NOW).unwrap();
    let err = verify_x509::verify_x509(
        &svid.x509.unwrap().leaf_der,
        issuer.x509_ca().unwrap(),
        NOW - 3600,
        0,
    )
    .unwrap_err();
    assert_eq!(err, ferro_svid_verify::VerifyError::NotYetValid);
}

#[test]
fn a_certificate_from_another_issuer_is_refused() {
    let mint = issuer();
    let other = Issuer::generate("kid-other", "ferrogate.test").unwrap();
    let svid = mint.issue(&params(), NOW).unwrap();

    let err = verify_x509::verify_x509(
        &svid.x509.unwrap().leaf_der,
        other.x509_ca().unwrap(),
        NOW + 60,
        0,
    )
    .unwrap_err();
    // Same trust domain, so the DNs match; only the signature can tell them
    // apart, and it must.
    assert_eq!(err, ferro_svid_verify::VerifyError::BadSignature);
}

#[test]
fn a_bundle_from_another_trust_domain_is_refused() {
    let mint = issuer();
    let other = Issuer::generate("kid-other", "ferrogate.other").unwrap();
    let svid = mint.issue(&params(), NOW).unwrap();

    let err = verify_x509::verify_x509(
        &svid.x509.unwrap().leaf_der,
        other.x509_ca().unwrap(),
        NOW + 60,
        0,
    )
    .unwrap_err();
    assert!(matches!(
        err,
        ferro_svid_verify::VerifyError::UnexpectedHeader(_)
    ));
}

#[test]
fn tampering_with_the_certificate_is_caught() {
    let issuer = issuer();
    let svid = issuer.issue(&params(), NOW).unwrap();
    let mut der = svid.x509.unwrap().leaf_der;

    // Flip a bit deep inside the body — past the header, before the signature.
    let idx = der.len() / 3;
    der[idx] ^= 0x01;

    let err = verify_x509::verify_x509(&der, issuer.x509_ca().unwrap(), NOW + 60, 0).unwrap_err();
    assert!(
        matches!(
            err,
            ferro_svid_verify::VerifyError::BadSignature
                | ferro_svid_verify::VerifyError::Malformed(_)
                | ferro_svid_verify::VerifyError::UnexpectedHeader(_)
        ),
        "unexpected error for a mutated certificate: {err}"
    );
}

#[test]
fn stripping_the_post_quantum_signature_is_refused() {
    // A downgrade attempt: keep the classical signature (which still verifies,
    // since it covers the body *with* the extension) but remove the ML-DSA half
    // by pointing the verifier at a body it no longer describes. The reference
    // verifier demands both, so removing either is fatal.
    let issuer = issuer();
    let svid = issuer.issue(&params(), NOW).unwrap();
    let der = svid.x509.unwrap().leaf_der;

    // Blank out the altSignatureValue OID (2.5.29.74 -> 06 03 55 1D 4A) so the
    // extension can no longer be found.
    let needle = [0x06u8, 0x03, 0x55, 0x1d, 0x4a];
    let at = der
        .windows(needle.len())
        .position(|w| w == needle)
        .expect("altSignatureValue OID present in the DER");
    let mut stripped = der.clone();
    stripped[at + 4] = 0x4b; // 2.5.29.75 — an OID the profile does not define.

    let err =
        verify_x509::verify_x509(&stripped, issuer.x509_ca().unwrap(), NOW + 60, 0).unwrap_err();
    assert!(
        matches!(
            err,
            ferro_svid_verify::VerifyError::BadSignature
                | ferro_svid_verify::VerifyError::UnexpectedHeader(_)
        ),
        "unexpected error: {err}"
    );
}

#[test]
fn revoking_the_host_revokes_the_certificate_too() {
    let issuer = issuer();
    let svid = issuer.issue(&params(), NOW).unwrap();
    let leaf = svid.x509.clone().unwrap();

    let mut set = issuer.jwks();
    set.crl = Some(
        issuer
            .sign_crl(CrlBody {
                issued_at: NOW,
                number: 1,
                entries: vec![CrlEntry {
                    target: RevocationTarget::Host {
                        spiffe_id: svid.spiffe_id.clone(),
                    },
                    reason: "compromise".to_string(),
                    revoked_at: NOW,
                    expires_at: NOW + 86_400,
                }],
            })
            .unwrap(),
    );
    let set = ferro_svid_verify::JwkSet::from_json(&serde_json::to_string(&set).unwrap()).unwrap();

    let err = verify_x509::verify_x509_unrevoked(&leaf.leaf_der, &set, NOW + 60, 0).unwrap_err();
    assert_eq!(err, ferro_svid_verify::VerifyError::Revoked);
}

#[test]
fn an_unrevoked_certificate_passes_the_crl_gate() {
    let issuer = issuer();
    let svid = issuer.issue(&params(), NOW).unwrap();
    let leaf = svid.x509.unwrap();

    let mut set = issuer.jwks();
    set.crl = Some(
        issuer
            .sign_crl(CrlBody {
                issued_at: NOW,
                number: 1,
                entries: vec![],
            })
            .unwrap(),
    );
    let set = ferro_svid_verify::JwkSet::from_json(&serde_json::to_string(&set).unwrap()).unwrap();

    verify_x509::verify_x509_unrevoked(&leaf.leaf_der, &set, NOW + 60, 0).unwrap();
}

#[test]
fn a_missing_crl_fails_closed() {
    let issuer = issuer();
    let svid = issuer.issue(&params(), NOW).unwrap();
    let err = verify_x509::verify_x509_unrevoked(
        &svid.x509.unwrap().leaf_der,
        &jwks(&issuer),
        NOW + 60,
        0,
    )
    .unwrap_err();
    assert_eq!(err, ferro_svid_verify::VerifyError::CrlStale);
}

// --- interop: a stack that knows nothing about FerroGate --------------------

#[test]
fn a_stock_x509_parser_reads_the_leaf_and_checks_its_chain() {
    use x509_parser::prelude::*;

    let issuer = issuer();
    let svid = issuer.issue(&params(), NOW).unwrap();
    let leaf_der = svid.x509.unwrap().leaf_der;
    let ca_der = issuer.x509_ca().unwrap().to_vec();

    let (rest, leaf) = X509Certificate::from_der(&leaf_der).expect("stock parser reads the leaf");
    assert!(rest.is_empty(), "no trailing garbage after the certificate");
    let (_, ca) = X509Certificate::from_der(&ca_der).expect("stock parser reads the bundle");

    assert_eq!(leaf.version(), X509Version::V3);
    assert!(!leaf.is_ca());
    assert!(ca.is_ca());

    // The SPIFFE ID is where a SPIFFE-aware consumer looks for it.
    let san = leaf
        .subject_alternative_name()
        .unwrap()
        .expect("subjectAltName")
        .value
        .general_names
        .iter()
        .filter_map(|n| match n {
            GeneralName::URI(u) => Some(*u),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(san, vec![svid.spiffe_id.as_str()]);

    // Chain shape, as any path builder would check it.
    assert_eq!(leaf.issuer(), ca.subject());
    assert!(leaf
        .validity()
        .is_valid_at(ASN1Time::from_timestamp(NOW + 60).unwrap()));
    assert!(!leaf
        .validity()
        .is_valid_at(ASN1Time::from_timestamp(NOW + 7200).unwrap()));

    // And the signature the stock stack actually verifies: Ed25519 over the
    // TBSCertificate, checked here by the parser's own verifier — no FerroGate
    // code in the loop.
    leaf.verify_signature(Some(ca.public_key()))
        .expect("a stock verifier accepts the native Ed25519 signature");
    ca.verify_signature(None)
        .expect("the bundle is a valid self-signed certificate");

    // The extensions carrying the post-quantum half are non-critical, so a
    // stack that ignores them is still conformant.
    for ext in leaf.extensions() {
        let oid = ext.oid.to_id_string();
        if matches!(oid.as_str(), "2.5.29.72" | "2.5.29.73" | "2.5.29.74") {
            assert!(!ext.critical, "{oid} must be non-critical for interop");
        }
    }
}
