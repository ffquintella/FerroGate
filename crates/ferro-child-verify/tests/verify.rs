//! Reference-verifier tests, fully self-contained: child tokens are signed here
//! with a raw [`CompositeSecretKey`] (replicating the minter's wire format) and
//! DPoP proofs with a raw `ed25519-dalek` key, so the verifier crate stands on
//! its own without depending on the MIA. The minter↔verifier round-trip against
//! the *real* `mia::helper::token::ChildTokenMinter` lives in
//! `crates/mia/tests/child_token_verify.rs`.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};
use ferro_child_verify::{
    jwk_thumbprint_ed25519, verify, verify_bound, DpopExpectation, JwkSet, VerifyError, CHILD_ALG,
    CHILD_SIGNING_CONTEXT, CHILD_TYP,
};
use ferro_crypto::composite::{CompositePublicKey, CompositeSecretKey};

const KID: &str = "host-deadbeefdeadbeef";
const HTM: &str = "POST";
const HTU: &str = "https://api.example.com/resource";

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// A self-signed child token plus the JWK set that verifies it. The composite
/// key is retained so tests can re-mint (e.g. a longer-lived token to isolate a
/// DPoP-staleness failure from token expiry).
struct Fixture {
    sk: CompositeSecretKey,
    jws: String,
    jwks: JwkSet,
    dpop_proof: String,
    dpop_jkt: String,
}

/// Mint a child token bound to `dpop_jkt`, expiring at `exp`, signed under
/// `sk`/`kid`, and return its compact JWS.
fn mint(sk: &CompositeSecretKey, kid: &str, dpop_jkt: &str, iat: i64, exp: i64) -> String {
    let header = serde_json::json!({ "alg": CHILD_ALG, "typ": CHILD_TYP, "kid": kid });
    let claims = serde_json::json!({
        "iss": "spiffe://ferrogate.test/host/abc",
        "sub": "spiffe://ferrogate.test/host/abc#app:abababababababab",
        "aud": HTU,
        "exp": exp,
        "iat": iat,
        "jti": "0123456789abcdef0123456789abcdef",
        "cnf": { "jkt": dpop_jkt },
        "ferrogate": {
            "parent_svid": "33".repeat(48),
            "actor_pid": 1234u32,
            "actor_uid": 1001u32,
            "actor_bin": "ab".repeat(48),
        },
    });
    let h = b64(&serde_json::to_vec(&header).unwrap());
    let p = b64(&serde_json::to_vec(&claims).unwrap());
    let signing_input = format!("{h}.{p}");
    let sig = sk
        .sign(CHILD_SIGNING_CONTEXT, signing_input.as_bytes())
        .unwrap();
    format!("{signing_input}.{}", b64(&sig.to_concat_bytes()))
}

/// Build a DPoP proof for `(htm, htu, iat)` under `ed_sk`; return `(proof, jkt)`.
fn dpop_proof(ed_sk: &SigningKey, htm: &str, htu: &str, iat: i64) -> (String, String) {
    let x = b64(ed_sk.verifying_key().as_bytes());
    let jkt = jwk_thumbprint_ed25519(&x);
    let header = serde_json::json!({
        "typ": "dpop+jwt",
        "alg": "EdDSA",
        "jwk": { "kty": "OKP", "crv": "Ed25519", "x": x },
    });
    let claims = serde_json::json!({
        "jti": "dpop-jti-0001",
        "htm": htm,
        "htu": htu,
        "iat": iat,
    });
    let h = b64(&serde_json::to_vec(&header).unwrap());
    let p = b64(&serde_json::to_vec(&claims).unwrap());
    let signing_input = format!("{h}.{p}");
    let sig = ed_sk.sign(signing_input.as_bytes());
    (format!("{signing_input}.{}", b64(&sig.to_bytes())), jkt)
}

fn jwks_for(kid: &str, pk: &CompositePublicKey) -> JwkSet {
    let set = serde_json::json!({
        "keys": [ { "kty": "FERROGATE-COMPOSITE", "kid": kid, "pub": b64(&pk.to_concat_bytes()) } ],
    });
    JwkSet::from_json(&set.to_string()).unwrap()
}

/// Standard happy fixture: token at iat=1000 exp=1600, DPoP proof at iat=1000.
fn fixture() -> Fixture {
    let (sk, pk) = CompositeSecretKey::generate().unwrap();
    let ed_sk = SigningKey::from_bytes(&[7u8; 32]);
    let (dpop_proof, dpop_jkt) = dpop_proof(&ed_sk, HTM, HTU, 1000);
    let jws = mint(&sk, KID, &dpop_jkt, 1000, 1600);
    Fixture {
        sk,
        jws,
        jwks: jwks_for(KID, &pk),
        dpop_proof,
        dpop_jkt,
    }
}

fn expect() -> DpopExpectation<'static> {
    DpopExpectation {
        htm: HTM,
        htu: HTU,
        max_age_secs: 60,
    }
}

#[test]
fn valid_token_verifies_against_jwks() {
    let f = fixture();
    let v = verify(&f.jws, &f.jwks, 1100, 30).expect("token verifies");
    assert_eq!(v.kid, KID);
    assert_eq!(v.claims.cnf.jkt, f.dpop_jkt);
    assert_eq!(v.claims.aud, HTU);
}

#[test]
fn bound_verification_accepts_matching_dpop_proof() {
    let f = fixture();
    let v = verify_bound(&f.jws, &f.jwks, Some(&f.dpop_proof), &expect(), 1010, 30)
        .expect("token + matching DPoP proof verify");
    assert_eq!(v.claims.cnf.jkt, f.dpop_jkt);
}

/// The headline replay test: a bearer token presented with NO DPoP proof is
/// rejected, even though the token signature itself is perfectly valid.
#[test]
fn token_without_dpop_proof_is_rejected() {
    let f = fixture();
    assert!(verify(&f.jws, &f.jwks, 1100, 30).is_ok());
    let err = verify_bound(&f.jws, &f.jwks, None, &expect(), 1010, 30).unwrap_err();
    assert_eq!(err, VerifyError::MissingDpopProof);
}

#[test]
fn dpop_proof_for_a_different_key_is_rejected() {
    let f = fixture();
    // A proof from an attacker's own (valid) DPoP key — its thumbprint cannot
    // match the cnf.jkt minted into the captured token.
    let attacker = SigningKey::from_bytes(&[9u8; 32]);
    let (other_proof, _) = dpop_proof(&attacker, HTM, HTU, 1010);
    let err = verify_bound(&f.jws, &f.jwks, Some(&other_proof), &expect(), 1010, 30).unwrap_err();
    assert_eq!(err, VerifyError::DpopThumbprintMismatch);
}

#[test]
fn dpop_proof_for_a_different_request_is_rejected() {
    let f = fixture();
    let ed_sk = SigningKey::from_bytes(&[7u8; 32]);
    let (wrong_uri, _) = dpop_proof(&ed_sk, HTM, "https://evil.example.com/x", 1010);
    let err = verify_bound(&f.jws, &f.jwks, Some(&wrong_uri), &expect(), 1010, 30).unwrap_err();
    assert_eq!(err, VerifyError::DpopBindingMismatch);
}

#[test]
fn stale_dpop_proof_is_rejected() {
    let f = fixture();
    // Re-mint a still-valid token (exp far in the future) so the only failure
    // is the DPoP proof's age: it was minted at iat=1000 and now=2000 with a
    // 60 s window puts it well outside the acceptable range.
    let long_lived = mint(&f.sk, KID, &f.dpop_jkt, 1000, 100_000);
    let err = verify_bound(
        &long_lived,
        &f.jwks,
        Some(&f.dpop_proof),
        &expect(),
        2000,
        30,
    )
    .unwrap_err();
    assert_eq!(err, VerifyError::DpopStale);
}

#[test]
fn expired_token_is_rejected() {
    let f = fixture();
    let err = verify(&f.jws, &f.jwks, 5000, 30).unwrap_err();
    assert_eq!(err, VerifyError::Expired);
}

#[test]
fn unknown_kid_is_rejected() {
    let f = fixture();
    let (_sk, other_pk) = CompositeSecretKey::generate().unwrap();
    let wrong_jwks = jwks_for("host-some-other-kid", &other_pk);
    let err = verify(&f.jws, &wrong_jwks, 1100, 30).unwrap_err();
    assert_eq!(err, VerifyError::UnknownKid(KID.to_string()));
}

#[test]
fn tampered_signature_is_rejected() {
    let f = fixture();
    // Flip the first character of the signature segment — that base64 position
    // maps to the high bits of the first byte, so it always stays a valid
    // alphabet symbol (no length/padding change) yet corrupts the signature.
    let sig_start = f.jws.rfind('.').unwrap() + 1;
    let mut bytes = f.jws.into_bytes();
    bytes[sig_start] = if bytes[sig_start] == b'A' { b'B' } else { b'A' };
    let tampered = String::from_utf8(bytes).unwrap();
    let err = verify(&tampered, &f.jwks, 1100, 30).unwrap_err();
    assert_eq!(err, VerifyError::BadSignature);
}

#[test]
fn wrong_key_does_not_verify() {
    let f = fixture();
    // A JWK set carrying the right kid but the wrong public key.
    let (_sk, other_pk) = CompositeSecretKey::generate().unwrap();
    let mismatched = jwks_for(KID, &other_pk);
    let err = verify(&f.jws, &mismatched, 1100, 30).unwrap_err();
    assert_eq!(err, VerifyError::BadSignature);
}
