//! End-to-end F09 check: a token minted by the *real*
//! [`mia::helper::token::ChildTokenMinter`] verifies under the independent
//! `ferro-child-verify` reference verifier, the `cnf.jkt` binding holds against
//! a matching DPoP proof, and a token presented with no DPoP proof is rejected.
//!
//! This is the contract the third-party API gateway relies on: the minter and a
//! verifier that shares none of its code agree on the wire format and the DPoP
//! sender constraint.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};
use ferro_child_verify::{
    jwk_thumbprint_ed25519, verify, verify_bound, DpopExpectation, JwkSet, VerifyError,
};
use ferro_crypto::composite::CompositeSecretKey;
use mia::helper::token::{ChildTokenMinter, MinterConfig};
use mia::helper::CallerIdentity;

const HTM: &str = "POST";
const HTU: &str = "https://api.example.com";

fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn actor() -> CallerIdentity {
    CallerIdentity {
        pid: 4321,
        uid: 1002,
        gid: 1002,
        bin_sha: [0xCD; 48],
    }
}

/// Build a DPoP proof under `ed_sk` for `(htm, htu, iat)`; return `(proof, jkt)`.
fn dpop_proof(ed_sk: &SigningKey, htm: &str, htu: &str, iat: i64) -> (String, String) {
    let x = b64(ed_sk.verifying_key().as_bytes());
    let jkt = jwk_thumbprint_ed25519(&x);
    let header = serde_json::json!({
        "typ": "dpop+jwt", "alg": "EdDSA",
        "jwk": { "kty": "OKP", "crv": "Ed25519", "x": x },
    });
    let claims = serde_json::json!({ "jti": "proof-1", "htm": htm, "htu": htu, "iat": iat });
    let signing_input = format!(
        "{}.{}",
        b64(&serde_json::to_vec(&header).unwrap()),
        b64(&serde_json::to_vec(&claims).unwrap())
    );
    let sig = ed_sk.sign(signing_input.as_bytes());
    (format!("{signing_input}.{}", b64(&sig.to_bytes())), jkt)
}

#[test]
fn minted_token_verifies_under_reference_verifier_and_enforces_dpop() {
    // Host composite key — the kid the minter stamps must match the JWKS kid,
    // both derived from the public key via `ferro_svid::child_signing_kid`.
    let (sk, pk) = CompositeSecretKey::generate().unwrap();
    let kid = ferro_svid::child_signing_kid(&pk);

    // The caller's DPoP key. Its thumbprint is what the MIA binds into the token.
    let ed_sk = SigningKey::from_bytes(&[3u8; 32]);
    let now = 1_700_000_000;
    let (proof, jkt) = dpop_proof(&ed_sk, HTM, HTU, now);

    let minter = ChildTokenMinter::new(
        sk,
        MinterConfig {
            host_spiffe_id: "spiffe://ferrogate.prod/host/abc".into(),
            parent_svid_sha384: [0x55; 48],
            kid: kid.clone(),
        },
    );
    let token = minter.mint(HTU, &jkt, 300, &actor(), now).unwrap();

    // The JWKS CMIS would publish for this host: the composite key under `kid`.
    let jwks_json = serde_json::json!({
        "keys": [ { "kty": "FERROGATE-COMPOSITE", "kid": kid, "pub": b64(&pk.to_concat_bytes()) } ],
    });
    let jwks = JwkSet::from_json(&jwks_json.to_string()).unwrap();

    // 1. The token alone verifies under the published JWKS.
    let v = verify(&token.jws, &jwks, now + 10, 30).expect("minted token verifies");
    assert_eq!(v.kid, kid);
    assert_eq!(v.claims.cnf.jkt, jkt);
    assert_eq!(v.claims.aud, HTU);
    assert_eq!(v.claims.ferrogate.actor_pid, 4321);

    let expect = DpopExpectation {
        htm: HTM,
        htu: HTU,
        max_age_secs: 60,
    };

    // 2. With the matching DPoP proof, the bound check passes.
    verify_bound(&token.jws, &jwks, Some(&proof), &expect, now + 10, 30)
        .expect("token + matching DPoP proof verify");

    // 3. Replay: the same valid token with NO DPoP proof is rejected.
    assert_eq!(
        verify_bound(&token.jws, &jwks, None, &expect, now + 10, 30).unwrap_err(),
        VerifyError::MissingDpopProof,
    );
}
