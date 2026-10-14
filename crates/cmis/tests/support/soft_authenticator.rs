//! A software FIDO2 authenticator for tests. It holds a real ES256 (P-256)
//! or EdDSA (Ed25519) key and produces real `authenticatorData`,
//! `clientDataJSON`, attestation objects and assertion signatures, so the
//! verifier is exercised end to end without hardware.
//!
//! Shared by the `cmis` unit tests (`admin::webauthn`, through `#[path]`) and
//! the integration tests (`tests/support`). It depends only on external
//! crates so it compiles in both places.

#![allow(
    dead_code,
    unreachable_pub,
    missing_docs,
    clippy::missing_panics_doc,
    clippy::must_use_candidate
)]

use base64::Engine as _;
use ciborium::Value;
use sha2::{Digest, Sha256};

/// authenticatorData flag: user present.
pub const UP: u8 = 0x01;
/// authenticatorData flag: user verified.
pub const UV: u8 = 0x04;
/// authenticatorData flag: backup eligible (a synced passkey).
pub const BE: u8 = 0x08;
/// authenticatorData flag: backed up.
pub const BS: u8 = 0x10;
/// authenticatorData flag: attested credential data included.
pub const AT: u8 = 0x40;
/// authenticatorData flag: extension data included.
pub const ED: u8 = 0x80;

/// The private key of the credential.
pub enum Key {
    /// ECDSA P-256 with SHA-256 (COSE -7).
    Es256(p256::ecdsa::SigningKey),
    /// Ed25519 (COSE -8).
    Ed25519(ed25519_dalek::SigningKey),
}

/// Attestation statement format to produce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fmt {
    /// `none`, empty statement.
    None,
    /// `packed` self attestation (signed by the credential key, no `x5c`).
    PackedSelf,
}

/// What `navigator.credentials.create()` would hand the relying party.
#[derive(Debug, Clone)]
pub struct Registration {
    pub credential_id: Vec<u8>,
    pub attestation_object: Vec<u8>,
    pub client_data_json: Vec<u8>,
}

/// What `navigator.credentials.get()` would hand the relying party.
#[derive(Debug, Clone)]
pub struct Assertion {
    pub credential_id: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    pub client_data_json: Vec<u8>,
    pub signature: Vec<u8>,
    pub user_handle: Vec<u8>,
}

/// One credential on a software authenticator.
pub struct SoftAuthenticator {
    pub key: Key,
    pub credential_id: Vec<u8>,
    pub aaguid: [u8; 16],
    /// Signature counter; incremented by every assertion when non-zero.
    pub counter: u32,
}

/// Unpadded base64url, as WebAuthn encodes the challenge.
pub fn b64url(data: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

/// A `clientDataJSON` document.
pub fn client_data(ty: &str, challenge: &[u8], origin: &str) -> Vec<u8> {
    format!(
        r#"{{"type":"{ty}","challenge":"{}","origin":"{origin}","crossOrigin":false}}"#,
        b64url(challenge)
    )
    .into_bytes()
}

/// CBOR encoding of a value.
pub fn cbor(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out).expect("CBOR encodes");
    out
}

impl SoftAuthenticator {
    /// An ES256 credential derived from `seed` (deterministic).
    pub fn es256(seed: u8) -> Self {
        let scalar = [seed.max(1); 32];
        Self {
            key: Key::Es256(p256::ecdsa::SigningKey::from_slice(&scalar).expect("valid scalar")),
            credential_id: vec![seed; 32],
            aaguid: [0xAA; 16],
            counter: 1,
        }
    }

    /// An Ed25519 credential derived from `seed` (deterministic).
    pub fn ed25519(seed: u8) -> Self {
        Self {
            key: Key::Ed25519(ed25519_dalek::SigningKey::from_bytes(&[seed; 32])),
            credential_id: vec![seed ^ 0x5A; 48],
            aaguid: [0xBB; 16],
            counter: 0,
        }
    }

    /// The credential public key as a COSE_Key.
    pub fn cose_key(&self) -> Vec<u8> {
        let int = |v: i64| Value::Integer(v.into());
        let value = match &self.key {
            Key::Es256(sk) => {
                let point = sk.verifying_key().to_sec1_point(false);
                Value::Map(vec![
                    (int(1), int(2)),
                    (int(3), int(-7)),
                    (int(-1), int(1)),
                    (int(-2), Value::Bytes(point.x().expect("x").to_vec())),
                    (int(-3), Value::Bytes(point.y().expect("y").to_vec())),
                ])
            }
            Key::Ed25519(sk) => Value::Map(vec![
                (int(1), int(1)),
                (int(3), int(-8)),
                (int(-1), int(6)),
                (
                    int(-2),
                    Value::Bytes(sk.verifying_key().to_bytes().to_vec()),
                ),
            ]),
        };
        cbor(&value)
    }

    /// Sign `msg` the way the authenticator would (DER for ES256).
    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        match &self.key {
            Key::Es256(sk) => {
                use p256::ecdsa::signature::Signer as _;
                let sig: p256::ecdsa::Signature = sk.sign(msg);
                sig.to_der().as_bytes().to_vec()
            }
            Key::Ed25519(sk) => {
                use ed25519_dalek::Signer as _;
                sk.sign(msg).to_bytes().to_vec()
            }
        }
    }

    /// `authenticatorData` for `rp_id`; with `attested` it carries this
    /// credential (registration).
    pub fn auth_data(&self, rp_id: &str, flags: u8, counter: u32, attested: bool) -> Vec<u8> {
        let mut out = Sha256::digest(rp_id.as_bytes()).to_vec();
        out.push(if attested { flags | AT } else { flags });
        out.extend_from_slice(&counter.to_be_bytes());
        if attested {
            out.extend_from_slice(&self.aaguid);
            let len = u16::try_from(self.credential_id.len()).expect("short id");
            out.extend_from_slice(&len.to_be_bytes());
            out.extend_from_slice(&self.credential_id);
            out.extend_from_slice(&self.cose_key());
        }
        out
    }

    /// An attestation object over `auth_data` and `client_data_json`.
    pub fn attestation_object(
        &self,
        fmt: Fmt,
        auth_data: &[u8],
        client_data_json: &[u8],
    ) -> Vec<u8> {
        let text = |s: &str| Value::Text(s.to_string());
        let statement = match fmt {
            Fmt::None => Value::Map(Vec::new()),
            Fmt::PackedSelf => {
                let mut signed = auth_data.to_vec();
                signed.extend_from_slice(&Sha256::digest(client_data_json));
                let alg: i64 = match self.key {
                    Key::Es256(_) => -7,
                    Key::Ed25519(_) => -8,
                };
                Value::Map(vec![
                    (text("alg"), Value::Integer(alg.into())),
                    (text("sig"), Value::Bytes(self.sign(&signed))),
                ])
            }
        };
        let fmt_name = match fmt {
            Fmt::None => "none",
            Fmt::PackedSelf => "packed",
        };
        cbor(&Value::Map(vec![
            (text("fmt"), text(fmt_name)),
            (text("attStmt"), statement),
            (text("authData"), Value::Bytes(auth_data.to_vec())),
        ]))
    }

    /// Register this credential (`none` attestation, UP and UV set).
    pub fn make_credential(&self, rp_id: &str, origin: &str, challenge: &[u8]) -> Registration {
        self.make_credential_with(rp_id, origin, challenge, UP | UV, Fmt::None)
    }

    /// Register this credential with explicit flags and attestation format.
    pub fn make_credential_with(
        &self,
        rp_id: &str,
        origin: &str,
        challenge: &[u8],
        flags: u8,
        fmt: Fmt,
    ) -> Registration {
        let client_data_json = client_data("webauthn.create", challenge, origin);
        let auth_data = self.auth_data(rp_id, flags, self.counter, true);
        Registration {
            credential_id: self.credential_id.clone(),
            attestation_object: self.attestation_object(fmt, &auth_data, &client_data_json),
            client_data_json,
        }
    }

    /// Answer a `get` ceremony (UP and UV set); advances a non-zero counter.
    pub fn get_assertion(&mut self, rp_id: &str, origin: &str, challenge: &[u8]) -> Assertion {
        if self.counter != 0 {
            self.counter += 1;
        }
        let counter = self.counter;
        self.get_assertion_with(rp_id, origin, challenge, UP | UV, counter)
    }

    /// Answer a `get` ceremony with explicit flags and counter.
    pub fn get_assertion_with(
        &self,
        rp_id: &str,
        origin: &str,
        challenge: &[u8],
        flags: u8,
        counter: u32,
    ) -> Assertion {
        let client_data_json = client_data("webauthn.get", challenge, origin);
        let authenticator_data = self.auth_data(rp_id, flags, counter, false);
        let mut signed = authenticator_data.clone();
        signed.extend_from_slice(&Sha256::digest(&client_data_json));
        Assertion {
            credential_id: self.credential_id.clone(),
            signature: self.sign(&signed),
            authenticator_data,
            client_data_json,
            user_handle: Vec::new(),
        }
    }
}
