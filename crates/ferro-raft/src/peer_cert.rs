//! Deterministic shared peer-TLS certificate for self-signed clusters.
//!
//! # Why this exists
//!
//! Hiqlite's inter-node transport authenticates peers with a shared-secret
//! three-way handshake; TLS there is for on-the-wire confidentiality, so its own
//! clients skip certificate validation. But hiqlite *also* runs a periodic
//! `split_brain_check` that fetches `/cluster/metrics/*` from peers using a
//! stock `reqwest` client — and that client does **platform/CA certificate
//! verification**. On a zero-config self-signed cluster (`CMIS_PEER_TLS=1`) each
//! node would otherwise mint its own ephemeral cert, which no peer can verify,
//! so the split-brain check fails every cycle with `UnknownIssuer` and
//! split-brain *detection* silently stops working.
//!
//! Rather than patch hiqlite, we make the peer cert verifiable: every node
//! derives the **same** CA + leaf certificate *deterministically from the shared
//! cluster secret* (no distribution needed — the secret is already shared), and
//! the caller advertises the CA via `SSL_CERT_FILE` so the platform-verifying
//! client trusts it. See [`crate::cluster`] for the wiring and
//! `docs/features/F05-cmis-ha.md` for the operator-facing description.
//!
//! Determinism is essential: each node both *presents* this cert (as its TLS
//! server identity) and *trusts* it (as a root). If two nodes derived different
//! bytes, neither could verify the other. We get byte-identical output by
//! deriving the keys from the secret via HMAC-SHA256 and relying on rcgen's
//! fixed default validity window — nothing here reads the clock or an RNG.

use std::collections::BTreeSet;

use rcgen::{
    BasicConstraints, CertificateParams, DnType, DistinguishedName, ExtendedKeyUsagePurpose,
    IsCa, Issuer, KeyPair, KeyUsagePurpose,
};
use ring::hmac;
use rustls_pki_types::PrivatePkcs8KeyDer;

/// The materialized shared peer certificate, all PEM-encoded.
// The `_pem` suffix documents the encoding and disambiguates these from the DER
// forms callers might expect; keeping it is clearer than dropping it.
#[allow(clippy::struct_field_names)]
pub(crate) struct SharedPeerCert {
    /// Leaf certificate followed by its issuing CA — what hiqlite presents as
    /// the TLS server identity (a full chain so a verifier can build a path).
    pub server_chain_pem: String,
    /// Private key for the leaf certificate.
    pub key_pem: String,
    /// The CA certificate alone — the trust anchor to advertise via
    /// `SSL_CERT_FILE` so the platform-verifying split-brain client accepts the
    /// leaf its peers present.
    pub ca_pem: String,
}

/// HMAC-SHA256 the label under `secret` to get a 32-byte key seed. HMAC is a
/// fine KDF for a single fixed-size output, and `ring` is already in the tree.
fn derive_seed(secret: &str, label: &[u8]) -> [u8; 32] {
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes());
    let tag = hmac::sign(&key, label);
    let mut seed = [0u8; 32];
    // HMAC-SHA256 is exactly 32 bytes.
    seed.copy_from_slice(tag.as_ref());
    seed
}

/// Wrap a raw 32-byte Ed25519 seed as a PKCS#8 v1 document. The encoding is
/// fixed by RFC 8410 §7: a constant 16-byte prefix followed by the seed. Doing
/// it by hand keeps the key derivation dependency-free and, crucially,
/// deterministic — `KeyPair::generate` would draw from an RNG.
fn ed25519_pkcs8_from_seed(seed: &[u8; 32]) -> Vec<u8> {
    const PREFIX: [u8; 16] = [
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
    let mut der = Vec::with_capacity(PREFIX.len() + seed.len());
    der.extend_from_slice(&PREFIX);
    der.extend_from_slice(seed);
    der
}

/// Build a deterministic Ed25519 [`KeyPair`] from a secret + label.
fn keypair_from_secret(secret: &str, label: &[u8]) -> Result<KeyPair, rcgen::Error> {
    let der = ed25519_pkcs8_from_seed(&derive_seed(secret, label));
    let pkcs8 = PrivatePkcs8KeyDer::from(der);
    KeyPair::from_pkcs8_der_and_sign_algo(&pkcs8, &rcgen::PKCS_ED25519)
}

fn dn(common_name: &str) -> DistinguishedName {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, common_name);
    dn
}

/// Derive the shared CA + leaf certificate for a cluster.
///
/// `secret` is the cluster's shared API secret; `sans` are the subject
/// alternative names the leaf must carry — every hostname/IP a peer might use
/// to reach this node's management API (the split-brain client checks the SAN
/// against the URL host). rcgen auto-classifies each string as an IP or DNS
/// name. The output is byte-identical on every node given the same inputs.
pub(crate) fn derive_shared_peer_cert(
    secret: &str,
    sans: &[String],
) -> Result<SharedPeerCert, rcgen::Error> {
    // --- CA (the trust anchor) ---
    let ca_key = keypair_from_secret(secret, b"ferrogate-peer-tls/ca/v1")?;
    let mut ca_params = CertificateParams::default();
    ca_params.distinguished_name = dn("FerroGate CMIS peer CA");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let ca_cert = ca_params.self_signed(&ca_key)?;
    let ca_pem = ca_cert.pem();

    // --- Leaf (the per-node server identity, signed by the CA) ---
    let leaf_key = keypair_from_secret(secret, b"ferrogate-peer-tls/leaf/v1")?;
    let mut leaf_params = CertificateParams::new(sans.to_vec())?;
    leaf_params.distinguished_name = dn("FerroGate CMIS peer");
    leaf_params.is_ca = IsCa::NoCa;
    leaf_params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ServerAuth,
        ExtendedKeyUsagePurpose::ClientAuth,
    ];
    leaf_params.use_authority_key_identifier_extension = true;

    let issuer = Issuer::from_params(&ca_params, &ca_key);
    let leaf_cert = leaf_params.signed_by(&leaf_key, &issuer)?;

    let mut server_chain_pem = leaf_cert.pem();
    server_chain_pem.push_str(&ca_pem);

    Ok(SharedPeerCert {
        server_chain_pem,
        key_pem: leaf_key.serialize_pem(),
        ca_pem,
    })
}

/// Collect the subject-alternative-name strings for a node's leaf cert from the
/// peer list: every distinct host that appears in a peer's API or Raft address.
/// Deterministic (sorted, de-duplicated) so all nodes derive the same SAN set.
pub(crate) fn sans_from_addrs<'a>(addrs: impl IntoIterator<Item = &'a str>) -> Vec<String> {
    let mut set = BTreeSet::new();
    for addr in addrs {
        set.insert(host_of(addr).to_string());
    }
    set.into_iter().collect()
}

/// The host portion of a `host:port` (or bracketed `[v6]:port`) address.
fn host_of(addr: &str) -> &str {
    if let Some(rest) = addr.strip_prefix('[') {
        // [::1]:9602 -> ::1
        if let Some((host, _)) = rest.split_once(']') {
            return host;
        }
    }
    // host:port -> host (rsplit so an unbracketed bare v6 is left intact)
    match addr.rsplit_once(':') {
        Some((host, _)) => host,
        None => addr,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use x509_parser::prelude::*;

    #[test]
    fn derivation_is_deterministic() {
        let sans = vec!["cmis1".to_string(), "127.0.0.1".to_string()];
        let a = derive_shared_peer_cert("shared-secret-0123456789", &sans).unwrap();
        let b = derive_shared_peer_cert("shared-secret-0123456789", &sans).unwrap();
        assert_eq!(a.server_chain_pem, b.server_chain_pem);
        assert_eq!(a.key_pem, b.key_pem);
        assert_eq!(a.ca_pem, b.ca_pem);
    }

    #[test]
    fn different_secret_yields_different_cert() {
        let sans = vec!["cmis1".to_string()];
        let a = derive_shared_peer_cert("secret-aaaaaaaaaaaaaaaa", &sans).unwrap();
        let b = derive_shared_peer_cert("secret-bbbbbbbbbbbbbbbb", &sans).unwrap();
        assert_ne!(a.ca_pem, b.ca_pem);
        assert_ne!(a.key_pem, b.key_pem);
    }

    #[test]
    fn leaf_carries_requested_sans_and_is_signed_by_ca() {
        let sans = vec!["cmis1".to_string(), "cmis2".to_string(), "127.0.0.1".to_string()];
        let cert = derive_shared_peer_cert("shared-secret-0123456789", &sans).unwrap();

        // The chain is leaf then CA.
        let pems: Vec<_> = pem::Pem::iter_from_buffer(cert.server_chain_pem.as_bytes())
            .map(|p| p.unwrap())
            .collect();
        assert_eq!(pems.len(), 2, "chain must be leaf + CA");

        let leaf = pems[0].parse_x509().unwrap();
        let ca = pems[1].parse_x509().unwrap();

        // Leaf SANs cover everything we asked for.
        let san_ext = leaf
            .subject_alternative_name()
            .unwrap()
            .expect("leaf has SAN");
        let names: Vec<String> = san_ext
            .value
            .general_names
            .iter()
            .map(|gn| match gn {
                GeneralName::DNSName(s) => (*s).to_string(),
                GeneralName::IPAddress(ip) => format!("{ip:?}"),
                other => format!("{other:?}"),
            })
            .collect();
        assert!(names.iter().any(|n| n == "cmis1"));
        assert!(names.iter().any(|n| n == "cmis2"));

        // Leaf is an end-entity; CA is a CA; the leaf chains to the CA.
        assert!(!leaf.is_ca());
        assert!(ca.is_ca());
        assert_eq!(leaf.issuer(), ca.subject());
    }
}
