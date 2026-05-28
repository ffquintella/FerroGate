//! Attestation report production and verification.
//!
//! Two production code paths are surfaced — AMD SEV-SNP and Intel TDX — and
//! a `SoftwareAttestor` is provided for unit tests. All three implement the
//! [`Attestor`] trait so callers (the [`crate::cluster`] orchestration and
//! the [`crate::psk`] handshake) are vendor-agnostic.
//!
//! ## Report shape
//!
//! Real SEV-SNP and TDX reports are large binary structures dictated by
//! their respective firmware specs. We model both with a normalised inner
//! `ReportBody` so the same allowlist and the same PSK transcript logic
//! work for either vendor. A `vendor_blob` field carries the raw report
//! bytes for forensic / audit purposes and is not consulted during the
//! security checks here.
//!
//! ## Signature model
//!
//! Each report is signed by a vendor key whose public form is rooted in a
//! configured root (`peer_roots`). In production:
//!
//! - **SEV-SNP** — VCEK chains up to AMD's ARK/ASK roots.
//! - **TDX**     — TD quote signed by a PCS-rooted attestation key.
//!
//! For test fidelity, the `SoftwareAttestor` uses an Ed25519 keypair that
//! plays the role of the per-replica VCEK/ECDSA-AK. Verifiers trust the
//! report iff the signing public key matches one in their configured root
//! set, the measurement is on the allowlist, and the report's nonce equals
//! the verifier-supplied challenge.

use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_384};

use crate::error::TeeError;
use crate::measurement::{Measurement, MEASUREMENT_LEN};

/// Which TEE vendor produced a report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AttestorKind {
    /// AMD SEV-SNP (VCEK-signed `MSG_REPORT_RSP`).
    SevSnp,
    /// Intel TDX (TD quote with PCS-rooted attestation key).
    Tdx,
    /// Test-only software attestor; never accepted in production
    /// configurations whose allowlist was built without explicit opt-in.
    Software,
}

/// Inner, vendor-normalised report body. Both SEV-SNP and TDX serialise into
/// this for the purposes of FerroGate's security checks.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReportBody {
    /// Which vendor produced this report.
    pub kind: AttestorKind,
    /// 48-byte enclave launch measurement.
    pub measurement: Measurement,
    /// 32-byte verifier-supplied challenge (`REPORT_DATA` / `qe_report_data`).
    pub nonce: [u8; 32],
    /// Application data bound into the report (e.g. a hash of the ML-KEM
    /// public key during peer attestation). Allows the report to bind to
    /// session state outside the 32-byte nonce slot.
    #[serde(default, with = "serde_bytes")]
    pub bound_data: Vec<u8>,
    /// Vendor firmware version reported alongside the measurement; cluster
    /// admission gates the minimum version (see `docs/features/F06`).
    pub firmware_version: u32,
    /// Monotonic counter from the vendor TCB; advisory, audited.
    pub tcb_svn: u64,
}

/// Wire-form attestation report: the normalised body plus the vendor's
/// signing public key and an Ed25519 signature over the canonical body
/// encoding under domain tag `ferro-tee-report-v1`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Report {
    /// Normalised body covered by the signature.
    pub body: ReportBody,
    /// Per-replica signing public key, rooted in the configured peer-roots.
    pub signer_pk: [u8; 32],
    /// Signature over `domain("ferro-tee-report-v1") || canonical(body)`.
    /// Always 64 bytes (Ed25519); checked at verify.
    #[serde(with = "serde_bytes")]
    pub signature: Vec<u8>,
    /// Vendor-native report bytes (forensic; not consulted by verify).
    #[serde(default, with = "serde_bytes")]
    pub vendor_blob: Vec<u8>,
}

/// Domain-separation tag for report signatures.
pub const REPORT_DOMAIN: &[u8] = b"ferro-tee-report-v1";

fn report_digest(body: &ReportBody) -> [u8; 48] {
    let bytes = canonical_body(body);
    let mut h = Sha3_384::new();
    h.update(REPORT_DOMAIN);
    h.update((bytes.len() as u64).to_be_bytes());
    h.update(&bytes);
    let mut out = [0u8; 48];
    out.copy_from_slice(&h.finalize());
    out
}

fn canonical_body(body: &ReportBody) -> Vec<u8> {
    // CBOR is canonical-ish enough here; the body has a fixed schema and
    // ciborium emits deterministic encoding for our integer types.
    let mut buf = Vec::with_capacity(128);
    ciborium::ser::into_writer(body, &mut buf).expect("canonical encoding");
    buf
}

/// Trait implemented by every report producer.
pub trait Attestor: Send + Sync {
    /// Vendor kind.
    fn kind(&self) -> AttestorKind;
    /// This replica's launch measurement.
    fn measurement(&self) -> Measurement;
    /// Produce a fresh report binding `nonce` and optional `bound_data`.
    fn produce(&self, nonce: [u8; 32], bound_data: &[u8]) -> Report;
    /// The signing public key advertised in this attestor's reports. Used
    /// by tests and by clusters that derive peer-root sets from a join
    /// procedure rather than a static config.
    fn signer_pk(&self) -> [u8; 32];
    /// Sealing-root secret bound to this replica. Real hardware derives
    /// this from the VCEK + measurement; the software attestor mirrors
    /// that with HKDF over its private key and measurement. Callers should
    /// treat the result as a high-entropy secret and not log it.
    fn sealing_root(&self) -> [u8; 32];
}

/// Set of vendor signing public keys this verifier accepts.
#[derive(Debug, Clone, Default)]
pub struct PeerRoots {
    keys: Vec<[u8; 32]>,
}

impl PeerRoots {
    /// Build a peer-roots set.
    pub fn new<I: IntoIterator<Item = [u8; 32]>>(it: I) -> Self {
        Self {
            keys: it.into_iter().collect(),
        }
    }
    /// Approve an additional signing public key.
    pub fn push(&mut self, pk: [u8; 32]) {
        self.keys.push(pk);
    }
    /// Whether the given key is rooted in this set.
    #[must_use]
    pub fn accepts(&self, pk: &[u8; 32]) -> bool {
        // Equality is over public keys — no constant-time requirement.
        self.keys.iter().any(|k| k == pk)
    }
    /// Number of approved keys.
    #[must_use]
    pub fn len(&self) -> usize {
        self.keys.len()
    }
    /// Whether the root set is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

/// Verify a report against a configured root set and the expected nonce.
///
/// Returns the report's measurement on success so the caller can check it
/// against an allowlist. Verification is fail-closed at every step.
pub fn verify_report(
    report: &Report,
    expected_nonce: &[u8; 32],
    expected_bound: &[u8],
    roots: &PeerRoots,
) -> Result<Measurement, TeeError> {
    if !roots.accepts(&report.signer_pk) {
        return Err(TeeError::BadReportSignature);
    }
    if &report.body.nonce != expected_nonce {
        return Err(TeeError::BadReport("nonce mismatch"));
    }
    if report.body.bound_data.as_slice() != expected_bound {
        return Err(TeeError::BadReport("bound_data mismatch"));
    }
    if report.body.measurement.as_bytes().len() != MEASUREMENT_LEN {
        return Err(TeeError::BadReport("measurement length"));
    }
    let vk =
        VerifyingKey::from_bytes(&report.signer_pk).map_err(|_| TeeError::BadReportSignature)?;
    if report.signature.len() != 64 {
        return Err(TeeError::BadReportSignature);
    }
    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(&report.signature);
    let sig = Signature::from_bytes(&sig_bytes);
    let digest = report_digest(&report.body);
    vk.verify(&digest, &sig)
        .map_err(|_| TeeError::BadReportSignature)?;
    Ok(report.body.measurement)
}

/// Test-only attestor that signs `Report`s with a per-instance Ed25519 key.
/// Has the same surface as the hardware paths so production code never
/// branches on attestor kind.
pub struct SoftwareAttestor {
    sk: SigningKey,
    pk: [u8; 32],
    measurement: Measurement,
    sealing_root: [u8; 32],
    firmware_version: u32,
    tcb_svn: u64,
    kind: AttestorKind,
}

impl SoftwareAttestor {
    /// Build a software attestor with the given measurement and a fresh
    /// signing key.
    #[must_use]
    pub fn generate(measurement: Measurement) -> Self {
        Self::generate_as(AttestorKind::Software, measurement)
    }

    /// Build a software attestor that masquerades as a specific vendor
    /// kind — used to test that the same verifier path handles both SEV-SNP
    /// and TDX reports identically.
    #[must_use]
    pub fn generate_as(kind: AttestorKind, measurement: Measurement) -> Self {
        let sk = SigningKey::generate(&mut OsRng);
        let pk = sk.verifying_key().to_bytes();

        // Sealing root: HKDF-equivalent — SHA3-384(sk || measurement) truncated.
        let mut h = Sha3_384::new();
        h.update(b"ferro-tee-sealing-root-v1");
        h.update(sk.to_bytes());
        h.update(measurement.as_bytes());
        let d = h.finalize();
        let mut sealing_root = [0u8; 32];
        sealing_root.copy_from_slice(&d[..32]);

        Self {
            sk,
            pk,
            measurement,
            sealing_root,
            firmware_version: 0x01_02_03_04,
            tcb_svn: 1,
            kind,
        }
    }
}

impl Attestor for SoftwareAttestor {
    fn kind(&self) -> AttestorKind {
        self.kind
    }
    fn measurement(&self) -> Measurement {
        self.measurement
    }
    fn signer_pk(&self) -> [u8; 32] {
        self.pk
    }
    fn sealing_root(&self) -> [u8; 32] {
        self.sealing_root
    }
    fn produce(&self, nonce: [u8; 32], bound_data: &[u8]) -> Report {
        let body = ReportBody {
            kind: self.kind,
            measurement: self.measurement,
            nonce,
            bound_data: bound_data.to_vec(),
            firmware_version: self.firmware_version,
            tcb_svn: self.tcb_svn,
        };
        let digest = report_digest(&body);
        let sig = self.sk.sign(&digest).to_bytes();
        Report {
            body,
            signer_pk: self.pk,
            signature: sig.to_vec(),
            vendor_blob: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roots_for(a: &SoftwareAttestor) -> PeerRoots {
        PeerRoots::new([a.signer_pk()])
    }

    #[test]
    fn snp_report_round_trips_through_verify() {
        let a = SoftwareAttestor::generate_as(AttestorKind::SevSnp, Measurement([7u8; 48]));
        let nonce = [9u8; 32];
        let rep = a.produce(nonce, b"bind");
        let m = verify_report(&rep, &nonce, b"bind", &roots_for(&a)).unwrap();
        assert_eq!(m, a.measurement());
        assert_eq!(rep.body.kind, AttestorKind::SevSnp);
    }

    #[test]
    fn tdx_report_round_trips_through_verify() {
        let a = SoftwareAttestor::generate_as(AttestorKind::Tdx, Measurement([8u8; 48]));
        let nonce = [3u8; 32];
        let rep = a.produce(nonce, b"");
        let m = verify_report(&rep, &nonce, b"", &roots_for(&a)).unwrap();
        assert_eq!(m, a.measurement());
        assert_eq!(rep.body.kind, AttestorKind::Tdx);
    }

    #[test]
    fn wrong_nonce_is_rejected() {
        let a = SoftwareAttestor::generate(Measurement([1u8; 48]));
        let rep = a.produce([1u8; 32], b"");
        let err = verify_report(&rep, &[2u8; 32], b"", &roots_for(&a)).unwrap_err();
        assert!(matches!(err, TeeError::BadReport(_)));
    }

    #[test]
    fn untrusted_signer_is_rejected() {
        let a = SoftwareAttestor::generate(Measurement([1u8; 48]));
        let rep = a.produce([1u8; 32], b"");
        let foreign = PeerRoots::new([[0u8; 32]]);
        let err = verify_report(&rep, &[1u8; 32], b"", &foreign).unwrap_err();
        assert!(matches!(err, TeeError::BadReportSignature));
    }

    #[test]
    fn tampered_body_is_rejected() {
        let a = SoftwareAttestor::generate(Measurement([1u8; 48]));
        let mut rep = a.produce([1u8; 32], b"");
        rep.body.tcb_svn = rep.body.tcb_svn.wrapping_add(1);
        let err = verify_report(&rep, &[1u8; 32], b"", &roots_for(&a)).unwrap_err();
        assert!(matches!(err, TeeError::BadReportSignature));
    }

    #[test]
    fn report_cbor_round_trips() {
        let a = SoftwareAttestor::generate(Measurement([4u8; 48]));
        let rep = a.produce([7u8; 32], b"hello");
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&rep, &mut buf).unwrap();
        let rep2: Report = ciborium::de::from_reader(buf.as_slice()).unwrap();
        let roots = PeerRoots::new([a.signer_pk()]);
        let m = verify_report(&rep2, &[7u8; 32], b"hello", &roots).unwrap();
        assert_eq!(m, a.measurement());
    }

    #[test]
    fn wrong_bound_data_is_rejected() {
        let a = SoftwareAttestor::generate(Measurement([1u8; 48]));
        let rep = a.produce([1u8; 32], b"hello");
        let err = verify_report(&rep, &[1u8; 32], b"world", &roots_for(&a)).unwrap_err();
        assert!(matches!(err, TeeError::BadReport(_)));
    }
}
