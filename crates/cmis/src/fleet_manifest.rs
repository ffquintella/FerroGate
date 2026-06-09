//! Fleet manifest format, live store, and signed-file loader (feature F13).
//!
//! Zero-touch bootstrap anchors a new host's first SVID in two facts: the TPM
//! vendor's signature on the EK certificate (verified later, in phase 2 of
//! `Attest`) and an **offline-signed fleet manifest** that enumerates the
//! SHA-384 hashes of every EK certificate the operator has approved. Before any
//! TPM verification work runs, CMIS checks the presented EK hash against the
//! manifest; an unknown host is rejected at the door.
//!
//! Three layers live here:
//!
//! - [`FleetManifest`] / [`SignedFleetManifest`] — the on-disk format. A
//!   manifest is only ever applied through a [`SignedFleetManifest`]: the
//!   [`FleetManifest`] together with a composite (Ed25519 + ML-DSA-65)
//!   signature carried by a trusted publisher key. Unsigned input has no path
//!   into the store. The signature covers the **canonical JSON** of the
//!   manifest under [`FLEET_SIGNING_CONTEXT`] so it can never be reinterpreted
//!   as an SVID, CRL, RIM, or audit-log signature.
//! - [`EnrolledHosts`] — the resolved, lookup-optimised snapshot (a hash set of
//!   48-byte EK digests) that the admission check consults.
//! - [`FleetStore`] — a cheaply-cloneable handle wrapping the live
//!   [`EnrolledHosts`] behind an `RwLock<Arc<…>>`. A refresh swaps the `Arc`
//!   under the write lock, so an in-flight `Attest` that took a [`snapshot`]
//!   sees a consistent set for the whole handshake — never a torn update.
//!
//! [`snapshot`]: FleetStore::snapshot

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ferro_attest::TrustedKeys;
use ferro_crypto::composite::{CompositeError, CompositeSecretKey, CompositeSignature};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

/// Domain-separation context for fleet-manifest signatures. Distinct from the
/// SVID, STH, CRL, and RIM contexts so a manifest signature can never be
/// replayed as any other artefact.
pub const FLEET_SIGNING_CONTEXT: &[u8] = b"ferrogate-fleet-v1";

/// Length of a hex-encoded SHA-384 (48 bytes ⇒ 96 lowercase-hex chars).
const EK_SHA_HEX_LEN: usize = 96;

/// The publishable contents of one fleet manifest generation.
///
/// Field declaration order is the canonical key order the signature covers
/// (`serde_json` preserves struct field order).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetManifest {
    /// Monotonic version. A refresh only applies a manifest strictly newer than
    /// the active one (see [`FleetManifestLoader::try_reload`]).
    pub version: u64,
    /// SPIFFE trust domain this manifest authorises hosts for. Advisory today —
    /// CMIS keys admission on the EK hash set — but recorded so an operator can
    /// tell two fleets' manifests apart at a glance.
    pub trust_domain: String,
    /// Unix-seconds the manifest was signed. Advisory / for operator audit.
    pub issued_at: i64,
    /// SHA-384 of every approved EK certificate, lowercase hex (96 chars each).
    pub enrolled_ek_sha384: Vec<String>,
}

impl FleetManifest {
    /// Encode this manifest to the canonical JSON form the signature covers.
    pub fn canonical_json(&self) -> Result<Vec<u8>, FleetError> {
        serde_json::to_vec(self).map_err(|e| FleetError::Json(e.to_string()))
    }

    /// Resolve the manifest into the lookup-optimised [`EnrolledHosts`] set,
    /// decoding and validating each hex digest to 48 bytes.
    pub fn to_enrolled(&self) -> Result<EnrolledHosts, FleetError> {
        let mut hashes = HashSet::with_capacity(self.enrolled_ek_sha384.len());
        for (i, h) in self.enrolled_ek_sha384.iter().enumerate() {
            let h = h.trim();
            if h.len() != EK_SHA_HEX_LEN {
                return Err(FleetError::BadEkHash(format!(
                    "ek[{i}]: expected {EK_SHA_HEX_LEN} hex chars, got {}",
                    h.len()
                )));
            }
            let bytes =
                hex::decode(h).map_err(|e| FleetError::BadEkHash(format!("ek[{i}]: {e}")))?;
            let mut d = [0u8; 48];
            d.copy_from_slice(&bytes);
            hashes.insert(d);
        }
        Ok(EnrolledHosts {
            version: self.version,
            enforced: true,
            hashes,
        })
    }
}

/// A [`FleetManifest`] paired with a composite signature and a publisher key id.
///
/// The on-disk JSON object is
/// `{ "manifest": …, "signer_kid": …, "signature_b64": … }`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedFleetManifest {
    /// The manifest contents.
    pub manifest: FleetManifest,
    /// Key id selecting the publisher key in a [`TrustedKeys`] set.
    pub signer_kid: String,
    /// base64url of the concatenated composite signature.
    pub signature_b64: String,
}

impl SignedFleetManifest {
    /// Sign `manifest` with `signer`. Intended for the offline `fleet-manifest`
    /// tool and test fixtures; production publishers use the F14 ceremony key.
    pub fn sign(
        manifest: FleetManifest,
        signer_kid: impl Into<String>,
        signer: &CompositeSecretKey,
    ) -> Result<Self, FleetError> {
        let bytes = manifest.canonical_json()?;
        let sig = signer
            .sign(FLEET_SIGNING_CONTEXT, &bytes)
            .map_err(FleetError::Sign)?;
        Ok(Self {
            manifest,
            signer_kid: signer_kid.into(),
            signature_b64: URL_SAFE_NO_PAD.encode(sig.to_concat_bytes()),
        })
    }

    /// Decode from JSON.
    pub fn from_json(json: &[u8]) -> Result<Self, FleetError> {
        serde_json::from_slice(json).map_err(|e| FleetError::Json(e.to_string()))
    }

    /// Verify the composite signature against the trust set. Returns a borrow of
    /// the inner manifest on success; never returns a manifest without first
    /// authenticating it. An unknown `signer_kid` is refused before any
    /// cryptographic work.
    pub fn verify<'a>(&'a self, trust: &TrustedKeys) -> Result<&'a FleetManifest, FleetError> {
        let pk = trust
            .get(&self.signer_kid)
            .ok_or_else(|| FleetError::UnknownKid(self.signer_kid.clone()))?;
        let sig_bytes = URL_SAFE_NO_PAD
            .decode(self.signature_b64.as_bytes())
            .map_err(|e| FleetError::BadSignature(format!("base64url: {e}")))?;
        let sig = CompositeSignature::from_concat_bytes(&sig_bytes)
            .map_err(|e| FleetError::BadSignature(e.to_string()))?;
        let payload = self.manifest.canonical_json()?;
        pk.verify(FLEET_SIGNING_CONTEXT, &payload, &sig)
            .map_err(|e| FleetError::BadSignature(e.to_string()))?;
        Ok(&self.manifest)
    }
}

/// The resolved enrolment set the admission check consults.
///
/// Construct an enforcing set via [`FleetManifest::to_enrolled`], or
/// [`EnrolledHosts::unenforced`] for a CMIS with no manifest configured (every
/// host is admitted — the pre-F13 behaviour).
#[derive(Debug, Clone)]
pub struct EnrolledHosts {
    version: u64,
    enforced: bool,
    hashes: HashSet<[u8; 48]>,
}

impl EnrolledHosts {
    /// An unenforced set: no manifest is configured, so admission is a no-op and
    /// every host proceeds to TPM verification (the pre-F13 default).
    #[must_use]
    pub fn unenforced() -> Self {
        Self {
            version: 0,
            enforced: false,
            hashes: HashSet::new(),
        }
    }

    /// Whether this set enforces a manifest (vs. admitting every host).
    #[must_use]
    pub fn is_enforced(&self) -> bool {
        self.enforced
    }

    /// The manifest version this set was resolved from (`0` when unenforced).
    #[must_use]
    pub fn version(&self) -> u64 {
        self.version
    }

    /// Whether `ek_sha` is enrolled.
    #[must_use]
    pub fn contains(&self, ek_sha: &[u8; 48]) -> bool {
        self.hashes.contains(ek_sha)
    }

    /// Number of enrolled EK hashes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.hashes.len()
    }

    /// Whether the enrolment set is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.hashes.is_empty()
    }

    /// Decide admission for `ek_sha` (fail-closed when enforcing).
    #[must_use]
    pub fn decide(&self, ek_sha: &[u8; 48]) -> EnrollmentDecision {
        if !self.enforced {
            EnrollmentDecision::NotEnforced
        } else if self.contains(ek_sha) {
            EnrollmentDecision::Enrolled
        } else {
            EnrollmentDecision::Rejected
        }
    }
}

/// Outcome of a pre-admission check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnrollmentDecision {
    /// No manifest configured — admission is skipped, host proceeds.
    NotEnforced,
    /// EK hash is in the active manifest — host proceeds.
    Enrolled,
    /// EK hash is not enrolled — host is refused before TPM verification.
    Rejected,
}

/// A cheaply-cloneable handle to the live [`EnrolledHosts`] snapshot.
///
/// Clones share one `RwLock<Arc<EnrolledHosts>>`; [`CmisState`] keeps one and
/// the [`FleetManifestLoader`] keeps another. A refresh swaps the inner `Arc`
/// under the write lock; readers call [`snapshot`] to take an `Arc` clone and
/// then run the whole handshake against that fixed view.
///
/// [`CmisState`]: crate::CmisState
/// [`snapshot`]: FleetStore::snapshot
#[derive(Clone)]
pub struct FleetStore {
    inner: Arc<RwLock<Arc<EnrolledHosts>>>,
}

impl FleetStore {
    /// A store with no manifest configured: every host is admitted.
    #[must_use]
    pub fn unenforced() -> Self {
        Self {
            inner: Arc::new(RwLock::new(Arc::new(EnrolledHosts::unenforced()))),
        }
    }

    /// A store pre-loaded with an enrolment set (test/bootstrap convenience).
    #[must_use]
    pub fn with_enrolled(hosts: EnrolledHosts) -> Self {
        Self {
            inner: Arc::new(RwLock::new(Arc::new(hosts))),
        }
    }

    /// Take a consistent snapshot of the current set. Cheap: an `Arc` clone.
    #[must_use]
    pub fn snapshot(&self) -> Arc<EnrolledHosts> {
        Arc::clone(&self.inner.read())
    }

    /// Atomically swap in a new enrolment set. In-flight readers holding an
    /// earlier [`snapshot`] are unaffected.
    ///
    /// [`snapshot`]: FleetStore::snapshot
    pub fn apply(&self, hosts: EnrolledHosts) {
        *self.inner.write() = Arc::new(hosts);
    }

    /// The active manifest version (`0` when unenforced).
    #[must_use]
    pub fn current_version(&self) -> u64 {
        self.inner.read().version()
    }

    /// Decide admission for `ek_sha` against the current snapshot.
    #[must_use]
    pub fn decide(&self, ek_sha: &[u8; 48]) -> EnrollmentDecision {
        self.snapshot().decide(ek_sha)
    }
}

impl Default for FleetStore {
    fn default() -> Self {
        Self::unenforced()
    }
}

/// What happened on a manifest reload attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FleetReloadOutcome {
    /// The on-disk manifest advanced the store; it is now the active set.
    Applied {
        /// The newly-applied manifest version.
        version: u64,
        /// Number of enrolled EK hashes now in force.
        enrolled: usize,
    },
    /// The on-disk manifest's version is not strictly newer than the active
    /// one; nothing changed.
    UpToDate {
        /// The version currently active in the store.
        version: u64,
    },
}

/// A loader binding a manifest file path, the publisher trust set, and the live
/// [`FleetStore`]. Mirrors `ferro_attest::RimLoader`.
pub struct FleetManifestLoader {
    path: PathBuf,
    trust: TrustedKeys,
    store: FleetStore,
}

impl FleetManifestLoader {
    /// Build a loader. The `store` handle should be a clone of the one held by
    /// [`CmisState`] so applies are visible to the admission check.
    ///
    /// [`CmisState`]: crate::CmisState
    #[must_use]
    pub fn new(path: impl Into<PathBuf>, trust: TrustedKeys, store: FleetStore) -> Self {
        Self {
            path: path.into(),
            trust,
            store,
        }
    }

    /// The manifest path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The shared store handle.
    #[must_use]
    pub fn store(&self) -> &FleetStore {
        &self.store
    }

    /// Read, verify, and (if strictly newer) apply the manifest on disk.
    ///
    /// Returns [`FleetReloadOutcome::UpToDate`] (not an error) when the on-disk
    /// version is `<=` the active one, so a polling loop can back off without
    /// escalating.
    pub fn try_reload(&self) -> Result<FleetReloadOutcome, FleetReloadError> {
        let bytes = std::fs::read(&self.path).map_err(|source| FleetReloadError::Io {
            path: self.path.clone(),
            source,
        })?;
        let signed = SignedFleetManifest::from_json(&bytes)?;
        let manifest = signed.verify(&self.trust)?;
        if manifest.version <= self.store.current_version() {
            return Ok(FleetReloadOutcome::UpToDate {
                version: self.store.current_version(),
            });
        }
        let enrolled = manifest.to_enrolled()?;
        let outcome = FleetReloadOutcome::Applied {
            version: enrolled.version(),
            enrolled: enrolled.len(),
        };
        self.store.apply(enrolled);
        Ok(outcome)
    }
}

/// Failure modes for manifest encoding / decoding / signing / verification.
#[derive(Debug, thiserror::Error)]
pub enum FleetError {
    /// JSON serialization or parsing failed.
    #[error("json: {0}")]
    Json(String),
    /// The composite signer failed.
    #[error("sign: {0}")]
    Sign(#[from] CompositeError),
    /// `signer_kid` is not in the trust set.
    #[error("unknown signer kid: {0}")]
    UnknownKid(String),
    /// The signature decoded but did not verify.
    #[error("bad signature: {0}")]
    BadSignature(String),
    /// An enrolled EK hash was not 96 hex chars / 48 bytes.
    #[error("bad ek hash: {0}")]
    BadEkHash(String),
}

/// Failure modes for a manifest reload.
#[derive(Debug, thiserror::Error)]
pub enum FleetReloadError {
    /// The manifest file could not be read.
    #[error("read {path}: {source}")]
    Io {
        /// Path that failed.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// The manifest failed to parse, decode, or pass signature verification.
    #[error("manifest: {0}")]
    Manifest(#[from] FleetError),
}

#[cfg(test)]
mod tests {
    use ferro_crypto::composite::CompositePublicKey;

    use super::*;

    fn keypair() -> (CompositeSecretKey, CompositePublicKey) {
        CompositeSecretKey::generate().unwrap()
    }

    fn ek_hex(byte: u8) -> String {
        hex::encode([byte; 48])
    }

    fn sample(version: u64, eks: &[u8]) -> FleetManifest {
        FleetManifest {
            version,
            trust_domain: "ferrogate.test".to_string(),
            issued_at: 1_700_000_000,
            enrolled_ek_sha384: eks.iter().map(|b| ek_hex(*b)).collect(),
        }
    }

    fn trust_with(kid: &str, pk: CompositePublicKey) -> TrustedKeys {
        let mut t = TrustedKeys::new();
        t.add(kid, pk);
        t
    }

    #[test]
    fn sign_then_verify_roundtrips() {
        let (sk, pk) = keypair();
        let signed = SignedFleetManifest::sign(sample(1, &[0xAA]), "fleet-1", &sk).unwrap();
        let trust = trust_with("fleet-1", pk);
        let verified = signed.verify(&trust).expect("verify ok");
        assert_eq!(verified.version, 1);
    }

    #[test]
    fn unknown_kid_is_refused_before_crypto() {
        let (sk, _pk) = keypair();
        let signed = SignedFleetManifest::sign(sample(1, &[0xAA]), "evil", &sk).unwrap();
        let err = signed.verify(&TrustedKeys::new()).unwrap_err();
        assert!(matches!(err, FleetError::UnknownKid(_)));
    }

    #[test]
    fn tampered_manifest_fails_signature() {
        let (sk, pk) = keypair();
        let mut signed = SignedFleetManifest::sign(sample(1, &[0xAA]), "fleet-1", &sk).unwrap();
        signed.manifest.enrolled_ek_sha384[0] = ek_hex(0xBB);
        let trust = trust_with("fleet-1", pk);
        assert!(matches!(
            signed.verify(&trust),
            Err(FleetError::BadSignature(_))
        ));
    }

    #[test]
    fn json_roundtrip_preserves_signature() {
        let (sk, pk) = keypair();
        let signed = SignedFleetManifest::sign(sample(3, &[1, 2, 3]), "p", &sk).unwrap();
        let blob = serde_json::to_vec(&signed).unwrap();
        let back = SignedFleetManifest::from_json(&blob).unwrap();
        let trust = trust_with("p", pk);
        back.verify(&trust).expect("verify after json roundtrip");
    }

    #[test]
    fn to_enrolled_rejects_bad_hex() {
        let mut m = sample(1, &[0xAA]);
        m.enrolled_ek_sha384[0] = "not-hex".to_string();
        assert!(matches!(m.to_enrolled(), Err(FleetError::BadEkHash(_))));
    }

    #[test]
    fn enrolled_lookup_and_decisions() {
        let hosts = sample(1, &[0xAA, 0xBB]).to_enrolled().unwrap();
        assert!(hosts.is_enforced());
        assert_eq!(hosts.len(), 2);
        assert_eq!(hosts.decide(&[0xAA; 48]), EnrollmentDecision::Enrolled);
        assert_eq!(hosts.decide(&[0xCC; 48]), EnrollmentDecision::Rejected);
    }

    #[test]
    fn unenforced_admits_everything() {
        let store = FleetStore::unenforced();
        assert_eq!(store.current_version(), 0);
        assert_eq!(store.decide(&[0x11; 48]), EnrollmentDecision::NotEnforced);
    }

    #[test]
    fn apply_swaps_snapshot_atomically() {
        let store = FleetStore::unenforced();
        // A snapshot taken before the swap keeps its (unenforced) view.
        let before = store.snapshot();
        store.apply(sample(5, &[0xAA]).to_enrolled().unwrap());
        assert_eq!(store.current_version(), 5);
        assert_eq!(store.decide(&[0xAA; 48]), EnrollmentDecision::Enrolled);
        assert_eq!(store.decide(&[0xBB; 48]), EnrollmentDecision::Rejected);
        // The pre-swap snapshot is unchanged.
        assert!(!before.is_enforced());
    }
}
