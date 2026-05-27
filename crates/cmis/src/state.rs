//! Shared CMIS issuance state: the composite issuer, the quote verifier, the
//! credential-activation seam, and the in-memory store of issued SVIDs used to
//! gate `Rotate`.
//!
//! The M2 store is a process-local `HashMap`. Raft replication of issued-SVID
//! metadata (so any cluster member can serve `Rotate`/`FetchSVID`) lands in
//! F05; the [`CmisStore`] seam is where that swap will happen.

use std::collections::HashMap;

use parking_lot::Mutex;
use rand_core::{OsRng, RngCore};

use ferro_attest::TpmQuoteVerifier;
use ferro_svid::{IssueParams, IssuedSvid, Issuer, LastAttestation};

use crate::credential::CredentialMaker;

/// Static issuance policy for a CMIS instance.
#[derive(Debug, Clone)]
pub struct CmisConfig {
    /// SPIFFE trust domain, e.g. `ferrogate.prod`.
    pub trust_domain: String,
    /// SVID lifetime in seconds (clamped to one hour by the issuer).
    pub svid_ttl_secs: u64,
    /// The live RIM policy epoch. A bump forces re-attestation on `Rotate`.
    pub policy_epoch: u64,
}

impl Default for CmisConfig {
    fn default() -> Self {
        Self {
            trust_domain: "ferrogate.dev".to_string(),
            svid_ttl_secs: 3600,
            policy_epoch: 1,
        }
    }
}

/// Everything needed to re-issue and gate renewals for one host.
#[derive(Debug, Clone)]
pub struct IssuedRecord {
    /// Parameters captured at the last full attestation, replayed on renewal.
    pub params: IssueParams,
    /// State gating renewal-vs-re-attestation.
    pub last_attestation: LastAttestation,
    /// The most recently issued bundle.
    pub bundle: IssuedSvid,
}

/// Process-wide CMIS state behind an `Arc`.
pub struct CmisState {
    /// The composite SVID issuer.
    pub issuer: Issuer,
    /// The TPM quote verifier (vendor roots + RIM allowlist).
    pub verifier: TpmQuoteVerifier,
    /// Phase-3 credential wrapper.
    pub credential_maker: Box<dyn CredentialMaker>,
    /// Static issuance policy.
    pub config: CmisConfig,
    issued: Mutex<HashMap<String, IssuedRecord>>,
}

impl CmisState {
    /// Assemble CMIS state from its parts.
    #[must_use]
    pub fn new(
        issuer: Issuer,
        verifier: TpmQuoteVerifier,
        credential_maker: Box<dyn CredentialMaker>,
        config: CmisConfig,
    ) -> Self {
        Self {
            issuer,
            verifier,
            credential_maker,
            config,
            issued: Mutex::new(HashMap::new()),
        }
    }

    /// Fill an N-byte buffer from the OS CSPRNG (nonces, phase-3 secrets).
    #[must_use]
    pub fn random_bytes<const N: usize>(&self) -> [u8; N] {
        let mut buf = [0u8; N];
        OsRng.fill_bytes(&mut buf);
        buf
    }

    /// Record a freshly attested+issued SVID, keyed by subject SPIFFE ID.
    pub fn record(&self, record: IssuedRecord) {
        self.issued
            .lock()
            .insert(record.bundle.spiffe_id.clone(), record);
    }

    /// Look up the stored record for a subject.
    #[must_use]
    pub fn lookup(&self, spiffe_id: &str) -> Option<IssuedRecord> {
        self.issued.lock().get(spiffe_id).cloned()
    }

    /// Replace the stored bundle for a subject after a renewal (the
    /// `last_attestation` window is intentionally left unchanged).
    pub fn update_bundle(&self, spiffe_id: &str, bundle: IssuedSvid) {
        if let Some(rec) = self.issued.lock().get_mut(spiffe_id) {
            rec.bundle = bundle;
        }
    }
}
