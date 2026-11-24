//! Test support (feature `test-support`): generated certificate chains and a
//! fake [`SignatureVerifier`], so the decision can be tested on every host.

#![allow(clippy::missing_panics_doc)] // test support: a fixture failure panics

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use rcgen::{date_time_ymd, BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};

use crate::facts::cert_facts;
use crate::model::{PinKind, PublisherRule, SignatureKind};
use crate::verifier::{CallerTarget, SignatureVerifier, VerifiedSignature, VerifyError};

/// A CA and a code-signing leaf it issued (DER).
#[derive(Debug, Clone)]
pub struct TestChain {
    /// The CA certificate.
    pub ca_der: Vec<u8>,
    /// The leaf certificate, subject `CN=<publisher>, O=FerroGate Tests`.
    pub leaf_der: Vec<u8>,
}

impl TestChain {
    /// A chain valid from 2020 to 2040.
    #[must_use]
    pub fn new(publisher: &str) -> Self {
        Self::with_leaf_window(publisher, (2020, 1, 1), (2040, 1, 1))
    }

    /// A chain whose leaf expired at the start of 2021.
    #[must_use]
    pub fn expired(publisher: &str) -> Self {
        Self::with_leaf_window(publisher, (2020, 1, 1), (2021, 1, 1))
    }

    fn with_leaf_window(publisher: &str, from: (i32, u8, u8), to: (i32, u8, u8)) -> Self {
        let ca_key = KeyPair::generate().expect("ca key");
        let mut ca = CertificateParams::new(Vec::<String>::new()).expect("ca params");
        ca.distinguished_name
            .push(DnType::CommonName, "FerroGate Test CA");
        ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca.not_before = date_time_ymd(2019, 1, 1);
        ca.not_after = date_time_ymd(2045, 1, 1);
        let ca_der = ca.self_signed(&ca_key).expect("ca cert").der().to_vec();

        let leaf_key = KeyPair::generate().expect("leaf key");
        let mut leaf = CertificateParams::new(Vec::<String>::new()).expect("leaf params");
        leaf.distinguished_name.push(DnType::CommonName, publisher);
        leaf.distinguished_name
            .push(DnType::OrganizationName, "FerroGate Tests");
        leaf.not_before = date_time_ymd(from.0, from.1, from.2);
        leaf.not_after = date_time_ymd(to.0, to.1, to.2);
        let issuer = Issuer::from_params(&ca, &ca_key);
        let leaf_der = leaf
            .signed_by(&leaf_key, &issuer)
            .expect("leaf cert")
            .der()
            .to_vec();
        Self { ca_der, leaf_der }
    }

    /// The chain as an OS verifier would return it (leaf first).
    #[must_use]
    pub fn signature(&self, kind: SignatureKind, timestamped: bool) -> VerifiedSignature {
        VerifiedSignature {
            kind,
            chain_der: vec![self.leaf_der.clone(), self.ca_der.clone()],
            timestamped,
        }
    }

    /// A rule pinning this chain's CA and its leaf's `pin_kind` digest.
    #[must_use]
    pub fn rule(&self, id: u8, kind: SignatureKind, pin_kind: PinKind) -> PublisherRule {
        let leaf = cert_facts(&self.leaf_der).expect("leaf facts");
        let ca = cert_facts(&self.ca_der).expect("ca facts");
        PublisherRule {
            publisher_id: [id; 16],
            kind,
            anchor_sha256: ca.cert_sha256,
            pin_kind,
            pin: leaf.pin(pin_kind),
            require_timestamp: false,
            expires_at: None,
        }
    }
}

/// A [`SignatureVerifier`] that returns a fixed answer and counts calls.
#[derive(Debug)]
pub struct FakeVerifier {
    answer: Mutex<Result<VerifiedSignature, VerifyError>>,
    calls: AtomicUsize,
}

impl FakeVerifier {
    /// Answer every call with `answer`.
    #[must_use]
    pub fn new(answer: Result<VerifiedSignature, VerifyError>) -> Self {
        Self {
            answer: Mutex::new(answer),
            calls: AtomicUsize::new(0),
        }
    }

    /// How many verifications were asked for.
    #[must_use]
    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    fn answer(&self) -> Result<VerifiedSignature, VerifyError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.answer
            .lock()
            .map_or(Err(VerifyError::Unsupported), |a| a.clone())
    }
}

impl SignatureVerifier for FakeVerifier {
    fn verify_caller(&self, _target: &CallerTarget<'_>) -> Result<VerifiedSignature, VerifyError> {
        self.answer()
    }

    fn verify_file(&self, _path: &std::path::Path) -> Result<VerifiedSignature, VerifyError> {
        self.answer()
    }
}
