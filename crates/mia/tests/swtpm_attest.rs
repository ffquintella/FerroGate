//! End-to-end attestation against a software TPM (`swtpm`).
//!
//! Spins up an `swtpm` instance, drives the real [`mia::tpm::TpmEngine`] to
//! create an EK and AIK, quote the policy PCRs, sign over a payload, and run
//! credential activation — then feeds the AIK public area, quote, and
//! signature through the CMIS-side [`ferro_attest::TpmQuoteVerifier`] and
//! asserts the whole chain is accepted. Negative cases (wrong nonce, tampered
//! quote, credential mismatch) are checked against the same real evidence.
//!
//! Linux-only and requires `swtpm` on `PATH`; skipped otherwise.
#![cfg(target_os = "linux")]

use std::net::TcpStream;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use ferro_attest::verify::{PcrSet, QuoteVerification, RejectReason};
use ferro_attest::{PolicyId, RimStore, TpmQuoteVerifier, Vendor, VendorTrustStore};

use mia::tpm::TpmEngine;

use sha2::{Digest as _, Sha384};
use tss_esapi::structures::{Digest, EncryptedSecret, IdObject};
use tss_esapi::tcti_ldr::TctiNameConf;

const DATA_PORT: u16 = 2321;
const NOW: i64 = 1_770_000_000;

/// A running `swtpm` process that is killed and reaped on drop.
struct Swtpm {
    child: Child,
    _state: tempdir::TempDir,
}

// Tiny inline temp-dir (avoids pulling a crate just for tests).
mod tempdir {
    use std::path::{Path, PathBuf};
    pub(crate) struct TempDir(PathBuf);
    impl TempDir {
        pub(crate) fn new(tag: &str) -> std::io::Result<Self> {
            let mut p = std::env::temp_dir();
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            p.push(format!("ferrogate-{tag}-{nanos}"));
            std::fs::create_dir_all(&p)?;
            Ok(Self(p))
        }
        pub(crate) fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

impl Swtpm {
    fn start() -> Option<Self> {
        if which("swtpm").is_none() {
            eprintln!("swtpm not found on PATH; skipping integration test");
            return None;
        }
        let state = tempdir::TempDir::new("swtpm").ok()?;
        let child = Command::new("swtpm")
            .args([
                "socket",
                "--tpm2",
                "--server",
                &format!("type=tcp,port={DATA_PORT},bindaddr=127.0.0.1"),
                "--ctrl",
                &format!("type=tcp,port={},bindaddr=127.0.0.1", DATA_PORT + 1),
                "--tpmstate",
                &format!("dir={}", state.path().display()),
                "--flags",
                "not-need-init,startup-clear",
            ])
            .spawn()
            .ok()?;

        // Wait for the command port to accept connections.
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if TcpStream::connect(("127.0.0.1", DATA_PORT)).is_ok() {
                return Some(Self {
                    child,
                    _state: state,
                });
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let mut me = Self {
            child,
            _state: state,
        };
        me.kill();
        None
    }

    fn tcti() -> TctiNameConf {
        format!("swtpm:host=127.0.0.1,port={DATA_PORT}")
            .parse()
            .expect("valid swtpm TCTI")
    }

    fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for Swtpm {
    fn drop(&mut self) {
        self.kill();
    }
}

fn which(bin: &str) -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|d| d.join(bin))
        .find(|p| p.is_file())
}

/// Mint a throwaway "vendor" root + EK leaf so the EK-chain step (which is
/// independent of the TPM's own EK key) has something to anchor to.
fn ek_chain() -> (Vec<u8>, Vec<u8>) {
    use rcgen::{date_time_ymd, BasicConstraints, CertificateParams, Issuer, IsCa, KeyPair};
    let ca_key = KeyPair::generate().unwrap();
    let mut ca = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca.not_before = date_time_ymd(2020, 1, 1);
    ca.not_after = date_time_ymd(2035, 1, 1);
    let ca_cert = ca.self_signed(&ca_key).unwrap();

    let leaf_key = KeyPair::generate().unwrap();
    let mut leaf = CertificateParams::new(vec!["ek.host".to_string()]).unwrap();
    leaf.not_before = date_time_ymd(2020, 1, 1);
    leaf.not_after = date_time_ymd(2035, 1, 1);
    let ca_issuer = Issuer::from_params(&ca, &ca_key);
    let leaf_cert = leaf.signed_by(&leaf_key, &ca_issuer).unwrap();
    (leaf_cert.der().to_vec(), ca_cert.der().to_vec())
}

#[test]
fn swtpm_quote_is_accepted_end_to_end() {
    let Some(swtpm) = Swtpm::start() else {
        return; // environment without swtpm; treated as skipped.
    };

    let _keep = &swtpm; // hold the process alive for the test's duration
    let mut engine = TpmEngine::new(Swtpm::tcti()).expect("open swtpm");
    let ek = engine.load_ek().expect("load EK");
    let aik = engine.create_aik(&ek).expect("create AIK");

    let nonce = [0x42u8; 32];
    let quote = engine.quote(&aik, &nonce).expect("quote");

    // Build the verifier inputs from the real TPM evidence.
    let (leaf_der, root_der) = ek_chain();
    let mut trust = VendorTrustStore::new();
    trust.add_root_der(&root_der, Vendor::Infineon).unwrap();

    let mut pcrs = PcrSet::new();
    let mut agg = Sha384::new();
    for (idx, value) in &quote.pcr_values {
        pcrs.insert(*idx, value.clone());
        agg.update(value);
    }
    let mut digest = [0u8; 48];
    digest.copy_from_slice(&agg.finalize());

    let rim = RimStore::new();
    rim.approve(digest, PolicyId("swtpm-test".into()));
    let verifier = TpmQuoteVerifier::new(trust, rim);

    let good = QuoteVerification {
        ek_cert_der: &leaf_der,
        ek_intermediates: &[],
        aik_pub: &aik.public_marshaled,
        quote_blob: &quote.attest_marshaled,
        signature: &quote.signature_marshaled,
        nonce: &nonce,
        pcrs: &pcrs,
        now: NOW,
    };
    let accepted = verifier.verify_quote(&good).expect("quote must verify");
    assert_eq!(accepted.vendor, Vendor::Infineon);
    assert_eq!(accepted.policy_id.as_str(), "swtpm-test");

    // Negative: a different nonce must be rejected.
    let other_nonce = [0u8; 32];
    let bad = QuoteVerification {
        nonce: &other_nonce,
        ..clone_inputs(&good, &leaf_der, &aik.public_marshaled, &quote)
    };
    assert_eq!(
        verifier.verify_quote(&bad),
        Err(RejectReason::NonceMismatch)
    );

    // Negative: tamper a byte of the quote body -> signature fails.
    let mut tampered_blob = quote.attest_marshaled.clone();
    *tampered_blob.last_mut().unwrap() ^= 0x01;
    let tampered = QuoteVerification {
        quote_blob: &tampered_blob,
        ..clone_inputs(&good, &leaf_der, &aik.public_marshaled, &quote)
    };
    assert_eq!(
        verifier.verify_quote(&tampered),
        Err(RejectReason::SignatureInvalid)
    );

    // Phase 4: the restricted AIK signs a payload (bound to hardware).
    let payload = b"composite-public-key-bytes";
    let aik_sig = engine.sign_aik(&aik, payload).expect("AIK sign");
    assert!(!aik_sig.is_empty());

    // Phase 3: credential activation round-trips and compares constant-time.
    credential_activation_roundtrips(&mut engine, &ek, &aik);
}

/// Rebuild a `QuoteVerification` borrowing the same evidence (the struct holds
/// references, so `..` spread needs owners that outlive the call).
fn clone_inputs<'a>(
    base: &QuoteVerification<'a>,
    leaf_der: &'a [u8],
    aik_pub: &'a [u8],
    quote: &'a mia::tpm::QuoteResult,
) -> QuoteVerification<'a> {
    QuoteVerification {
        ek_cert_der: leaf_der,
        ek_intermediates: &[],
        aik_pub,
        quote_blob: &quote.attest_marshaled,
        signature: &quote.signature_marshaled,
        nonce: base.nonce,
        pcrs: base.pcrs,
        now: base.now,
    }
}

fn credential_activation_roundtrips(
    engine: &mut TpmEngine,
    ek: &mia::tpm::LoadedKey,
    aik: &mia::tpm::LoadedKey,
) {
    use ferro_attest::credential_secret_matches;

    // CMIS side: wrap a fresh secret under the EK, addressed to the AIK name.
    let aik_name = {
        let ctx = engine.context_mut();
        let (_, name, _) = ctx.read_public(aik.handle).expect("read AIK public");
        name
    };
    let secret_bytes = [0x9Cu8; 32];
    let credential = Digest::try_from(secret_bytes.to_vec()).unwrap();

    let (id_object, enc_secret): (IdObject, EncryptedSecret) = {
        let ctx = engine.context_mut();
        ctx.make_credential(ek.handle, credential, aik_name)
            .expect("MakeCredential")
    };

    // MIA side: only the TPM holding both EK and AIK can release the secret.
    let released = engine
        .activate_credential(aik, ek, id_object, enc_secret)
        .expect("ActivateCredential");

    assert!(credential_secret_matches(&secret_bytes, &released));
    let mut wrong = secret_bytes;
    wrong[0] ^= 0xFF;
    assert!(!credential_secret_matches(&wrong, &released));
}
