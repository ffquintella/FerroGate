//! `Rotate` host proof (T293): a host renews by signing a `RotateDoc` with
//! the machine key its SVID is bound to, under `ferrogate-rotate-v1`. Only
//! the host-key tier renews, only from its latest SVID, only on the short
//! path; refusals after authentication audit `AttestFail`, renewals
//! `SvidIssued`.

#![allow(clippy::large_futures)]

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use cmis::credential::{CredentialError, CredentialMaker, WrappedCredential};
use cmis::host_auth::HostCallConfig;
use cmis::{CmisConfig, CmisState, IssuedRecord, MachineIdentitySvc};
use ferro_attest::{RimStore, TpmQuoteVerifier, VendorTrustStore};
use ferro_audit::{AuditEvent, AuditLog, AuditStore, Hash384, InProcessSigner};
use ferro_proto::v1::machine_identity_server::MachineIdentity;
use ferro_proto::v1::{HostCallAuth, RotateRequest, SvidBundle};
use ferro_raft::Cluster;
use ferro_sep::{MachineKey, SoftwareMachineKey};
use ferro_svid::envelope::{self, JwsHeader};
use ferro_svid::host_call::{self, RotateDoc, AUDIT_FORWARD_CONTEXT, ROTATE_CONTEXT};
use ferro_svid::{
    host_uuid_from_ek_digest, IssueParams, IssuedSvid, Issuer, LastAttestation, RevocationTarget,
    REATTEST_WINDOW_SECS,
};
use sha2::{Digest, Sha256, Sha384};
use tonic::Code;

struct UnusedCredentialMaker;
impl CredentialMaker for UnusedCredentialMaker {
    fn make_credential(
        &self,
        _ek_pub: &[u8],
        _aik_pub: &[u8],
        _secret: &[u8],
    ) -> Result<WrappedCredential, CredentialError> {
        Err(CredentialError::Wrap("unused".to_string()))
    }
}

struct TmpDirs(Vec<std::path::PathBuf>);
impl Drop for TmpDirs {
    fn drop(&mut self) {
        for dir in &self.0 {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// A nonce unique within the test process.
fn nonce() -> [u8; 16] {
    static N: AtomicU64 = AtomicU64::new(1);
    let mut out = [0u8; 16];
    out[..8].copy_from_slice(&N.fetch_add(1, Ordering::Relaxed).to_le_bytes());
    out[8..12].copy_from_slice(&std::process::id().to_le_bytes());
    out
}

fn sha384(bytes: &[u8]) -> [u8; 48] {
    let mut out = [0u8; 48];
    out.copy_from_slice(&Sha384::digest(bytes));
    out
}

fn jkt_of(key: &SoftwareMachineKey) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(key.public_spki_der()))
}

/// The issuer key id of every fixture; a foreign issuer reuses it, so only
/// the signature tells them apart.
const KID: &str = "cmis-test-rotate";
const TRUST_DOMAIN: &str = "ferrogate.test";

/// One attested host: its machine key, the SVID bound to it, the parameters
/// it was attested with and its machine fingerprint.
struct Host {
    key: SoftwareMachineKey,
    issued: IssuedSvid,
    uuid: String,
    fingerprint: [u8; 48],
    params: IssueParams,
}

impl Host {
    fn jws(&self) -> &str {
        &self.issued.jws
    }

    fn spiffe_id(&self) -> &str {
        &self.issued.spiffe_id
    }
}

/// Mint a host under `issuer` with fingerprint byte `fp` and SVID policy
/// `policy_id` (`"host-key"`, or anything else for TPM), issued at `iat`.
fn mint_host(issuer: &Issuer, fp: u8, policy_id: &str, iat: i64) -> Host {
    let key = SoftwareMachineKey::generate().unwrap();
    let fingerprint = [fp; 48];
    let params = IssueParams {
        ek_cert_sha384: fingerprint,
        // The host-key tier stores the fingerprint as its state digest.
        pcr_digest: fingerprint,
        policy_id: policy_id.into(),
        dpop_jkt: jkt_of(&key),
        ttl_secs: 3600,
        tee_evidence_id: None,
        subject_pub: None,
    };
    let svid = issuer.issue(&params, iat).unwrap();
    Host {
        key,
        issued: svid,
        uuid: host_uuid_from_ek_digest(&fingerprint).to_string(),
        fingerprint,
        params,
    }
}

struct Fixture {
    svc: MachineIdentitySvc,
    state: Arc<CmisState>,
    _dirs: TmpDirs,
}

async fn setup_with(config: CmisConfig) -> Fixture {
    static COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let issuer = Issuer::generate(KID, TRUST_DOMAIN).unwrap();
    let verifier = TpmQuoteVerifier::new(VendorTrustStore::default(), RimStore::new());
    let tmp =
        std::env::temp_dir().join(format!("ferrogate-cmis-rotate-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    let store: Arc<dyn AuditStore> = Arc::new(ferro_audit::LocalDiskWormStore::open(&tmp).unwrap());
    let (signer, _pk) = InProcessSigner::generate("audit-test-rotate").unwrap();
    let audit = AuditLog::new(store, Arc::new(signer)).unwrap();
    let raft_dir = std::env::temp_dir().join(format!(
        "ferrogate-cmis-rotate-raft-{}-{n}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&raft_dir);
    let cluster = Arc::new(
        Cluster::start_single_node(raft_dir.to_string_lossy().into_owned())
            .await
            .unwrap(),
    );
    let state = Arc::new(CmisState::new(
        issuer,
        verifier,
        Box::new(UnusedCredentialMaker),
        config,
        audit,
        cluster,
    ));
    Fixture {
        svc: MachineIdentitySvc::new(Arc::clone(&state)),
        state,
        _dirs: TmpDirs(vec![tmp, raft_dir]),
    }
}

async fn setup() -> Fixture {
    setup_with(CmisConfig::default()).await
}

impl Fixture {
    /// A host minted by this CMIS, issued now.
    fn host(&self, fp: u8, policy_id: &str) -> Host {
        mint_host(&self.state.issuer, fp, policy_id, now_unix())
    }

    /// Store `h`'s record as a full attestation at `attested_at` under the
    /// live epoch, exactly as `Attest` does.
    async fn seed(&self, h: &Host, attested_at: i64) {
        self.state
            .record(IssuedRecord {
                params: h.params.clone(),
                last_attestation: LastAttestation {
                    at: attested_at,
                    pcr_digest: h.fingerprint,
                    policy_epoch: self.state.current_epoch(),
                },
                bundle: h.issued.clone(),
                hostname: None,
                child_pub: None,
            })
            .await;
    }

    /// A host-key host attested now, with its record stored.
    async fn attested(&self, fp: u8) -> Host {
        let h = self.host(fp, "host-key");
        self.seed(&h, now_unix()).await;
        h
    }

    async fn stored_jws(&self, h: &Host) -> Option<String> {
        self.state.lookup(h.spiffe_id()).await.map(|r| r.bundle.jws)
    }

    /// The leaf hash of the newest audit event.
    fn last_leaf(&self) -> [u8; 48] {
        let len = u64::try_from(self.state.audit.len()).unwrap();
        self.state.audit.inclusion_proof(len - 1).unwrap().leaf_hash
    }

    fn assert_last_event(&self, event: &AuditEvent) {
        let want = ferro_audit::leaf_hash(&ferro_audit::event::encode(event).unwrap());
        assert_eq!(self.last_leaf(), want, "newest audit event is {event:?}");
    }
}

/// What a test may vary when building a proof.
struct Proof<'a> {
    signer: &'a SoftwareMachineKey,
    /// The SVID in `HostCallAuth.svid_jws`.
    auth_svid: &'a str,
    /// The SVID the signed document names (normally the same).
    doc_svid: &'a str,
    /// `RotateRequest.current_svid`.
    current_svid: String,
    host_uuid: &'a str,
    issued_at: i64,
    nonce: [u8; 16],
    state_digest: [u8; 48],
    context: &'a [u8],
}

impl<'a> Proof<'a> {
    fn honest(h: &'a Host) -> Self {
        Self {
            signer: &h.key,
            auth_svid: h.jws(),
            doc_svid: h.jws(),
            current_svid: h.jws().to_string(),
            host_uuid: &h.uuid,
            issued_at: now_unix(),
            nonce: nonce(),
            state_digest: h.fingerprint,
            context: ROTATE_CONTEXT,
        }
    }

    fn request(&self) -> RotateRequest {
        let doc = RotateDoc::new(
            self.host_uuid,
            self.issued_at,
            self.nonce,
            self.doc_svid,
            self.state_digest,
        );
        let doc = host_call::encode_rotate(&doc).unwrap();
        let sig = self
            .signer
            .sign(&host_call::signing_input(self.context, &doc))
            .unwrap();
        RotateRequest {
            current_svid: self.current_svid.clone(),
            pcr_values: Vec::new(),
            known_epoch: 0,
            auth: Some(HostCallAuth {
                svid_jws: self.auth_svid.to_string(),
                sep_pub: self.signer.public_spki_der(),
                sig,
            }),
            doc,
        }
    }
}

async fn rotate(f: &Fixture, req: RotateRequest) -> Result<SvidBundle, tonic::Status> {
    f.svc
        .rotate(tonic::Request::new(req))
        .await
        .map(tonic::Response::into_inner)
}

/// `req` fails host authentication: nothing issued, stored or audited.
async fn refused_unauthenticated(f: &Fixture, h: &Host, req: RotateRequest) {
    refused_with(f, h, req, Code::Unauthenticated, "host_auth_failed").await;
}

async fn refused_with(f: &Fixture, h: &Host, req: RotateRequest, code: Code, message: &str) {
    let before = f.state.audit.len();
    let stored = f.stored_jws(h).await;
    let e = rotate(f, req).await.expect_err("must be refused");
    assert_eq!((e.code(), e.message()), (code, message));
    assert_eq!(f.state.audit.len(), before, "nothing audited");
    assert_eq!(
        f.stored_jws(h).await,
        stored,
        "the stored SVID is untouched"
    );
}

/// `req` authenticates but is refused with FAILED_PRECONDITION; exactly one
/// `AttestFail { reason }` is audited and nothing is stored.
async fn refused_precondition(f: &Fixture, h: &Host, req: RotateRequest, reason: &str) {
    let before = f.state.audit.len();
    let stored = f.stored_jws(h).await;
    let e = rotate(f, req).await.expect_err("must be refused");
    assert_eq!(
        (e.code(), e.message()),
        (Code::FailedPrecondition, "re-attestation required")
    );
    assert_eq!(f.state.audit.len(), before + 1, "one refusal audited");
    f.assert_last_event(&AuditEvent::AttestFail {
        reason: reason.to_string(),
    });
    assert_eq!(
        f.stored_jws(h).await,
        stored,
        "the stored SVID is untouched"
    );
}

// ---- success -----------------------------------------------------------------

#[tokio::test]
async fn rotate_succeeds_short_path() {
    let f = setup().await;
    let h = f.attested(0x42).await;
    let attested_at = f
        .state
        .lookup(h.spiffe_id())
        .await
        .unwrap()
        .last_attestation;

    let renewed = rotate(&f, Proof::honest(&h).request())
        .await
        .expect("an in-window host-key renewal takes the short path");

    assert_eq!(renewed.spiffe_id, h.spiffe_id());
    assert_ne!(renewed.jws, h.jws(), "a fresh SVID");
    // It verifies under this CMIS's JWKS and stays bound to the same key.
    let jwks = ferro_svid_verify::JwkSet::from_json(
        &serde_json::to_string(&f.state.published_jwks()).unwrap(),
    )
    .unwrap();
    let verified = ferro_svid_verify::verify(&renewed.jws, &jwks, now_unix(), 0).unwrap();
    assert_eq!(verified.claims.sub, h.spiffe_id());
    assert_eq!(verified.claims.cnf.jkt, jkt_of(&h.key));
    assert_eq!(verified.claims.attest.policy_id, "host-key");
    // The renewal replaced the stored bundle, and only the bundle.
    let rec = f.state.lookup(h.spiffe_id()).await.unwrap();
    assert_eq!(rec.bundle.jws, renewed.jws);
    assert_eq!(
        rec.last_attestation, attested_at,
        "the window does not move"
    );
}

#[tokio::test]
async fn rotate_records_audit_event() {
    let f = setup().await;
    let h = f.attested(0x42).await;
    let before = f.state.audit.len();
    let renewed = rotate(&f, Proof::honest(&h).request()).await.unwrap();
    assert_eq!(f.state.audit.len(), before + 1, "exactly one event");
    f.assert_last_event(&AuditEvent::SvidIssued {
        cert_sha: Hash384(sha384(renewed.jws.as_bytes())),
        spiffe_id: h.spiffe_id().to_string(),
    });
}

#[tokio::test]
async fn rotate_accepts_an_empty_current_svid() {
    let f = setup().await;
    let h = f.attested(0x42).await;
    let mut p = Proof::honest(&h);
    p.current_svid = String::new();
    rotate(&f, p.request())
        .await
        .expect("current_svid is optional; auth.svid_jws names the SVID");
}

// ---- authentication ----------------------------------------------------------

/// The pre-T293 attack: an envelope naming a known host, with the attacker's
/// key in `cnf.jkt` and a far `exp`, used to mint a genuine SVID.
#[tokio::test]
async fn rotate_rejects_forged_unsigned_svid() {
    let f = setup().await;
    let h = f.attested(0x42).await;
    let attacker = SoftwareMachineKey::generate().unwrap();

    let decoded = envelope::decode(h.jws()).unwrap();
    let mut claims = decoded.claims.clone();
    claims.exp += 30 * 86_400;
    claims.cnf.jkt = jkt_of(&attacker);
    let input = envelope::signing_input(&JwsHeader::new(KID), &claims).unwrap();
    // The genuine signature over other claims, and no signature at all.
    for forged in [
        envelope::compact(&input, &decoded.signature),
        envelope::compact(&input, &[]),
    ] {
        let mut p = Proof::honest(&h);
        p.signer = &attacker;
        p.auth_svid = &forged;
        p.doc_svid = &forged;
        p.current_svid.clone_from(&forged);
        refused_unauthenticated(&f, &h, p.request()).await;
    }
}

#[tokio::test]
async fn rotate_rejects_svid_from_other_issuer() {
    let f = setup().await;
    let h = f.attested(0x42).await;
    // Same trust domain, kid and host: only the signing key differs.
    let foreign = Issuer::generate(KID, TRUST_DOMAIN).unwrap();
    let forged = mint_host(&foreign, 0x42, "host-key", now_unix());
    assert_eq!(forged.spiffe_id(), h.spiffe_id());
    refused_unauthenticated(&f, &h, Proof::honest(&forged).request()).await;
}

#[tokio::test]
async fn rotate_rejects_expired_svid() {
    let f = setup().await;
    // Issued two hours ago for one hour; the record is still in its window.
    let h = mint_host(&f.state.issuer, 0x42, "host-key", now_unix() - 7200);
    f.seed(&h, now_unix() - 7200).await;
    refused_unauthenticated(&f, &h, Proof::honest(&h).request()).await;
}

#[tokio::test]
async fn rotate_requires_host_proof() {
    let f = setup().await;
    let h = f.attested(0x42).await;
    let other = f.attested(0x43).await;

    // The pre-T293 request shape: just the SVID, no proof.
    refused_unauthenticated(
        &f,
        &h,
        RotateRequest {
            current_svid: h.jws().to_string(),
            ..Default::default()
        },
    )
    .await;

    // A bad signature.
    let mut req = Proof::honest(&h).request();
    req.auth.as_mut().unwrap().sig = vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01];
    refused_unauthenticated(&f, &h, req).await;

    // A tampered document.
    let mut req = Proof::honest(&h).request();
    let last = req.doc.len() - 1;
    req.doc[last] ^= 0x01;
    refused_unauthenticated(&f, &h, req).await;

    // A signature made for another RPC.
    let mut p = Proof::honest(&h);
    p.context = AUDIT_FORWARD_CONTEXT;
    refused_unauthenticated(&f, &h, p.request()).await;

    // A document naming another SVID than the one presented.
    let mut p = Proof::honest(&h);
    p.doc_svid = other.jws();
    refused_unauthenticated(&f, &h, p.request()).await;

    // `current_svid` naming another SVID than the one presented.
    let mut p = Proof::honest(&h);
    p.current_svid = other.jws().to_string();
    refused_unauthenticated(&f, &h, p.request()).await;

    // A document naming another host.
    let mut p = Proof::honest(&h);
    p.host_uuid = &other.uuid;
    refused_with(&f, &h, p.request(), Code::PermissionDenied, "host_mismatch").await;

    // The genuine renewal still goes through afterwards.
    rotate(&f, Proof::honest(&h).request())
        .await
        .expect("the genuine request");
}

#[tokio::test]
async fn rotate_rejects_an_oversized_current_svid_before_any_crypto() {
    let f = setup().await;
    let h = f.attested(0x42).await;
    let mut p = Proof::honest(&h);
    p.current_svid = "a".repeat(16 * 1024 + 1);
    refused_with(&f, &h, p.request(), Code::InvalidArgument, "field_too_long").await;
}

#[tokio::test]
async fn rotate_rejects_key_not_bound_to_svid() {
    let f = setup().await;
    let h = f.attested(0x42).await;
    let other = f.attested(0x43).await;
    // The other host's machine key signs, presenting this host's SVID.
    let mut p = Proof::honest(&h);
    p.signer = &other.key;
    refused_unauthenticated(&f, &h, p.request()).await;
}

#[tokio::test]
async fn rotate_rejects_replayed_nonce() {
    let f = setup().await;
    let h = f.attested(0x42).await;
    let req = Proof::honest(&h).request();
    rotate(&f, req.clone()).await.expect("first use");
    // The exact replay is refused as a replay, before the superseded check.
    let before = f.state.audit.len();
    let e = rotate(&f, req).await.expect_err("replay");
    assert_eq!(
        (e.code(), e.message()),
        (Code::Unauthenticated, "host_auth_failed")
    );
    assert_eq!(f.state.audit.len(), before);
}

#[tokio::test]
async fn rotate_rejects_stale_doc() {
    let f = setup().await;
    let h = f.attested(0x42).await;
    let mut p = Proof::honest(&h);
    p.issued_at = now_unix() - 301;
    refused_unauthenticated(&f, &h, p.request()).await;
    let mut p = Proof::honest(&h);
    p.issued_at = now_unix() + 305;
    refused_unauthenticated(&f, &h, p.request()).await;
}

#[tokio::test]
async fn rotate_refuses_revoked_host() {
    let f = setup().await;
    let h = f.attested(0x42).await;
    f.state.revoke(
        RevocationTarget::Host {
            spiffe_id: h.spiffe_id().to_string(),
        },
        "compromised",
        now_unix(),
    );
    refused_unauthenticated(&f, &h, Proof::honest(&h).request()).await;
}

#[tokio::test]
async fn rotate_refuses_revoked_svid() {
    let f = setup().await;
    let h = f.attested(0x42).await;
    f.state.revoke(
        RevocationTarget::Svid {
            cert_sha: hex::encode(sha384(h.jws().as_bytes())),
        },
        "key-compromise",
        now_unix(),
    );
    refused_unauthenticated(&f, &h, Proof::honest(&h).request()).await;
}

#[tokio::test]
async fn rotate_rate_limited() {
    let f = setup_with(CmisConfig {
        host_calls: HostCallConfig {
            rotate_per_hour: 2,
            ..Default::default()
        },
        ..CmisConfig::default()
    })
    .await;
    let mut h = f.attested(0x42).await;
    for _ in 0..2 {
        let renewed = rotate(&f, Proof::honest(&h).request())
            .await
            .expect("within budget");
        h.issued.jws = renewed.jws;
    }
    let before = f.state.audit.len();
    let e = rotate(&f, Proof::honest(&h).request())
        .await
        .expect_err("third renewal in the hour");
    assert_eq!(
        (e.code(), e.message()),
        (Code::ResourceExhausted, "rate_limited")
    );
    let retry_after: u64 = e
        .metadata()
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
        .expect("a numeric retry-after");
    assert!(
        (1..=1800).contains(&retry_after),
        "retry-after {retry_after}"
    );
    assert_eq!(f.state.audit.len(), before, "nothing issued or audited");
    // The budget is per host.
    let other = f.attested(0x43).await;
    rotate(&f, Proof::honest(&other).request())
        .await
        .expect("another host has its own budget");
}

// ---- authenticated refusals ------------------------------------------------------

#[tokio::test]
async fn rotate_refuses_tpm_tier() {
    let f = setup().await;
    let h = f.host(0x42, "test-fleet");
    f.seed(&h, now_unix()).await;
    refused_precondition(
        &f,
        &h,
        Proof::honest(&h).request(),
        "rotate-tier-requires-attest",
    )
    .await;
}

#[tokio::test]
async fn rotate_rejects_superseded_svid() {
    let f = setup().await;
    let h = f.attested(0x42).await;
    let renewed = rotate(&f, Proof::honest(&h).request()).await.unwrap();

    // The SVID it replaced cannot renew again, even with a fresh proof.
    refused_precondition(&f, &h, Proof::honest(&h).request(), "rotate-superseded").await;

    // Neither can an older SVID still inside its lifetime (bound to its own
    // key).
    let older = mint_host(&f.state.issuer, 0x42, "host-key", now_unix() - 60);
    refused_precondition(&f, &h, Proof::honest(&older).request(), "rotate-superseded").await;

    // The latest one can.
    let mut latest = h;
    latest.issued.jws = renewed.jws;
    rotate(&f, Proof::honest(&latest).request())
        .await
        .expect("the latest SVID renews");
}

#[tokio::test]
async fn rotate_refuses_state_digest_drift() {
    let f = setup().await;
    let h = f.attested(0x42).await;
    let mut p = Proof::honest(&h);
    p.state_digest = [0xEE; 48];
    refused_precondition(&f, &h, p.request(), "rotate-reattest-state-drift").await;
}

#[tokio::test]
async fn rotate_refuses_after_epoch_bump() {
    let f = setup().await;
    let h = f.attested(0x42).await;
    let (_old, _new) = f.state.bump_epoch();
    refused_precondition(
        &f,
        &h,
        Proof::honest(&h).request(),
        "rotate-reattest-epoch-bump",
    )
    .await;
}

#[tokio::test]
async fn rotate_refuses_outside_the_reattest_window() {
    let f = setup().await;
    let h = f.host(0x42, "host-key");
    f.seed(&h, now_unix() - REATTEST_WINDOW_SECS - 60).await;
    refused_precondition(
        &f,
        &h,
        Proof::honest(&h).request(),
        "rotate-reattest-window-expired",
    )
    .await;
}

#[tokio::test]
async fn rotate_of_an_unknown_subject_is_not_found() {
    let f = setup().await;
    // A valid SVID of this CMIS whose record is gone.
    let h = f.host(0x42, "host-key");
    let before = f.state.audit.len();
    let e = rotate(&f, Proof::honest(&h).request())
        .await
        .expect_err("no record");
    assert_eq!(e.code(), Code::NotFound);
    assert_eq!(f.state.audit.len(), before + 1);
    f.assert_last_event(&AuditEvent::AttestFail {
        reason: "rotate-unknown-subject".to_string(),
    });
    assert!(f.stored_jws(&h).await.is_none(), "nothing stored");
}

/// Two renewals racing from one SVID: the stored-SVID check is repeated
/// inside the write, so at most one is issued.
#[tokio::test]
async fn rotate_concurrent_renewals_issue_at_most_one_svid() {
    let f = setup().await;
    let h = f.attested(0x42).await;
    let (first, second) = tokio::join!(
        rotate(&f, Proof::honest(&h).request()),
        rotate(&f, Proof::honest(&h).request()),
    );
    let (won, lost) = match (first, second) {
        (Ok(issued), Err(refused)) | (Err(refused), Ok(issued)) => (issued, refused),
        (Ok(_), Ok(_)) => panic!("both renewals were issued"),
        (Err(e1), Err(e2)) => panic!("both refused: {e1:?} / {e2:?}"),
    };
    assert_eq!(lost.code(), Code::FailedPrecondition);
    assert_eq!(f.stored_jws(&h).await.as_deref(), Some(won.jws.as_str()));
}
