//! The `MachineIdentity` gRPC service: the four-phase `Attest` handshake plus
//! `Rotate`, `FetchSVID`, and `JWKS`.
//!
//! Client-visible errors map to the small fixed status set in `docs/cmis.md`
//! §"Error model"; the precise reason is logged for the audit trail but never
//! returned, so a probing client learns nothing about which check tripped.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status, Streaming};

use base64::Engine as _;
use ferro_attest::{
    credential_secret_matches, verify_aik_signature, verify_host_key_csr,
    verify_host_key_evidence, PcrSet, QuoteVerification, RejectReason,
};
use ferro_audit::{AuditEvent, Hash384};
use ferro_crypto::composite::{CompositePublicKey, CompositeSignature};
use ferro_proto::v1::attest_request::Phase as ReqPhase;
use ferro_proto::v1::attest_response::Phase as RespPhase;
use ferro_proto::v1::machine_identity_server::{MachineIdentity, MachineIdentityServer};
use ferro_proto::v1::{
    AllowEntryMsg, AllowlistSummary, AppendAuditRequest, AppendAuditResponse, AttestRequest,
    AttestResponse, BumpEpochRequest, BumpEpochResponse, Challenge, ConsistencyProofRequest,
    ConsistencyProofResponse, DeleteAllowlistRequest, DeleteAllowlistResponse,
    DeleteProposalRequest, DeleteProposalResponse, FetchRequest, GetAllowlistRequest,
    GetAllowlistResponse, GetEnrollmentKeyRequest, GetEnrollmentKeyResponse, HealthRequest,
    HealthResponse, InclusionProofRequest, InclusionProofResponse, JwksRequest, JwksResponse,
    LatestSthRequest, LatestSthResponse, ListAllowlistsRequest, ListAllowlistsResponse,
    ListProposalsRequest, ListProposalsResponse, ListSvidsRequest, ListSvidsResponse,
    NodeRole as ProtoNodeRole, Nonce, PendingProposal, ProposeAllowlistRequest,
    ProposeAllowlistResponse, RevokeHostRequest, RevokeResponse, RevokeSvidRequest, RotateRequest,
    SetAllowlistRequest, SetAllowlistResponse, SignedTreeHead, SvidBundle, SvidSummary,
};
use ferro_raft::NodeRole;
use ferro_svid::{
    decide_renewal, IssueParams, IssuedSvid, LastAttestation, RenewalDecision, RevocationTarget,
};
use sha2::{Digest, Sha256, Sha384};

use crate::fleet_manifest::EnrollmentDecision;
use crate::pcr::aggregate_digest;
use crate::state::{CmisState, HostKeyBinding, IssuedRecord, ProposalPolicy};

/// gRPC front end over a shared [`CmisState`].
#[derive(Clone)]
pub struct MachineIdentitySvc {
    state: Arc<CmisState>,
}

impl MachineIdentitySvc {
    /// Wrap shared state in the service front end.
    #[must_use]
    pub fn new(state: Arc<CmisState>) -> Self {
        Self { state }
    }

    /// Build the tonic server wrapper, ready to add to a `Server` router.
    #[must_use]
    pub fn into_server(self) -> MachineIdentityServer<Self> {
        MachineIdentityServer::new(self)
    }

    /// Publish a fresh CRL right now so a revocation reaches consumers within
    /// one publish cycle (here, immediately) rather than waiting for the next
    /// periodic tick. A signing failure is surfaced to the admin caller.
    #[allow(clippy::result_large_err)] // `tonic::Status` is the RPC error shape.
    fn publish_crl_now(&self, now: i64) -> Result<u64, Status> {
        self.state.publish_crl(now).map_err(|e| {
            tracing::error!(error = %e, "CRL publish failed");
            Status::unavailable("issuer temporarily unavailable")
        })
    }
}

/// Upper bound on a caller-allowlist validity window (30 days). Operators
/// re-issue rather than mint long-lived lists, keeping the signed artefact
/// short enough that the MIA's freshness check stays meaningful.
const MAX_ALLOWLIST_TTL_SECS: i64 = 30 * 86_400;

/// Validate and decode a lowercase-hex `SHA-384` (96 hex chars ⇒ 48 bytes).
#[allow(clippy::result_large_err)] // `tonic::Status` is the RPC error shape.
fn parse_cert_sha(s: &str) -> Result<[u8; 48], Status> {
    let bytes =
        hex::decode(s.trim()).map_err(|_| Status::invalid_argument("cert_sha is not hex"))?;
    let arr: [u8; 48] = bytes
        .try_into()
        .map_err(|_| Status::invalid_argument("cert_sha must be 48 bytes (SHA-384)"))?;
    Ok(arr)
}

/// Validate an allowlist entry's `bin_sha`: either the [`BIN_SHA_WILDCARD`]
/// (`"*"`, any binary) or a lowercase-hex `SHA-384`. Rejected here so a
/// malformed list never reaches the signer (and the MIA later rejects nothing
/// it could have caught here).
#[allow(clippy::result_large_err)] // `tonic::Status` is the RPC error shape.
fn validate_bin_sha(s: &str) -> Result<(), Status> {
    if s.trim() == ferro_svid::allowlist::BIN_SHA_WILDCARD {
        return Ok(());
    }
    parse_cert_sha(s)
        .map(|_| ())
        .map_err(|_| Status::invalid_argument("entry bin_sha must be hex SHA-384 or \"*\""))
}

/// Normalise the operator-supplied revocation reason to a bounded opcode so the
/// CRL and audit log never carry unbounded free-text. An empty reason becomes
/// the catch-all `"unspecified"`.
fn revocation_reason(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return "unspecified".to_string();
    }
    trimmed.chars().take(64).collect()
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// Append `event` to the audit log and seal a fresh STH. Audit failures are
/// logged and swallowed — they must never take down the issuance path. (A
/// future hardened CMIS may instead refuse to serve while audit is wedged;
/// noted in `docs/audit.md`.)
fn audit_record(state: &CmisState, event: AuditEvent, now: i64) {
    if let Err(e) = state.audit.append(&event) {
        // ERROR, not WARN: a failing append usually means every later append
        // fails too (e.g. a wedged WORM store), and operators must see that.
        tracing::error!(error = %e, "audit append failed");
        return;
    }
    if let Err(e) = state.audit.produce_sth(now) {
        tracing::error!(error = %e, "audit STH produce failed");
    }
}

/// Record an `AttestFail` event with a stable opcode. Never user input.
fn audit_fail(state: &CmisState, opcode: &'static str, now: i64) {
    audit_record(
        state,
        AuditEvent::AttestFail {
            reason: opcode.to_string(),
        },
        now,
    );
}

/// Collapse a verifier rejection into the small fixed gRPC status set from
/// `docs/cmis.md` §"Error model" — the only place CMIS distinguishes
/// `NotInRim` (a precondition violation) from a quote-validation failure.
fn verifier_status(reason: &RejectReason) -> Status {
    match reason {
        RejectReason::NotInRim => Status::failed_precondition("attestation failed"),
        _ => Status::permission_denied("attestation failed"),
    }
}

fn sha384(bytes: &[u8]) -> [u8; 48] {
    let mut out = [0u8; 48];
    out.copy_from_slice(&Sha384::digest(bytes));
    out
}

/// Verify a presented host SVID JWS was issued by this CMIS and is currently
/// valid, returning `(host_uuid, cnf.jkt, subject_spiffe_id)`. Used by
/// `ProposeAllowlist` to bind a proposal to an attested host in-band (there is
/// no mTLS; the SVID is the host's bearer of identity here). Verifies only
/// against the current issuer key — a host presenting a rotated/cross-signed
/// SVID re-attests rather than proposes, which is acceptable at bootstrap time.
#[allow(clippy::result_large_err)] // `tonic::Status` is the RPC error shape.
fn verify_proposing_svid(
    state: &CmisState,
    svid_jws: &str,
    now: i64,
) -> Result<(String, String, String), Status> {
    let decoded = ferro_svid::envelope::decode(svid_jws)
        .map_err(|_| Status::unauthenticated("malformed svid"))?;
    let sig = CompositeSignature::from_concat_bytes(&decoded.signature)
        .map_err(|_| Status::unauthenticated("malformed svid signature"))?;
    state
        .issuer
        .public_key()
        .verify(
            ferro_svid::SVID_SIGNING_CONTEXT,
            decoded.signing_input.as_bytes(),
            &sig,
        )
        .map_err(|_| Status::unauthenticated("svid not issued by this cmis"))?;
    let claims = decoded.claims;
    if now < claims.nbf || now > claims.exp {
        return Err(Status::unauthenticated("svid is not currently valid"));
    }
    let host_uuid = claims
        .sub
        .rsplit_once("/host/")
        .map(|(_, u)| u.to_string())
        .filter(|u| !u.is_empty())
        .ok_or_else(|| Status::unauthenticated("svid subject is not a host id"))?;
    Ok((host_uuid, claims.cnf.jkt, claims.sub))
}

/// Decode a stored, already-signed live allowlist into its document (metadata
/// only — no re-verify, it is our own artefact). `None` on any decode failure.
fn decode_live_doc(bytes: &[u8]) -> Option<ferro_svid::AllowlistDoc> {
    ferro_svid::allowlist::decode(bytes)
        .and_then(|s| ferro_svid::allowlist::decode_body(&s.body))
        .ok()
}

/// Decode the entry set of a stored, already-signed live allowlist (metadata
/// only — no re-verify, it is our own artefact). `None` on any decode failure.
fn decode_live_entries(bytes: &[u8]) -> Option<Vec<ferro_svid::AllowEntry>> {
    decode_live_doc(bytes).map(|doc| doc.entries)
}

/// Re-stamp a stored allowlist with a fresh validity window when its current one
/// is past half-life (or already expired), so a fetching MIA always loads an
/// allowlist comfortably inside its `max_age_secs` staleness bound instead of
/// rejecting an aged one as `TooOld`/`Expired` and failing closed.
///
/// Only `issued_at`/`not_after` move — the entry set (and the issuer's trust
/// domain) are reproduced unchanged, re-signed with the issuance key. The
/// issuer seed is replicated across the cluster, so any node (leader or
/// follower) can do this on the read path with no Raft write: the refreshed
/// bytes are *served*, not persisted, leaving the stored artefact (and the
/// `issued_at` an operator sees via `ListAllowlists`) as provisioned.
///
/// Fails safe: on any decode/sign/encode failure the stored bytes are served
/// unchanged — the MIA still applies its own freshness check, so a stale serve
/// degrades to the previous behaviour rather than handing out nothing.
fn refresh_served_allowlist(
    issuer: &ferro_svid::Issuer,
    stored: Vec<u8>,
    ttl_secs: i64,
    now: i64,
) -> Vec<u8> {
    let Some(doc) = decode_live_doc(&stored) else {
        return stored;
    };
    // Serve the stored bytes untouched while the window is less than half spent
    // and not yet expired — re-signing every fetch would be needless work.
    let half_life = doc.issued_at.saturating_add(ttl_secs / 2);
    if now <= half_life && now <= doc.not_after {
        return stored;
    }
    let not_after = now.saturating_add(ttl_secs);
    match issuer
        .sign_allowlist(doc.entries, now, not_after)
        .ok()
        .and_then(|signed| ferro_svid::allowlist::encode(&signed).ok())
    {
        Some(fresh) => fresh,
        None => stored,
    }
}

/// Order-insensitive equality of two `(uid, bin_sha)` entry sets.
fn entries_match(a: &[ferro_svid::AllowEntry], b: &[ferro_svid::AllowEntry]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut a: Vec<_> = a.iter().map(|e| (e.uid, e.bin_sha.as_str())).collect();
    let mut b: Vec<_> = b.iter().map(|e| (e.uid, e.bin_sha.as_str())).collect();
    a.sort_unstable();
    b.sort_unstable();
    a == b
}

/// CBOR-encode proposed entries for the pending-proposal store.
fn encode_allow_entries(entries: &[ferro_svid::AllowEntry]) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(128);
    ciborium::into_writer(entries, &mut out).map_err(|e| e.to_string())?;
    Ok(out)
}

/// Decode proposed entries previously stored by [`encode_allow_entries`].
fn decode_allow_entries(bytes: &[u8]) -> Result<Vec<ferro_svid::AllowEntry>, String> {
    ciborium::from_reader(bytes).map_err(|e| e.to_string())
}

/// Pull the next request from the stream, mapping disconnect/None to an error.
async fn next_request(inbound: &mut Streaming<AttestRequest>) -> Result<ReqPhase, Status> {
    match inbound.message().await? {
        Some(AttestRequest { phase: Some(p) }) => Ok(p),
        Some(AttestRequest { phase: None }) => {
            Err(Status::invalid_argument("empty attest request"))
        }
        None => Err(Status::aborted("client closed stream early")),
    }
}

/// Sanitise the host's self-reported hostname before it is stored or shown to
/// an operator. The value is host-controlled free text and display-only —
/// never identity — so keep only printable ASCII, cap the length, and return
/// `None` when nothing usable remains.
fn display_hostname(raw: &str) -> Option<String> {
    const MAX_HOSTNAME_CHARS: usize = 64;
    let cleaned: String = raw
        .trim()
        .chars()
        .filter(char::is_ascii_graphic)
        .take(MAX_HOSTNAME_CHARS)
        .collect();
    (!cleaned.is_empty()).then_some(cleaned)
}

async fn send(
    tx: &mpsc::Sender<Result<AttestResponse, Status>>,
    phase: RespPhase,
) -> Result<(), Status> {
    tx.send(Ok(AttestResponse { phase: Some(phase) }))
        .await
        .map_err(|_| Status::aborted("client closed stream"))
}

/// Drive the full four-phase handshake. Any error terminates the stream with
/// the appropriate status; the detailed reason is logged, not returned.
///
/// The function is long by design: the linear shape mirrors the four-phase
/// protocol so reviewers can follow it top-to-bottom without chasing helpers.
#[allow(clippy::too_many_lines)]
async fn run_attest(
    state: Arc<CmisState>,
    inbound: &mut Streaming<AttestRequest>,
    tx: &mpsc::Sender<Result<AttestResponse, Status>>,
) -> Result<(), Status> {
    let now = unix_now();

    // Server speaks first: issue the qualifyingData nonce for the quote.
    let nonce = state.random_bytes::<32>();
    send(
        tx,
        RespPhase::Nonce(Nonce {
            nonce: nonce.to_vec(),
        }),
    )
    .await?;

    // Phase 2 — hardware and boot attestation.
    let ReqPhase::Init(init) = next_request(inbound).await? else {
        audit_fail(&state, "init-expected", now);
        return Err(Status::invalid_argument("expected attest init"));
    };

    // Display-only operator label, sanitised once here for both profiles.
    let hostname = display_hostname(&init.hostname);

    // Profile split (F15): a TPM-less host sets `host_key` and runs a 3-phase
    // handshake with no credential-activation round. Branch before any
    // TPM-specific work.
    if let Some(host_key) = init.host_key {
        return run_attest_host_key(state, inbound, tx, &nonce, host_key, hostname, now).await;
    }

    // F13 pre-admission: gate the host on the offline-signed fleet manifest
    // *before* any TPM verification work runs. The EK-cert hash is the only
    // input. With no manifest configured this is a no-op; once one is loaded an
    // un-enrolled host is refused here, the cheapest possible point.
    let ek_sha = Hash384(sha384(&init.ek_cert));
    match state.check_enrollment(&ek_sha.0) {
        EnrollmentDecision::Rejected => {
            tracing::warn!("pre-admission: EK not in fleet manifest");
            audit_record(
                &state,
                AuditEvent::HostRejected {
                    ek_sha,
                    reason: "not-enrolled".to_string(),
                },
                now,
            );
            return Err(Status::permission_denied("attestation failed"));
        }
        EnrollmentDecision::Enrolled => {
            audit_record(&state, AuditEvent::HostEnrolled { ek_sha }, now);
        }
        // No manifest configured — nothing to record; proceed as pre-F13.
        EnrollmentDecision::NotEnforced => {}
    }

    let mut pcrs = PcrSet::new();
    for pv in &init.pcr_values {
        pcrs.insert(u8::try_from(pv.index).unwrap_or(u8::MAX), pv.value.clone());
    }
    let verification = QuoteVerification {
        ek_cert_der: &init.ek_cert,
        ek_intermediates: &init.ek_intermediates,
        aik_pub: &init.aik_pub,
        quote_blob: &init.quote_blob,
        signature: &init.signature,
        nonce: &nonce,
        pcrs: &pcrs,
        now,
    };
    let verified = match state.verifier.verify_quote(&verification) {
        Ok(v) => v,
        Err(reason) => {
            tracing::warn!(reason = %reason, "phase 2 quote verification failed");
            let opcode = match reason {
                RejectReason::NotInRim => "quote-not-in-rim",
                _ => "quote-verify-failed",
            };
            audit_fail(&state, opcode, now);
            return Err(verifier_status(&reason));
        }
    };

    // Phase 2 succeeded — record an AttestStart with the EK / AIK identities.
    audit_record(
        &state,
        AuditEvent::AttestStart {
            ek_sha: Hash384(sha384(&init.ek_cert)),
            aik_sha: Hash384(sha384(&init.aik_pub)),
            policy_id: verified.policy_id.as_str().to_string(),
        },
        now,
    );

    // Phase 3 — credential activation (proof of residency).
    let secret = state.random_bytes::<32>();
    let wrapped = state
        .credential_maker
        .make_credential(&init.ek_cert, &init.aik_pub, &secret)
        .map_err(|e| {
            tracing::error!(error = %e, "MakeCredential failed");
            audit_fail(&state, "credential-wrap-failed", now);
            Status::unavailable("issuer temporarily unavailable")
        })?;
    send(
        tx,
        RespPhase::Challenge(Challenge {
            credential_blob: wrapped.credential_blob,
            secret_blob: wrapped.secret_blob,
        }),
    )
    .await?;

    let ReqPhase::ChallengeResponse(challenge_resp) = next_request(inbound).await? else {
        audit_fail(&state, "challenge-resp-expected", now);
        return Err(Status::invalid_argument("expected challenge response"));
    };
    if !credential_secret_matches(&secret, &challenge_resp.secret) {
        tracing::warn!("phase 3 credential activation mismatch");
        audit_fail(&state, "credential-mismatch", now);
        return Err(Status::permission_denied("attestation failed"));
    }

    // Phase 4 — TPM-bound composite CSR and issuance.
    let ReqPhase::Csr(csr) = next_request(inbound).await? else {
        audit_fail(&state, "csr-expected", now);
        return Err(Status::invalid_argument("expected CSR"));
    };
    if let Err(reason) = verify_aik_signature(&init.aik_pub, &csr.composite_pub, &csr.aik_sig) {
        tracing::warn!(reason = %reason, "phase 4 AIK signature over CSR failed");
        audit_fail(&state, "aik-sig-invalid", now);
        return Err(Status::permission_denied("attestation failed"));
    }

    // Publish the host's composite key so downstream verifiers can validate the
    // child tokens (F09) the MIA will mint with it. A malformed key here is the
    // host's problem, not the issuer's — log and continue rather than fail the
    // attestation, since the SVID itself does not depend on JWKS publication.
    match CompositePublicKey::from_concat_bytes(&csr.composite_pub) {
        Ok(pk) => state.register_child_key(&pk),
        Err(e) => tracing::warn!(error = %e, "could not publish host child-token key"),
    }

    let params = IssueParams {
        ek_cert_sha384: sha384(&init.ek_cert),
        pcr_digest: verified.pcr_digest,
        policy_id: verified.policy_id.as_str().to_string(),
        dpop_jkt: csr.dpop_jkt,
        ttl_secs: state.config.svid_ttl_secs,
        tee_evidence_id: None,
    };
    let issued = state.issuer.issue(&params, now).map_err(|e| {
        tracing::error!(error = %e, "SVID issuance failed");
        audit_fail(&state, "issuance-failed", now);
        Status::unavailable("issuer temporarily unavailable")
    })?;

    // SVID minted — record it in the audit log alongside the issued bundle.
    audit_record(
        &state,
        AuditEvent::SvidIssued {
            cert_sha: Hash384(sha384(issued.jws.as_bytes())),
            spiffe_id: issued.spiffe_id.clone(),
        },
        now,
    );

    state
        .record(IssuedRecord {
            params: params.clone(),
            last_attestation: LastAttestation {
                at: now,
                pcr_digest: verified.pcr_digest,
                policy_epoch: state.current_epoch(),
            },
            bundle: issued.clone(),
            hostname,
            child_pub: Some(csr.composite_pub.clone()),
        })
        .await;

    tracing::info!(spiffe_id = %issued.spiffe_id, "issued SVID via full attestation");
    send(tx, RespPhase::Svid(to_bundle(&issued))).await?;
    Ok(())
}

/// The synthetic policy id stamped on SVIDs issued through the TPM-less
/// host-key profile (F15). It records, in the issued credential and the audit
/// log, that this host proved a hardware-bound key but **not** measured boot —
/// a lower assurance tier than an EK-rooted, RIM-checked TPM quote. Policy can
/// key on this prefix to refuse host-key SVIDs in sensitive trust domains.
const HOST_KEY_POLICY_ID: &str = "host-key";

/// Drive the 3-phase host-key handshake (feature F15): the nonce was already
/// sent, here we verify the phase-2 evidence, gate on the fleet manifest, then
/// take the phase-4 CSR (there is no phase-3 credential activation) and issue.
#[allow(clippy::too_many_lines)] // linear handshake, mirrors run_attest
async fn run_attest_host_key(
    state: Arc<CmisState>,
    inbound: &mut Streaming<AttestRequest>,
    tx: &mpsc::Sender<Result<AttestResponse, Status>>,
    nonce: &[u8],
    evidence: ferro_proto::v1::HostKeyEvidence,
    hostname: Option<String>,
    now: i64,
) -> Result<(), Status> {
    let facts = evidence.facts.unwrap_or_default();

    // Cryptographic verification: the facts hash to the claimed fingerprint and
    // the signature over `nonce ‖ H` checks out under the presented key.
    let verified = verify_host_key_evidence(
        &facts.board_serial,
        &facts.platform_uuid,
        &facts.disk_serial,
        &evidence.fingerprint,
        &evidence.sep_pub,
        nonce,
        &evidence.signature,
    )
    .map_err(|reason| {
        tracing::warn!(%reason, "host-key phase 2 verification failed");
        audit_fail(&state, "host-key-verify-failed", now);
        Status::permission_denied("attestation failed")
    })?;

    // Pre-admission: the fingerprint must be enrolled in the offline-signed
    // fleet manifest, exactly like an EK hash. The fingerprint is a 48-byte
    // SHA-384, so it shares the EK-hash admission set.
    let fp_sha = Hash384(verified.fingerprint);
    match state.check_enrollment(&verified.fingerprint) {
        EnrollmentDecision::Rejected => {
            tracing::warn!("pre-admission: host fingerprint not in fleet manifest");
            audit_record(
                &state,
                AuditEvent::HostRejected {
                    ek_sha: fp_sha,
                    reason: "not-enrolled".to_string(),
                },
                now,
            );
            return Err(Status::permission_denied("attestation failed"));
        }
        EnrollmentDecision::Enrolled => {
            audit_record(&state, AuditEvent::HostEnrolled { ek_sha: fp_sha }, now);
        }
        EnrollmentDecision::NotEnforced => {}
    }

    // Bind the fingerprint to the presented machine key: an operator
    // pre-registered key must match exactly; otherwise the key is trusted on
    // first use and pinned. A key that differs from the bound one is a rebind
    // attempt — refuse it.
    match state.bind_host_key(&verified.fingerprint, &evidence.sep_pub) {
        HostKeyBinding::Mismatch => {
            tracing::warn!("host-key binding mismatch: presented key != bound key");
            audit_record(
                &state,
                AuditEvent::HostRejected {
                    ek_sha: fp_sha,
                    reason: "key-rebind".to_string(),
                },
                now,
            );
            return Err(Status::permission_denied("attestation failed"));
        }
        binding => {
            tracing::debug!(?binding, "host-key binding accepted");
        }
    }

    audit_record(
        &state,
        AuditEvent::AttestStart {
            ek_sha: fp_sha,
            aik_sha: Hash384(sha384(&evidence.sep_pub)),
            policy_id: HOST_KEY_POLICY_ID.to_string(),
        },
        now,
    );

    // Phase 4 — composite CSR, bound to the machine key (no phase-3 activation).
    let ReqPhase::Csr(csr) = next_request(inbound).await? else {
        audit_fail(&state, "csr-expected", now);
        return Err(Status::invalid_argument("expected CSR"));
    };
    if let Err(reason) = verify_host_key_csr(&evidence.sep_pub, &csr.composite_pub, &csr.aik_sig) {
        tracing::warn!(%reason, "host-key phase 4 CSR signature failed");
        audit_fail(&state, "host-key-csr-sig-invalid", now);
        return Err(Status::permission_denied("attestation failed"));
    }

    match CompositePublicKey::from_concat_bytes(&csr.composite_pub) {
        Ok(pk) => state.register_child_key(&pk),
        Err(e) => tracing::warn!(error = %e, "could not publish host child-token key"),
    }

    // No PCRs exist on this profile; reuse the fingerprint as the stable
    // `pcr_digest` so the subject UUID and renewal-drift logic stay well-defined.
    let params = IssueParams {
        ek_cert_sha384: verified.fingerprint,
        pcr_digest: verified.fingerprint,
        policy_id: HOST_KEY_POLICY_ID.to_string(),
        dpop_jkt: csr.dpop_jkt,
        ttl_secs: state.config.svid_ttl_secs,
        tee_evidence_id: None,
    };
    let issued = state.issuer.issue(&params, now).map_err(|e| {
        tracing::error!(error = %e, "host-key SVID issuance failed");
        audit_fail(&state, "issuance-failed", now);
        Status::unavailable("issuer temporarily unavailable")
    })?;

    audit_record(
        &state,
        AuditEvent::SvidIssued {
            cert_sha: Hash384(sha384(issued.jws.as_bytes())),
            spiffe_id: issued.spiffe_id.clone(),
        },
        now,
    );

    state
        .record(IssuedRecord {
            params: params.clone(),
            last_attestation: LastAttestation {
                at: now,
                pcr_digest: verified.fingerprint,
                policy_epoch: state.current_epoch(),
            },
            bundle: issued.clone(),
            hostname,
            child_pub: Some(csr.composite_pub.clone()),
        })
        .await;

    tracing::info!(spiffe_id = %issued.spiffe_id, "issued SVID via host-key attestation (F15)");
    send(tx, RespPhase::Svid(to_bundle(&issued))).await?;
    Ok(())
}

fn to_bundle(issued: &IssuedSvid) -> SvidBundle {
    SvidBundle {
        jws: issued.jws.clone(),
        issued_at: issued.iat,
        expires_at: issued.exp,
        spiffe_id: issued.spiffe_id.clone(),
    }
}

#[tonic::async_trait]
impl MachineIdentity for MachineIdentitySvc {
    type AttestStream = ReceiverStream<Result<AttestResponse, Status>>;

    async fn attest(
        &self,
        request: Request<Streaming<AttestRequest>>,
    ) -> Result<Response<Self::AttestStream>, Status> {
        let state = self.state.clone();
        let mut inbound = request.into_inner();
        let (tx, rx) = mpsc::channel(8);
        tokio::spawn(async move {
            if let Err(status) = run_attest(state, &mut inbound, &tx).await {
                let _ = tx.send(Err(status)).await;
            }
        });
        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn fetch_svid(
        &self,
        request: Request<FetchRequest>,
    ) -> Result<Response<SvidBundle>, Status> {
        let spiffe_id = request.into_inner().spiffe_id;
        match self.state.lookup(&spiffe_id).await {
            Some(rec) => Ok(Response::new(to_bundle(&rec.bundle))),
            None => Err(Status::not_found("no SVID for subject")),
        }
    }

    async fn rotate(
        &self,
        request: Request<RotateRequest>,
    ) -> Result<Response<SvidBundle>, Status> {
        let req = request.into_inner();
        let now = unix_now();

        // Identify the subject from the presented SVID without trusting it yet:
        // the stored record is the source of truth for what was attested.
        let decoded = ferro_svid::envelope::decode(&req.current_svid)
            .map_err(|_| Status::invalid_argument("malformed SVID"))?;
        let subject = decoded.claims.sub;

        let record = self
            .state
            .lookup(&subject)
            .await
            .ok_or_else(|| Status::not_found("unknown subject; full attestation required"))?;

        let current_digest = aggregate_digest(
            &req.pcr_values
                .iter()
                .map(|pv| (u8::try_from(pv.index).unwrap_or(u8::MAX), pv.value.clone()))
                .collect::<Vec<_>>(),
        );

        match decide_renewal(
            &record.last_attestation,
            now,
            &current_digest,
            self.state.current_epoch(),
        ) {
            RenewalDecision::ShortPath => {
                let issued = self
                    .state
                    .issuer
                    .issue(&record.params, now)
                    .map_err(|_| Status::unavailable("issuer temporarily unavailable"))?;
                self.state.update_bundle(&subject, issued.clone()).await;
                tracing::info!(spiffe_id = %subject, "renewed SVID (short path)");
                Ok(Response::new(to_bundle(&issued)))
            }
            RenewalDecision::FullReattest(reason) => {
                tracing::info!(
                    spiffe_id = %subject,
                    reason = ?reason,
                    "rotate refused; full re-attestation required"
                );
                Err(Status::failed_precondition("re-attestation required"))
            }
        }
    }

    async fn jwks(&self, request: Request<JwksRequest>) -> Result<Response<JwksResponse>, Status> {
        // On-miss rehydrate: a verifier that names the kid it is about to
        // check gives this replica the chance to pull a host key it never
        // witnessed out of the replicated store before answering (the
        // cross-node gap `register_child_key` being process-local leaves).
        let kid_hint = &request.get_ref().kid_hint;
        if !kid_hint.is_empty() {
            self.state.ensure_child_key_published(kid_hint).await;
        }
        let json = serde_json::to_string(&self.state.published_jwks())
            .map_err(|_| Status::internal("jwks encode"))?;
        Ok(Response::new(JwksResponse { jwks_json: json }))
    }

    async fn get_enrollment_key(
        &self,
        _request: Request<GetEnrollmentKeyRequest>,
    ) -> Result<Response<GetEnrollmentKeyResponse>, Status> {
        // The enrollment key that signs caller allowlists is the issuer's
        // composite key (allowlist signatures use a distinct domain-separation
        // context, so reuse is safe). Publish the public half as concat bytes.
        let public_key = self.state.issuer.public_key().to_concat_bytes();
        Ok(Response::new(GetEnrollmentKeyResponse { public_key }))
    }

    async fn get_allowlist(
        &self,
        request: Request<GetAllowlistRequest>,
    ) -> Result<Response<GetAllowlistResponse>, Status> {
        let host_uuid = request.into_inner().host_uuid;
        if host_uuid.trim().is_empty() {
            return Err(Status::invalid_argument("empty host_uuid"));
        }
        // Unauthenticated by design: the body is integrity-protected by its
        // signature and is not secret. Absent ⇒ empty bytes, not an error, so a
        // host can poll before one is provisioned.
        //
        // Re-stamp an aging allowlist with a fresh validity window before serving
        // it (auto-renewal), so a long-lived but unchanged allowlist never rots
        // into a `TooOld`/`Expired` rejection on the MIA — the entry set is
        // unchanged, only the window moves. Served, not persisted.
        let signed_allowlist = match self.state.get_allowlist(&host_uuid).await {
            Some(stored) => refresh_served_allowlist(
                &self.state.issuer,
                stored,
                self.state.config.allowlist_ttl_secs,
                unix_now(),
            ),
            None => Vec::new(),
        };
        Ok(Response::new(GetAllowlistResponse { signed_allowlist }))
    }

    async fn set_allowlist(
        &self,
        request: Request<SetAllowlistRequest>,
    ) -> Result<Response<SetAllowlistResponse>, Status> {
        let req = request.into_inner();
        let now = unix_now();

        if req.host_uuid.trim().is_empty() {
            return Err(Status::invalid_argument("empty host_uuid"));
        }
        // Validate every entry up front so a malformed list never reaches the
        // signer (and the MIA later rejects nothing it could have caught here).
        let mut entries = Vec::with_capacity(req.entries.len());
        for e in &req.entries {
            // The MIA decodes `bin_sha` exactly the same way (hex SHA-384, or
            // the `"*"` any-binary wildcard).
            validate_bin_sha(&e.bin_sha)?;
            entries.push(ferro_svid::AllowEntry {
                uid: e.uid,
                bin_sha: e.bin_sha.trim().to_string(),
            });
        }

        // Clamp the validity window to something sane; 0 ⇒ the configured
        // default (`CMIS_ALLOWLIST_TTL_SECS`, 96 h floor).
        let ttl = if req.ttl_secs <= 0 {
            self.state.config.allowlist_ttl_secs
        } else {
            req.ttl_secs.min(MAX_ALLOWLIST_TTL_SECS)
        };
        let not_after = now.saturating_add(ttl);
        let entry_count = u32::try_from(entries.len()).unwrap_or(u32::MAX);

        let signed = self
            .state
            .issuer
            .sign_allowlist(entries, now, not_after)
            .map_err(|e| {
                tracing::error!(error = %e, "allowlist signing failed");
                Status::internal("allowlist signing failed")
            })?;
        let bytes = ferro_svid::allowlist::encode(&signed).map_err(|e| {
            tracing::error!(error = %e, "allowlist encode failed");
            Status::internal("allowlist encode failed")
        })?;

        self.state.put_allowlist(&req.host_uuid, bytes, now).await;
        audit_record(
            &self.state,
            AuditEvent::AllowlistSet {
                host_uuid: req.host_uuid.clone(),
                entry_count,
                not_after,
            },
            now,
        );
        tracing::info!(host_uuid = %req.host_uuid, entry_count, not_after, "allowlist set");
        Ok(Response::new(SetAllowlistResponse {
            issued_at: now,
            not_after,
        }))
    }

    async fn delete_allowlist(
        &self,
        request: Request<DeleteAllowlistRequest>,
    ) -> Result<Response<DeleteAllowlistResponse>, Status> {
        let host_uuid = request.into_inner().host_uuid;
        if host_uuid.trim().is_empty() {
            return Err(Status::invalid_argument("empty host_uuid"));
        }
        let existed = self.state.delete_allowlist(&host_uuid).await;
        if existed {
            let now = unix_now();
            audit_record(
                &self.state,
                AuditEvent::AllowlistDeleted {
                    host_uuid: host_uuid.clone(),
                },
                now,
            );
            tracing::info!(%host_uuid, "allowlist deleted");
        }
        Ok(Response::new(DeleteAllowlistResponse { existed }))
    }

    async fn list_allowlists(
        &self,
        _request: Request<ListAllowlistsRequest>,
    ) -> Result<Response<ListAllowlistsResponse>, Status> {
        let items = self
            .state
            .list_allowlists()
            .await
            .into_iter()
            .filter_map(|(host_uuid, bytes)| {
                // Decode for metadata only — this is our own stored, already
                // signed artefact, so a re-verify here would be redundant. A row
                // that fails to decode is logged and skipped, never failing the
                // whole listing (mirrors `list_svids`).
                match ferro_svid::allowlist::decode(&bytes)
                    .and_then(|s| ferro_svid::allowlist::decode_body(&s.body))
                {
                    Ok(doc) => Some(AllowlistSummary {
                        host_uuid,
                        issued_at: doc.issued_at,
                        not_after: doc.not_after,
                        entry_count: u32::try_from(doc.entries.len()).unwrap_or(u32::MAX),
                    }),
                    Err(e) => {
                        tracing::error!(error = %e, %host_uuid, "stored allowlist failed to decode");
                        None
                    }
                }
            })
            .collect();
        Ok(Response::new(ListAllowlistsResponse { items }))
    }

    #[allow(clippy::too_many_lines)] // one linear verify→policy→store flow.
    async fn propose_allowlist(
        &self,
        request: Request<ProposeAllowlistRequest>,
    ) -> Result<Response<ProposeAllowlistResponse>, Status> {
        use ferro_proto::v1::propose_allowlist_response::Outcome;
        let req = request.into_inner();
        let now = unix_now();

        // 1. Verify the presenting SVID was issued by this CMIS and is still
        //    valid; pull out the host UUID and the DPoP key thumbprint it binds.
        let (svid_host_uuid, cnf_jkt, proposer_spiffe_id) =
            verify_proposing_svid(&self.state, &req.svid_jws, now)?;

        // 2. The presented machine key must be the one the SVID is bound to.
        let computed_jkt = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(Sha256::digest(&req.sep_pub));
        if computed_jkt != cnf_jkt {
            return Err(Status::unauthenticated("sep_pub does not match svid cnf.jkt"));
        }

        // 3. The proposal signature must verify under that key, over the
        //    domain-separated signing input.
        let signing_input = ferro_svid::allowlist::proposal_signing_input(&req.signed_proposal);
        ferro_sep::verify_p256(&req.sep_pub, &signing_input, &req.proposal_sig)
            .map_err(|_| Status::unauthenticated("proposal signature did not verify"))?;

        // 4. Decode the proposal and bind it to the attested host.
        let proposal = ferro_svid::allowlist::decode_proposal(&req.signed_proposal)
            .map_err(|_| Status::invalid_argument("malformed proposal body"))?;
        if proposal.host_uuid != svid_host_uuid {
            return Err(Status::permission_denied(
                "proposal host_uuid does not match the proposing SVID",
            ));
        }
        // Light replay guard; the SVID's own validity is the real freshness
        // anchor (it is short-lived and was checked above).
        if proposal.issued_at > now.saturating_add(300) {
            return Err(Status::invalid_argument("proposal issued_at is in the future"));
        }
        // Validate entries exactly as `set_allowlist` does.
        let mut entries = Vec::with_capacity(proposal.entries.len());
        for e in &proposal.entries {
            validate_bin_sha(&e.bin_sha)?;
            entries.push(ferro_svid::AllowEntry {
                uid: e.uid,
                bin_sha: e.bin_sha.trim().to_string(),
            });
        }
        let entry_count = u32::try_from(entries.len()).unwrap_or(u32::MAX);

        // 5. Compare against the current live allowlist, and apply policy.
        let current = self.state.get_allowlist(&proposal.host_uuid).await;
        let current_entries = current.as_deref().and_then(decode_live_entries);
        if current_entries
            .as_ref()
            .is_some_and(|cur| entries_match(cur, &entries))
        {
            return Ok(Response::new(ProposeAllowlistResponse {
                outcome: Outcome::Unchanged as i32,
                issued_at: 0,
                not_after: 0,
            }));
        }

        let has_existing = current.is_some();
        let policy = self.state.config.allowlist_proposal_policy;
        let auto_adopt = match policy {
            ProposalPolicy::Off => false,
            ProposalPolicy::BootstrapOnly => !has_existing,
            ProposalPolicy::Always => true,
        };

        if auto_adopt {
            let not_after = now.saturating_add(self.state.config.allowlist_ttl_secs);
            let signed = self
                .state
                .issuer
                .sign_allowlist(entries, now, not_after)
                .map_err(|e| {
                    tracing::error!(error = %e, "allowlist signing failed");
                    Status::internal("allowlist signing failed")
                })?;
            let bytes = ferro_svid::allowlist::encode(&signed).map_err(|e| {
                tracing::error!(error = %e, "allowlist encode failed");
                Status::internal("allowlist encode failed")
            })?;
            self.state
                .put_allowlist(&proposal.host_uuid, bytes, now)
                .await;
            // A previously queued proposal for this host is now moot.
            self.state.delete_proposal(&proposal.host_uuid).await;
            audit_record(
                &self.state,
                AuditEvent::AllowlistAutoAdopted {
                    host_uuid: proposal.host_uuid.clone(),
                    entry_count,
                    not_after,
                },
                now,
            );
            tracing::info!(host_uuid = %proposal.host_uuid, entry_count, not_after, "allowlist proposal auto-adopted (bootstrap)");
            return Ok(Response::new(ProposeAllowlistResponse {
                outcome: Outcome::AutoAdopted as i32,
                issued_at: now,
                not_after,
            }));
        }

        // Queue for operator review. Store the proposed entries as CBOR.
        let entries_cbor = encode_allow_entries(&entries).map_err(|e| {
            tracing::error!(error = %e, "proposal entries encode failed");
            Status::internal("proposal encode failed")
        })?;
        self.state
            .put_proposal(
                &proposal.host_uuid,
                crate::state::ProposalRecord {
                    entries_cbor,
                    proposer_spiffe_id: proposer_spiffe_id.clone(),
                    proposed_at: now,
                },
            )
            .await;
        audit_record(
            &self.state,
            AuditEvent::AllowlistProposed {
                host_uuid: proposal.host_uuid.clone(),
                entry_count,
                proposer_spiffe_id,
            },
            now,
        );
        tracing::info!(host_uuid = %proposal.host_uuid, entry_count, "allowlist proposal queued for review");
        Ok(Response::new(ProposeAllowlistResponse {
            outcome: Outcome::Pending as i32,
            issued_at: 0,
            not_after: 0,
        }))
    }

    async fn list_proposals(
        &self,
        _request: Request<ListProposalsRequest>,
    ) -> Result<Response<ListProposalsResponse>, Status> {
        let items = self
            .state
            .list_proposals()
            .await
            .into_iter()
            .filter_map(|(host_uuid, rec)| {
                // Decode the stored entries for the operator; a row that fails to
                // decode is logged and skipped, never failing the whole listing.
                match decode_allow_entries(&rec.entries_cbor) {
                    Ok(entries) => Some(PendingProposal {
                        host_uuid,
                        entries: entries
                            .into_iter()
                            .map(|e| AllowEntryMsg {
                                uid: e.uid,
                                bin_sha: e.bin_sha,
                            })
                            .collect(),
                        proposer_spiffe_id: rec.proposer_spiffe_id,
                        proposed_at: rec.proposed_at,
                    }),
                    Err(e) => {
                        tracing::error!(error = %e, %host_uuid, "stored proposal failed to decode");
                        None
                    }
                }
            })
            .collect();
        Ok(Response::new(ListProposalsResponse { items }))
    }

    async fn delete_proposal(
        &self,
        request: Request<DeleteProposalRequest>,
    ) -> Result<Response<DeleteProposalResponse>, Status> {
        let host_uuid = request.into_inner().host_uuid;
        if host_uuid.trim().is_empty() {
            return Err(Status::invalid_argument("empty host_uuid"));
        }
        let existed = self.state.delete_proposal(&host_uuid).await;
        if existed {
            let now = unix_now();
            audit_record(
                &self.state,
                AuditEvent::AllowlistProposalRejected {
                    host_uuid: host_uuid.clone(),
                },
                now,
            );
            tracing::info!(%host_uuid, "allowlist proposal rejected");
        }
        Ok(Response::new(DeleteProposalResponse { existed }))
    }

    async fn revoke_svid(
        &self,
        request: Request<RevokeSvidRequest>,
    ) -> Result<Response<RevokeResponse>, Status> {
        let req = request.into_inner();
        let now = unix_now();

        // `cert_sha` must be a 96-char lowercase-hex SHA-384. Normalising and
        // validating here keeps a single canonical key in the CRL and gives the
        // audit event a real `Hash384`.
        let cert_bytes = parse_cert_sha(&req.cert_sha)?;
        let cert_sha = hex::encode(cert_bytes);
        let reason = revocation_reason(&req.reason);

        self.state.revoke(
            RevocationTarget::Svid {
                cert_sha: cert_sha.clone(),
            },
            reason.clone(),
            now,
        );
        audit_record(
            &self.state,
            AuditEvent::SvidRevoked {
                cert_sha: Hash384(cert_bytes),
                reason,
            },
            now,
        );
        let number = self.publish_crl_now(now)?;
        tracing::info!(%cert_sha, crl_number = number, "SVID revoked");
        Ok(Response::new(RevokeResponse { crl_number: number }))
    }

    async fn revoke_host(
        &self,
        request: Request<RevokeHostRequest>,
    ) -> Result<Response<RevokeResponse>, Status> {
        let req = request.into_inner();
        let now = unix_now();

        if req.spiffe_id.is_empty() {
            return Err(Status::invalid_argument("empty spiffe_id"));
        }
        let reason = revocation_reason(&req.reason);

        self.state.revoke(
            RevocationTarget::Host {
                spiffe_id: req.spiffe_id.clone(),
            },
            reason.clone(),
            now,
        );
        audit_record(
            &self.state,
            AuditEvent::HostRevoked {
                spiffe_id: req.spiffe_id.clone(),
                reason,
            },
            now,
        );
        let number = self.publish_crl_now(now)?;
        tracing::info!(spiffe_id = %req.spiffe_id, crl_number = number, "host revoked");
        Ok(Response::new(RevokeResponse { crl_number: number }))
    }

    async fn bump_epoch(
        &self,
        request: Request<BumpEpochRequest>,
    ) -> Result<Response<BumpEpochResponse>, Status> {
        let req = request.into_inner();
        let now = unix_now();
        // Reuse the same bounded-opcode normalisation as revocation so the audit
        // log never carries unbounded operator free-text.
        let reason = revocation_reason(&req.reason);

        let (old_epoch, new_epoch) = self.state.bump_epoch();
        audit_record(
            &self.state,
            AuditEvent::PolicyEpochBumped {
                old_epoch,
                new_epoch,
                reason,
            },
            now,
        );
        tracing::info!(old_epoch, new_epoch, "RIM policy epoch bumped");
        Ok(Response::new(BumpEpochResponse { new_epoch }))
    }

    async fn list_svids(
        &self,
        _request: Request<ListSvidsRequest>,
    ) -> Result<Response<ListSvidsResponse>, Status> {
        let svids = self
            .state
            .list_svids()
            .await
            .iter()
            .map(|rec| SvidSummary {
                spiffe_id: rec.bundle.spiffe_id.clone(),
                // The same lowercase-hex SHA-384 of the compact JWS that
                // `RevokeSvid` keys on, so an operator can copy it straight
                // across.
                cert_sha: hex::encode(sha384(rec.bundle.jws.as_bytes())),
                issued_at: rec.bundle.iat,
                expires_at: rec.bundle.exp,
                policy_id: rec.params.policy_id.clone(),
                policy_epoch: rec.last_attestation.policy_epoch,
                hostname: rec.hostname.clone().unwrap_or_default(),
            })
            .collect();
        Ok(Response::new(ListSvidsResponse { svids }))
    }

    async fn latest_sth(
        &self,
        _request: Request<LatestSthRequest>,
    ) -> Result<Response<LatestSthResponse>, Status> {
        let sth = self
            .state
            .audit
            .latest_sth()
            .ok_or_else(|| Status::not_found("no STH produced yet"))?;
        Ok(Response::new(LatestSthResponse {
            sth: Some(to_proto_sth(&sth)?),
        }))
    }

    async fn inclusion_proof(
        &self,
        request: Request<InclusionProofRequest>,
    ) -> Result<Response<InclusionProofResponse>, Status> {
        let req = request.into_inner();
        let p = self
            .state
            .audit
            .inclusion_proof(req.leaf_index)
            .map_err(|e| {
                tracing::warn!(error = %e, "inclusion proof requested for out-of-range index");
                Status::not_found("leaf out of range")
            })?;
        Ok(Response::new(InclusionProofResponse {
            leaf_hash: p.leaf_hash.to_vec(),
            leaf_index: p.leaf_index,
            tree_size: p.tree_size,
            root_hash: p.root_hash.to_vec(),
            audit_path: p.audit_path.iter().map(|h| h.to_vec()).collect(),
        }))
    }

    async fn consistency_proof(
        &self,
        request: Request<ConsistencyProofRequest>,
    ) -> Result<Response<ConsistencyProofResponse>, Status> {
        let req = request.into_inner();
        let p = self
            .state
            .audit
            .consistency_proof(req.old_size)
            .map_err(|e| {
                tracing::warn!(error = %e, "consistency proof requested out of range");
                Status::invalid_argument("old_size out of range")
            })?;
        Ok(Response::new(ConsistencyProofResponse {
            old_size: p.old_size,
            new_size: p.new_size,
            new_root_hash: p.new_root_hash.to_vec(),
            audit_path: p.audit_path.iter().map(|h| h.to_vec()).collect(),
        }))
    }

    async fn health(
        &self,
        _request: Request<HealthRequest>,
    ) -> Result<Response<HealthResponse>, Status> {
        let (healthy, role) = self.state.health().await;
        let proto_role = match role {
            NodeRole::Leader => ProtoNodeRole::Leader,
            NodeRole::Follower => ProtoNodeRole::Follower,
            NodeRole::Learner => ProtoNodeRole::Learner,
            NodeRole::Unknown => ProtoNodeRole::Unknown,
        };
        let node_id = self.state.cluster().node_id();
        Ok(Response::new(HealthResponse {
            healthy,
            role: proto_role as i32,
            node_id,
        }))
    }

    async fn append_audit_event(
        &self,
        request: Request<AppendAuditRequest>,
    ) -> Result<Response<AppendAuditResponse>, Status> {
        let req = request.into_inner();
        let event = ferro_audit::event::decode(&req.event_cbor).map_err(|e| {
            tracing::warn!(error = %e, "forwarded audit event failed to decode");
            Status::invalid_argument("malformed audit event")
        })?;
        let now = unix_now();
        let leaf_index = self.state.audit.append(&event).map_err(|e| {
            tracing::error!(error = %e, "audit append (forwarded) failed");
            Status::unavailable("audit log unavailable")
        })?;
        if let Err(e) = self.state.audit.produce_sth(now) {
            tracing::warn!(error = %e, "audit STH produce failed after forward");
        }
        Ok(Response::new(AppendAuditResponse { leaf_index }))
    }
}

#[allow(clippy::result_large_err)] // `tonic::Status` is the unavoidable error shape here.
fn to_proto_sth(sth: &ferro_audit::SignedTreeHead) -> Result<SignedTreeHead, Status> {
    let sig_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(sth.signature_b64.as_bytes())
        .map_err(|_| Status::internal("sth signature base64"))?;
    Ok(SignedTreeHead {
        body_cbor: sth.body_cbor.clone(),
        signer_kid: sth.signer_kid.clone(),
        signature: sig_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::{decode_live_doc, display_hostname, refresh_served_allowlist, validate_bin_sha};

    fn test_issuer() -> ferro_svid::Issuer {
        ferro_svid::Issuer::from_seed(&[7u8; 32], "cmis-test", "ferrogate.test")
    }

    fn sign_at(issuer: &ferro_svid::Issuer, issued_at: i64, ttl: i64) -> Vec<u8> {
        let entries = vec![ferro_svid::AllowEntry {
            uid: Some(503),
            bin_sha: "*".to_string(),
        }];
        let signed = issuer
            .sign_allowlist(entries, issued_at, issued_at + ttl)
            .unwrap();
        ferro_svid::allowlist::encode(&signed).unwrap()
    }

    #[test]
    fn fresh_allowlist_is_served_unchanged() {
        let issuer = test_issuer();
        let ttl = 72 * 3600;
        let stored = sign_at(&issuer, 1_000_000, ttl);
        // now is only a third into the window — below half-life, so untouched.
        let served = refresh_served_allowlist(&issuer, stored.clone(), ttl, 1_000_000 + ttl / 3);
        assert_eq!(served, stored, "a still-fresh allowlist must not be re-signed");
    }

    #[test]
    fn aged_allowlist_is_restamped_with_a_fresh_window() {
        let issuer = test_issuer();
        let ttl = 72 * 3600;
        let issued_at = 1_000_000;
        let stored = sign_at(&issuer, issued_at, ttl);
        // Past half-life: must be re-stamped to (now, now + ttl).
        let now = issued_at + ttl / 2 + 1;
        let served = refresh_served_allowlist(&issuer, stored.clone(), ttl, now);
        assert_ne!(served, stored, "an aged allowlist must be re-signed");
        let doc = decode_live_doc(&served).expect("served allowlist decodes");
        assert_eq!(doc.issued_at, now);
        assert_eq!(doc.not_after, now + ttl);
        // Entries (and trust domain) are preserved across the renewal.
        assert_eq!(doc.entries.len(), 1);
        assert_eq!(doc.entries[0].uid, Some(503));
        assert_eq!(doc.entries[0].bin_sha, "*");
    }

    #[test]
    fn expired_allowlist_is_renewed_not_dropped() {
        let issuer = test_issuer();
        let ttl = 72 * 3600;
        let issued_at = 1_000_000;
        let stored = sign_at(&issuer, issued_at, ttl);
        // Well past not_after — still renewed so a host is never locked out.
        let now = issued_at + ttl * 10;
        let served = refresh_served_allowlist(&issuer, stored, ttl, now);
        let doc = decode_live_doc(&served).expect("served allowlist decodes");
        assert_eq!(doc.issued_at, now);
        assert_eq!(doc.not_after, now + ttl);
    }

    #[test]
    fn undecodable_bytes_are_served_unchanged() {
        let issuer = test_issuer();
        let garbage = vec![0xde, 0xad, 0xbe, 0xef];
        let served = refresh_served_allowlist(&issuer, garbage.clone(), 72 * 3600, 9_999_999);
        assert_eq!(served, garbage, "unparseable bytes fail safe (served as-is)");
    }

    #[test]
    fn validate_bin_sha_accepts_hex_and_wildcard_rejects_garbage() {
        // A real lowercase-hex SHA-384.
        assert!(validate_bin_sha(&"a".repeat(96)).is_ok());
        // The any-binary wildcard, with surrounding whitespace tolerated.
        assert!(validate_bin_sha("*").is_ok());
        assert!(validate_bin_sha("  *  ").is_ok());
        // Neither hex nor the wildcard.
        assert!(validate_bin_sha("not-hex").is_err());
        assert!(validate_bin_sha("**").is_err());
        // Right alphabet, wrong length.
        assert!(validate_bin_sha("abcd").is_err());
    }

    #[test]
    fn hostname_passes_through_clean_values() {
        assert_eq!(
            display_hostname("segdc1vds0005"),
            Some("segdc1vds0005".to_string())
        );
        assert_eq!(
            display_hostname("  web-01.prod  "),
            Some("web-01.prod".to_string())
        );
    }

    #[test]
    fn hostname_strips_control_and_non_ascii() {
        assert_eq!(
            display_hostname("evil\x1b[2Jhost\nname"),
            Some("evil[2Jhostname".to_string())
        );
        assert_eq!(display_hostname("máquina"), Some("mquina".to_string()));
    }

    #[test]
    fn hostname_caps_length_and_drops_empty() {
        let long = "a".repeat(200);
        assert_eq!(display_hostname(&long).unwrap().len(), 64);
        assert_eq!(display_hostname(""), None);
        assert_eq!(display_hostname("  \t\x07 "), None);
    }
}
