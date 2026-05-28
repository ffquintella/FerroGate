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
    credential_secret_matches, verify_aik_signature, PcrSet, QuoteVerification, RejectReason,
};
use ferro_audit::{AuditEvent, Hash384};
use ferro_proto::v1::attest_request::Phase as ReqPhase;
use ferro_proto::v1::attest_response::Phase as RespPhase;
use ferro_proto::v1::machine_identity_server::{MachineIdentity, MachineIdentityServer};
use ferro_proto::v1::{
    AppendAuditRequest, AppendAuditResponse, AttestRequest, AttestResponse, Challenge,
    ConsistencyProofRequest, ConsistencyProofResponse, FetchRequest, HealthRequest, HealthResponse,
    InclusionProofRequest, InclusionProofResponse, JwksRequest, JwksResponse, LatestSthRequest,
    LatestSthResponse, Nonce, NodeRole as ProtoNodeRole, RotateRequest, SignedTreeHead, SvidBundle,
};
use ferro_raft::NodeRole;
use ferro_svid::{decide_renewal, IssueParams, IssuedSvid, LastAttestation, RenewalDecision};
use sha2::{Digest, Sha384};

use crate::pcr::aggregate_digest;
use crate::state::{CmisState, IssuedRecord};

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
        tracing::warn!(error = %e, "audit append failed");
        return;
    }
    if let Err(e) = state.audit.produce_sth(now) {
        tracing::warn!(error = %e, "audit STH produce failed");
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
                policy_epoch: state.config.policy_epoch,
            },
            bundle: issued.clone(),
        })
        .await;

    tracing::info!(spiffe_id = %issued.spiffe_id, "issued SVID via full attestation");
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
            self.state.config.policy_epoch,
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

    async fn jwks(&self, _request: Request<JwksRequest>) -> Result<Response<JwksResponse>, Status> {
        let json = serde_json::to_string(&self.state.issuer.jwks())
            .map_err(|_| Status::internal("jwks encode"))?;
        Ok(Response::new(JwksResponse { jwks_json: json }))
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
        let node_id = self.state.cluster().map_or(0, |c| c.node_id());
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
