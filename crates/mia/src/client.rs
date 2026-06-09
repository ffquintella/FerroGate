//! The MIA-side attestation client.
//!
//! [`run_attest`] drives the four-phase handshake (`docs/protocol.md`) against
//! a CMIS `MachineIdentity` endpoint and returns the issued SVID together with
//! the freshly generated composite private key the MIA must seal locally.
//!
//! The TPM-specific work — producing a quote for the server nonce, activating
//! the phase-3 credential, and AIK-signing the composite CSR — is supplied
//! through the [`AttestEvidence`] trait so the same handshake logic runs
//! against a real TPM (Linux) or a software stand-in (tests).

use ferro_crypto::composite::{CompositePublicKey, CompositeSecretKey};
use ferro_crypto::pin::SpkiPin;
use ferro_proto::v1::attest_request::Phase as ReqPhase;
use ferro_proto::v1::attest_response::Phase as RespPhase;
use ferro_proto::v1::machine_identity_client::MachineIdentityClient;
use ferro_proto::v1::{
    AttestInit, AttestRequest, ChallengeResponse, Csr, HostKeyEvidence, MachineFacts, PcrValue,
    SvidBundle,
};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::Channel;
use tonic::Request;

/// Dial a CMIS `MachineIdentity` endpoint over the FerroGate hybrid-PQC
/// transport (feature F01), authenticating the server by SPKI pin.
///
/// `endpoint` is an `https://host:port` authority; `pins` are the accepted
/// SHA-384 SPKI pins of the CMIS certificate. The returned client is backed by
/// a [`Channel`] whose connections:
///
/// - use the `X25519MLKEM768`-only provider, so a non-hybrid CMIS is rejected
///   at the handshake; and
/// - trust the server by SPKI pin, not a CA chain, so a wrong-pin (or
///   otherwise-valid-but-unpinned) server is rejected before any application
///   RPC — the hostname is used only for SNI/routing.
///
/// # Panics
///
/// Panics if `pins` is empty; see [`ferro_crypto::transport::client_config`].
pub async fn connect_pinned(
    endpoint: &str,
    pins: Vec<SpkiPin>,
) -> anyhow::Result<MachineIdentityClient<Channel>> {
    // The dialer itself is not MIA-specific — it lives in `ferro-transport`
    // and returns a bare `Channel`, shared with the `ferrogate` operator CLI.
    // Here we just wrap it in the generated `MachineIdentity` client.
    let channel = ferro_transport::connect_pinned(endpoint, pins).await?;
    Ok(MachineIdentityClient::new(channel))
}

/// Fetch the CMIS enrollment public key (the composite key that signs caller
/// allowlists) from a pinned CMIS endpoint.
///
/// Returns the key as composite concat bytes — exactly what
/// [`ferro_crypto::composite::CompositePublicKey::from_concat_bytes`] and the
/// `allowlist.key` file expect. `endpoint` is an `https://host:port` authority
/// and `pins` are the accepted SHA-384 SPKI pins of the CMIS certificate.
pub async fn fetch_enrollment_key(endpoint: &str, pins: Vec<SpkiPin>) -> anyhow::Result<Vec<u8>> {
    use ferro_proto::v1::GetEnrollmentKeyRequest;

    let mut client = connect_pinned(endpoint, pins).await?;
    let resp = client
        .get_enrollment_key(Request::new(GetEnrollmentKeyRequest {}))
        .await?
        .into_inner();
    if resp.public_key.is_empty() {
        anyhow::bail!("CMIS returned an empty enrollment key");
    }
    Ok(resp.public_key)
}

/// A produced PCR quote and the raw values backing it.
pub struct QuoteEvidence {
    /// Marshaled `TPMS_ATTEST`.
    pub attest_blob: Vec<u8>,
    /// Marshaled `TPMT_SIGNATURE`.
    pub signature: Vec<u8>,
    /// Raw `(index, value)` PCR readings, ascending.
    pub pcr_values: Vec<(u8, Vec<u8>)>,
}

/// Hardware-backed steps of the handshake. Implementations are blocking (TPM
/// I/O); the handshake calls them between async network turns.
pub trait AttestEvidence {
    /// The EK certificate (DER).
    fn ek_cert(&self) -> Vec<u8>;
    /// Intermediate CA certs bridging the EK cert to a vendor root (DER).
    fn ek_intermediates(&self) -> Vec<Vec<u8>> {
        Vec::new()
    }
    /// The marshaled AIK public area (`TPMT_PUBLIC`).
    fn aik_pub(&self) -> Vec<u8>;
    /// Quote the policy PCR set with `nonce` as qualifyingData.
    fn quote(&mut self, nonce: &[u8]) -> anyhow::Result<QuoteEvidence>;
    /// Recover the phase-3 secret via `TPM2_ActivateCredential`.
    fn activate(&mut self, credential_blob: &[u8], secret_blob: &[u8]) -> anyhow::Result<Vec<u8>>;
    /// AIK-sign `message` (the TPM hashes it internally, then signs).
    fn sign_aik(&mut self, message: &[u8]) -> anyhow::Result<Vec<u8>>;
}

/// The result of a successful attestation: the issued bundle and the composite
/// key pair the SVID is bound to. The private key must be sealed locally.
pub struct AttestedSvid {
    /// The issued SVID bundle.
    pub bundle: SvidBundle,
    /// The composite private key matching the SVID's CSR public key.
    pub svid_secret: CompositeSecretKey,
    /// The composite public key (for convenience / sealing alongside).
    pub svid_public: CompositePublicKey,
}

/// Failure modes for the attestation client.
#[derive(Debug, thiserror::Error)]
pub enum AttestClientError {
    /// A gRPC transport or status error.
    #[error("transport: {0}")]
    Transport(#[from] tonic::Status),
    /// The server sent an out-of-order or unexpected message.
    #[error("protocol: {0}")]
    Protocol(String),
    /// A TPM/evidence operation failed.
    #[error("evidence: {0}")]
    Evidence(#[from] anyhow::Error),
    /// Composite key generation failed.
    #[error("keygen: {0}")]
    KeyGen(String),
}

/// Run the full handshake. `dpop_jkt` is the thumbprint of the MIA's DPoP key
/// (minted elsewhere; see F09) that the SVID will be bound to.
pub async fn run_attest<T: AttestEvidence>(
    client: &mut MachineIdentityClient<Channel>,
    evidence: &mut T,
    dpop_jkt: String,
) -> Result<AttestedSvid, AttestClientError> {
    let (tx, rx) = mpsc::channel::<AttestRequest>(8);
    let mut responses = client
        .attest(Request::new(ReceiverStream::new(rx)))
        .await?
        .into_inner();

    // Phase 1.5 — receive the server nonce.
    let nonce = match next(&mut responses).await? {
        RespPhase::Nonce(n) => n.nonce,
        other => return Err(unexpected("nonce", &other)),
    };

    // Phase 2 — quote and send init.
    let quote = evidence.quote(&nonce)?;
    let init = AttestInit {
        ek_cert: evidence.ek_cert(),
        ek_intermediates: evidence.ek_intermediates(),
        aik_pub: evidence.aik_pub(),
        quote_blob: quote.attest_blob,
        signature: quote.signature,
        pcr_values: quote
            .pcr_values
            .into_iter()
            .map(|(index, value)| PcrValue {
                index: u32::from(index),
                value,
            })
            .collect(),
        host_key: None,
    };
    send(&tx, ReqPhase::Init(init)).await?;

    // Phase 3 — activate the credential and prove residency.
    let challenge = match next(&mut responses).await? {
        RespPhase::Challenge(c) => c,
        other => return Err(unexpected("challenge", &other)),
    };
    let secret = evidence.activate(&challenge.credential_blob, &challenge.secret_blob)?;
    send(
        &tx,
        ReqPhase::ChallengeResponse(ChallengeResponse { secret }),
    )
    .await?;

    // Phase 4 — generate the composite SVID key, AIK-sign it, send the CSR.
    let (svid_secret, svid_public) =
        CompositeSecretKey::generate().map_err(|e| AttestClientError::KeyGen(e.to_string()))?;
    let composite_pub = svid_public.to_concat_bytes();
    let aik_sig = evidence.sign_aik(&composite_pub)?;
    send(
        &tx,
        ReqPhase::Csr(Csr {
            composite_pub,
            dpop_jkt,
            aik_sig,
        }),
    )
    .await?;

    // Receive the issued SVID.
    let bundle = match next(&mut responses).await? {
        RespPhase::Svid(b) => b,
        other => return Err(unexpected("svid", &other)),
    };

    drop(tx);
    Ok(AttestedSvid {
        bundle,
        svid_secret,
        svid_public,
    })
}

/// Run the TPM-less **host-key** handshake (feature F15): a 3-phase variant of
/// [`run_attest`] with no phase-3 credential activation.
///
/// `facts` are this machine's hardware identifiers (see `ferro-machineid`);
/// `key` is the machine signing key — a [`ferro_sep::enclave::SecureEnclaveKey`]
/// on a SEP-equipped Mac, or a [`ferro_sep::SoftwareMachineKey`] elsewhere. The
/// fingerprint `H` is derived from `facts`; `key` signs `nonce ‖ H` in phase 2
/// and the composite CSR in phase 4.
pub async fn run_attest_host_key(
    client: &mut MachineIdentityClient<Channel>,
    facts: &ferro_machineid::MachineFacts,
    key: &dyn ferro_sep::MachineKey,
    dpop_jkt: String,
) -> Result<AttestedSvid, AttestClientError> {
    let (tx, rx) = mpsc::channel::<AttestRequest>(8);
    let mut responses = client
        .attest(Request::new(ReceiverStream::new(rx)))
        .await?
        .into_inner();

    // Phase 1.5 — receive the server nonce.
    let nonce = match next(&mut responses).await? {
        RespPhase::Nonce(n) => n.nonce,
        other => return Err(unexpected("nonce", &other)),
    };

    // Phase 2 — sign nonce ‖ H with the machine key and send the evidence.
    let fingerprint = facts.fingerprint();
    let sig = key
        .sign(&ferro_sep::host_key_binding(&nonce, fingerprint.as_bytes()))
        .map_err(|e| AttestClientError::Evidence(anyhow::Error::new(e)))?;
    let facts = facts.normalised();
    let init = AttestInit {
        host_key: Some(HostKeyEvidence {
            fingerprint: fingerprint.as_bytes().to_vec(),
            facts: Some(MachineFacts {
                board_serial: facts.board_serial,
                platform_uuid: facts.platform_uuid,
                disk_serial: facts.disk_serial,
            }),
            sep_pub: key.public_spki_der(),
            signature: sig,
        }),
        ..Default::default()
    };
    send(&tx, ReqPhase::Init(init)).await?;

    // Phase 4 — generate the composite SVID key, machine-key-sign it, send CSR.
    // (No phase-3 challenge: residency is not separately proven on this profile.)
    let (svid_secret, svid_public) =
        CompositeSecretKey::generate().map_err(|e| AttestClientError::KeyGen(e.to_string()))?;
    let composite_pub = svid_public.to_concat_bytes();
    let aik_sig = key
        .sign(&composite_pub)
        .map_err(|e| AttestClientError::Evidence(anyhow::Error::new(e)))?;
    send(
        &tx,
        ReqPhase::Csr(Csr {
            composite_pub,
            dpop_jkt,
            aik_sig,
        }),
    )
    .await?;

    // Receive the issued SVID.
    let bundle = match next(&mut responses).await? {
        RespPhase::Svid(b) => b,
        other => return Err(unexpected("svid", &other)),
    };

    drop(tx);
    Ok(AttestedSvid {
        bundle,
        svid_secret,
        svid_public,
    })
}

async fn next(
    responses: &mut tonic::Streaming<ferro_proto::v1::AttestResponse>,
) -> Result<RespPhase, AttestClientError> {
    match responses.message().await? {
        Some(ferro_proto::v1::AttestResponse { phase: Some(p) }) => Ok(p),
        Some(_) => Err(AttestClientError::Protocol("empty response".to_string())),
        None => Err(AttestClientError::Protocol(
            "server closed stream early".to_string(),
        )),
    }
}

async fn send(tx: &mpsc::Sender<AttestRequest>, phase: ReqPhase) -> Result<(), AttestClientError> {
    tx.send(AttestRequest { phase: Some(phase) })
        .await
        .map_err(|_| AttestClientError::Protocol("request stream closed".to_string()))
}

fn unexpected(want: &str, got: &RespPhase) -> AttestClientError {
    let got = match got {
        RespPhase::Nonce(_) => "nonce",
        RespPhase::Challenge(_) => "challenge",
        RespPhase::Svid(_) => "svid",
    };
    AttestClientError::Protocol(format!("expected {want}, got {got}"))
}
