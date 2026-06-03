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

use std::io;

use ferro_crypto::composite::{CompositePublicKey, CompositeSecretKey};
use ferro_crypto::pin::SpkiPin;
use ferro_crypto::tls::ProviderMode;
use ferro_proto::v1::attest_request::Phase as ReqPhase;
use ferro_proto::v1::attest_response::Phase as RespPhase;
use ferro_proto::v1::machine_identity_client::MachineIdentityClient;
use ferro_proto::v1::{AttestInit, AttestRequest, ChallengeResponse, Csr, PcrValue, SvidBundle};
use hyper_util::rt::TokioIo;
use rustls_pki_types::ServerName;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_rustls::TlsConnector;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::{Channel, Endpoint, Uri};
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
    let tls = ferro_crypto::transport::client_config(ProviderMode::HybridOnly, pins)?;
    let connector = TlsConnector::from(tls);

    // The custom connector performs the TLS upgrade itself, so tonic's own
    // (disabled) TLS must not engage: hand the `Endpoint` an `http://`
    // authority derived from the requested host:port. The connector still
    // wraps every connection in hybrid-PQC TLS below.
    let requested: Uri = endpoint
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid endpoint {endpoint:?}: {e}"))?;
    let host = requested
        .host()
        .ok_or_else(|| anyhow::anyhow!("endpoint {endpoint:?} has no host"))?;
    let port = requested.port_u16().unwrap_or(8443);
    let ep = Endpoint::from_shared(format!("http://{host}:{port}"))?;

    let service = tower::service_fn(move |uri: Uri| {
        let connector = connector.clone();
        async move {
            let host = uri
                .host()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "endpoint has no host"))?;
            let port = uri.port_u16().unwrap_or(8443);
            let server_name = ServerName::try_from(host.to_string()).map_err(|e| {
                io::Error::new(io::ErrorKind::InvalidInput, format!("invalid server name: {e}"))
            })?;
            let tcp = TcpStream::connect((host, port)).await?;
            let tls = connector.connect(server_name, tcp).await?;
            Ok::<_, io::Error>(TokioIo::new(tls))
        }
    });

    let channel = ep.connect_with_connector(service).await?;
    Ok(MachineIdentityClient::new(channel))
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
