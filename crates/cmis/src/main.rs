//! `cmis` — Central Machine Identity Service binary.
//!
//! A thin wrapper: assemble [`cmis::CmisState`] and serve the
//! [`cmis::MachineIdentitySvc`] gRPC surface. The M2 bring-up server listens in
//! plaintext gRPC; hybrid-PQC TLS termination (F01) and a TEE-resident issuance
//! key (F06) are layered on in later milestones, as is a configured phase-3
//! credential maker. Until then `JWKS` is fully functional and `Attest` will
//! report the credential service as unavailable.

#![forbid(unsafe_code)]

use std::sync::Arc;

use cmis::credential::{CredentialError, CredentialMaker, WrappedCredential};
use cmis::{CmisConfig, CmisState, MachineIdentitySvc};
use ferro_attest::{RimStore, TpmQuoteVerifier, VendorTrustStore};
use ferro_svid::Issuer;
use tracing_subscriber::EnvFilter;

/// Placeholder phase-3 maker for the unconfigured bring-up server. A real
/// deployment injects a TCG `MakeCredential` implementation; this one refuses
/// so no half-configured node can appear to attest hosts.
struct UnconfiguredCredentialMaker;

impl CredentialMaker for UnconfiguredCredentialMaker {
    fn make_credential(
        &self,
        _ek_pub: &[u8],
        _aik_pub: &[u8],
        _secret: &[u8],
    ) -> Result<WrappedCredential, CredentialError> {
        Err(CredentialError::Wrap(
            "credential maker not configured on this node".to_string(),
        ))
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    let addr = std::env::var("CMIS_LISTEN")
        .unwrap_or_else(|_| "127.0.0.1:8443".to_string())
        .parse()?;

    let issuer = Issuer::generate("cmis-dev-1", "ferrogate.dev")?;
    let verifier = TpmQuoteVerifier::new(VendorTrustStore::default(), RimStore::new());
    let state = Arc::new(CmisState::new(
        issuer,
        verifier,
        Box::new(UnconfiguredCredentialMaker),
        CmisConfig::default(),
    ));

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        %addr,
        "FerroGate CMIS — plaintext gRPC bring-up server (M2)"
    );

    tonic::transport::Server::builder()
        .add_service(MachineIdentitySvc::new(state).into_server())
        .serve(addr)
        .await?;
    Ok(())
}
