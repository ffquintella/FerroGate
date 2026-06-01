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
use cmis::fleet_manifest::FleetManifestLoader;
use cmis::{CmisConfig, CmisState, MachineIdentitySvc};
use ferro_attest::{RimStore, TpmQuoteVerifier, TrustedKeys, VendorTrustStore};
use ferro_crypto::composite::CompositePublicKey;
use ferro_audit::{AuditLog, AuditStore, InProcessSigner, LocalDiskWormStore, SthSigner};
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

/// Build the fleet-manifest publisher trust set from the environment.
///
/// `CMIS_FLEET_SIGNER_KID` selects the key id the manifest is signed under and
/// `CMIS_FLEET_SIGNER_PUB` carries that publisher's composite public key as
/// lowercase hex of its `ed25519(32) || ml-dsa-65(1952)` concat form (the same
/// form the `fleet-manifest` tool prints). Production deployments source this
/// from the F14 ceremony's published root key.
fn load_fleet_trust() -> anyhow::Result<TrustedKeys> {
    let kid = std::env::var("CMIS_FLEET_SIGNER_KID")
        .map_err(|_| anyhow::anyhow!("CMIS_FLEET_MANIFEST set but CMIS_FLEET_SIGNER_KID missing"))?;
    let pub_hex = std::env::var("CMIS_FLEET_SIGNER_PUB")
        .map_err(|_| anyhow::anyhow!("CMIS_FLEET_MANIFEST set but CMIS_FLEET_SIGNER_PUB missing"))?;
    let pub_bytes =
        hex::decode(pub_hex.trim()).map_err(|e| anyhow::anyhow!("CMIS_FLEET_SIGNER_PUB hex: {e}"))?;
    let pk = CompositePublicKey::from_concat_bytes(&pub_bytes)
        .map_err(|e| anyhow::anyhow!("CMIS_FLEET_SIGNER_PUB: {e}"))?;
    let mut trust = TrustedKeys::new();
    trust.add(kid, pk);
    Ok(trust)
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

    // M3 audit log: local-disk WORM store + in-process composite signer. The
    // production swap (S3 Object Lock + TEE threshold signer) lands in M4.
    let worm_root =
        std::env::var("CMIS_AUDIT_ROOT").unwrap_or_else(|_| "/var/lib/ferrogate/audit".to_string());
    let store: Arc<dyn AuditStore> = Arc::new(LocalDiskWormStore::open(worm_root)?);
    let (signer, _audit_pk) = InProcessSigner::generate("cmis-dev-audit-1")
        .map_err(|e| anyhow::anyhow!("audit signer: {e}"))?;
    tracing::info!(audit_kid = signer.kid(), "audit signer ready");
    let audit = AuditLog::new(store, Arc::new(signer));

    let state = Arc::new(CmisState::new(
        issuer,
        verifier,
        Box::new(UnconfiguredCredentialMaker),
        CmisConfig::default(),
        audit,
    ));

    // F13 zero-touch enrolment. If a signed fleet manifest is configured, load
    // it now (fail-closed: a configured-but-unloadable manifest aborts startup
    // rather than admitting every host) and spawn a watcher to hot-reload it.
    // With no manifest configured CMIS stays unenforced — every host that can
    // attest is admitted, exactly as before F13.
    let _fleet_watcher = match std::env::var("CMIS_FLEET_MANIFEST") {
        Ok(path) if !path.is_empty() => {
            let trust = load_fleet_trust()?;
            let loader = Arc::new(FleetManifestLoader::new(path, trust, state.fleet().clone()));
            match loader.try_reload() {
                Ok(outcome) => tracing::info!(?outcome, "fleet manifest loaded"),
                Err(e) => return Err(anyhow::anyhow!("fleet manifest load failed: {e}")),
            }
            Some(cmis::fleet_watcher::spawn(
                loader,
                cmis::fleet_watcher::DEFAULT_REFRESH_INTERVAL,
            ))
        }
        _ => {
            tracing::warn!("no CMIS_FLEET_MANIFEST configured — fleet enrolment unenforced");
            None
        }
    };

    // Keep the published CRL fresh (feature F11). Revocations publish inline on
    // the admin RPC; this heartbeat republishes every 60 s so consumers' 5-min
    // freshness check keeps passing in steady state.
    let _crl_publisher = cmis::crl_publisher::spawn(
        Arc::clone(&state),
        cmis::crl_publisher::DEFAULT_PUBLISH_INTERVAL,
    );

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
