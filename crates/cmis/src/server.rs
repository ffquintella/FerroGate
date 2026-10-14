//! Listener composition for the CMIS daemon.
//!
//! - **Main listener** (`CMIS_LISTEN`): the `MachineIdentity` service, hybrid
//!   PQC TLS when `CMIS_TLS_CERT` + `CMIS_TLS_KEY` are set, plaintext bring-up
//!   otherwise. The legacy admin RPCs are served here only while
//!   `CMIS_LEGACY_ADMIN_ON_MAIN` is true, and only with TLS: in plaintext mode
//!   they answer `FAILED_PRECONDITION (tls_required)` (F20 §1).
//! - **Admin listener** (`CMIS_ADMIN_LISTEN`, default `127.0.0.1:8444`): the
//!   `Admin` service plus `MachineIdentity`, hybrid-PQC TLS 1.3 only, optional
//!   mTLS (`CMIS_ADMIN_CLIENT_CA`). It never starts without TLS material.
//!
//! Both listeners sit behind [`AdminAuthLayer`], the single enforcement point
//! of the method access table.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustls_pki_types::pem::PemObject;
use rustls_pki_types::CertificateDer;
use tokio::net::TcpListener;
use tokio_rustls::rustls::ServerConfig;

use ferro_crypto::tls::ProviderMode;

use crate::admin::authz::AdminAuthz;
use crate::admin::clock::SystemClock;
use crate::admin::keys::AdminKeys;
use crate::admin::{AdminAuthLayer, AdminConfig, AdminState, AdminSvc, ListenerKind};
use crate::state::CmisState;
use crate::MachineIdentitySvc;

/// Serve the `MachineIdentity` service on `listener`, over TLS when
/// `tls` is set.
pub async fn serve_main(
    listener: TcpListener,
    tls: Option<Arc<ServerConfig>>,
    state: Arc<CmisState>,
    authz: Option<Arc<AdminAuthz>>,
    legacy_admin_on_main: bool,
) -> Result<(), tonic::transport::Error> {
    let layer = AdminAuthLayer::new(
        authz,
        ListenerKind::Main,
        tls.is_some(),
        legacy_admin_on_main,
    );
    let router = tonic::transport::Server::builder()
        .layer(layer)
        .add_service(MachineIdentitySvc::new(state).into_server());
    match tls {
        Some(cfg) => {
            router
                .serve_with_incoming(crate::transport::tls_incoming(listener, cfg))
                .await
        }
        None => {
            router
                .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
                .await
        }
    }
}

/// Serve the admin listener: `Admin` plus `MachineIdentity`, TLS only.
pub async fn serve_admin(
    listener: TcpListener,
    tls: Arc<ServerConfig>,
    state: Arc<CmisState>,
    authz: Arc<AdminAuthz>,
) -> Result<(), tonic::transport::Error> {
    let layer = AdminAuthLayer::new(Some(Arc::clone(&authz)), ListenerKind::Admin, true, true);
    tonic::transport::Server::builder()
        .layer(layer)
        .add_service(MachineIdentitySvc::new(state).into_server())
        .add_service(AdminSvc::new(authz).into_server())
        .serve_with_incoming(crate::transport::tls_incoming(listener, tls))
        .await
}

/// Build the admin listener's TLS config: its own certificate or the main
/// listener's, hybrid-PQC only, with mTLS when a client CA is configured.
/// `None` when no certificate is available (the admin listener then does not
/// start).
pub fn admin_tls_config(
    cfg: &AdminConfig,
    main_identity: Option<&(PathBuf, PathBuf)>,
) -> anyhow::Result<Option<Arc<ServerConfig>>> {
    let pair = match (&cfg.tls_cert, &cfg.tls_key) {
        (Some(c), Some(k)) => Some((c.clone(), k.clone())),
        _ => main_identity.cloned(),
    };
    let Some((cert, key)) = pair else {
        return Ok(None);
    };
    let (chain, key) = crate::transport::load_pem_identity(&cert, &key)?;
    let config = match &cfg.client_ca {
        Some(ca) => ferro_crypto::transport::server_config_with_client_auth(
            ProviderMode::HybridOnly,
            chain,
            key,
            load_ca_bundle(ca)?,
        )?,
        None => ferro_crypto::transport::server_config(ProviderMode::HybridOnly, chain, key)?,
    };
    Ok(Some(config))
}

fn load_ca_bundle(path: &Path) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    let bytes = std::fs::read(path)
        .map_err(|e| anyhow::anyhow!("reading CMIS_ADMIN_CLIENT_CA {}: {e}", path.display()))?;
    let certs = CertificateDer::pem_slice_iter(&bytes)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow::anyhow!("parsing CMIS_ADMIN_CLIENT_CA {}: {e}", path.display()))?;
    if certs.is_empty() {
        anyhow::bail!("no certificates in CMIS_ADMIN_CLIENT_CA {}", path.display());
    }
    Ok(certs)
}

/// Start the admin subsystem. On failure it logs at `error` and returns
/// `None`: host-facing service continues, and every admin method answers
/// `UNAVAILABLE` (fail closed).
pub async fn start_admin(cmis: Arc<CmisState>, cfg: AdminConfig) -> Option<Arc<AdminAuthz>> {
    let keys = match AdminKeys::load(&cfg.secrets_key, &cfg.pseudonym_key) {
        Ok(k) => k,
        Err(e) => {
            tracing::error!(event = "admin.init.failed", error = %e, "admin subsystem disabled");
            return None;
        }
    };
    match AdminState::new(cmis, cfg, keys, Arc::new(SystemClock)).await {
        Ok(state) => Some(Arc::new(AdminAuthz::new(state))),
        Err(e) => {
            tracing::error!(event = "admin.init.failed", error = %e, "admin subsystem disabled");
            None
        }
    }
}

/// Run CMIS: the main listener on `main_addr` and, when TLS material exists,
/// the admin listener. TLS for the main listener comes from `CMIS_TLS_CERT` +
/// `CMIS_TLS_KEY` (both or neither).
pub async fn run(
    main_addr: SocketAddr,
    state: Arc<CmisState>,
    admin_cfg: AdminConfig,
) -> anyhow::Result<()> {
    let main_identity = match (
        std::env::var_os("CMIS_TLS_CERT"),
        std::env::var_os("CMIS_TLS_KEY"),
    ) {
        (Some(cert), Some(key)) => Some((PathBuf::from(cert), PathBuf::from(key))),
        (None, None) => None,
        _ => anyhow::bail!("CMIS_TLS_CERT and CMIS_TLS_KEY must be set together"),
    };
    let main_tls = match &main_identity {
        Some((cert, key)) => {
            let (chain, key) = crate::transport::load_pem_identity(cert, key)?;
            Some(ferro_crypto::transport::server_config(
                ProviderMode::HybridOnly,
                chain,
                key,
            )?)
        }
        None => None,
    };
    let admin_tls = admin_tls_config(&admin_cfg, main_identity.as_ref())?;
    let admin_addr = admin_cfg.listen;
    let legacy_on_main = admin_cfg.legacy_admin_on_main;

    // Without any TLS material no admin method can be served (plaintext
    // listeners answer `tls_required` before consulting the admin state), so
    // the admin subsystem — and its key files — is not started at all.
    let authz = if admin_tls.is_some() {
        start_admin(Arc::clone(&state), admin_cfg).await
    } else {
        None
    };

    let admin_task = match (&admin_tls, &authz) {
        (Some(tls), Some(authz)) => {
            match crate::admin::bootstrap::arm(authz.state()).await {
                Ok(outcome) => tracing::info!(?outcome, "admin bootstrap check"),
                Err(e) => tracing::error!(error = %e, "admin bootstrap arming failed"),
            }
            let listener = TcpListener::bind(admin_addr).await?;
            tracing::info!(
                %admin_addr,
                mtls = authz.state().config().client_ca.is_some(),
                "FerroGate CMIS admin listener — hybrid-PQC TLS (X25519MLKEM768-only)"
            );
            let (tls, state, authz) = (Arc::clone(tls), Arc::clone(&state), Arc::clone(authz));
            Some(tokio::spawn(async move {
                serve_admin(listener, tls, state, authz).await
            }))
        }
        (None, _) => {
            tracing::warn!(
                "admin listener NOT started: no TLS certificate (set CMIS_TLS_CERT/KEY or \
                 CMIS_ADMIN_TLS_CERT/KEY); admin methods are unavailable"
            );
            None
        }
        (Some(_), None) => {
            tracing::error!("admin listener NOT started: the admin subsystem failed to initialise");
            None
        }
    };

    let listener = TcpListener::bind(main_addr).await?;
    if main_tls.is_some() {
        tracing::info!(
            version = env!("CARGO_PKG_VERSION"),
            %main_addr,
            legacy_admin_on_main = legacy_on_main,
            "FerroGate CMIS — hybrid-PQC TLS gRPC server (X25519MLKEM768-only)"
        );
    } else {
        tracing::warn!(
            version = env!("CARGO_PKG_VERSION"),
            %main_addr,
            "FerroGate CMIS — PLAINTEXT gRPC bring-up server (set CMIS_TLS_CERT + CMIS_TLS_KEY \
             for hybrid-PQC TLS); admin methods answer tls_required"
        );
    }
    let main = serve_main(listener, main_tls, state, authz, legacy_on_main);
    match admin_task {
        Some(task) => {
            tokio::select! {
                r = main => r?,
                r = task => r??,
            }
        }
        None => main.await?,
    }
    Ok(())
}
