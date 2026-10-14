//! The daemon's F19 host services for one environment, wired together: the
//! registration service behind the helper API and the allowlist sync loop
//! that also drives its outbox (F19 §6.5, §7.6).
//!
//! `main.rs` builds the inputs (CMIS resolver, host credentials, the helper
//! server's allowlist handle) and calls [`start`]; everything else lives
//! here so the binary stays thin.

use std::sync::Arc;
use std::time::Duration;

use ferro_audit::AuditEvent;
use tokio::sync::mpsc;

use crate::allowlist_sync::{AllowlistSink, AllowlistSync, SyncConfig, SyncState, SyncTrigger};
use crate::host_api::{CredentialSlot, HostApi, ResolverApi};
use crate::registration::{Registrar, RegistrarConfig};

/// What [`start`] needs.
pub struct ServiceInputs<'a> {
    /// The environment's configuration.
    pub config: &'a crate::config::Config,
    /// CMIS, when configured.
    pub resolver: Option<crate::endpoint::CmisResolver>,
    /// The host credentials (filled now or by a later re-attestation).
    pub creds: CredentialSlot,
    /// The helper server's allowlist handle.
    pub sink: Arc<dyn AllowlistSink>,
    /// The generation already in force ([`crate::allowlist_sync::load_in_force`]).
    pub held: Option<SyncState>,
    /// Nothing is in force: sync at once instead of after a random delay.
    pub sync_now: bool,
    /// The helper audit sink.
    pub audit: mpsc::Sender<AuditEvent>,
    /// The environment's status.
    pub status: crate::status::StatusHandle,
    /// The clock.
    pub clock: crate::helper::Clock,
    /// Linux: callers are IMA-verified.
    pub ima_enforced: bool,
}

/// The running services.
pub struct Services {
    /// The registration handler for the helper server; `None` when its
    /// configuration is invalid (logged).
    pub registrar: Option<Registrar>,
    /// Wakes the sync loop (`SIGHUP`, re-attestation); `None` when the sync
    /// is off.
    pub sync_trigger: Option<SyncTrigger>,
}

/// CMIS is not configured: host calls fail, so requests stay queued.
struct Unconfigured;

impl HostApi for Unconfigured {
    fn submit_app_request(
        &self,
        _req: ferro_proto::v1::SubmitAppRequestRequest,
    ) -> futures::future::BoxFuture<
        '_,
        Result<ferro_proto::v1::SubmitAppRequestResponse, tonic::Status>,
    > {
        Box::pin(async { Err(tonic::Status::unavailable("cmis_not_configured")) })
    }

    fn app_request_status(
        &self,
        _req: ferro_proto::v1::GetAppRequestStatusRequest,
    ) -> futures::future::BoxFuture<
        '_,
        Result<ferro_proto::v1::GetAppRequestStatusResponse, tonic::Status>,
    > {
        Box::pin(async { Err(tonic::Status::unavailable("cmis_not_configured")) })
    }

    fn sync_allowlist(
        &self,
        _req: ferro_proto::v1::SyncAllowlistRequest,
    ) -> futures::future::BoxFuture<'_, Result<ferro_proto::v1::SyncAllowlistResponse, tonic::Status>>
    {
        Box::pin(async { Err(tonic::Status::unavailable("cmis_not_configured")) })
    }

    fn get_allowlist(
        &self,
        _host_uuid: String,
    ) -> futures::future::BoxFuture<'_, Result<Option<Vec<u8>>, tonic::Status>> {
        Box::pin(async { Err(tonic::Status::unavailable("cmis_not_configured")) })
    }
}

/// Start the registration service and, with `allowlist.sync` on and CMIS
/// configured, the sync loop (which also flushes the registration outbox).
/// Without the sync the outbox is flushed on its own at the sync interval.
#[must_use]
pub fn start(inputs: ServiceInputs<'_>) -> Services {
    let ServiceInputs {
        config,
        resolver,
        creds,
        sink,
        held,
        sync_now,
        audit,
        status,
        clock,
        ima_enforced,
    } = inputs;
    let api: Arc<dyn HostApi> = match resolver.clone() {
        Some(r) => Arc::new(ResolverApi::new(r)),
        None => Arc::new(Unconfigured),
    };
    let trigger = SyncTrigger::new();
    let registrar = match RegistrarConfig::from_config(config, ima_enforced) {
        Ok(cfg) => Some(
            Registrar::new(cfg, Arc::clone(&api), creds.clone(), trigger.clone(), clock)
                .with_status(status.clone()),
        ),
        Err(e) => {
            tracing::error!(error = %e, "registration configuration invalid; registration disabled");
            None
        }
    };
    let interval = config.allowlist_sync_interval();

    if config.allowlist_sync_enabled() && resolver.is_some() {
        let mut sync = AllowlistSync::new(SyncConfig::from_config(config), api, creds, sink, held)
            .with_trigger(trigger.clone())
            .with_audit(audit)
            .with_status(status);
        if let Some(r) = &registrar {
            sync = sync.with_hook(Arc::new(r.clone()));
        }
        tracing::info!(
            interval_secs = interval.as_secs(),
            "allowlist sync started (SyncAllowlist, v2)"
        );
        tokio::spawn(sync.run(sync_now));
        return Services {
            registrar,
            sync_trigger: Some(trigger),
        };
    }
    if config.allowlist_sync_enabled() {
        tracing::warn!("allowlist.sync is set but CMIS is not configured; not syncing");
    }
    if let (Some(r), true) = (&registrar, resolver.is_some()) {
        let r = r.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval.max(Duration::from_secs(60))).await;
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX));
                r.refresh(now).await;
            }
        });
    }
    Services {
        registrar,
        sync_trigger: None,
    }
}
