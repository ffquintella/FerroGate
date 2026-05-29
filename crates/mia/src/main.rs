//! `mia` — Machine Identity Agent binary.
//!
//! The daemon initializes logging and, when configured, stands up the local
//! helper API (feature F08): a Unix-domain-socket listener that mints
//! DPoP-bound child tokens for vetted local callers. The TPM attestation loop
//! and sealed-SVID recovery (features F02/F04) are not yet wired into the
//! binary; until they are, the helper API runs with **no** host SVID and so
//! refuses to mint (`no_host_svid`) while still enforcing caller
//! authentication and the signed allowlist — a fail-safe, deployable surface.
//!
//! Configuration is by environment variable:
//!
//! - `FERROGATE_HELPER_SOCKET` — socket path; its presence enables the helper
//!   API. Absent ⇒ the daemon logs a banner and exits.
//! - `FERROGATE_HELPER_SOCKET_MODE` — octal mode for the socket (default `660`).
//! - `FERROGATE_ALLOWLIST` — path to the signed CBOR allowlist. Absent ⇒ the
//!   API denies every caller (fail closed).
//! - `FERROGATE_ALLOWLIST_KEY` — path to the trusted CMIS enrollment public key
//!   (composite concat bytes) used to verify the allowlist. Required whenever
//!   `FERROGATE_ALLOWLIST` is set.
//! - `FERROGATE_ALLOWLIST_MAX_AGE_SECS` — max allowlist age (default `86400`).
//! - `FERROGATE_IMA_LOG` — override the IMA runtime-measurement log path.
//!
//! `unsafe` is forbidden in this crate (see `docs/features/F12-mia-hardening.md`).

#![forbid(unsafe_code)]

use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        component = "mia",
        "FerroGate Machine Identity Agent"
    );

    run().await
}

/// Daemon entry point. Starts the helper API when `FERROGATE_HELPER_SOCKET` is
/// set, otherwise prints a banner and exits.
async fn run() -> anyhow::Result<()> {
    let Some(socket) = std::env::var_os("FERROGATE_HELPER_SOCKET") else {
        println!(
            "mia v{} — daemon idle; set FERROGATE_HELPER_SOCKET to start the helper API.",
            env!("CARGO_PKG_VERSION")
        );
        return Ok(());
    };
    start_helper_api(std::path::PathBuf::from(socket)).await
}

#[cfg(target_os = "linux")]
async fn start_helper_api(socket_path: std::path::PathBuf) -> anyhow::Result<()> {
    use std::time::Duration;

    use anyhow::Context as _;
    use std::sync::Arc;

    use ferro_crypto::composite::CompositePublicKey;
    use mia::helper::auth::ImaCallerAuth;
    use mia::helper::{system_clock, Allowlist, CrlCache, HelperServer, HelperServerConfig};
    use tokio::sync::mpsc;

    let socket_mode = env_octal("FERROGATE_HELPER_SOCKET_MODE", 0o660)?;
    let max_age = env_i64("FERROGATE_ALLOWLIST_MAX_AGE_SECS", 86_400)?;
    let clock = system_clock();

    // Audit sink: a forwarder task drains helper events. For now it logs them;
    // CMIS forwarding rides on F07's `AppendAuditEvent` path (`audit_client`).
    let (audit_tx, mut audit_rx) = mpsc::channel(256);
    tokio::spawn(async move {
        while let Some(event) = audit_rx.recv().await {
            tracing::info!(?event, "helper-api audit event");
        }
    });

    // Allowlist: configured ⇒ load and verify (fail loudly); absent ⇒ deny all.
    let allowlist = match std::env::var_os("FERROGATE_ALLOWLIST") {
        Some(path) => {
            let key_path = std::env::var_os("FERROGATE_ALLOWLIST_KEY")
                .context("FERROGATE_ALLOWLIST is set but FERROGATE_ALLOWLIST_KEY is missing")?;
            let key_bytes = std::fs::read(&key_path).context("reading FERROGATE_ALLOWLIST_KEY")?;
            let trusted = CompositePublicKey::from_concat_bytes(&key_bytes)
                .map_err(|e| anyhow::anyhow!("trusted allowlist key: {e}"))?;
            let bytes = std::fs::read(&path).context("reading FERROGATE_ALLOWLIST")?;
            let al = Allowlist::load(&bytes, &trusted, clock(), max_age)
                .map_err(|e| anyhow::anyhow!("allowlist verification failed: {e}"))?;
            tracing::info!(trust_domain = al.trust_domain(), "loaded signed allowlist");
            Some(al)
        }
        None => {
            tracing::warn!(
                "no FERROGATE_ALLOWLIST configured; helper API denies all callers (fail closed)"
            );
            None
        }
    };

    let auth = match std::env::var_os("FERROGATE_IMA_LOG") {
        Some(p) => ImaCallerAuth::with_ima_log(std::path::PathBuf::from(p)),
        None => ImaCallerAuth::new(),
    };

    let config = HelperServerConfig {
        socket_path: socket_path.clone(),
        socket_mode,
        socket_gid: None,
        windows_group: None,
        max_concurrent: 64,
        read_timeout: Duration::from_secs(5),
    };

    // No minter yet: the host SVID composite key arrives with the attestation
    // loop (F04). Until then the server authenticates and authorizes callers
    // but refuses to mint with `no_host_svid`. The CRL cache (feature F11)
    // starts empty — once the attestation loop lands it will be fed by a puller
    // (`mia::helper::crl::spawn_puller`) against the host's CMIS endpoint; until
    // then an empty cache simply means the (absent) minter stays disabled.
    let crl = Arc::new(CrlCache::new());
    let server = HelperServer::bind(config, auth, None, allowlist, crl, audit_tx, clock)?;
    tracing::warn!(
        "host SVID not present; token minting disabled (returns no_host_svid) until attestation lands"
    );
    let mode_octal = format!("{socket_mode:o}");
    tracing::info!(socket = %socket_path.display(), mode = mode_octal.as_str(), "helper API listening");

    server.serve_with_shutdown(shutdown_signal()).await;
    tracing::info!("helper API shut down cleanly");
    Ok(())
}

#[cfg(not(target_os = "linux"))]
#[allow(clippy::unused_async)] // async to match the Linux signature at the call site
async fn start_helper_api(_socket_path: std::path::PathBuf) -> anyhow::Result<()> {
    anyhow::bail!(
        "the helper API requires Linux (SO_PEERCRED + IMA caller attestation); \
         this platform is unsupported"
    )
}

/// Resolve when the process receives `SIGINT` (Ctrl-C) or `SIGTERM`.
#[cfg(target_os = "linux")]
async fn shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};

    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    let term = async {
        if let Ok(mut s) = signal(SignalKind::terminate()) {
            s.recv().await;
        }
    };
    tokio::select! {
        () = ctrl_c => tracing::info!("received SIGINT; shutting down"),
        () = term => tracing::info!("received SIGTERM; shutting down"),
    }
}

/// Parse an octal `u32` from an environment variable, or use `default`.
#[cfg(target_os = "linux")]
fn env_octal(key: &str, default: u32) -> anyhow::Result<u32> {
    match std::env::var(key) {
        Ok(s) => u32::from_str_radix(s.trim_start_matches("0o"), 8)
            .map_err(|e| anyhow::anyhow!("{key} is not octal: {e}")),
        Err(_) => Ok(default),
    }
}

/// Parse an `i64` from an environment variable, or use `default`.
#[cfg(target_os = "linux")]
fn env_i64(key: &str, default: i64) -> anyhow::Result<i64> {
    match std::env::var(key) {
        Ok(s) => s
            .parse()
            .map_err(|e| anyhow::anyhow!("{key} is not an integer: {e}")),
        Err(_) => Ok(default),
    }
}
