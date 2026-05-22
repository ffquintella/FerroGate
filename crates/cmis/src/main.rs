//! `cmis` — Central Machine Identity Service binary.
//!
//! M0 stub: prints a banner and exits. The gRPC server, Raft glue, and
//! attestation handler land across milestones M2–M4. See
//! `docs/cmis.md` and the per-feature documents under
//! `docs/features/`.

#![forbid(unsafe_code)]

use tracing_subscriber::EnvFilter;

fn main() -> anyhow::Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        component = "cmis",
        "FerroGate Central Machine Identity Service (M0 stub)"
    );
    println!(
        "cmis v{} — M0 stub; no listeners started.",
        env!("CARGO_PKG_VERSION")
    );
    Ok(())
}
