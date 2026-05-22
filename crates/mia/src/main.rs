//! `mia` — Machine Identity Agent binary.
//!
//! M0 stub: prints a banner and exits. Hardening, TPM glue, and helper API
//! land across milestones M2 and M5. See `docs/mia.md` and the per-feature
//! documents under `docs/features/`.
//!
//! `unsafe` is forbidden in this crate (see `docs/features/F12-mia-hardening.md`).

#![forbid(unsafe_code)]

use tracing_subscriber::EnvFilter;

fn main() -> anyhow::Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        component = "mia",
        "FerroGate Machine Identity Agent (M0 stub)"
    );
    println!(
        "mia v{} — M0 stub; no TPM or helper API yet.",
        env!("CARGO_PKG_VERSION")
    );
    Ok(())
}
