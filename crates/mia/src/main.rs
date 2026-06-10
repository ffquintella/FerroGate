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
//! The binary also exposes an interactive `mia setup` subcommand: a
//! rich-terminal wizard (see [`mia::setup`]) that walks an operator through the
//! configuration below. With no subcommand, `mia` is the daemon.
//!
//! ## Configuration
//!
//! MIA reads an optional TOML configuration file ([`mia::config`]) and overlays
//! environment variables on top, so the precedence is
//! **defaults < config file < environment**. The file is found at
//! `--config <path>`, then `$FERROGATE_CONFIG`, then `/etc/ferrogate/mia.toml`
//! (absent ⇒ env/defaults only). A deployment that sets everything through the
//! systemd `EnvironmentFile` keeps working with no file present.
//!
//! The environment variables (each also a TOML key — see `dist/mia.toml`):
//!
//! - `FERROGATE_HELPER_SOCKET` (`helper.socket`) — socket path; its presence
//!   enables the helper API. Absent ⇒ the daemon logs a banner and exits.
//! - `FERROGATE_HELPER_SOCKET_MODE` (`helper.socket_mode`) — octal socket mode
//!   (default `660`).
//! - `FERROGATE_HELPER_SOCKET_GID` (`helper.socket_gid`) — numeric gid to own
//!   the socket so that group's members may open it (Unix only; set by
//!   `make mia-install` to the dedicated FerroGate group).
//! - `FERROGATE_ALLOWLIST` (`allowlist.path`) — path to the signed CBOR
//!   allowlist. Absent ⇒ the API denies every caller (fail closed).
//! - `FERROGATE_ALLOWLIST_KEY` (`allowlist.key`) — path to the trusted CMIS
//!   enrollment public key used to verify the allowlist. Required whenever the
//!   allowlist is set.
//! - `FERROGATE_ALLOWLIST_MAX_AGE_SECS` (`allowlist.max_age_secs`) — max
//!   allowlist age (default `86400`).
//! - `FERROGATE_IMA_LOG` (`attestation.ima_log`) — override the IMA
//!   runtime-measurement log path.
//!
//! `unsafe` is forbidden in this crate (see `docs/features/F12-mia-hardening.md`).

#![forbid(unsafe_code)]

use tracing_subscriber::EnvFilter;

fn main() -> anyhow::Result<()> {
    // Subcommand dispatch. `mia` with no subcommand is the daemon (the systemd
    // ExecStart); `mia setup` is the interactive configuration wizard, which
    // must run BEFORE logging init, hardening, and the async runtime — it is
    // synchronous terminal I/O and must not inherit the seccomp profile or the
    // dropped privileges the daemon installs.
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("setup") => return mia::setup::run(&args[1..]),
        Some("test") => return mia::selftest::run(&args[1..]),
        Some("-h" | "--help") => {
            print_usage();
            return Ok(());
        }
        Some("--version" | "-V") => {
            println!("mia {}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        // A bare non-flag token is an unknown subcommand; flags (e.g. --config)
        // belong to the daemon and are parsed below.
        Some(other) if !other.starts_with('-') => {
            anyhow::bail!("unknown subcommand: {other}\n\nrun `mia --help` for usage")
        }
        _ => {}
    }

    // Resolve the configuration before logging/hardening: the file gives us the
    // log directive, and a malformed file must fail loudly and early.
    let config_path = parse_config_flag(&args)?;
    let (config, source) = mia::config::Config::load(config_path.as_deref())?;

    let filter =
        EnvFilter::try_new(config.log_directive()).unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        component = "mia",
        "FerroGate Machine Identity Agent"
    );
    if let Some(path) = &source {
        tracing::info!(config = %path.display(), "loaded configuration file");
    } else {
        tracing::debug!("no configuration file; using environment and defaults");
    }

    // Apply the hardening profile (feature F12) on the single startup thread,
    // *before* building the async runtime — so the seccomp filter is inherited
    // by every tokio worker and `mlockall(MCL_FUTURE)` covers their allocations,
    // and before any TPM or network I/O. Fatal on failure: a MIA that cannot
    // harden must not serve.
    #[cfg(target_os = "linux")]
    mia::hardening::harden()?;
    #[cfg(not(target_os = "linux"))]
    tracing::debug!("hardening profile (seccomp/mlockall/privilege-drop) applies on Linux only");

    // Build the multi-threaded runtime by hand (rather than `#[tokio::main]`) so
    // hardening runs first. `enable_all` wires the I/O and time drivers the
    // helper server and CMIS client need.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(run(config))
}

/// Parse the daemon's `--config`/`-c <path>` flag from `args`. Returns the
/// requested path, if any. Errors on a missing argument or an unknown flag.
fn parse_config_flag(args: &[String]) -> anyhow::Result<Option<std::path::PathBuf>> {
    let mut config = None;
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "-c" | "--config" => {
                let path = it
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--config requires a path argument"))?;
                config = Some(std::path::PathBuf::from(path));
            }
            other => anyhow::bail!("unknown option: {other}\n\nrun `mia --help` for usage"),
        }
    }
    Ok(config)
}

/// Top-level CLI usage banner.
fn print_usage() {
    println!(
        "mia {} — FerroGate Machine Identity Agent\n\
         \n\
         usage: mia [--config <path>]\n\
         \x20      mia <command>\n\
         \n\
         commands:\n\
         \x20 (none)   run the agent daemon\n\
         \x20 setup    interactive wizard that writes the agent's config file\n\
         \x20 test     check CMIS connectivity and helper-token issuance\n\
         \n\
         options:\n\
         \x20 -c, --config <path>   TOML config file (default {}, then\n\
         \x20                       $FERROGATE_CONFIG; environment variables override it)\n\
         \x20 -h, --help            show this help\n\
         \x20 -V, --version         print the version\n\
         \n\
         Run `mia setup --help` for the wizard's options and `mia test --help`\n\
         for the self-test's.",
        env!("CARGO_PKG_VERSION"),
        mia::config::system_config_path().display(),
    );
}

/// Daemon entry point. Starts the helper API when a helper socket is
/// configured, otherwise prints a banner and exits.
// The serve path holds a composite key (~4 KB ML-DSA) across awaits during
// attestation; the large future is inherent, not a bug.
#[allow(clippy::large_futures)]
async fn run(config: mia::config::Config) -> anyhow::Result<()> {
    if config.helper_socket().is_none() {
        println!(
            "mia v{} — daemon idle; set a helper socket (helper.socket / \
             FERROGATE_HELPER_SOCKET) to start the helper API.",
            env!("CARGO_PKG_VERSION")
        );
        return Ok(());
    }
    start_helper_api(&config).await
}

/// Build the platform's caller authenticator (Linux: SO_PEERCRED + IMA).
#[cfg(target_os = "linux")]
fn build_auth(config: &mia::config::Config) -> mia::helper::auth::ImaCallerAuth {
    use mia::helper::auth::ImaCallerAuth;
    match config.attestation.ima_log.as_deref() {
        Some(p) => ImaCallerAuth::with_ima_log(p.to_path_buf()),
        None => ImaCallerAuth::new(),
    }
}

/// Build the platform's caller authenticator (macOS: peer-cred + image hash).
#[cfg(target_os = "macos")]
fn build_auth(_config: &mia::config::Config) -> mia::helper::auth::MacCallerAuth {
    mia::helper::auth::MacCallerAuth::new()
}

/// Build the platform's caller authenticator (Windows: PID + image hash +
/// Authenticode).
#[cfg(windows)]
fn build_auth(_config: &mia::config::Config) -> mia::helper::auth::WindowsCallerAuth {
    mia::helper::auth::WindowsCallerAuth::new()
}

/// Start the local helper API. Supported on Linux, macOS, and Windows; the only
/// per-OS difference is the caller authenticator ([`build_auth`]) and the
/// transport `HelperServer` resolves from the target (UDS on Unix, a named pipe
/// on Windows).
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
#[allow(clippy::large_futures)] // attestation future holds a composite key
async fn start_helper_api(config: &mia::config::Config) -> anyhow::Result<()> {
    use anyhow::Context as _;
    let socket_path = config
        .helper_socket()
        .context("internal: start_helper_api called without a helper socket")?
        .to_path_buf();
    serve(config, socket_path, build_auth(config)).await
}

/// Resolve where the persistent machine signing key lives — beside the system
/// config (e.g. `/Library/Application Support/FerroGate/host-key.bin` on macOS).
fn host_key_path() -> std::path::PathBuf {
    mia::config::system_config_path().parent().map_or_else(
        || std::path::PathBuf::from("mia-host-key.bin"),
        |d| d.join("host-key.bin"),
    )
}

/// Bootstrap the host SVID via the TPM-less **host-key** attestation profile
/// (feature F15) and build the child-token minter the helper API mints with.
///
/// Returns `None` — with a logged reason — when CMIS is not configured, the
/// platform has no hardware fingerprint, or attestation fails. In every such
/// case the helper API still starts; it just refuses to mint (`no_host_svid`)
/// until a later attempt succeeds.
///
/// The signing key is a persistent [`ferro_sep::SoftwareMachineKey`]. Upgrading
/// the daemon to a non-exportable Secure-Enclave key needs keychain-backed
/// persistence in `ferro-sep` (see docs/features/F15.md) — the SEP backend's
/// cryptographic core is already proven by `ferro-sep`'s live test.
#[allow(clippy::too_many_lines)] // linear bootstrap: dial → attest → build minter
#[allow(clippy::large_futures)] // holds a composite key (~4 KB ML-DSA) across awaits
async fn bootstrap_host_svid(config: &mia::config::Config) -> Option<HostSession> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use ferro_crypto::pin::SpkiPin;
    use ferro_sep::MachineKey as _;
    use mia::helper::{ChildTokenMinter, MinterConfig};
    use sha2::{Digest, Sha256, Sha384};

    let endpoint = config.cmis.endpoint.as_deref()?;
    let Some(pin_hex) = config.cmis.spki_pin.as_deref() else {
        tracing::error!("cmis.endpoint is set but cmis.spki_pin is missing; cannot attest");
        return None;
    };
    let pin = match SpkiPin::from_hex(pin_hex.trim()) {
        Ok(p) => p,
        Err(e) => {
            tracing::error!(error = %e, "cmis.spki_pin is not a valid SHA-384 SPKI pin");
            return None;
        }
    };

    let facts = match ferro_machineid::collect_facts() {
        Ok(f) => f,
        Err(e) => {
            tracing::warn!(error = %e, "cannot collect a hardware fingerprint; host-key attestation skipped");
            return None;
        }
    };
    let key_path = host_key_path();
    let key = match ferro_sep::SoftwareMachineKey::open_or_create(&key_path) {
        Ok(k) => k,
        Err(e) => {
            tracing::error!(error = %e, path = %key_path.display(), "cannot open machine signing key");
            return None;
        }
    };

    // Host DPoP confirmation key thumbprint. A host-bound stand-in derived from
    // the machine key until the host DPoP key (F09) is wired; CMIS records it as
    // the SVID's `cnf.jkt`.
    let dpop_jkt = URL_SAFE_NO_PAD.encode(Sha256::digest(key.public_spki_der()));

    let mut client = match mia::client::connect_pinned(endpoint, vec![pin]).await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, %endpoint, "could not connect to CMIS for attestation");
            return None;
        }
    };
    let attested = match mia::client::run_attest_host_key(&mut client, &facts, &key, dpop_jkt).await
    {
        Ok(a) => a,
        Err(e) => {
            tracing::error!(error = %e, "host-key attestation failed");
            return None;
        }
    };

    let mut parent = [0u8; 48];
    parent.copy_from_slice(&Sha384::digest(attested.bundle.jws.as_bytes()));
    let cfg = MinterConfig {
        host_spiffe_id: attested.bundle.spiffe_id.clone(),
        parent_svid_sha384: parent,
        kid: ferro_svid::child_signing_kid(&attested.svid_public),
    };
    tracing::info!(
        spiffe_id = %attested.bundle.spiffe_id,
        fingerprint = %facts.fingerprint().to_hex(),
        "host SVID obtained via host-key attestation; token minting enabled"
    );
    Some(HostSession {
        spiffe_id: attested.bundle.spiffe_id.clone(),
        jws: attested.bundle.jws.clone(),
        minter: ChildTokenMinter::new(attested.svid_secret, cfg),
    })
}

/// The outcome of a successful host attestation: the token minter the helper API
/// mints with, plus the host's SVID SPIFFE id (its EK/fingerprint-derived
/// identity, used to key the host's allowlist fetch).
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
struct HostSession {
    minter: mia::helper::ChildTokenMinter,
    spiffe_id: String,
    /// The host's compact-JWS SVID, presented when proposing an allowlist.
    jws: String,
}

/// Extract the host UUID from a host SVID SPIFFE id (`spiffe://<td>/host/<uuid>`)
/// — the key CMIS stores a host's allowlist under.
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
fn host_uuid_from_spiffe_id(spiffe_id: &str) -> Option<&str> {
    spiffe_id
        .rsplit_once("/host/")
        .map(|(_, uuid)| uuid)
        .filter(|u| !u.is_empty())
}

/// If `allowlist.fetch` is enabled, fetch this host's signed allowlist from CMIS
/// (keyed by its EK-derived host UUID) and write it to `allowlist.path` before
/// the daemon loads it. Every failure mode is non-fatal and logged: the daemon
/// then falls back to whatever is already on disk (or fails closed if nothing
/// is), exactly as if auto-fetch were off.
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
async fn maybe_fetch_allowlist(config: &mia::config::Config, host_spiffe_id: Option<&str>) {
    use ferro_crypto::pin::SpkiPin;

    if !config.allowlist.fetch {
        return;
    }
    let Some(path) = config.allowlist.path.as_deref() else {
        tracing::warn!("allowlist.fetch is set but allowlist.path is unset; nothing to write");
        return;
    };
    let Some(spiffe_id) = host_spiffe_id else {
        tracing::warn!(
            "allowlist.fetch is set but no host SVID this start; keeping any existing allowlist"
        );
        return;
    };
    let Some(host_uuid) = host_uuid_from_spiffe_id(spiffe_id) else {
        tracing::warn!(%spiffe_id, "could not derive host UUID from SVID; skipping allowlist fetch");
        return;
    };
    let (Some(endpoint), Some(pin_hex)) = (
        config.cmis.endpoint.as_deref(),
        config.cmis.spki_pin.as_deref(),
    ) else {
        tracing::warn!("allowlist.fetch is set but cmis.endpoint/spki_pin are missing; skipping");
        return;
    };
    let pin = match SpkiPin::from_hex(pin_hex.trim()) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "cmis.spki_pin invalid; skipping allowlist fetch");
            return;
        }
    };

    match mia::client::fetch_allowlist(endpoint, vec![pin], host_uuid).await {
        Ok(Some(bytes)) => {
            if let Err(e) = write_allowlist_file(path, &bytes) {
                tracing::warn!(error = %e, path = %path.display(), "could not write fetched allowlist; keeping existing file");
            } else {
                tracing::info!(%host_uuid, path = %path.display(), bytes = bytes.len(), "fetched signed allowlist from CMIS");
            }
        }
        Ok(None) => {
            tracing::warn!(%host_uuid, "CMIS has no allowlist for this host; keeping any existing file");
        }
        Err(e) => {
            tracing::warn!(error = %e, "allowlist fetch failed; keeping any existing file");
        }
    }
}

/// Write the signed allowlist CBOR to `path`, creating parent dirs. The body is
/// integrity-protected by its signature (not secret), so `0644` like the key.
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
fn write_allowlist_file(path: &std::path::Path, bytes: &[u8]) -> anyhow::Result<()> {
    use anyhow::Context as _;
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
    }
    std::fs::write(path, bytes).with_context(|| format!("writing {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644));
    }
    Ok(())
}

/// Spawn the background allowlist-propose task (host-driven allowlist
/// bootstrap). It periodically snapshots the callers the helper API has observed
/// (granted *and* denied) and sends them to CMIS, signed by the host machine key
/// and accompanied by the host SVID. CMIS auto-adopts the first proposal on a
/// host with no allowlist (TOFU) or queues it for operator review; see
/// `ProposeAllowlist`.
///
/// Every precondition failure logs and returns without spawning — proposing is
/// strictly opt-in best-effort. The SVID presented is the one obtained at
/// startup; once it expires CMIS rejects further proposals until mia restarts
/// (scheduled re-attestation is a follow-up).
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
#[allow(clippy::too_many_lines)] // precondition checks + the periodic loop.
fn maybe_spawn_propose_task(
    config: &mia::config::Config,
    host_spiffe_id: Option<&str>,
    host_jws: Option<String>,
    ledger: mia::helper::CallerLedger,
) {
    use ferro_crypto::pin::SpkiPin;
    use ferro_sep::MachineKey as _;
    use std::time::{SystemTime, UNIX_EPOCH};

    let Some(spiffe_id) = host_spiffe_id else {
        tracing::warn!("allowlist.propose is set but no host SVID this start; not proposing");
        return;
    };
    let Some(jws) = host_jws else {
        tracing::warn!("allowlist.propose is set but host SVID JWS is missing; not proposing");
        return;
    };
    let Some(host_uuid) = host_uuid_from_spiffe_id(spiffe_id).map(str::to_string) else {
        tracing::warn!(%spiffe_id, "could not derive host UUID; not proposing");
        return;
    };
    let (Some(endpoint), Some(pin_hex)) =
        (config.cmis.endpoint.clone(), config.cmis.spki_pin.clone())
    else {
        tracing::warn!(
            "allowlist.propose is set but cmis.endpoint/spki_pin are missing; not proposing"
        );
        return;
    };
    let pin = match SpkiPin::from_hex(pin_hex.trim()) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "cmis.spki_pin invalid; not proposing");
            return;
        }
    };
    let key = match ferro_sep::SoftwareMachineKey::open_or_create(&host_key_path()) {
        Ok(k) => k,
        Err(e) => {
            tracing::error!(error = %e, "cannot open machine key; not proposing");
            return;
        }
    };
    let sep_pub = key.public_spki_der();
    let interval = std::time::Duration::from_secs(config.allowlist_propose_interval());
    tracing::info!(%host_uuid, interval_secs = config.allowlist_propose_interval(), "allowlist-propose task started");

    tokio::spawn(async move {
        let mut last_sent: Option<Vec<(u32, [u8; 48])>> = None;
        let mut ticker = tokio::time::interval(interval);
        // The first tick fires immediately; skip it so we never propose before a
        // caller has connected.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            let mut snapshot = ledger.snapshot();
            if snapshot.is_empty() {
                continue;
            }
            snapshot.sort_unstable();
            if last_sent.as_ref() == Some(&snapshot) {
                continue; // nothing new since the last successful proposal
            }
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX));
            let entries = snapshot
                .iter()
                .map(|(uid, bin)| ferro_svid::AllowEntry {
                    uid: *uid,
                    bin_sha: hex::encode(bin),
                })
                .collect();
            let doc = ferro_svid::ProposalDoc {
                host_uuid: host_uuid.clone(),
                issued_at: now,
                entries,
            };
            let body = match ferro_svid::allowlist::encode_proposal(&doc) {
                Ok(b) => b,
                Err(e) => {
                    tracing::warn!(error = %e, "encode proposal failed");
                    continue;
                }
            };
            let sig = match key.sign(&ferro_svid::allowlist::proposal_signing_input(&body)) {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(error = %e, "sign proposal failed");
                    continue;
                }
            };
            match mia::client::propose_allowlist(
                &endpoint,
                vec![pin],
                body,
                sig,
                jws.clone(),
                sep_pub.clone(),
            )
            .await
            {
                Ok(outcome) => {
                    tracing::info!(
                        ?outcome,
                        entries = snapshot.len(),
                        "proposed observed allowlist to CMIS"
                    );
                    last_sent = Some(snapshot);
                }
                Err(e) => tracing::warn!(error = %e, "allowlist proposal failed; will retry"),
            }
        }
    });
}

/// Interval between CRL pulls. CMIS republishes every 60 s and the helper-API
/// mint gate tolerates 300 s + 60 s leeway, so pulling at the publish cadence
/// keeps the cache fresh with margin for several consecutive failed pulls.
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
const CRL_PULL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

/// Start the background CRL puller (feature F11) feeding `cache` from the CMIS
/// `JWKS` RPC over a pinned channel.
///
/// Without a usable CMIS configuration nothing can be pulled, so the cache
/// stays empty and every mint is refused (`crl_stale`, fail closed) — that is
/// loudly logged rather than silently accepted. The initial dial is retried
/// forever: CMIS being down at boot must not permanently disable minting.
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
fn maybe_spawn_crl_puller(
    config: &mia::config::Config,
    cache: std::sync::Arc<mia::helper::CrlCache>,
) {
    use ferro_crypto::pin::SpkiPin;

    let (Some(endpoint), Some(pin_hex)) =
        (config.cmis.endpoint.clone(), config.cmis.spki_pin.clone())
    else {
        tracing::warn!(
            "cmis.endpoint/spki_pin not configured; no CRL can be pulled, so token minting \
             stays disabled (crl_stale, fail closed)"
        );
        return;
    };
    let pin = match SpkiPin::from_hex(pin_hex.trim()) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(
                error = %e,
                "cmis.spki_pin invalid; no CRL can be pulled, so token minting stays disabled \
                 (crl_stale, fail closed)"
            );
            return;
        }
    };

    tokio::spawn(async move {
        loop {
            match mia::client::connect_pinned(&endpoint, vec![pin]).await {
                Ok(client) => {
                    // The channel redials on demand after transient drops, so
                    // one successful connect is enough to hand the pull loop;
                    // it only resolves if the puller task itself dies.
                    let puller =
                        mia::helper::crl::spawn_puller(client, cache.clone(), CRL_PULL_INTERVAL);
                    let _ = puller.await;
                    tracing::warn!("CRL puller stopped unexpectedly; restarting");
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e, %endpoint,
                        "cannot connect to CMIS for CRL pulls; retrying (minting stays \
                         fail-closed until the first verified pull)"
                    );
                }
            }
            tokio::time::sleep(CRL_PULL_INTERVAL).await;
        }
    });
}

/// Bind and serve the helper API with the given caller authenticator. Shared by
/// every supported platform.
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
#[allow(clippy::large_futures)] // attestation future holds a composite key
async fn serve<A>(
    config: &mia::config::Config,
    socket_path: std::path::PathBuf,
    auth: A,
) -> anyhow::Result<()>
where
    A: mia::helper::auth::CallerAuth,
{
    use anyhow::Context as _;
    use mia::helper::{system_clock, CrlCache, HelperServer, HelperServerConfig};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::mpsc;

    let max_age = config.allowlist_max_age();
    let clock = system_clock();

    // Audit sink: a forwarder task drains helper events. For now it logs them;
    // CMIS forwarding rides on F07's `AppendAuditEvent` path (`audit_client`).
    let (audit_tx, mut audit_rx) = mpsc::channel(256);
    tokio::spawn(async move {
        while let Some(event) = audit_rx.recv().await {
            tracing::info!(?event, "helper-api audit event");
        }
    });

    // Attest to CMIS first: a successful attestation yields the host SVID (and
    // thus the EK-derived identity that keys this host's allowlist) and the
    // token minter. When CMIS isn't configured or attestation fails, there is no
    // session — the helper API still serves but refuses to mint (`no_host_svid`).
    let session = bootstrap_host_svid(config).await;
    let host_spiffe_id = session.as_ref().map(|s| s.spiffe_id.clone());
    let host_jws = session.as_ref().map(|s| s.jws.clone());
    let minter = session.map(|s| s.minter);
    if minter.is_none() {
        tracing::warn!(
            "host SVID not present; token minting disabled (returns no_host_svid) until a future attestation succeeds"
        );
    }

    // Optionally refresh the on-disk allowlist from CMIS before loading it, so
    // the served body stays in sync with what the operator provisioned.
    maybe_fetch_allowlist(config, host_spiffe_id.as_deref()).await;

    // Allowlist: configured ⇒ load and verify, denying all callers (fail
    // closed) on a missing file or a verification failure rather than crashing
    // — a crash here would loop under the service supervisor and unbind the
    // helper socket, hiding the real error behind ECONNREFUSED. Absent
    // configuration also denies all.
    let allowlist = if let Some(path) = config.allowlist.path.as_deref() {
        let key_path = config.allowlist.key.as_deref().context(
            "allowlist.path is set but allowlist.key (FERROGATE_ALLOWLIST_KEY) is missing",
        )?;
        mia::helper::allowlist::load_at_startup(path, key_path, clock(), max_age)
            .with_context(|| format!("reading allowlist (allowlist.path) {}", path.display()))?
    } else {
        tracing::warn!("no allowlist configured; helper API denies all callers (fail closed)");
        None
    };

    let helper_config = HelperServerConfig {
        socket_path: socket_path.clone(),
        // `socket_mode`/`socket_gid` are Unix-only; `windows_group` is
        // Windows-only. Each transport ignores the fields that don't apply.
        socket_mode: config.socket_mode()?,
        socket_gid: config.socket_gid()?,
        windows_group: config.helper.windows_group.clone(),
        max_concurrent: 64,
        read_timeout: Duration::from_secs(5),
    };

    // The CRL cache (feature F11) starts empty and the mint gate fails closed;
    // the puller's first verified pull (within seconds of startup) opens it.
    let crl = Arc::new(CrlCache::new());
    maybe_spawn_crl_puller(config, Arc::clone(&crl));
    let server = HelperServer::bind(helper_config, auth, minter, allowlist, crl, audit_tx, clock)?;
    tracing::info!(listener = %socket_path.display(), "helper API listening");

    // Optionally propose the callers the helper API observes back to CMIS, so a
    // host with no allowlist can bootstrap its own (subject to CMIS policy).
    if config.allowlist.propose {
        maybe_spawn_propose_task(config, host_spiffe_id.as_deref(), host_jws, server.ledger());
    }

    server.serve_with_shutdown(shutdown_signal()).await;
    tracing::info!("helper API shut down cleanly");
    Ok(())
}

/// Fallback for platforms with no helper transport (neither Unix nor Windows).
#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
#[allow(clippy::unused_async)] // async to match the cross-platform signature
async fn start_helper_api(_config: &mia::config::Config) -> anyhow::Result<()> {
    anyhow::bail!("unsupported platform: mia's helper API runs on Linux, macOS, and Windows")
}

/// Resolve when the process is asked to stop: `SIGINT`/`SIGTERM` on Unix,
/// Ctrl-C / Ctrl-Break on Windows.
#[cfg(unix)]
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

/// Resolve when the process receives Ctrl-C / Ctrl-Break (Windows).
#[cfg(windows)]
async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("received Ctrl-C; shutting down");
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos", windows)))]
mod tests {
    use super::host_uuid_from_spiffe_id;

    #[test]
    fn extracts_host_uuid_from_spiffe_id() {
        let uuid = "11111111-1111-8111-8111-111111111111";
        assert_eq!(
            host_uuid_from_spiffe_id(&format!("spiffe://ferrogate.test/host/{uuid}")),
            Some(uuid)
        );
    }

    #[test]
    fn rejects_ids_without_a_host_segment() {
        assert_eq!(
            host_uuid_from_spiffe_id("spiffe://ferrogate.test/cmis"),
            None
        );
        assert_eq!(
            host_uuid_from_spiffe_id("spiffe://ferrogate.test/host/"),
            None
        );
        assert_eq!(host_uuid_from_spiffe_id(""), None);
    }
}
