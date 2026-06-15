//! `mia test` — operator-facing connectivity and token-issuance self-test.
//!
//! Exercises the full path a local application depends on, in order:
//!
//! 1. **configuration** — a CMIS endpoint and SPKI pin are resolved;
//! 2. **CMIS connection** — a pinned hybrid-PQC TLS connection is established
//!    (the dial is eager, so DNS, TCP, the X25519MLKEM768 handshake, and the
//!    SPKI pin are all validated here);
//! 3. **cluster identity** — when CMIS is an HA cluster (an SRV record with
//!    more than one node), every reachable node is dialed and confirmed to
//!    serve the *same* issuer enrollment key. Nodes that disagree silently
//!    break machine login: a client load-balanced across the SRV name fetches
//!    an allowlist signed by one node but verifies it against another's key
//!    (`bad signature`). A single static endpoint has nothing to cross-check;
//! 4. **CMIS CRL publishing** — the `JWKS` RPC returns a signature-valid,
//!    fresh CRL (the helper API fail-closed gates minting on this, F11);
//! 5. **helper token mint** — a real `HelperReq` is sent over the local helper
//!    socket and the reply is interpreted.
//!
//! Every failing step prints targeted remediation hints (mirroring the
//! runbooks under `docs/operations/runbooks/`), and the command exits non-zero
//! so provisioning scripts can gate on it. Like `mia setup`, this is a client
//! command: it runs without the daemon's hardening profile and never touches
//! the TPM.

use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context as _;

use crate::config::Config;
use crate::endpoint::CmisResolver;
use crate::helper::crl::{CrlIngestError, CRL_FRESHNESS_LEEWAY_SECS};
// Used only by `mint_failure_advice` (unix `check_mint` + tests).
#[cfg(any(unix, test))]
use crate::helper::proto::ErrorCode;

/// Timeout applied to each network step so a black-holed endpoint cannot make
/// the self-test hang.
const STEP_TIMEOUT: Duration = Duration::from_secs(10);

/// Audience the test token is minted for when `--audience` is not given. The
/// `.invalid` TLD guarantees it never names a real relying party.
const DEFAULT_AUDIENCE: &str = "https://selftest.ferrogate.invalid";

/// Run the `mia test` subcommand. `args` is everything after `test` on the
/// command line.
pub fn run(args: &[String]) -> anyhow::Result<()> {
    let Some(opts) = Opts::parse(args)? else {
        return Ok(()); // --help printed
    };

    let (config, source) = Config::load(opts.config.as_deref(), opts.environment.as_deref())?;
    println!(
        "FerroGate MIA self-test (mia {})",
        env!("CARGO_PKG_VERSION")
    );
    match &source {
        Some(path) => println!("config: {}", path.display()),
        None => println!("config: none found — using environment and defaults"),
    }
    println!();

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(run_checks(&config, &opts.audience))
}

/// Parsed `mia test` command-line options.
struct Opts {
    /// `--config <path>` override (same as the daemon's flag).
    config: Option<PathBuf>,
    /// `--environment <env>` selector (same as the daemon's flag); selects
    /// `mia-<env>.toml`. Mutually exclusive with `config`.
    environment: Option<String>,
    /// `--audience <aud>` for the test mint.
    audience: String,
}

impl Opts {
    /// Parse `args`; `Ok(None)` means help was printed and the caller should
    /// exit successfully.
    fn parse(args: &[String]) -> anyhow::Result<Option<Self>> {
        let mut config = None;
        let mut environment = None;
        let mut audience = DEFAULT_AUDIENCE.to_string();
        let mut it = args.iter();
        while let Some(arg) = it.next() {
            match arg.as_str() {
                "-h" | "--help" => {
                    print_help();
                    return Ok(None);
                }
                "-c" | "--config" => {
                    let path = it.next().context("--config requires a path argument")?;
                    config = Some(PathBuf::from(path));
                }
                "-e" | "--environment" => {
                    let env = it.next().context("--environment requires a name argument")?;
                    environment = Some(env.clone());
                }
                "-a" | "--audience" => {
                    let aud = it.next().context("--audience requires a value")?;
                    audience.clone_from(aud);
                }
                other => anyhow::bail!("unknown argument: {other}\n\n{USAGE}"),
            }
        }
        Ok(Some(Self {
            config,
            environment,
            audience,
        }))
    }
}

const USAGE: &str =
    "usage: mia test [--config <path> | --environment <env>] [--audience <aud>]";

fn print_help() {
    println!(
        "mia test — check CMIS connectivity and helper-token issuance\n\
         \n\
         {USAGE}\n\
         \n\
         Runs four checks: configuration, the pinned hybrid-PQC TLS connection\n\
         to CMIS, CMIS CRL publishing, and a live token mint through the local\n\
         helper socket. Prints remediation hints on failure and exits non-zero\n\
         if any check fails.\n\
         \n\
         options:\n\
         \x20 -c, --config <path>     TOML config file (same resolution as the daemon)\n\
         \x20 -e, --environment <env> select mia-<env>.toml from the standard config\n\
         \x20                         locations instead of mia.toml; excludes --config\n\
         \x20 -a, --audience <aud>    audience for the test token (default {DEFAULT_AUDIENCE})\n\
         \x20 -h, --help              show this help"
    );
}

/// Outcome of the server-side CRL check, threaded into the mint diagnostics so
/// a `crl_stale` refusal can say which side is at fault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ServerCrl {
    /// CMIS published a signature-valid, fresh CRL.
    Fresh,
    /// CMIS is reachable but its CRL is stale, absent, or unverifiable.
    Broken,
    /// The check could not run (no connection).
    Unknown,
}

/// Execute the four checks in order, printing as it goes. Returns an error —
/// and therefore a non-zero exit — if any check failed.
async fn run_checks(config: &Config, audience: &str) -> anyhow::Result<()> {
    let mut failures: Vec<&str> = Vec::new();

    // 1. configuration ----------------------------------------------------
    let resolver = check_config(config);
    if resolver.is_none() {
        failures.push("configuration");
    }

    // 2. CMIS connection / 3. CRL publishing ------------------------------
    let mut server_crl = ServerCrl::Unknown;
    if let Some(resolver) = &resolver {
        match connect_best(resolver).await {
            Ok((endpoint, mut client)) => {
                report(
                    "[2/5] CMIS connection",
                    "ok",
                    &format!("{endpoint} — hybrid-PQC TLS established, SPKI pin verified"),
                );
                // 3. cluster identity ----------------------------------------
                if !check_cluster_identity(resolver).await {
                    failures.push("cluster identity");
                }
                // 4. CRL publishing ------------------------------------------
                server_crl = check_server_crl(&mut client).await;
                if server_crl != ServerCrl::Fresh {
                    failures.push("CMIS CRL publishing");
                }
            }
            Err(e) => {
                failures.push("CMIS connection");
                report("[2/5] CMIS connection", "FAIL", &format!("{e:#}"));
                hints(&[
                    format!("Check basic reachability: DNS and TCP to {}.", resolver.describe()),
                    "A TLS handshake error usually means the SPKI pin no longer matches the served \
                     certificate (a cert rotation without a config update), or the server does not \
                     offer hybrid X25519MLKEM768 — non-hybrid servers are rejected by design."
                        .to_string(),
                    "Compare cmis.spki_pin against the pin of the live certificate(s), and confirm \
                     the CMIS service is up. For an SRV record, check it resolves to the live nodes \
                     (`dig SRV <name>`) and that they share the pinned identity.".to_string(),
                ]);
                report(
                    "[3/5] cluster identity",
                    "skip",
                    "no connection — fix step 2 first",
                );
                report(
                    "[4/5] CMIS CRL publishing",
                    "skip",
                    "no connection — fix step 2 first",
                );
            }
        }
    } else {
        report(
            "[2/5] CMIS connection",
            "skip",
            "no usable CMIS configuration",
        );
        report(
            "[3/5] cluster identity",
            "skip",
            "no usable CMIS configuration",
        );
        report(
            "[4/5] CMIS CRL publishing",
            "skip",
            "no usable CMIS configuration",
        );
    }

    // 5. helper token mint -------------------------------------------------
    if !check_mint(config, audience, server_crl).await {
        failures.push("helper token mint");
    }

    println!();
    if failures.is_empty() {
        println!("all checks passed — the helper API is emitting tokens.");
        Ok(())
    } else {
        anyhow::bail!("self-test failed: {}", failures.join(", "));
    }
}

/// Step 1: build the CMIS resolver from `config` — a single static endpoint, or
/// an SRV record for HA. Reports the configured source and validates the pin.
fn check_config(config: &Config) -> Option<CmisResolver> {
    let label = "[1/5] configuration";
    match CmisResolver::from_config(&config.cmis) {
        Ok(Some(r)) => {
            let detail = if r.is_srv() {
                format!("SRV {} (high-availability discovery)", r.describe())
            } else {
                format!("endpoint {}", r.describe())
            };
            report(label, "ok", &detail);
            Some(r)
        }
        Ok(None) => {
            report(label, "FAIL", "neither cmis.endpoint nor cmis.srv is set");
            hints(&[
                "Run `mia setup` (or set FERROGATE_CMIS_ENDPOINT / FERROGATE_CMIS_SRV) to point \
                 the agent at CMIS: a single https://host:port, or an SRV record like \
                 _cmis._tcp.example.com for a high-availability cluster."
                    .to_string(),
            ]);
            None
        }
        Err(e) => {
            report(label, "FAIL", &format!("{e:#}"));
            hints(&[
                "Set exactly one of cmis.endpoint / cmis.srv, plus a valid cmis.spki_pin \
                 (lowercase-hex SHA-384, 96 chars). `mia setup` can fetch and confirm the pin."
                    .to_string(),
            ]);
            None
        }
    }
}

/// Step 2: select a live CMIS node. For an SRV source, resolve the candidates,
/// probe each best-first (printing per-node reachability so the operator sees
/// the HA picture), and return the first that completes the pinned hybrid-PQC
/// handshake; a static source dials its single endpoint. Each dial is bounded by
/// [`STEP_TIMEOUT`].
async fn connect_best(
    resolver: &CmisResolver,
) -> anyhow::Result<(
    String,
    ferro_proto::v1::machine_identity_client::MachineIdentityClient<tonic::transport::Channel>,
)> {
    let candidates = resolver
        .candidates()
        .await
        .context("resolving CMIS candidates")?;
    if resolver.is_srv() {
        println!(
            "        SRV {} resolved to {} candidate(s):",
            resolver.describe(),
            candidates.len()
        );
    }
    let pins = resolver.pins().to_vec();
    let mut last_err: Option<String> = None;
    for ep in &candidates {
        match tokio::time::timeout(STEP_TIMEOUT, crate::client::connect_pinned(ep, pins.clone()))
            .await
        {
            Ok(Ok(client)) => {
                if resolver.is_srv() {
                    println!("          ✓ {ep}");
                }
                return Ok((ep.clone(), client));
            }
            Ok(Err(e)) => {
                if resolver.is_srv() {
                    println!("          ✗ {ep}: {e}");
                }
                last_err = Some(format!("{ep}: {e}"));
            }
            Err(_) => {
                if resolver.is_srv() {
                    println!("          ✗ {ep}: timed out after {}s", STEP_TIMEOUT.as_secs());
                }
                last_err = Some(format!("{ep}: timed out"));
            }
        }
    }
    anyhow::bail!(
        "no reachable CMIS node among {} candidate(s){}",
        candidates.len(),
        last_err.map_or(String::new(), |e| format!(" (last: {e})"))
    )
}

/// Step 3: when CMIS is an HA cluster, confirm every reachable node serves the
/// same issuer enrollment key — the key host allowlists are signed under. Nodes
/// that disagree are a split-brain signing identity: behind one SRV name a
/// client fetches an allowlist signed by one node yet verifies it against
/// another's key, so machine login fails with `bad signature` even though each
/// node's *own* self-test passes (each node is internally self-consistent). A
/// single static endpoint — or an SRV that resolves to one node — has no peers
/// to cross-check and passes trivially.
///
/// Returns `true` when the cluster presents one identity (or there is nothing
/// to cross-check), `false` on divergence.
async fn check_cluster_identity(resolver: &CmisResolver) -> bool {
    let label = "[3/5] cluster identity";
    if !resolver.is_srv() {
        report(label, "ok", "single endpoint — no cluster to cross-check");
        return true;
    }
    let candidates = match resolver.candidates().await {
        Ok(c) => c,
        Err(e) => {
            // SRV resolution / reachability is step 2's concern — don't double-fail.
            report(label, "skip", &format!("could not resolve SRV candidates: {e:#}"));
            return true;
        }
    };
    if candidates.len() < 2 {
        report(label, "ok", "SRV resolved to a single node — no peers to cross-check");
        return true;
    }

    // Probe every node for the enrollment key it serves, then group by that key:
    // one group means a single signing identity, more than one means split brain.
    let pins = resolver.pins().to_vec();
    let mut probes: Vec<(String, Vec<u8>)> = Vec::new();
    let mut unreachable = 0usize;
    for ep in &candidates {
        match probe_enrollment_key(ep, &pins).await {
            Ok(key) => probes.push((ep.clone(), key)),
            Err(e) => {
                unreachable += 1;
                println!("          ✗ {ep}: {e:#}");
            }
        }
    }

    let groups = group_by_identity(probes);
    let compared: usize = groups.iter().map(|(_, eps)| eps.len()).sum();
    if compared == 0 {
        report(label, "skip", "no nodes answered the enrollment-key RPC (see step 2)");
        return true;
    }

    if groups.len() == 1 {
        report(
            label,
            "ok",
            &format!(
                "{compared} node(s) share one signing identity (key {})",
                key_fp(&groups[0].0)
            ),
        );
        if unreachable > 0 {
            hints(&[format!(
                "{unreachable} node(s) could not be checked; re-run when every SRV target is up."
            )]);
        }
        true
    } else {
        report(
            label,
            "FAIL",
            &format!(
                "CMIS nodes serve {} different enrollment keys — split-brain signing identity",
                groups.len()
            ),
        );
        for (key, eps) in &groups {
            println!("          key {} ⇐ {}", key_fp(key), eps.join(", "));
        }
        hints(&[
            "Behind one SRV name a client fetches an allowlist signed by one node but verifies it \
             against another's key, so machine login fails with `bad signature` even though each \
             node's own `mia test` passes."
                .to_string(),
            "The cluster's issuer master seed must be identical on every node. Current CMIS \
             replicates the seed automatically; if nodes still diverge, one is running an older \
             build that kept a per-node local seed — unify it (install the leader's \
             /var/lib/ferrogate/issuer/issuer.seed on the others and restart) or upgrade."
                .to_string(),
            "After unifying, re-pin and re-fetch on every enrolled host: `mia refresh-key` then \
             `mia resync-allowlist` (add `-e <env>` for a named environment)."
                .to_string(),
        ]);
        false
    }
}

/// Dial one CMIS node over pinned hybrid-PQC TLS and fetch its issuer
/// enrollment key, bounding both the connect and the RPC by [`STEP_TIMEOUT`].
async fn probe_enrollment_key(
    endpoint: &str,
    pins: &[ferro_crypto::pin::SpkiPin],
) -> anyhow::Result<Vec<u8>> {
    let mut client = tokio::time::timeout(
        STEP_TIMEOUT,
        crate::client::connect_pinned(endpoint, pins.to_vec()),
    )
    .await
    .map_err(|_| anyhow::anyhow!("connect timed out after {}s", STEP_TIMEOUT.as_secs()))??;
    tokio::time::timeout(STEP_TIMEOUT, crate::client::fetch_enrollment_key(&mut client))
        .await
        .map_err(|_| {
            anyhow::anyhow!("enrollment-key RPC timed out after {}s", STEP_TIMEOUT.as_secs())
        })?
}

/// Group `(endpoint, enrollment_key)` probes by the key served. One entry in
/// the result means a single signing identity across the cluster; more than one
/// means split brain. Endpoints keep their probe order within each group.
fn group_by_identity(probes: Vec<(String, Vec<u8>)>) -> Vec<(Vec<u8>, Vec<String>)> {
    let mut groups: Vec<(Vec<u8>, Vec<String>)> = Vec::new();
    for (ep, key) in probes {
        if let Some(g) = groups.iter_mut().find(|(k, _)| *k == key) {
            g.1.push(ep);
        } else {
            groups.push((key, vec![ep]));
        }
    }
    groups
}

/// Short, stable fingerprint of an enrollment key for display — the first 12
/// hex chars of its SHA-384. Equality is always checked on the full bytes; this
/// is only so an operator can eyeball which nodes agree.
fn key_fp(key: &[u8]) -> String {
    use sha2::{Digest, Sha384};
    let mut s = hex::encode(Sha384::digest(key));
    s.truncate(12);
    s
}

/// Step 4: fetch the JWKS and check the embedded CRL verifies and is fresh.
async fn check_server_crl(
    client: &mut ferro_proto::v1::machine_identity_client::MachineIdentityClient<
        tonic::transport::Channel,
    >,
) -> ServerCrl {
    let label = "[4/5] CMIS CRL publishing";
    let jwks = match tokio::time::timeout(
        STEP_TIMEOUT,
        client.jwks(tonic::Request::new(ferro_proto::v1::JwksRequest {})),
    )
    .await
    {
        Ok(Ok(resp)) => resp.into_inner().jwks_json,
        Ok(Err(status)) => {
            report(label, "FAIL", &format!("JWKS RPC failed: {status}"));
            hints(&[
                "The connection is up but the RPC errored — check the CMIS service log; a \
                     version mismatch between mia and CMIS can also surface here."
                    .to_string(),
            ]);
            return ServerCrl::Broken;
        }
        Err(_) => {
            report(
                label,
                "FAIL",
                &format!("JWKS RPC timed out after {}s", STEP_TIMEOUT.as_secs()),
            );
            hints(&[
                "The server accepted the connection but did not answer — check CMIS health \
                     and load."
                    .to_string(),
            ]);
            return ServerCrl::Broken;
        }
    };

    let body =
        match crate::helper::crl::ingest(&jwks) {
            Ok(body) => body,
            Err(CrlIngestError::Absent) => {
                report(label, "FAIL", "JWKS carries no x-ferrogate-crl extension");
                hints(&[
                    "CMIS is not publishing a CRL: either the server predates revocation support \
                     (F11) or its publisher task is disabled. Without a CRL every MIA refuses to \
                     mint (fail closed) — upgrade or fix the CMIS deployment."
                        .to_string(),
                ]);
                return ServerCrl::Broken;
            }
            Err(CrlIngestError::Verify(e)) => {
                report(
                    label,
                    "FAIL",
                    &format!("CRL signature verification failed: {e}"),
                );
                hints(&[
                "The CRL is signed under a key not in the published JWKS — this typically follows \
                 a botched root-key rotation (CRL signed by the old key, JWKS already serving the \
                 new one, or vice versa).".to_string(),
                "See docs/operations/runbooks/crl-stale.md; if this is fleet-wide, escalate to \
                 security and preserve a failing sample.".to_string(),
            ]);
                return ServerCrl::Broken;
            }
            Err(CrlIngestError::MalformedJwks(e)) => {
                report(label, "FAIL", &format!("malformed JWKS JSON: {e}"));
                hints(&[
                    "The endpoint answered with something that is not a FerroGate JWKS — confirm \
                     the configured endpoint really is a CMIS server."
                        .to_string(),
                ]);
                return ServerCrl::Broken;
            }
        };

    let now = unix_now();
    let age = body.age(now);
    if body.is_fresh(now, CRL_FRESHNESS_LEEWAY_SECS) {
        report(
            label,
            "ok",
            &format!("CRL #{}, age {age}s (fresh)", body.number),
        );
        ServerCrl::Fresh
    } else {
        report(
            label,
            "FAIL",
            &format!(
                "CRL #{} is stale: issued {age}s ago (limit 300s + 60s leeway)",
                body.number
            ),
        );
        hints(&[
            "CMIS publishes a fresh CRL every 60s; a stale one on the server itself means the \
             publisher task is stuck — roll the CMIS replica, it republishes on startup."
                .to_string(),
            "If the age is only slightly over the limit, also compare this host's clock with the \
             server's (NTP skew trips the same gate). See \
             docs/operations/runbooks/crl-stale.md."
                .to_string(),
        ]);
        ServerCrl::Broken
    }
}

/// Step 4: request a real child token through the helper socket and interpret
/// the reply. Returns `true` when a token was minted.
#[cfg(unix)]
async fn check_mint(config: &Config, audience: &str, server_crl: ServerCrl) -> bool {
    use crate::helper::proto::{read_frame, write_frame, HelperReq, HelperResp};

    let label = "[5/5] helper token mint";
    let Some(socket) = config.helper_socket() else {
        report(label, "FAIL", "helper.socket is not configured");
        hints(&[
            "The helper API is enabled by configuring a socket path (helper.socket / \
                 FERROGATE_HELPER_SOCKET); without it no tokens can be served to local \
                 applications. Run `mia setup` to configure one."
                .to_string(),
        ]);
        return false;
    };

    let mut stream = match tokio::net::UnixStream::connect(socket).await {
        Ok(s) => s,
        Err(e) => {
            report(
                label,
                "FAIL",
                &format!("cannot open {}: {e}", socket.display()),
            );
            hints(&socket_connect_advice(e.kind()));
            return false;
        }
    };

    // A syntactically valid DPoP thumbprint (base64url SHA-256) standing in
    // for a real caller key — the mint path only embeds it in the token.
    let dpop_jkt = selftest_jkt();
    let req = HelperReq {
        audience: audience.to_string(),
        dpop_jkt,
        ttl_secs: 60,
    };

    let exchange = async {
        write_frame(&mut stream, &req).await?;
        read_frame::<_, HelperResp>(&mut stream).await
    };
    let resp = match tokio::time::timeout(STEP_TIMEOUT, exchange).await {
        Ok(Ok(resp)) => resp,
        Ok(Err(e)) => {
            report(label, "FAIL", &format!("helper protocol error: {e}"));
            hints(&[
                "The daemon accepted the connection but the exchange failed — check the \
                     daemon log; a version mismatch between this binary and the running daemon \
                     can also surface here."
                    .to_string(),
            ]);
            return false;
        }
        Err(_) => {
            report(
                label,
                "FAIL",
                &format!("no reply within {}s", STEP_TIMEOUT.as_secs()),
            );
            hints(&[
                "The daemon accepted the connection but never replied — check the daemon \
                     log for panics or saturation."
                    .to_string(),
            ]);
            return false;
        }
    };

    match resp {
        HelperResp::Token(tok) => {
            let remaining = tok.exp - unix_now();
            report(
                label,
                "ok",
                &format!(
                    "token minted for {audience} (expires in {remaining}s, {} bytes)",
                    tok.jws.len()
                ),
            );
            true
        }
        HelperResp::Error { code, retry_after } => {
            let mut detail = format!("refused: {code:?}");
            if let Some(secs) = retry_after {
                use std::fmt::Write as _;
                let _ = write!(detail, " (retry after {secs}s)");
            }
            report(label, "FAIL", &detail);
            hints(&mint_failure_advice(code, server_crl));
            false
        }
    }
}

/// Remediation hints for a failed connect to the helper socket.
#[cfg(unix)]
fn socket_connect_advice(kind: std::io::ErrorKind) -> Vec<String> {
    match kind {
        std::io::ErrorKind::NotFound => vec![
            "The socket does not exist — the mia daemon is probably not running (or runs with a \
             different helper.socket path). Check the service status and the daemon log for \
             'helper API listening'."
                .to_string(),
        ],
        std::io::ErrorKind::PermissionDenied => vec![
            "The socket exists but this user may not open it: membership in the socket's group \
             is required (the dedicated FerroGate group, e.g. `_ferrogate` on macOS or the group \
             passed to `make mia-install`)."
                .to_string(),
            "Add the user to that group (a new login is needed for it to take effect) or re-run \
             the test as a permitted user."
                .to_string(),
        ],
        std::io::ErrorKind::ConnectionRefused => vec![
            "The socket file exists but nothing is listening — it is likely stale and the \
             daemon is down or restart-looping. Check the service status and the daemon log \
             for a startup error repeating at the supervisor's restart interval."
                .to_string(),
            "A common cause is a CMIS redeploy that changed the enrollment key, so locally \
             pinned material no longer verifies (e.g. 'allowlist verification failed'): \
             re-fetch the enrollment key with `mia setup` and restart the daemon."
                .to_string(),
        ],
        _ => vec!["Check the daemon log and the socket path/permissions.".to_string()],
    }
}

/// Named-pipe self-test is not implemented; report it honestly rather than
/// passing vacuously.
// Must mirror the unix signature (the caller awaits it), so it stays `async`
// even though this stub has nothing to await.
#[cfg(not(unix))]
#[allow(clippy::unused_async)]
async fn check_mint(_config: &Config, _audience: &str, _server_crl: ServerCrl) -> bool {
    report(
        "[5/5] helper token mint",
        "FAIL",
        "the named-pipe self-test is not supported on this platform yet",
    );
    false
}

/// Remediation hints for each helper-API refusal, specialised by what the
/// server-side CRL check (step 3) found.
// Only the unix `check_mint` calls this; `test` keeps it compiled for the
// platform-independent advice-text tests below.
#[cfg(any(unix, test))]
fn mint_failure_advice(code: ErrorCode, server_crl: ServerCrl) -> Vec<String> {
    match code {
        ErrorCode::CrlStale => {
            let mut lines = vec![
                "The daemon refuses to mint because its cached CRL is missing or older than 5 \
                 minutes — the fail-closed revocation gate (F11)."
                    .to_string(),
            ];
            match server_crl {
                ServerCrl::Fresh => lines.push(
                    "CMIS is publishing a fresh, valid CRL (step 3 passed), so the running \
                     daemon is not ingesting it. Daemon builds before 0.19 never start the CRL \
                     puller (`mia::helper::crl::spawn_puller` was not wired in `main.rs`) — \
                     check the daemon's version and upgrade it. On a current build, check the \
                     daemon log for 'CRL refresh failed' (the daemon's own connectivity or a \
                     verification mismatch)."
                        .to_string(),
                ),
                ServerCrl::Broken => lines.push(
                    "The server-side CRL is itself stale or unverifiable (step 3 failed) — fix \
                     CMIS first; the daemon will recover within a minute once the server \
                     publishes a fresh CRL it can verify. See \
                     docs/operations/runbooks/crl-stale.md."
                        .to_string(),
                ),
                ServerCrl::Unknown => lines.push(
                    "The server-side CRL could not be checked (steps 2/3 did not pass) — restore \
                     CMIS connectivity first, then re-run this test."
                        .to_string(),
                ),
            }
            lines
        }
        ErrorCode::PermissionDenied => vec![
            "The daemon answered but refused this caller: either caller authentication failed, \
             this binary/uid pair is not on the host's signed allowlist, or the host SVID is \
             revoked. The daemon log's LocalDenied event names the exact reason."
                .to_string(),
            "`mia`'s own binary is self-trusted by the daemon (it always mints for the daemon's \
             own executable), so a refusal of *this* self-test usually means something other \
             than allowlisting: the running daemon predates the self-trust change (version skew \
             between this binary and the daemon — align them), caller authentication failed \
             (the daemon log shows e.g. 'ima-mismatch' — the on-disk `mia` binary was modified \
             after the daemon started, so its hash no longer matches), or the host SVID was \
             revoked ('svid-revoked')."
                .to_string(),
            "If the reason is 'not-allowlisted' for some *other* caller, everything upstream \
             (socket, caller auth, host SVID, CRL gate) works — provision that caller with \
             `ferrogate allowlist set`, or enable allowlist.propose and approve the pending \
             proposal on CMIS."
                .to_string(),
            "If the daemon log shows 'allowlist verification failed' at startup, the daemon is \
             serving in deny-all mode because the locally pinned enrollment key no longer \
             verifies the allowlist (common after a CMIS redeploy changed the signing key) — \
             re-fetch the key with `mia setup` and restart the daemon."
                .to_string(),
        ],
        ErrorCode::NoHostSvid => vec![
            "The daemon holds no host SVID, so it cannot mint anything. Attestation to CMIS \
             failed or has not completed — the daemon log should show 'host SVID obtained' at \
             startup; if it does not, check the daemon's own CMIS connectivity and attestation \
             errors."
                .to_string(),
        ],
        ErrorCode::MalformedRequest => vec![
            "The daemon rejected the request as malformed — this points at a bug or a protocol \
             mismatch between this binary and the running daemon; align their versions."
                .to_string(),
        ],
        ErrorCode::RateLimited => vec![
            "The daemon is shedding load; retry shortly. Persistent rate-limiting under no real \
             load suggests a stuck client flooding the socket — check the audit log for the \
             culprit pid."
                .to_string(),
        ],
        ErrorCode::Internal => vec![
            "The daemon hit an unexpected internal error while minting — check the daemon log \
             around this timestamp ('mint-failed')."
                .to_string(),
        ],
    }
}

/// Base64url SHA-256 thumbprint stand-in for the test request's DPoP key.
#[cfg(unix)]
fn selftest_jkt() -> String {
    use base64::Engine as _;
    use sha2::Digest as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(sha2::Sha256::digest(b"ferrogate-mia-selftest-dpop-key"))
}

/// Current Unix time in seconds.
fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// Print one aligned check line.
fn report(step: &str, status: &str, detail: &str) {
    println!("{step:<28} {status:<5} {detail}");
}

/// Print indented hint lines under a failing check.
fn hints(lines: &[String]) {
    for line in lines {
        println!("        - {line}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_defaults_and_overrides() {
        let opts = Opts::parse(&[]).unwrap().unwrap();
        assert_eq!(opts.audience, DEFAULT_AUDIENCE);
        assert!(opts.config.is_none());
        assert!(opts.environment.is_none());

        let args: Vec<String> = ["--config", "/tmp/x.toml", "--audience", "https://a.example"]
            .iter()
            .map(ToString::to_string)
            .collect();
        let opts = Opts::parse(&args).unwrap().unwrap();
        assert_eq!(
            opts.config.as_deref(),
            Some(std::path::Path::new("/tmp/x.toml"))
        );
        assert_eq!(opts.audience, "https://a.example");

        // `--environment` is parsed into its own slot.
        let args: Vec<String> = ["--environment", "staging"]
            .iter()
            .map(ToString::to_string)
            .collect();
        let opts = Opts::parse(&args).unwrap().unwrap();
        assert_eq!(opts.environment.as_deref(), Some("staging"));
        assert!(opts.config.is_none());
    }

    #[test]
    fn parse_rejects_unknown_flags() {
        let args = vec!["--bogus".to_string()];
        assert!(Opts::parse(&args).is_err());
    }

    #[test]
    fn help_short_circuits() {
        let args = vec!["--help".to_string()];
        assert!(Opts::parse(&args).unwrap().is_none());
    }

    #[test]
    fn crl_stale_advice_names_the_failing_side() {
        let fresh = mint_failure_advice(ErrorCode::CrlStale, ServerCrl::Fresh).join("\n");
        assert!(fresh.contains("spawn_puller"));

        let broken = mint_failure_advice(ErrorCode::CrlStale, ServerCrl::Broken).join("\n");
        assert!(broken.contains("crl-stale.md"));

        let unknown = mint_failure_advice(ErrorCode::CrlStale, ServerCrl::Unknown).join("\n");
        assert!(unknown.contains("connectivity"));
    }

    #[test]
    fn permission_denied_advice_points_at_the_allowlist() {
        let advice = mint_failure_advice(ErrorCode::PermissionDenied, ServerCrl::Fresh).join("\n");
        assert!(advice.contains("allowlist"));
        assert!(advice.contains("LocalDenied"));
    }

    #[test]
    fn agreeing_nodes_collapse_to_one_identity() {
        let key = vec![0xAAu8; 32];
        let groups = group_by_identity(vec![
            ("https://a:8443".into(), key.clone()),
            ("https://b:8443".into(), key.clone()),
            ("https://c:8443".into(), key),
        ]);
        assert_eq!(groups.len(), 1, "all nodes share one key => one group");
        assert_eq!(groups[0].1.len(), 3);
    }

    #[test]
    fn divergent_nodes_are_detected_as_split_brain() {
        // The HML failure: two nodes signing under different seeds.
        let groups = group_by_identity(vec![
            ("https://n3:8443".into(), vec![0x08u8; 32]),
            ("https://n4:8443".into(), vec![0xa0u8; 32]),
        ]);
        assert_eq!(groups.len(), 2, "distinct keys => split brain");
        // Each distinct identity lists exactly the node(s) that served it.
        assert_eq!(groups[0].1, vec!["https://n3:8443".to_string()]);
        assert_eq!(groups[1].1, vec!["https://n4:8443".to_string()]);
    }

    #[test]
    fn key_fingerprint_is_stable_short_and_distinguishing() {
        let a = key_fp(&[0x01u8; 32]);
        let b = key_fp(&[0x02u8; 32]);
        assert_eq!(a.len(), 12);
        assert_eq!(a, key_fp(&[0x01u8; 32]), "deterministic");
        assert_ne!(a, b, "different keys => different fingerprints");
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
