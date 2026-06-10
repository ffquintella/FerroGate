//! `mia test` — operator-facing connectivity and token-issuance self-test.
//!
//! Exercises the full path a local application depends on, in order:
//!
//! 1. **configuration** — a CMIS endpoint and SPKI pin are resolved;
//! 2. **CMIS connection** — a pinned hybrid-PQC TLS connection is established
//!    (the dial is eager, so DNS, TCP, the X25519MLKEM768 handshake, and the
//!    SPKI pin are all validated here);
//! 3. **CMIS CRL publishing** — the `JWKS` RPC returns a signature-valid,
//!    fresh CRL (the helper API fail-closed gates minting on this, F11);
//! 4. **helper token mint** — a real `HelperReq` is sent over the local helper
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
use ferro_crypto::pin::SpkiPin;

use crate::config::Config;
use crate::helper::crl::{CrlIngestError, CRL_FRESHNESS_LEEWAY_SECS};
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

    let (config, source) = Config::load(opts.config.as_deref())?;
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
    /// `--audience <aud>` for the test mint.
    audience: String,
}

impl Opts {
    /// Parse `args`; `Ok(None)` means help was printed and the caller should
    /// exit successfully.
    fn parse(args: &[String]) -> anyhow::Result<Option<Self>> {
        let mut config = None;
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
                "-a" | "--audience" => {
                    let aud = it.next().context("--audience requires a value")?;
                    audience.clone_from(aud);
                }
                other => anyhow::bail!("unknown argument: {other}\n\n{USAGE}"),
            }
        }
        Ok(Some(Self { config, audience }))
    }
}

const USAGE: &str = "usage: mia test [--config <path>] [--audience <aud>]";

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
    let cmis = check_config(config);
    if cmis.is_none() {
        failures.push("configuration");
    }

    // 2. CMIS connection / 3. CRL publishing ------------------------------
    let mut server_crl = ServerCrl::Unknown;
    if let Some((endpoint, pin)) = &cmis {
        match dial_cmis(endpoint, *pin).await {
            Ok(mut client) => {
                report(
                    "[2/4] CMIS connection",
                    "ok",
                    &format!("{endpoint} — hybrid-PQC TLS established, SPKI pin verified"),
                );
                server_crl = check_server_crl(&mut client).await;
                if server_crl != ServerCrl::Fresh {
                    failures.push("CMIS CRL publishing");
                }
            }
            Err(e) => {
                failures.push("CMIS connection");
                report("[2/4] CMIS connection", "FAIL", &format!("{e:#}"));
                hints(&[
                    format!("Check basic reachability: DNS for the host and TCP to the port in {endpoint}."),
                    "A TLS handshake error usually means the SPKI pin no longer matches the served \
                     certificate (a cert rotation without a config update), or the server does not \
                     offer hybrid X25519MLKEM768 — non-hybrid servers are rejected by design."
                        .to_string(),
                    "Compare cmis.spki_pin against the pin of the live certificate, and confirm the \
                     CMIS service is up on the target host.".to_string(),
                ]);
                report(
                    "[3/4] CMIS CRL publishing",
                    "skip",
                    "no connection — fix step 2 first",
                );
            }
        }
    } else {
        report(
            "[2/4] CMIS connection",
            "skip",
            "no usable CMIS configuration",
        );
        report(
            "[3/4] CMIS CRL publishing",
            "skip",
            "no usable CMIS configuration",
        );
    }

    // 4. helper token mint -------------------------------------------------
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

/// Step 1: resolve and validate the CMIS endpoint and pin from `config`.
fn check_config(config: &Config) -> Option<(String, SpkiPin)> {
    let label = "[1/4] configuration";
    let Some(endpoint) = config.cmis.endpoint.as_deref() else {
        report(label, "FAIL", "cmis.endpoint is not set");
        hints(&[
            "Run `mia setup` (or set FERROGATE_CMIS_ENDPOINT) to point the agent at a CMIS \
                 server, e.g. https://cmis.example.com:8443."
                .to_string(),
        ]);
        return None;
    };
    let Some(pin_hex) = config.cmis.spki_pin.as_deref() else {
        report(
            label,
            "FAIL",
            "cmis.endpoint is set but cmis.spki_pin is missing",
        );
        hints(&[
            "The CMIS server is authenticated by SPKI pin, not a CA chain; without a pin the \
                 agent cannot dial it. `mia setup` can fetch and confirm the pin interactively."
                .to_string(),
        ]);
        return None;
    };
    match SpkiPin::from_hex(pin_hex.trim()) {
        Ok(pin) => {
            report(label, "ok", &format!("endpoint {endpoint}"));
            Some((endpoint.to_string(), pin))
        }
        Err(e) => {
            report(label, "FAIL", &format!("cmis.spki_pin is invalid: {e}"));
            hints(&[
                "The pin must be the lowercase-hex SHA-384 of the server certificate's SPKI \
                     (96 hex chars). Re-run `mia setup` to re-fetch it."
                    .to_string(),
            ]);
            None
        }
    }
}

/// Step 2: dial CMIS over pinned hybrid-PQC TLS (eager — validates the
/// handshake), bounded by [`STEP_TIMEOUT`].
async fn dial_cmis(
    endpoint: &str,
    pin: SpkiPin,
) -> anyhow::Result<
    ferro_proto::v1::machine_identity_client::MachineIdentityClient<tonic::transport::Channel>,
> {
    tokio::time::timeout(
        STEP_TIMEOUT,
        crate::client::connect_pinned(endpoint, vec![pin]),
    )
    .await
    .map_err(|_| anyhow::anyhow!("timed out after {}s", STEP_TIMEOUT.as_secs()))?
}

/// Step 3: fetch the JWKS and check the embedded CRL verifies and is fresh.
async fn check_server_crl(
    client: &mut ferro_proto::v1::machine_identity_client::MachineIdentityClient<
        tonic::transport::Channel,
    >,
) -> ServerCrl {
    let label = "[3/4] CMIS CRL publishing";
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

    let label = "[4/4] helper token mint";
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
        _ => vec!["Check the daemon log and the socket path/permissions.".to_string()],
    }
}

/// Named-pipe self-test is not implemented; report it honestly rather than
/// passing vacuously.
#[cfg(not(unix))]
async fn check_mint(_config: &Config, _audience: &str, _server_crl: ServerCrl) -> bool {
    report(
        "[4/4] helper token mint",
        "FAIL",
        "the named-pipe self-test is not supported on this platform yet",
    );
    false
}

/// Remediation hints for each helper-API refusal, specialised by what the
/// server-side CRL check (step 3) found.
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
            "If the reason is 'not-allowlisted', everything upstream (socket, caller auth, host \
             SVID, CRL gate) works — provision this caller with `ferrogate allowlist set`, or \
             enable allowlist.propose and approve the pending proposal on CMIS."
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
}
