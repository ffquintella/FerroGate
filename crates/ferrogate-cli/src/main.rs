//! `ferrogate` — the operator CLI.
//!
//! A thin gRPC client over the `MachineIdentity` admin surface (feature F04).
//! Every subcommand maps onto an already-existing CMIS RPC — the CLI adds no
//! server-side logic of its own, it just gives an operator an ergonomic way to
//! drive the methods CMIS already exposes:
//!
//! - `status`              → `Health`     (cluster readiness, Raft role, node id)
//! - `list-svids`          → `ListSvids`  (issued-SVID inventory)
//! - `revoke-svid <sha>`   → `RevokeSvid` (revoke one SVID by cert SHA-384)
//! - `revoke-host <id>`    → `RevokeHost` (revoke every SVID/child token for a host)
//! - `bump-epoch`          → `BumpEpoch`  (force fleet-wide re-attestation)
//!
//! It targets the local CMIS by default (`http://127.0.0.1:8443`, the plaintext
//! bring-up endpoint), overridable with `--endpoint` or `FERROGATE_CMIS_ENDPOINT`.
//!
//! When the endpoint is an `https://` URL the CLI speaks the FerroGate
//! hybrid-PQC TLS transport (feature F01) via the shared
//! [`ferro_transport::connect_pinned`] dialer: TLS 1.3 with the
//! `X25519MLKEM768`-only group, authenticating CMIS by SPKI pin (not a CA
//! chain). The pin is taken from `--spki-pin`/`FERROGATE_CMIS_SPKI_PIN`, or
//! derived from a server certificate PEM (`--tls-cert`/`FERROGATE_CMIS_TLS_CERT`,
//! defaulting to `/etc/ferrogate/tls/cmis.crt`). That default is the cert the
//! Puppet module mounts into the cmis container, so a loopback `https://`
//! invocation inside the container needs no extra flags. A plaintext `http://`
//! endpoint keeps the legacy dev/bring-up behaviour.

#![forbid(unsafe_code)]

mod allowlist;

use ferro_crypto::pin::SpkiPin;
use ferro_proto::v1::machine_identity_client::MachineIdentityClient;
use ferro_proto::v1::{
    BumpEpochRequest, HealthRequest, ListSvidsRequest, NodeRole, RevokeHostRequest,
    RevokeSvidRequest,
};
use tonic::transport::Channel;

const DEFAULT_ENDPOINT: &str = "http://127.0.0.1:8443";

/// In-container mount point of the CMIS server certificate (PEM), as placed by
/// the `puppet-ferrogate` module. Used as the default SPKI-pin source for an
/// `https://` endpoint when no explicit pin or cert path is supplied.
const DEFAULT_TLS_CERT: &str = "/etc/ferrogate/tls/cmis.crt";

fn usage() -> &'static str {
    "ferrogate — FerroGate operator CLI\n\
     \n\
     usage: ferrogate [--endpoint <url>] <command> [args]\n\
     \n\
     commands:\n\
     \x20 status                           cluster health, Raft role, node id\n\
     \x20 list-svids                       list issued SVIDs (spiffe id, cert sha, ttl)\n\
     \x20 revoke-svid <cert_sha> [reason]  revoke one SVID by lowercase-hex SHA-384\n\
     \x20 revoke-host <spiffe_id> [reason] revoke every SVID + child token for a host\n\
     \x20 bump-epoch [reason]              advance the RIM policy epoch (mass re-attest)\n\
     \x20 allowlist <subcommand> ...       manage per-host signed caller allowlists\n\
     \x20                                  (run `ferrogate allowlist help` for details)\n\
     \x20 spki-pin [--format hex|env|flag] print the CMIS SPKI pin from its cert\n\
     \x20                                  (--tls-cert / $FERROGATE_CMIS_TLS_CERT); no\n\
     \x20                                  connection is made\n\
     \n\
     options:\n\
     \x20 --endpoint <url>   CMIS gRPC endpoint (default http://127.0.0.1:8443,\n\
     \x20                    or $FERROGATE_CMIS_ENDPOINT). An https:// endpoint is\n\
     \x20                    dialed over hybrid-PQC TLS and authenticated by SPKI pin.\n\
     \x20 --spki-pin <hex>   accepted CMIS SPKI pin (lowercase-hex SHA-384); repeatable,\n\
     \x20                    or comma-separated in $FERROGATE_CMIS_SPKI_PIN. Takes\n\
     \x20                    precedence over --tls-cert.\n\
     \x20 --tls-cert <path>  PEM server certificate to derive the SPKI pin from\n\
     \x20                    (or $FERROGATE_CMIS_TLS_CERT; default\n\
     \x20                    /etc/ferrogate/tls/cmis.crt). Used only for https://\n\
     \x20                    endpoints when no --spki-pin is given.\n\
     \x20 -V, --version      print the ferrogate version and exit"
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    match run().await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            std::process::ExitCode::FAILURE
        }
    }
}

async fn run() -> anyhow::Result<()> {
    let (global, args) = parse_global_args(std::env::args().skip(1).collect());

    let Some((command, rest)) = args.split_first() else {
        println!("{}", usage());
        return Ok(());
    };

    if matches!(command.as_str(), "help" | "-h" | "--help") {
        println!("{}", usage());
        return Ok(());
    }

    if matches!(command.as_str(), "version" | "-V" | "--version") {
        println!("ferrogate {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    // `allowlist` help works without a connection, so short-circuit before the
    // dial when the operator only wants the subcommand reference.
    if command == "allowlist" && matches!(rest.first().map(String::as_str), None | Some("help" | "-h" | "--help")) {
        println!("{}", allowlist::usage());
        return Ok(());
    }

    // `spki-pin` is a purely local cert→pin computation; it never talks to
    // CMIS, so resolve it before the dial.
    if command == "spki-pin" {
        return spki_pin(&global, rest);
    }

    // Reject an unknown command before dialing CMIS, so a typo gives a usage
    // error rather than a connection failure.
    if !matches!(
        command.as_str(),
        "status" | "list-svids" | "revoke-svid" | "revoke-host" | "bump-epoch" | "allowlist"
    ) {
        anyhow::bail!("unknown command: {command}\n\n{}", usage());
    }

    let mut client = connect(&global).await?;

    match command.as_str() {
        "status" => status(&mut client).await,
        "list-svids" => list_svids(&mut client).await,
        "revoke-svid" => revoke_svid(&mut client, rest).await,
        "revoke-host" => revoke_host(&mut client, rest).await,
        "bump-epoch" => bump_epoch(&mut client, rest).await,
        "allowlist" => {
            let (sub, sub_args) = rest
                .split_first()
                .expect("allowlist with no subcommand handled above");
            allowlist::run(&mut client, sub, sub_args).await
        }
        _ => unreachable!("command validated above"),
    }
}

/// Connection-shaping options pulled out of the raw arg list, shared by every
/// subcommand.
struct GlobalArgs {
    /// CMIS gRPC endpoint. `https://` selects the pinned TLS transport.
    endpoint: String,
    /// Explicit SPKI pins (lowercase-hex SHA-384). Highest-precedence pin
    /// source; empty if none were supplied on the command line or in the env.
    spki_pins: Vec<String>,
    /// Explicit server-cert PEM path to derive the pin from when no explicit
    /// pin is given; `None` falls back to [`DEFAULT_TLS_CERT`].
    tls_cert: Option<String>,
}

/// Pull the global connection flags (anywhere in the arg list) out of the raw
/// args. Precedence for each setting: an explicit flag (last one wins for
/// `--endpoint`/`--tls-cert`; `--spki-pin` accumulates) overrides the matching
/// environment variable, which overrides the built-in default.
fn parse_global_args(raw: Vec<String>) -> (GlobalArgs, Vec<String>) {
    let mut endpoint =
        std::env::var("FERROGATE_CMIS_ENDPOINT").unwrap_or_else(|_| DEFAULT_ENDPOINT.to_string());
    // Explicit --spki-pin flags accumulate; only if none are given do we fall
    // back to the comma-separated env list.
    let mut spki_pins: Vec<String> = Vec::new();
    let mut tls_cert = std::env::var("FERROGATE_CMIS_TLS_CERT").ok();
    let mut rest = Vec::with_capacity(raw.len());
    let mut it = raw.into_iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--endpoint" | "-e" => {
                if let Some(url) = it.next() {
                    endpoint = url;
                }
            }
            "--spki-pin" => {
                if let Some(pin) = it.next() {
                    spki_pins.push(pin);
                }
            }
            "--tls-cert" => {
                if let Some(path) = it.next() {
                    tls_cert = Some(path);
                }
            }
            _ => rest.push(arg),
        }
    }
    if spki_pins.is_empty() {
        if let Ok(env_pins) = std::env::var("FERROGATE_CMIS_SPKI_PIN") {
            spki_pins.extend(
                env_pins
                    .split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string),
            );
        }
    }
    (
        GlobalArgs {
            endpoint,
            spki_pins,
            tls_cert,
        },
        rest,
    )
}

/// Render a gRPC error as a one-line operator message instead of tonic's full
/// `Status` debug (which trails the gRPC metadata map).
fn rpc_err(s: tonic::Status) -> anyhow::Error {
    anyhow::anyhow!("CMIS refused the request ({:?}): {}", s.code(), s.message())
}

async fn connect(global: &GlobalArgs) -> anyhow::Result<MachineIdentityClient<Channel>> {
    let endpoint = &global.endpoint;
    if endpoint.starts_with("https://") {
        // Hybrid-PQC TLS, SPKI-pinned. The pin is resolved up front so a
        // missing/wrong pin is reported clearly rather than surfacing as an
        // opaque handshake failure.
        let pins = resolve_pins(global)?;
        let channel = ferro_transport::connect_pinned(endpoint, pins)
            .await
            .map_err(|e| {
                anyhow::anyhow!("connect to CMIS at `{endpoint}` over TLS failed: {e:#}")
            })?;
        Ok(MachineIdentityClient::new(channel))
    } else {
        // Plaintext bring-up path: `http://` or a bare authority, unchanged.
        let channel = Channel::from_shared(endpoint.clone())
            .map_err(|e| anyhow::anyhow!("invalid endpoint `{endpoint}`: {e}"))?
            .connect()
            .await
            .map_err(|e| anyhow::anyhow!("connect to CMIS at `{endpoint}` failed: {e}"))?;
        Ok(MachineIdentityClient::new(channel))
    }
}

/// Resolve the SPKI pin set for an `https://` endpoint, in precedence order:
///
/// 1. explicit `--spki-pin` / `$FERROGATE_CMIS_SPKI_PIN` hex pins;
/// 2. else the first certificate of the server-cert PEM at `--tls-cert` /
///    `$FERROGATE_CMIS_TLS_CERT`, defaulting to [`DEFAULT_TLS_CERT`];
/// 3. else a clear error explaining how to supply a pin or cert.
fn resolve_pins(global: &GlobalArgs) -> anyhow::Result<Vec<SpkiPin>> {
    if !global.spki_pins.is_empty() {
        return global
            .spki_pins
            .iter()
            .map(|hex| {
                SpkiPin::from_hex(hex)
                    .map_err(|e| anyhow::anyhow!("invalid --spki-pin `{hex}`: {e}"))
            })
            .collect();
    }

    let explicit_cert = global.tls_cert.is_some();
    let cert_path = global.tls_cert.as_deref().unwrap_or(DEFAULT_TLS_CERT);
    let pin = pin_from_cert(cert_path).map_err(|e| {
        // The default path is the in-container mount; if it is absent the
        // caller is likely running outside the container and must supply a pin
        // or point at a cert explicitly.
        if explicit_cert {
            e
        } else {
            anyhow::anyhow!(
                "no SPKI pin available for the https:// endpoint: {e}. \
                 Supply --spki-pin <hex> (or $FERROGATE_CMIS_SPKI_PIN), or \
                 --tls-cert <path> (or $FERROGATE_CMIS_TLS_CERT) pointing at the \
                 CMIS server certificate."
            )
        }
    })?;
    Ok(vec![pin])
}

/// Read a PEM server certificate and derive its SPKI pin (SHA-384 over the
/// DER `SubjectPublicKeyInfo`). Uses the first certificate in the file, which
/// is the leaf for a CMIS server cert.
fn pin_from_cert(cert_path: &str) -> anyhow::Result<SpkiPin> {
    let cert_bytes = std::fs::read(cert_path)
        .map_err(|e| anyhow::anyhow!("reading TLS cert `{cert_path}`: {e}"))?;
    let mut reader = std::io::BufReader::new(&cert_bytes[..]);
    let cert = rustls_pemfile::certs(&mut reader)
        .next()
        .ok_or_else(|| anyhow::anyhow!("no certificate found in `{cert_path}`"))?
        .map_err(|e| anyhow::anyhow!("parsing TLS cert `{cert_path}`: {e}"))?;
    SpkiPin::from_certificate_der(cert.as_ref())
        .map_err(|e| anyhow::anyhow!("deriving SPKI pin from `{cert_path}`: {e}"))
}

async fn status(client: &mut MachineIdentityClient<Channel>) -> anyhow::Result<()> {
    let resp = client
        .health(HealthRequest {})
        .await
        .map_err(rpc_err)?
        .into_inner();
    let role = match NodeRole::try_from(resp.role).unwrap_or(NodeRole::Unknown) {
        NodeRole::Leader => "leader",
        NodeRole::Follower => "follower",
        NodeRole::Learner => "learner",
        NodeRole::Unknown => "unknown (single-replica or transitioning)",
    };
    println!("healthy: {}", resp.healthy);
    println!("role:    {role}");
    println!("node_id: {}", resp.node_id);
    Ok(())
}

async fn list_svids(client: &mut MachineIdentityClient<Channel>) -> anyhow::Result<()> {
    let resp = client
        .list_svids(ListSvidsRequest {})
        .await
        .map_err(rpc_err)?
        .into_inner();
    if resp.svids.is_empty() {
        println!("(no issued SVIDs)");
        return Ok(());
    }
    println!("{} issued SVID(s):", resp.svids.len());
    for s in &resp.svids {
        println!();
        println!("  spiffe_id:    {}", s.spiffe_id);
        println!("  cert_sha:     {}", s.cert_sha);
        println!("  issued_at:    {} (unix)", s.issued_at);
        println!("  expires_at:   {} (unix)", s.expires_at);
        println!("  policy_id:    {}", s.policy_id);
        println!("  policy_epoch: {}", s.policy_epoch);
    }
    Ok(())
}

async fn revoke_svid(
    client: &mut MachineIdentityClient<Channel>,
    args: &[String],
) -> anyhow::Result<()> {
    let Some(cert_sha) = args.first() else {
        anyhow::bail!("revoke-svid needs a cert_sha (lowercase-hex SHA-384, 96 chars)");
    };
    let reason = args.get(1).cloned().unwrap_or_default();
    let resp = client
        .revoke_svid(RevokeSvidRequest {
            cert_sha: cert_sha.clone(),
            reason,
        })
        .await
        .map_err(rpc_err)?
        .into_inner();
    println!(
        "revoked SVID {cert_sha}; published CRL #{}",
        resp.crl_number
    );
    Ok(())
}

async fn revoke_host(
    client: &mut MachineIdentityClient<Channel>,
    args: &[String],
) -> anyhow::Result<()> {
    let Some(spiffe_id) = args.first() else {
        anyhow::bail!("revoke-host needs a spiffe_id");
    };
    let reason = args.get(1).cloned().unwrap_or_default();
    let resp = client
        .revoke_host(RevokeHostRequest {
            spiffe_id: spiffe_id.clone(),
            reason,
        })
        .await
        .map_err(rpc_err)?
        .into_inner();
    println!(
        "revoked host {spiffe_id}; published CRL #{}",
        resp.crl_number
    );
    Ok(())
}

async fn bump_epoch(
    client: &mut MachineIdentityClient<Channel>,
    args: &[String],
) -> anyhow::Result<()> {
    let reason = args.first().cloned().unwrap_or_default();
    let resp = client
        .bump_epoch(BumpEpochRequest { reason })
        .await
        .map_err(rpc_err)?
        .into_inner();
    println!("RIM policy epoch bumped; now in force: {}", resp.new_epoch);
    Ok(())
}

/// Print the CMIS server's SPKI pin (lowercase-hex SHA-384), derived locally
/// from its certificate PEM — no connection to CMIS is made. This is the value
/// clients put in `--spki-pin` / `$FERROGATE_CMIS_SPKI_PIN` to authenticate the
/// server over the hybrid-PQC TLS transport, so an operator can read it off a
/// CMIS node and publish it.
///
/// The certificate is taken from `--tls-cert` / `$FERROGATE_CMIS_TLS_CERT`,
/// defaulting to [`DEFAULT_TLS_CERT`] (the in-container mount). `--format`
/// selects how the pin is rendered for easy export:
///
/// - `hex`  (default) → the bare lowercase-hex pin;
/// - `env`            → `FERROGATE_CMIS_SPKI_PIN=<hex>`;
/// - `flag`           → `--spki-pin <hex>`.
fn spki_pin(global: &GlobalArgs, args: &[String]) -> anyhow::Result<()> {
    let mut format = "hex";
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--format" | "-f" => {
                format = it
                    .next()
                    .map(String::as_str)
                    .ok_or_else(|| anyhow::anyhow!("--format needs a value (hex|env|flag)"))?;
            }
            other => anyhow::bail!("unknown spki-pin argument: {other}"),
        }
    }

    let cert_path = global.tls_cert.as_deref().unwrap_or(DEFAULT_TLS_CERT);
    let hex = pin_from_cert(cert_path)?.to_hex();
    match format {
        "hex" => println!("{hex}"),
        "env" => println!("FERROGATE_CMIS_SPKI_PIN={hex}"),
        "flag" => println!("--spki-pin {hex}"),
        other => anyhow::bail!("unknown --format `{other}` (expected hex|env|flag)"),
    }
    Ok(())
}
