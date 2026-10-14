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
//! - `enrollment-key`      → `GetEnrollmentKey` (print the fingerprint of the
//!   key that signs caller allowlists, for `mia allowlist-key fetch
//!   --expect-fingerprint`)
//!
//! It targets the local CMIS by default (`http://127.0.0.1:8443`, the plaintext
//! bring-up endpoint), overridable with `--endpoint` or `FERROGATE_CMIS_ENDPOINT`.
//!
//! **Administrator sign-in (feature F20).** The admin RPCs (`list-svids`,
//! `revoke-*`, `bump-epoch`, and every `allowlist` subcommand except `get` and
//! `show`) require an authenticated admin session and go to the CMIS admin
//! listener (`--admin-endpoint`, default `https://127.0.0.1:8444`, or
//! `$FERROGATE_ADMIN_ENDPOINT`), pinned like the main endpoint. The session
//! comes from `--session-file` (`ferrogate admin login --session-file …`) or,
//! without one, from an interactive sign-in that ends with the command. See
//! `ferrogate admin help`.
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

mod admin;
mod allowlist;

use ferro_crypto::composite::CompositePublicKey;
use ferro_crypto::pin::SpkiPin;
use ferro_proto::v1::machine_identity_client::MachineIdentityClient;
use ferro_proto::v1::{
    BumpEpochRequest, GetEnrollmentKeyRequest, HealthRequest, ListSvidsRequest, NodeRole,
    RevokeHostRequest, RevokeSvidRequest,
};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::CertificateDer;
use tonic::service::interceptor::InterceptedService;
use tonic::transport::Channel;

const DEFAULT_ENDPOINT: &str = "http://127.0.0.1:8443";

/// `MachineIdentity` client that carries the admin session (if any).
pub(crate) type CmisClient = MachineIdentityClient<InterceptedService<Channel, admin::Bearer>>;

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
     \x20 enrollment-key [--format hex|flag|public-key]\n\
     \x20                                  print the SHA-384 fingerprint of the CMIS\n\
     \x20                                  enrollment key, or its public-only base64url\n\
     \x20                                  encoding for the MIA setup GUI\n\
     \x20 spki-pin [--format hex|env|flag] print the CMIS SPKI pin from its cert\n\
     \x20                                  (--tls-cert / $FERROGATE_CMIS_TLS_CERT); no\n\
     \x20                                  connection is made\n\
     \x20 admin <subcommand> ...           administrator sign-in and accounts (F20)\n\
     \x20                                  (run `ferrogate admin help` for details)\n\
     \n\
     Admin commands (list-svids, revoke-*, bump-epoch, allowlist other than\n\
     get/show, admin ...) need a signed-in administrator and use the admin\n\
     listener; the others use --endpoint.\n\
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
     \x20 --admin-endpoint <url>  CMIS admin listener (default https://127.0.0.1:8444,\n\
     \x20                    or $FERROGATE_ADMIN_ENDPOINT); pinned like --endpoint.\n\
     \x20 --session-file <path>  keep the admin session in this 0600 file (or\n\
     \x20                    $FERROGATE_SESSION_FILE); prefer a tmpfs such as\n\
     \x20                    $XDG_RUNTIME_DIR. Without it each admin command signs in.\n\
     \x20 --device-file <path>  where the server-issued device token is kept (0600;\n\
     \x20                    default ~/.config/ferrogate/admin-device.token, or\n\
     \x20                    $FERROGATE_DEVICE_FILE; empty disables)\n\
     \x20 --client-cert <pem> --client-key <pem>  client certificate for an admin\n\
     \x20                    listener that requires mTLS ($FERROGATE_ADMIN_CLIENT_CERT/_KEY)\n\
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

    // `allowlist` / `admin` help works without a connection, so short-circuit
    // before the dial when the operator only wants the subcommand reference.
    let wants_help = matches!(
        rest.first().map(String::as_str),
        None | Some("help" | "-h" | "--help")
    );
    if command == "allowlist" && wants_help {
        println!("{}", allowlist::usage());
        return Ok(());
    }
    if command == "admin" && wants_help {
        println!("{}", admin::usage());
        return Ok(());
    }

    // `spki-pin` is a purely local cert→pin computation; it never talks to
    // CMIS, so resolve it before the dial.
    if command == "spki-pin" {
        return spki_pin(&global, rest);
    }

    // `enrollment-key` validates its own arguments before the dial, so a typo
    // gives a usage error rather than a connection attempt.
    if command == "enrollment-key" {
        let format = enrollment_key_format(rest)?;
        let mut client = connect(&global).await?;
        return enrollment_key(&mut client, format).await;
    }

    // Reject an unknown command before dialing CMIS, so a typo gives a usage
    // error rather than a connection failure.
    if !matches!(
        command.as_str(),
        "status"
            | "list-svids"
            | "revoke-svid"
            | "revoke-host"
            | "bump-epoch"
            | "allowlist"
            | "admin"
    ) {
        anyhow::bail!("unknown command: {command}\n\n{}", usage());
    }

    let prompter = admin::Prompter::new();
    if command == "admin" {
        let (sub, sub_args) = rest
            .split_first()
            .expect("admin with no subcommand handled above");
        let channel = connect_admin_channel(&global).await?;
        return admin::run(
            admin::AdminArgs {
                channel,
                session_file: global.session_file.as_deref(),
                device_file: global.device_file.as_deref(),
                prompter: &prompter,
            },
            sub,
            sub_args,
        )
        .await;
    }

    // Public reads keep using the main endpoint and need no session.
    let public = command == "status"
        || (command == "allowlist"
            && matches!(rest.first().map(String::as_str), Some("get" | "show")));
    if public {
        let mut client = connect(&global).await?;
        return dispatch(&mut client, command, rest).await;
    }

    // Admin RPCs: a signed-in session on the admin listener (F20 Phase 0).
    let channel = connect_admin_channel(&global).await?;
    let session = admin::session_for_command(
        channel.clone(),
        global.session_file.as_deref(),
        global.device_file.as_deref(),
        &prompter,
    )
    .await?;
    let mut client: CmisClient =
        MachineIdentityClient::with_interceptor(channel.clone(), session.bearer());
    let mut result = dispatch(&mut client, command, rest).await;
    if result.as_ref().is_err_and(admin::needs_step_up) {
        // Nothing was changed: the first write of the command was refused.
        admin::step_up(channel.clone(), &session, &prompter).await?;
        result = dispatch(&mut client, command, rest).await;
    }
    admin::finish(channel, &session).await;
    result
}

async fn dispatch(client: &mut CmisClient, command: &str, rest: &[String]) -> anyhow::Result<()> {
    match command {
        "status" => status(client).await,
        "list-svids" => list_svids(client).await,
        "revoke-svid" => revoke_svid(client, rest).await,
        "revoke-host" => revoke_host(client, rest).await,
        "bump-epoch" => bump_epoch(client, rest).await,
        "allowlist" => {
            let (sub, sub_args) = rest
                .split_first()
                .expect("allowlist with no subcommand handled above");
            allowlist::run(client, sub, sub_args).await
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
    /// CMIS admin listener (F20).
    admin_endpoint: String,
    /// Opt-in file holding the admin session token.
    session_file: Option<std::path::PathBuf>,
    /// Client certificate and key (PEM) for an mTLS admin listener.
    client_cert: Option<String>,
    /// Private key for `client_cert`.
    client_key: Option<String>,
    /// Where the server-issued device token is kept (`None`: not kept).
    device_file: Option<std::path::PathBuf>,
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
    let mut admin_endpoint = std::env::var("FERROGATE_ADMIN_ENDPOINT")
        .unwrap_or_else(|_| admin::DEFAULT_ADMIN_ENDPOINT.to_string());
    let mut session_file = std::env::var_os("FERROGATE_SESSION_FILE").map(std::path::PathBuf::from);
    let mut client_cert = std::env::var("FERROGATE_ADMIN_CLIENT_CERT").ok();
    let mut client_key = std::env::var("FERROGATE_ADMIN_CLIENT_KEY").ok();
    let mut device_file = match std::env::var_os("FERROGATE_DEVICE_FILE") {
        Some(v) if v.is_empty() => None,
        Some(v) => Some(std::path::PathBuf::from(v)),
        None => admin::default_device_file(),
    };
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
            "--admin-endpoint" => {
                if let Some(url) = it.next() {
                    admin_endpoint = url;
                }
            }
            "--session-file" => {
                if let Some(path) = it.next() {
                    session_file = Some(std::path::PathBuf::from(path));
                }
            }
            "--client-cert" => {
                if let Some(path) = it.next() {
                    client_cert = Some(path);
                }
            }
            "--client-key" => {
                if let Some(path) = it.next() {
                    client_key = Some(path);
                }
            }
            "--device-file" => {
                if let Some(path) = it.next() {
                    device_file = (!path.is_empty()).then(|| std::path::PathBuf::from(path));
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
            admin_endpoint,
            session_file,
            client_cert,
            client_key,
            device_file,
        },
        rest,
    )
}

/// A CMIS refusal, kept typed so callers can react to specific reasons (for
/// example `step_up_required`). Renders as a one-line operator message instead
/// of tonic's full `Status` debug (which trails the gRPC metadata map).
#[derive(Debug)]
pub(crate) struct CmisError(pub(crate) tonic::Status);

impl std::fmt::Display for CmisError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "CMIS refused the request ({:?}): {}",
            self.0.code(),
            self.0.message()
        )?;
        if let Some(rules) = self
            .0
            .metadata()
            .get("x-ferrogate-policy-failures")
            .and_then(|v| v.to_str().ok())
        {
            write!(f, " [{rules}]")?;
        }
        if let Some(wait) = self
            .0
            .metadata()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
        {
            write!(f, " (retry after {wait} s)")?;
        }
        Ok(())
    }
}

impl std::error::Error for CmisError {}

/// Wrap a gRPC error for the operator (see [`CmisError`]).
pub(crate) fn rpc_err(s: tonic::Status) -> anyhow::Error {
    anyhow::Error::new(CmisError(s))
}

/// Dial the CMIS admin listener (always pinned hybrid-PQC TLS; with a client
/// certificate when one is configured).
async fn connect_admin_channel(global: &GlobalArgs) -> anyhow::Result<Channel> {
    let endpoint = &global.admin_endpoint;
    if !endpoint.starts_with("https://") {
        anyhow::bail!("the admin endpoint must be https:// (got `{endpoint}`): admin traffic is never plaintext");
    }
    let pins = resolve_pins(global)?;
    let channel = match (&global.client_cert, &global.client_key) {
        (Some(cert), Some(key)) => {
            let chain = CertificateDer::pem_file_iter(cert)
                .map_err(|e| anyhow::anyhow!("reading client certificate {cert}: {e}"))?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| anyhow::anyhow!("parsing client certificate {cert}: {e}"))?;
            let key = rustls_pki_types::PrivateKeyDer::from_pem_file(key)
                .map_err(|e| anyhow::anyhow!("reading client key {key}: {e}"))?;
            ferro_transport::connect_pinned_with_client_auth(endpoint, pins, chain, key).await
        }
        (None, None) => ferro_transport::connect_pinned(endpoint, pins).await,
        _ => anyhow::bail!("--client-cert and --client-key must be given together"),
    };
    channel.map_err(|e| {
        anyhow::anyhow!("connect to the CMIS admin listener at `{endpoint}` failed: {e:#}")
    })
}

async fn connect(global: &GlobalArgs) -> anyhow::Result<CmisClient> {
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
        Ok(MachineIdentityClient::with_interceptor(
            channel,
            admin::Bearer::none(),
        ))
    } else {
        // Plaintext bring-up path: `http://` or a bare authority, unchanged.
        let channel = Channel::from_shared(endpoint.clone())
            .map_err(|e| anyhow::anyhow!("invalid endpoint `{endpoint}`: {e}"))?
            .connect()
            .await
            .map_err(|e| anyhow::anyhow!("connect to CMIS at `{endpoint}` failed: {e}"))?;
        Ok(MachineIdentityClient::with_interceptor(
            channel,
            admin::Bearer::none(),
        ))
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
    let cert = CertificateDer::pem_slice_iter(&cert_bytes)
        .next()
        .ok_or_else(|| anyhow::anyhow!("no certificate found in `{cert_path}`"))?
        .map_err(|e| anyhow::anyhow!("parsing TLS cert `{cert_path}`: {e}"))?;
    SpkiPin::from_certificate_der(cert.as_ref())
        .map_err(|e| anyhow::anyhow!("deriving SPKI pin from `{cert_path}`: {e}"))
}

/// Output form of `enrollment-key`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EnrollmentKeyFormat {
    /// The bare 96-hex-digit fingerprint.
    Hex,
    /// `--expect-fingerprint <hex>`, ready to paste after `mia allowlist-key fetch`.
    Flag,
    /// Base64url-without-padding of the composite public key's concat encoding.
    PublicKey,
}

/// Parse `enrollment-key [--format hex|flag|public-key]`.
fn enrollment_key_format(args: &[String]) -> anyhow::Result<EnrollmentKeyFormat> {
    let mut format = EnrollmentKeyFormat::Hex;
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--format" | "-f" => {
                format = match it.next().map(String::as_str) {
                    Some("hex") => EnrollmentKeyFormat::Hex,
                    Some("flag") => EnrollmentKeyFormat::Flag,
                    Some("public-key") => EnrollmentKeyFormat::PublicKey,
                    _ => anyhow::bail!("--format needs a value: hex, flag or public-key"),
                };
            }
            other => anyhow::bail!("unknown enrollment-key argument: {other}"),
        }
    }
    Ok(format)
}

/// Render the requested public enrollment-key representation.
fn render_enrollment_key(key: &CompositePublicKey, format: EnrollmentKeyFormat) -> String {
    use base64::Engine as _;

    match format {
        EnrollmentKeyFormat::Hex => key.fingerprint_hex(),
        EnrollmentKeyFormat::Flag => {
            format!("--expect-fingerprint {}", key.fingerprint_hex())
        }
        EnrollmentKeyFormat::PublicKey => {
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key.to_concat_bytes())
        }
    }
}

/// `enrollment-key` → `GetEnrollmentKey`: print the fingerprint
/// ([`CompositePublicKey::fingerprint_hex`]) of the key CMIS signs caller
/// allowlists with — the CMIS-side value an operator compares with what
/// `mia allowlist-key fetch` prints on a host, or passes to it as
/// `--expect-fingerprint`. `--format public-key` prints only the public concat
/// encoding for pasting into MIA setup; private key material is never returned
/// by this RPC or handled here.
async fn enrollment_key(
    client: &mut CmisClient,
    format: EnrollmentKeyFormat,
) -> anyhow::Result<()> {
    let resp = client
        .get_enrollment_key(GetEnrollmentKeyRequest {})
        .await
        .map_err(rpc_err)?
        .into_inner();
    let key = CompositePublicKey::from_concat_bytes(&resp.public_key).map_err(|e| {
        anyhow::anyhow!("CMIS returned something that is not a composite public key: {e}")
    })?;
    println!("{}", render_enrollment_key(&key, format));
    Ok(())
}

async fn status(client: &mut CmisClient) -> anyhow::Result<()> {
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

async fn list_svids(client: &mut CmisClient) -> anyhow::Result<()> {
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
        if !s.hostname.is_empty() {
            println!(
                "  hostname:     {} (self-reported, display only)",
                s.hostname
            );
        }
        println!("  cert_sha:     {}", s.cert_sha);
        println!("  issued_at:    {} (unix)", s.issued_at);
        println!("  expires_at:   {} (unix)", s.expires_at);
        println!("  policy_id:    {}", s.policy_id);
        println!("  policy_epoch: {}", s.policy_epoch);
    }
    Ok(())
}

async fn revoke_svid(client: &mut CmisClient, args: &[String]) -> anyhow::Result<()> {
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

async fn revoke_host(client: &mut CmisClient, args: &[String]) -> anyhow::Result<()> {
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

async fn bump_epoch(client: &mut CmisClient, args: &[String]) -> anyhow::Result<()> {
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
