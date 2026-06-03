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
//! Hybrid-PQC TLS (feature F01) is a later seam; until CMIS terminates TLS this
//! speaks the same plaintext gRPC the server listens on.

#![forbid(unsafe_code)]

use ferro_proto::v1::machine_identity_client::MachineIdentityClient;
use ferro_proto::v1::{
    BumpEpochRequest, HealthRequest, ListSvidsRequest, NodeRole, RevokeHostRequest,
    RevokeSvidRequest,
};
use tonic::transport::Channel;

const DEFAULT_ENDPOINT: &str = "http://127.0.0.1:8443";

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
     \n\
     options:\n\
     \x20 --endpoint <url>   CMIS gRPC endpoint (default http://127.0.0.1:8443,\n\
     \x20                    or $FERROGATE_CMIS_ENDPOINT)\n\
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
    let (endpoint, args) = parse_global_args(std::env::args().skip(1).collect());

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

    // Reject an unknown command before dialing CMIS, so a typo gives a usage
    // error rather than a connection failure.
    if !matches!(
        command.as_str(),
        "status" | "list-svids" | "revoke-svid" | "revoke-host" | "bump-epoch"
    ) {
        anyhow::bail!("unknown command: {command}\n\n{}", usage());
    }

    let mut client = connect(&endpoint).await?;

    match command.as_str() {
        "status" => status(&mut client).await,
        "list-svids" => list_svids(&mut client).await,
        "revoke-svid" => revoke_svid(&mut client, rest).await,
        "revoke-host" => revoke_host(&mut client, rest).await,
        "bump-epoch" => bump_epoch(&mut client, rest).await,
        _ => unreachable!("command validated above"),
    }
}

/// Pull `--endpoint <url>` (anywhere in the arg list) out of the raw args,
/// falling back to `$FERROGATE_CMIS_ENDPOINT` then the local default.
fn parse_global_args(raw: Vec<String>) -> (String, Vec<String>) {
    let mut endpoint =
        std::env::var("FERROGATE_CMIS_ENDPOINT").unwrap_or_else(|_| DEFAULT_ENDPOINT.to_string());
    let mut rest = Vec::with_capacity(raw.len());
    let mut it = raw.into_iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--endpoint" | "-e" => {
                if let Some(url) = it.next() {
                    endpoint = url;
                }
            }
            _ => rest.push(arg),
        }
    }
    (endpoint, rest)
}

/// Render a gRPC error as a one-line operator message instead of tonic's full
/// `Status` debug (which trails the gRPC metadata map).
fn rpc_err(s: tonic::Status) -> anyhow::Error {
    anyhow::anyhow!("CMIS refused the request ({:?}): {}", s.code(), s.message())
}

async fn connect(endpoint: &str) -> anyhow::Result<MachineIdentityClient<Channel>> {
    let channel = Channel::from_shared(endpoint.to_string())
        .map_err(|e| anyhow::anyhow!("invalid endpoint `{endpoint}`: {e}"))?
        .connect()
        .await
        .map_err(|e| anyhow::anyhow!("connect to CMIS at `{endpoint}` failed: {e}"))?;
    Ok(MachineIdentityClient::new(channel))
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
