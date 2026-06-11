//! `ferrogate allowlist …` — manage the per-host signed caller allowlists CMIS
//! stores and serves.
//!
//! Every subcommand maps onto a CMIS allowlist RPC; CMIS does the signing (the
//! issuer secret never leaves the server), so the CLI only assembles entries,
//! resolves the host UUID, and renders results.
//!
//! - `set`    → `SetAllowlist`    (replace a host's allowlist wholesale)
//! - `add`    → `GetAllowlist`+`SetAllowlist` (read-modify-write: add entries)
//! - `remove` → `GetAllowlist`+`SetAllowlist` (read-modify-write: drop entries)
//! - `get`    → `GetAllowlist`    (write the raw signed CBOR to a file/stdout)
//! - `show`   → `GetAllowlist`    (decode and print entries + validity)
//! - `list`   → `ListAllowlists`  (every provisioned host)
//! - `delete` → `DeleteAllowlist`
//!
//! Host-driven proposals (mia sends the callers it observes; CMIS auto-adopts
//! the first one on a host with no allowlist, else queues it):
//!
//! - `proposals` → `ListProposals`  (every pending proposal)
//! - `review`    → `ListProposals`+`GetAllowlist` (diff a host's proposal vs live)
//! - `approve`   → `SetAllowlist`+`DeleteProposal` (sign the proposed entries)
//! - `reject`    → `DeleteProposal`
//!
//! A host is named by its EK-derived UUID. Supply it directly with `--host`, or
//! let the CLI derive it from the EK certificate (`--ek-cert <pem>`) or the EK
//! certificate's SHA-384 (`--ek-sha384 <hex>`).

use std::collections::HashMap;

use ferro_proto::v1::machine_identity_client::MachineIdentityClient;
use ferro_proto::v1::{
    AllowEntryMsg, DeleteAllowlistRequest, DeleteProposalRequest, GetAllowlistRequest,
    ListAllowlistsRequest, ListProposalsRequest, PendingProposal, SetAllowlistRequest,
};
use ferro_svid::allowlist::{self, AllowEntry, AllowlistDoc};
use ferro_svid::host_uuid_from_ek_digest;
use sha2::{Digest, Sha384};
use tonic::transport::Channel;

use crate::rpc_err;

/// Default validity window applied on `add`/`remove` when neither `--ttl` nor an
/// existing allowlist's remaining window is available (one day).
const DEFAULT_TTL_SECS: i64 = 86_400;

pub(crate) fn usage() -> &'static str {
    "ferrogate allowlist — manage per-host signed caller allowlists\n\
     \n\
     usage: ferrogate allowlist <subcommand> [args]\n\
     \n\
     subcommands (<selector> is one of the host-selector flags listed below):\n\
     \x20 set     <selector> (--entry [uid:]sha | --bin [uid:]path)... [--ttl secs]\n\
     \x20                  replace the host's allowlist with exactly these callers\n\
     \x20 add     <selector> (--entry [uid:]sha | --bin [uid:]path)... [--ttl secs]\n\
     \x20                  add callers to the host's existing allowlist\n\
     \x20 remove  <selector> (--uid N | --bin-sha hex|* | --uid N --bin-sha hex|*) [--ttl secs]\n\
     \x20                  drop matching callers (a uid, a binary, or one pinned pair) and re-sign\n\
     \x20 get     <selector> [--out path]   fetch the raw signed CBOR (stdout if no --out)\n\
     \x20 show    <selector>                fetch and print the entries + validity\n\
     \x20 list                              every host that has a stored allowlist\n\
     \x20 delete  <selector>                remove the host's stored allowlist\n\
     \x20 proposals                         every pending host-driven proposal\n\
     \x20 review  <selector>                diff a host's pending proposal vs its live allowlist\n\
     \x20 approve <selector> [--ttl secs]   sign+store the proposed entries, then clear the proposal\n\
     \x20 reject  <selector>                drop the host's pending proposal\n\
     \n\
     host selector <selector> (exactly one of):\n\
     \x20 --host <uuid>       the EK-derived host UUID directly\n\
     \x20 --ek-cert <pem>     derive the UUID from an EK certificate PEM\n\
     \x20 --ek-sha384 <hex>   derive the UUID from the EK certificate's SHA-384\n\
     \n\
     entries (omit the `uid:` prefix to permit the binary run by ANY user; use\n\
     a `<sha>` of `*` to permit ANY binary):\n\
     \x20 --entry <uid>:<sha>   pin to uid; lowercase-hex SHA-384 of the permitted binary\n\
     \x20 --entry <sha>         wildcard uid: any user running this binary\n\
     \x20 --entry <uid>:*       wildcard binary: this uid running any binary\n\
     \x20 --entry *             wildcard both: any user running any binary\n\
     \x20 --bin   <uid>:<path>  pin to uid; a binary whose SHA-384 the CLI computes\n\
     \x20 --bin   <path>        wildcard uid: any user running this binary"
}

/// Dispatch an `allowlist` subcommand.
pub(crate) async fn run(
    client: &mut MachineIdentityClient<Channel>,
    sub: &str,
    args: &[String],
) -> anyhow::Result<()> {
    let flags = Flags::parse(args);
    match sub {
        "set" => set(client, &flags).await,
        "add" => add(client, &flags).await,
        "remove" => remove(client, &flags).await,
        "get" => get(client, &flags).await,
        "show" => show(client, &flags).await,
        "list" => list(client).await,
        "delete" => delete(client, &flags).await,
        "proposals" => proposals(client).await,
        "review" => review(client, &flags).await,
        "approve" => approve(client, &flags).await,
        "reject" => reject(client, &flags).await,
        "help" | "-h" | "--help" => {
            println!("{}", usage());
            Ok(())
        }
        other => anyhow::bail!("unknown allowlist subcommand: {other}\n\n{}", usage()),
    }
}

// ---- subcommands -----------------------------------------------------------

async fn set(client: &mut MachineIdentityClient<Channel>, flags: &Flags) -> anyhow::Result<()> {
    let host_uuid = flags.host_uuid()?;
    let entries = flags.entries()?;
    if entries.is_empty() {
        anyhow::bail!("set needs at least one --entry or --bin (use `delete` to clear a host)");
    }
    let ttl = flags.ttl()?.unwrap_or(DEFAULT_TTL_SECS);
    let resp = put(client, &host_uuid, entries, ttl).await?;
    println!(
        "set allowlist for {host_uuid}: issued_at={}, not_after={}",
        resp.0, resp.1
    );
    Ok(())
}

async fn add(client: &mut MachineIdentityClient<Channel>, flags: &Flags) -> anyhow::Result<()> {
    let host_uuid = flags.host_uuid()?;
    let new_entries = flags.entries()?;
    if new_entries.is_empty() {
        anyhow::bail!("add needs at least one --entry or --bin");
    }
    let existing = fetch_doc(client, &host_uuid).await?;
    let mut entries = existing.as_ref().map(|d| d.entries.clone()).unwrap_or_default();
    for e in new_entries {
        if !entries.iter().any(|x| x.uid == e.uid && x.bin_sha == e.bin_sha) {
            entries.push(e);
        }
    }
    let ttl = flags.ttl()?.unwrap_or_else(|| remaining_ttl(existing.as_ref()));
    let resp = put(client, &host_uuid, entries, ttl).await?;
    println!(
        "updated allowlist for {host_uuid}: issued_at={}, not_after={}",
        resp.0, resp.1
    );
    Ok(())
}

async fn remove(client: &mut MachineIdentityClient<Channel>, flags: &Flags) -> anyhow::Result<()> {
    let host_uuid = flags.host_uuid()?;
    // Either filter may be given. `--uid N` drops entries pinned to N; `--bin-sha
    // X` drops every entry for that binary (any scope, including a wildcard);
    // together they drop the N-pinned entry for X. At least one is required.
    let uid: Option<u32> = flags
        .one("--uid")
        .map(|u| {
            u.parse::<u32>()
                .map_err(|_| anyhow::anyhow!("--uid must be a u32, got `{u}`"))
        })
        .transpose()?;
    let bin_sha = flags.one("--bin-sha").map(normalize_sha).transpose()?;
    if uid.is_none() && bin_sha.is_none() {
        anyhow::bail!("remove needs --uid <N> and/or --bin-sha <hex>");
    }

    let Some(doc) = fetch_doc(client, &host_uuid).await? else {
        anyhow::bail!("no allowlist stored for {host_uuid}");
    };
    let before = doc.entries.len();
    let entries: Vec<AllowEntry> = doc
        .entries
        .into_iter()
        .filter(|e| {
            // An entry is dropped only if it matches every filter given. `--uid N`
            // matches the pinned entry for N (never a wildcard); omitting --uid
            // matches any scope.
            let uid_match = uid.is_none_or(|u| e.uid == Some(u));
            let sha_match = bin_sha.as_ref().is_none_or(|b| *b == e.bin_sha);
            !(uid_match && sha_match)
        })
        .collect();
    if entries.len() == before {
        anyhow::bail!("no matching entry to remove for {host_uuid}");
    }
    let ttl = flags.ttl()?.unwrap_or(DEFAULT_TTL_SECS);
    let resp = put(client, &host_uuid, entries, ttl).await?;
    println!(
        "removed {} entr(y/ies) for {host_uuid}; not_after={}",
        before - resp.2,
        resp.1
    );
    Ok(())
}

async fn get(client: &mut MachineIdentityClient<Channel>, flags: &Flags) -> anyhow::Result<()> {
    let host_uuid = flags.host_uuid()?;
    let bytes = fetch_bytes(client, &host_uuid).await?;
    let Some(bytes) = bytes else {
        anyhow::bail!("no allowlist stored for {host_uuid}");
    };
    if let Some(out) = flags.one("--out") {
        std::fs::write(out, &bytes)
            .map_err(|e| anyhow::anyhow!("writing `{out}`: {e}"))?;
        println!("wrote {} bytes to {out}", bytes.len());
    } else {
        use std::io::Write as _;
        std::io::stdout()
            .write_all(&bytes)
            .map_err(|e| anyhow::anyhow!("writing stdout: {e}"))?;
    }
    Ok(())
}

async fn show(client: &mut MachineIdentityClient<Channel>, flags: &Flags) -> anyhow::Result<()> {
    let host_uuid = flags.host_uuid()?;
    let Some(doc) = fetch_doc(client, &host_uuid).await? else {
        anyhow::bail!("no allowlist stored for {host_uuid}");
    };
    println!("host_uuid:    {host_uuid}");
    println!("trust_domain: {}", doc.trust_domain);
    println!("issued_at:    {} (unix)", doc.issued_at);
    println!("not_after:    {} (unix)", doc.not_after);
    println!("entries:      {}", doc.entries.len());
    for e in &doc.entries {
        println!("  uid={:<7} bin_sha={}", fmt_uid(e.uid), e.bin_sha);
    }
    Ok(())
}

async fn list(client: &mut MachineIdentityClient<Channel>) -> anyhow::Result<()> {
    let resp = client
        .list_allowlists(ListAllowlistsRequest {})
        .await
        .map_err(rpc_err)?
        .into_inner();
    if resp.items.is_empty() {
        println!("(no stored allowlists)");
        return Ok(());
    }
    println!("{} stored allowlist(s):", resp.items.len());
    for it in &resp.items {
        println!();
        println!("  host_uuid:   {}", it.host_uuid);
        println!("  issued_at:   {} (unix)", it.issued_at);
        println!("  not_after:   {} (unix)", it.not_after);
        println!("  entry_count: {}", it.entry_count);
    }
    Ok(())
}

async fn delete(client: &mut MachineIdentityClient<Channel>, flags: &Flags) -> anyhow::Result<()> {
    let host_uuid = flags.host_uuid()?;
    let resp = client
        .delete_allowlist(DeleteAllowlistRequest {
            host_uuid: host_uuid.clone(),
        })
        .await
        .map_err(rpc_err)?
        .into_inner();
    if resp.existed {
        println!("deleted allowlist for {host_uuid}");
    } else {
        println!("no allowlist stored for {host_uuid} (nothing to delete)");
    }
    Ok(())
}

async fn proposals(client: &mut MachineIdentityClient<Channel>) -> anyhow::Result<()> {
    let items = fetch_proposals(client).await?;
    if items.is_empty() {
        println!("(no pending proposals)");
        return Ok(());
    }
    println!("{} pending proposal(s):", items.len());
    for p in &items {
        println!();
        println!("  host_uuid:   {}", p.host_uuid);
        println!("  proposer:    {}", p.proposer_spiffe_id);
        println!("  proposed_at: {} (unix)", p.proposed_at);
        println!("  entries:     {}", p.entries.len());
    }
    println!("\nReview one with `ferrogate allowlist review <host>`.");
    Ok(())
}

async fn review(client: &mut MachineIdentityClient<Channel>, flags: &Flags) -> anyhow::Result<()> {
    let host_uuid = flags.host_uuid()?;
    let Some(proposal) = fetch_proposal(client, &host_uuid).await? else {
        anyhow::bail!("no pending proposal for {host_uuid}");
    };
    // Compare proposed entries against whatever is live today, so the operator
    // sees exactly what approving would change.
    let live: Vec<AllowEntry> = fetch_doc(client, &host_uuid)
        .await?
        .map(|d| d.entries)
        .unwrap_or_default();
    let live_set: std::collections::HashSet<(Option<u32>, &str)> =
        live.iter().map(|e| (e.uid, e.bin_sha.as_str())).collect();
    let proposed: Vec<(Option<u32>, String)> = proposal
        .entries
        .iter()
        .map(|e| (e.uid, e.bin_sha.clone()))
        .collect();
    let proposed_set: std::collections::HashSet<(Option<u32>, &str)> =
        proposed.iter().map(|(u, s)| (*u, s.as_str())).collect();

    println!("host_uuid:   {host_uuid}");
    println!("proposer:    {}", proposal.proposer_spiffe_id);
    println!("proposed_at: {} (unix)", proposal.proposed_at);
    println!(
        "live allowlist: {}",
        if live.is_empty() {
            "(none — approving bootstraps this host)".to_string()
        } else {
            format!("{} entr(y/ies)", live.len())
        }
    );
    println!("\nproposed entries ({}):", proposed.len());
    for (uid, sha) in &proposed {
        let mark = if live_set.contains(&(*uid, sha.as_str())) {
            "    " // unchanged
        } else {
            "  + " // new vs live
        };
        println!("{mark}uid={:<7} bin_sha={sha}", fmt_uid(*uid));
    }
    // Entries live today but absent from the proposal — approving would drop them.
    let dropped: Vec<_> = live
        .iter()
        .filter(|e| !proposed_set.contains(&(e.uid, e.bin_sha.as_str())))
        .collect();
    if !dropped.is_empty() {
        println!("\nwould be removed ({}):", dropped.len());
        for e in dropped {
            println!("  - uid={:<7} bin_sha={}", fmt_uid(e.uid), e.bin_sha);
        }
    }
    println!("\nApprove with `ferrogate allowlist approve {host_uuid}` or reject with `… reject {host_uuid}`.");
    Ok(())
}

async fn approve(client: &mut MachineIdentityClient<Channel>, flags: &Flags) -> anyhow::Result<()> {
    let host_uuid = flags.host_uuid()?;
    let Some(proposal) = fetch_proposal(client, &host_uuid).await? else {
        anyhow::bail!("no pending proposal for {host_uuid}");
    };
    let entries: Vec<AllowEntry> = proposal
        .entries
        .into_iter()
        .map(|e| AllowEntry {
            uid: e.uid,
            bin_sha: e.bin_sha,
        })
        .collect();
    if entries.is_empty() {
        anyhow::bail!("proposal for {host_uuid} has no entries; reject it instead");
    }
    let ttl = flags.ttl()?.unwrap_or(DEFAULT_TTL_SECS);
    let resp = put(client, &host_uuid, entries, ttl).await?;
    // Clear the now-applied proposal so it does not linger in the review queue.
    client
        .delete_proposal(DeleteProposalRequest {
            host_uuid: host_uuid.clone(),
        })
        .await
        .map_err(rpc_err)?;
    println!(
        "approved proposal for {host_uuid}: {} entr(y/ies) signed; not_after={}",
        resp.2, resp.1
    );
    Ok(())
}

async fn reject(client: &mut MachineIdentityClient<Channel>, flags: &Flags) -> anyhow::Result<()> {
    let host_uuid = flags.host_uuid()?;
    let resp = client
        .delete_proposal(DeleteProposalRequest {
            host_uuid: host_uuid.clone(),
        })
        .await
        .map_err(rpc_err)?
        .into_inner();
    if resp.existed {
        println!("rejected pending proposal for {host_uuid}");
    } else {
        println!("no pending proposal for {host_uuid} (nothing to reject)");
    }
    Ok(())
}

// ---- RPC helpers -----------------------------------------------------------

/// Fetch every pending proposal.
async fn fetch_proposals(
    client: &mut MachineIdentityClient<Channel>,
) -> anyhow::Result<Vec<PendingProposal>> {
    let resp = client
        .list_proposals(ListProposalsRequest {})
        .await
        .map_err(rpc_err)?
        .into_inner();
    Ok(resp.items)
}

/// Fetch the pending proposal for one host (`None` when none pending).
async fn fetch_proposal(
    client: &mut MachineIdentityClient<Channel>,
    host_uuid: &str,
) -> anyhow::Result<Option<PendingProposal>> {
    Ok(fetch_proposals(client)
        .await?
        .into_iter()
        .find(|p| p.host_uuid == host_uuid))
}

/// Push entries to CMIS and return `(issued_at, not_after, new_entry_count)`.
async fn put(
    client: &mut MachineIdentityClient<Channel>,
    host_uuid: &str,
    entries: Vec<AllowEntry>,
    ttl_secs: i64,
) -> anyhow::Result<(i64, i64, usize)> {
    let count = entries.len();
    let proto_entries = entries
        .into_iter()
        .map(|e| AllowEntryMsg {
            uid: e.uid,
            bin_sha: e.bin_sha,
        })
        .collect();
    let resp = client
        .set_allowlist(SetAllowlistRequest {
            host_uuid: host_uuid.to_string(),
            entries: proto_entries,
            ttl_secs,
        })
        .await
        .map_err(rpc_err)?
        .into_inner();
    Ok((resp.issued_at, resp.not_after, count))
}

/// Fetch the raw signed-allowlist bytes for a host (`None` when none stored).
async fn fetch_bytes(
    client: &mut MachineIdentityClient<Channel>,
    host_uuid: &str,
) -> anyhow::Result<Option<Vec<u8>>> {
    let resp = client
        .get_allowlist(GetAllowlistRequest {
            host_uuid: host_uuid.to_string(),
        })
        .await
        .map_err(rpc_err)?
        .into_inner();
    Ok((!resp.signed_allowlist.is_empty()).then_some(resp.signed_allowlist))
}

/// Fetch and decode the allowlist body for a host (`None` when none stored).
async fn fetch_doc(
    client: &mut MachineIdentityClient<Channel>,
    host_uuid: &str,
) -> anyhow::Result<Option<AllowlistDoc>> {
    let Some(bytes) = fetch_bytes(client, host_uuid).await? else {
        return Ok(None);
    };
    let signed = allowlist::decode(&bytes)
        .map_err(|e| anyhow::anyhow!("decoding stored allowlist for {host_uuid}: {e}"))?;
    let doc = allowlist::decode_body(&signed.body)
        .map_err(|e| anyhow::anyhow!("decoding allowlist body for {host_uuid}: {e}"))?;
    Ok(Some(doc))
}

/// Seconds left on an existing allowlist, falling back to the default window.
/// Negative/expired windows collapse to the default so a re-sign is meaningful.
fn remaining_ttl(existing: Option<&AllowlistDoc>) -> i64 {
    match existing {
        Some(doc) => {
            let left = doc.not_after - doc.issued_at;
            if left > 0 {
                left
            } else {
                DEFAULT_TTL_SECS
            }
        }
        None => DEFAULT_TTL_SECS,
    }
}

// ---- flag parsing ----------------------------------------------------------

/// Repeated-friendly view of `--key value` flags within a subcommand's args.
struct Flags {
    values: HashMap<String, Vec<String>>,
}

impl Flags {
    fn parse(args: &[String]) -> Self {
        let mut values: HashMap<String, Vec<String>> = HashMap::new();
        let mut it = args.iter();
        while let Some(arg) = it.next() {
            if let Some(key) = arg.strip_prefix("--") {
                if let Some(val) = it.next() {
                    values
                        .entry(format!("--{key}"))
                        .or_default()
                        .push(val.clone());
                }
            }
        }
        Self { values }
    }

    /// The last value given for `key`, if any (last-wins for single-valued flags).
    fn one(&self, key: &str) -> Option<&str> {
        self.values.get(key).and_then(|v| v.last()).map(String::as_str)
    }

    fn many(&self, key: &str) -> &[String] {
        self.values.get(key).map_or(&[], Vec::as_slice)
    }

    /// Resolve the target host UUID from exactly one of `--host`/`--ek-cert`/
    /// `--ek-sha384`.
    fn host_uuid(&self) -> anyhow::Result<String> {
        let host = self.one("--host");
        let ek_cert = self.one("--ek-cert");
        let ek_sha = self.one("--ek-sha384");
        match (host, ek_cert, ek_sha) {
            (Some(h), None, None) => {
                if h.trim().is_empty() {
                    anyhow::bail!("--host must be non-empty");
                }
                Ok(h.trim().to_string())
            }
            (None, Some(path), None) => {
                let pem = std::fs::read(path)
                    .map_err(|e| anyhow::anyhow!("reading EK cert `{path}`: {e}"))?;
                let mut reader = std::io::BufReader::new(&pem[..]);
                let cert = rustls_pemfile::certs(&mut reader)
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("no certificate found in `{path}`"))?
                    .map_err(|e| anyhow::anyhow!("parsing EK cert `{path}`: {e}"))?;
                let digest: [u8; 48] = Sha384::digest(cert.as_ref()).into();
                Ok(host_uuid_from_ek_digest(&digest).to_string())
            }
            (None, None, Some(hex_str)) => {
                let raw = hex::decode(hex_str.trim())
                    .map_err(|_| anyhow::anyhow!("--ek-sha384 is not hex"))?;
                let digest: [u8; 48] = raw
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("--ek-sha384 must be 48 bytes (SHA-384)"))?;
                Ok(host_uuid_from_ek_digest(&digest).to_string())
            }
            (None, None, None) => {
                anyhow::bail!("a host selector is required: --host, --ek-cert, or --ek-sha384")
            }
            _ => anyhow::bail!("give exactly one of --host, --ek-cert, --ek-sha384"),
        }
    }

    /// Parse `--entry uid:sha` and `--bin uid:path` flags into allow-entries.
    fn entries(&self) -> anyhow::Result<Vec<AllowEntry>> {
        let mut out = Vec::new();
        for raw in self.many("--entry") {
            let (uid, sha) = split_uid(raw, "--entry")?;
            out.push(AllowEntry {
                uid,
                bin_sha: normalize_sha(sha)?,
            });
        }
        for raw in self.many("--bin") {
            let (uid, path) = split_uid(raw, "--bin")?;
            let data = std::fs::read(path)
                .map_err(|e| anyhow::anyhow!("reading binary `{path}` for --bin: {e}"))?;
            let bin_sha = hex::encode(Sha384::digest(&data));
            out.push(AllowEntry { uid, bin_sha });
        }
        Ok(out)
    }

    /// Parse an optional `--ttl <secs>` flag.
    fn ttl(&self) -> anyhow::Result<Option<i64>> {
        self.one("--ttl")
            .map(|s| {
                s.parse::<i64>()
                    .map_err(|_| anyhow::anyhow!("--ttl must be a positive integer, got `{s}`"))
                    .and_then(|n| {
                        if n > 0 {
                            Ok(n)
                        } else {
                            Err(anyhow::anyhow!("--ttl must be positive"))
                        }
                    })
            })
            .transpose()
    }
}

/// Split a flag value into an optional uid and the rest. A `uid:value` prefix
/// pins the entry to that uid; a bare `value` (no colon) is a wildcard entry
/// (`uid = None`) that matches the binary run by any user (ADR-0002).
fn split_uid<'a>(raw: &'a str, flag: &str) -> anyhow::Result<(Option<u32>, &'a str)> {
    match raw.split_once(':') {
        Some((uid, rest)) => {
            let uid: u32 = uid
                .trim()
                .parse()
                .map_err(|_| anyhow::anyhow!("{flag} uid must be a u32, got `{uid}`"))?;
            Ok((Some(uid), rest.trim()))
        }
        None => Ok((None, raw.trim())),
    }
}

/// Render an entry's uid for display: a wildcard prints as `*`.
fn fmt_uid(uid: Option<u32>) -> String {
    uid.map_or_else(|| "*".to_string(), |u| u.to_string())
}

/// Validate and normalize a `bin_sha`: the `"*"` any-binary wildcard, or a
/// lowercase-hex SHA-384 (96 hex chars ⇒ 48 bytes).
fn normalize_sha(s: impl AsRef<str>) -> anyhow::Result<String> {
    let s = s.as_ref().trim();
    if s == allowlist::BIN_SHA_WILDCARD {
        return Ok(allowlist::BIN_SHA_WILDCARD.to_string());
    }
    let raw = hex::decode(s).map_err(|_| anyhow::anyhow!("bin_sha is not hex: `{s}`"))?;
    if raw.len() != 48 {
        anyhow::bail!("bin_sha must be 48 bytes (SHA-384), got {} bytes", raw.len());
    }
    Ok(s.to_lowercase())
}
