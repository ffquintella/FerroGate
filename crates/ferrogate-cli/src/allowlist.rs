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
//! A host is named by its EK-derived UUID. Supply it directly with `--host`, or
//! let the CLI derive it from the EK certificate (`--ek-cert <pem>`) or the EK
//! certificate's SHA-384 (`--ek-sha384 <hex>`).

use std::collections::HashMap;

use ferro_proto::v1::machine_identity_client::MachineIdentityClient;
use ferro_proto::v1::{
    AllowEntryMsg, DeleteAllowlistRequest, GetAllowlistRequest, ListAllowlistsRequest,
    SetAllowlistRequest,
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
     subcommands:\n\
     \x20 set     <host> (--entry uid:sha | --bin uid:path)... [--ttl secs]\n\
     \x20                  replace the host's allowlist with exactly these callers\n\
     \x20 add     <host> (--entry uid:sha | --bin uid:path)... [--ttl secs]\n\
     \x20                  add callers to the host's existing allowlist\n\
     \x20 remove  <host> --uid N [--bin-sha hex] [--ttl secs]\n\
     \x20                  drop a caller (or every entry for a uid) and re-sign\n\
     \x20 get     <host> [--out path]   fetch the raw signed CBOR (stdout if no --out)\n\
     \x20 show    <host>                fetch and print the entries + validity\n\
     \x20 list                          every host that has a stored allowlist\n\
     \x20 delete  <host>                remove the host's stored allowlist\n\
     \n\
     host selector (one of):\n\
     \x20 --host <uuid>       the EK-derived host UUID directly\n\
     \x20 --ek-cert <pem>     derive the UUID from an EK certificate PEM\n\
     \x20 --ek-sha384 <hex>   derive the UUID from the EK certificate's SHA-384\n\
     \n\
     entries:\n\
     \x20 --entry <uid>:<sha>   uid + lowercase-hex SHA-384 of the permitted binary\n\
     \x20 --bin   <uid>:<path>  uid + a binary whose SHA-384 the CLI computes"
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
    let Some(uid) = flags.one("--uid") else {
        anyhow::bail!("remove needs --uid <N>");
    };
    let uid: u32 = uid
        .parse()
        .map_err(|_| anyhow::anyhow!("--uid must be a u32, got `{uid}`"))?;
    let bin_sha = flags.one("--bin-sha").map(normalize_sha).transpose()?;

    let Some(doc) = fetch_doc(client, &host_uuid).await? else {
        anyhow::bail!("no allowlist stored for {host_uuid}");
    };
    let before = doc.entries.len();
    let entries: Vec<AllowEntry> = doc
        .entries
        .into_iter()
        .filter(|e| {
            // Drop the matching uid (+ bin_sha if given); keep everything else.
            !(e.uid == uid && bin_sha.as_ref().is_none_or(|b| *b == e.bin_sha))
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
        println!("  uid={:<7} bin_sha={}", e.uid, e.bin_sha);
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

// ---- RPC helpers -----------------------------------------------------------

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

/// Split a `uid:rest` flag value into its parts.
fn split_uid<'a>(raw: &'a str, flag: &str) -> anyhow::Result<(u32, &'a str)> {
    let (uid, rest) = raw
        .split_once(':')
        .ok_or_else(|| anyhow::anyhow!("{flag} must be `uid:value`, got `{raw}`"))?;
    let uid: u32 = uid
        .trim()
        .parse()
        .map_err(|_| anyhow::anyhow!("{flag} uid must be a u32, got `{uid}`"))?;
    Ok((uid, rest.trim()))
}

/// Validate and normalize a lowercase-hex SHA-384 (96 hex chars ⇒ 48 bytes).
fn normalize_sha(s: impl AsRef<str>) -> anyhow::Result<String> {
    let s = s.as_ref().trim();
    let raw = hex::decode(s).map_err(|_| anyhow::anyhow!("bin_sha is not hex: `{s}`"))?;
    if raw.len() != 48 {
        anyhow::bail!("bin_sha must be 48 bytes (SHA-384), got {} bytes", raw.len());
    }
    Ok(s.to_lowercase())
}
