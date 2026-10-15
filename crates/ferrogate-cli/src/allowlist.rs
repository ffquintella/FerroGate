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
//!
//! **Approvals mode (F19 §11 step 5).** Once CMIS runs in `approvals` mode
//! (`GetAllowlistMode`) the legacy bodies are read-only: `add` becomes a
//! direct registration (`AdminRegisterApplication`, one entry, a fresh TOTP
//! code, the binary's `--path` and `--platform` on the host) and `remove`
//! revokes the matching approvals (`ListApprovals` + `RevokeApproval`, a
//! `--reason-code`). `set`, `delete` and `approve` are refused by CMIS
//! (`mode_approvals`) with a hint to these commands.

use std::collections::HashMap;

use ferro_proto::admin_v1::{
    ApprovalInfo, GetAllowlistModeRequest, ListApprovalsRequest, PageRequest, RevokeApprovalRequest,
};
use ferro_proto::v1::{
    AllowEntryMsg, DeleteAllowlistRequest, DeleteProposalRequest, GetAllowlistRequest,
    ListAllowlistsRequest, ListProposalsRequest, PendingProposal, SetAllowlistRequest,
};
use ferro_svid::allowlist::{self, AllowEntry, AllowlistDoc};
use ferro_svid::host_uuid_from_ek_digest;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::CertificateDer;
use sha2::{Digest, Sha384};

use crate::admin::{has_flag, printable, Admin, Prompter};
use crate::{apps, rpc_err, CmisClient, CmisError};

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
     \x20 --bin   <path>        wildcard uid: any user running this binary\n\
     \n\
     approvals mode (after `ferrogate admin set-allowlist-mode approvals`; F19):\n\
     \x20 legacy allowlists are read-only (set, delete and approve are refused).\n\
     \x20 add     <selector> (--entry <uid>:<sha> | --bin <uid>:<path>) --path <path on host>\n\
     \x20         --platform linux|macos|windows --user <name> [apps register terms flags]\n\
     \x20                  registers ONE binary as an approval (needs a TOTP code)\n\
     \x20 remove  <selector> (--uid N | --bin-sha hex|*)... --reason-code <n> [--yes]\n\
     \x20                  lists the matching approvals, asks, and revokes them (final;\n\
     \x20                  the records are kept). --yes when not on a terminal"
}

/// The signed-in admin client and prompter of an admin `allowlist`
/// command, for the approvals-mode mapping of `add` and `remove`.
pub(crate) struct AdminCtx<'a> {
    /// `ferrogate.admin.v1.Admin` client carrying the session.
    pub(crate) admin: Admin,
    /// Prompts (the TOTP code of a direct registration).
    pub(crate) prompter: &'a Prompter,
}

/// Flags of the approvals-mode `add` that take no value.
const SWITCHES: [&str; 3] = ["--any-path", "--no-expiry", "--path-protected"];

/// Confirms the approvals-mode `remove` without a prompt.
const YES: &str = "--yes";

/// Valued flags of the approvals-mode `add` passed on to `admin apps register`.
const REGISTER_PASS_THROUGH: [&str; 10] = [
    "--user-kind",
    "--sid",
    "--size",
    "--format",
    "--version",
    "--reason",
    "--policy",
    "--continuity",
    "--expires-at",
    "--note",
];

/// Most approvals one approvals-mode `remove` looks through.
const MAX_REMOVE_SCAN: usize = 10_000;

/// Whether CMIS runs in `approvals` mode (asked only for admin commands).
/// A CMIS older than the mode switch (`UNIMPLEMENTED`) is in legacy mode.
async fn approvals_mode(ctx: &mut AdminCtx<'_>) -> anyhow::Result<bool> {
    match ctx
        .admin
        .get_allowlist_mode(GetAllowlistModeRequest {})
        .await
    {
        Ok(m) => Ok(m.into_inner().mode == 2),
        Err(s) if s.code() == tonic::Code::Unimplemented => Ok(false),
        Err(s) => Err(rpc_err(s)),
    }
}

/// A clearer error for the legacy writes CMIS refuses in approvals mode.
fn explain_mode(e: anyhow::Error) -> anyhow::Error {
    let refused = e.chain().any(|c| {
        c.downcast_ref::<CmisError>().is_some_and(|x| {
            x.0.code() == tonic::Code::FailedPrecondition && x.0.message() == "mode_approvals"
        })
    });
    if refused {
        e.context(
            "CMIS runs in approvals mode: legacy allowlists are read-only. Use `ferrogate \
             allowlist add|remove` (direct registration / revocation) or `ferrogate admin apps`",
        )
    } else {
        e
    }
}

/// Dispatch an `allowlist` subcommand.
pub(crate) async fn run(
    client: &mut CmisClient,
    ctx: Option<&mut AdminCtx<'_>>,
    sub: &str,
    args: &[String],
) -> anyhow::Result<()> {
    let valued: Vec<String> = args
        .iter()
        .filter(|a| !SWITCHES.contains(&a.as_str()) && a.as_str() != YES)
        .cloned()
        .collect();
    let flags = Flags::parse(&valued);
    if let Some(ctx) = ctx {
        if matches!(sub, "add" | "remove") && approvals_mode(ctx).await? {
            return if sub == "add" {
                approvals_add(ctx, &flags, args).await
            } else {
                approvals_remove(ctx, &flags, has_flag(args, YES)).await
            };
        }
    }
    match sub {
        "set" => set(client, &flags).await.map_err(explain_mode),
        "add" => add(client, &flags).await.map_err(explain_mode),
        "remove" => remove(client, &flags).await.map_err(explain_mode),
        "get" => get(client, &flags).await,
        "show" => show(client, &flags).await,
        "list" => list(client).await,
        "delete" => delete(client, &flags).await.map_err(explain_mode),
        "proposals" => proposals(client).await,
        "review" => review(client, &flags).await,
        "approve" => approve(client, &flags).await.map_err(explain_mode),
        "reject" => reject(client, &flags).await,
        "help" | "-h" | "--help" => {
            println!("{}", usage());
            Ok(())
        }
        other => anyhow::bail!("unknown allowlist subcommand: {other}\n\n{}", usage()),
    }
}

// ---- approvals mode (F19 §11 step 5) -------------------------------------------

/// `add` in approvals mode: one entry becomes a direct registration
/// (`ferrogate admin apps register`) of the binary at `--path` on the host.
async fn approvals_add(
    ctx: &mut AdminCtx<'_>,
    flags: &Flags,
    raw: &[String],
) -> anyhow::Result<()> {
    let host_uuid = flags.host_uuid()?;
    if flags.one("--ttl").is_some() {
        anyhow::bail!("--ttl applies to legacy allowlists; approvals take --expires-at <unix>");
    }
    let entries = flags.entries()?;
    let [entry] = entries.as_slice() else {
        anyhow::bail!(
            "in approvals mode `add` registers exactly one --entry or --bin (each needs its \
             own TOTP code)"
        );
    };
    let Some(uid) = entry.uid else {
        anyhow::bail!(
            "in approvals mode an entry needs a uid (`<uid>:<sha>`); for every user use \
             `ferrogate admin apps register --any-user --confirm-any-user`"
        );
    };
    if entry.bin_is_wildcard() {
        anyhow::bail!("in approvals mode a binary is approved by its hash; `*` is legacy only");
    }
    let need = |name: &str| {
        flags.one(name).map(str::to_string).ok_or_else(|| {
            anyhow::anyhow!(
                "in approvals mode `add` needs {name} (the binary on the host: --path <canonical \
                 path> --platform linux|macos|windows --user <name>)"
            )
        })
    };
    let mut register: Vec<String> = vec![
        "register".into(),
        "--host".into(),
        host_uuid,
        "--path".into(),
        need("--path")?,
        "--sha384".into(),
        entry.bin_sha.clone(),
        "--platform".into(),
        need("--platform")?,
        "--uid".into(),
        uid.to_string(),
        "--user".into(),
        need("--user")?,
    ];
    for name in REGISTER_PASS_THROUGH {
        if let Some(v) = flags.one(name) {
            register.push(name.to_string());
            register.push(v.to_string());
        }
    }
    for name in SWITCHES {
        if has_flag(raw, name) {
            register.push(name.to_string());
        }
    }
    apps::validate(&register)?;
    println!("CMIS runs in approvals mode: registering the binary as an approval");
    apps::run(&mut ctx.admin, &register, ctx.prompter).await
}

/// The active or expired approvals of `host_uuid` matching `uid` and/or
/// `bin_sha`. Refuses (nothing revoked) a host with more approvals than one
/// command scans.
async fn matching_approvals(
    admin: &mut Admin,
    host_uuid: &str,
    uid: Option<i64>,
    bin_sha: Option<&str>,
) -> anyhow::Result<Vec<ApprovalInfo>> {
    let mut matches = Vec::new();
    let mut token = String::new();
    let mut scanned = 0usize;
    loop {
        let page = admin
            .list_approvals(ListApprovalsRequest {
                states: vec![1, 2],
                host_uuid: host_uuid.to_string(),
                include_superseded: true,
                ascending: true,
                page: Some(PageRequest {
                    page_size: 100,
                    page_token: token.clone(),
                }),
                ..ListApprovalsRequest::default()
            })
            .await
            .map_err(rpc_err)?
            .into_inner();
        scanned += page.items.len();
        matches.extend(page.items.into_iter().filter(|a| {
            uid.is_none_or(|u| a.user.as_ref().and_then(|x| x.uid) == Some(u))
                && bin_sha.is_none_or(|b| b == a.bin_sha)
        }));
        if page.next_page_token.is_empty() {
            return Ok(matches);
        }
        if scanned >= MAX_REMOVE_SCAN {
            anyhow::bail!(
                "{host_uuid} has more than {MAX_REMOVE_SCAN} approvals; nothing was revoked. \
                 Revoke them one by one with `ferrogate admin apps revoke`"
            );
        }
        token = page.next_page_token;
    }
}

/// `remove` in approvals mode: revoke every active or expired approval of
/// the host that matches `--uid` and/or `--bin-sha` (records are kept),
/// after listing them and a confirmation (`--yes` when not on a terminal).
/// A revocation is final: a revoked legacy import is never re-imported.
async fn approvals_remove(ctx: &mut AdminCtx<'_>, flags: &Flags, yes: bool) -> anyhow::Result<()> {
    let host_uuid = flags.host_uuid()?;
    let uid: Option<i64> = flags
        .one("--uid")
        .map(|u| {
            u.parse::<u32>()
                .map(i64::from)
                .map_err(|_| anyhow::anyhow!("--uid must be a u32, got `{u}`"))
        })
        .transpose()?;
    let bin_sha = flags.one("--bin-sha").map(normalize_sha).transpose()?;
    if uid.is_none() && bin_sha.is_none() {
        anyhow::bail!("remove needs --uid <N> and/or --bin-sha <hex>");
    }
    let reason_code: u32 = flags
        .one("--reason-code")
        .ok_or_else(|| anyhow::anyhow!("in approvals mode `remove` needs --reason-code <n>"))?
        .parse()
        .ok()
        .filter(|n| *n != 0)
        .ok_or_else(|| anyhow::anyhow!("--reason-code must be a positive number"))?;

    let matches = matching_approvals(&mut ctx.admin, &host_uuid, uid, bin_sha.as_deref()).await?;
    if matches.is_empty() {
        anyhow::bail!("no matching approval to revoke for {host_uuid}");
    }
    println!("approvals to revoke on {host_uuid}:");
    for a in &matches {
        println!(
            "  {}  uid={}  bin_sha={}",
            printable(&a.approval_id),
            a.user
                .as_ref()
                .and_then(|u| u.uid)
                .map_or_else(|| "*".to_string(), |u| u.to_string()),
            printable(&a.bin_sha)
        );
    }
    if !yes {
        if !ctx.prompter.is_tty() {
            anyhow::bail!("revoking is final: re-run with --yes to confirm");
        }
        if !ctx.prompter.confirm("Revoke these approvals (final)?")? {
            anyhow::bail!("cancelled; nothing was revoked");
        }
    }
    for a in &matches {
        let r = ctx
            .admin
            .revoke_approval(RevokeApprovalRequest {
                idempotency_key: uuid::Uuid::new_v4().to_string(),
                approval_id: a.approval_id.clone(),
                reason_code,
                expected_row_version: a.row_version,
            })
            .await
            .map_err(rpc_err)?
            .into_inner();
        println!(
            "revoked approval {} (bin_sha={}; allowlist generation {})",
            printable(&a.approval_id),
            printable(&a.bin_sha),
            r.allowlist_generation
        );
    }
    Ok(())
}

// ---- subcommands -----------------------------------------------------------

async fn set(client: &mut CmisClient, flags: &Flags) -> anyhow::Result<()> {
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

async fn add(client: &mut CmisClient, flags: &Flags) -> anyhow::Result<()> {
    let host_uuid = flags.host_uuid()?;
    let new_entries = flags.entries()?;
    if new_entries.is_empty() {
        anyhow::bail!("add needs at least one --entry or --bin");
    }
    let existing = fetch_doc(client, &host_uuid).await?;
    let mut entries = existing
        .as_ref()
        .map(|d| d.entries.clone())
        .unwrap_or_default();
    for e in new_entries {
        if !entries
            .iter()
            .any(|x| x.uid == e.uid && x.bin_sha == e.bin_sha)
        {
            entries.push(e);
        }
    }
    let ttl = flags
        .ttl()?
        .unwrap_or_else(|| remaining_ttl(existing.as_ref()));
    let resp = put(client, &host_uuid, entries, ttl).await?;
    println!(
        "updated allowlist for {host_uuid}: issued_at={}, not_after={}",
        resp.0, resp.1
    );
    Ok(())
}

async fn remove(client: &mut CmisClient, flags: &Flags) -> anyhow::Result<()> {
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

async fn get(client: &mut CmisClient, flags: &Flags) -> anyhow::Result<()> {
    let host_uuid = flags.host_uuid()?;
    let bytes = fetch_bytes(client, &host_uuid).await?;
    let Some(bytes) = bytes else {
        anyhow::bail!("no allowlist stored for {host_uuid}");
    };
    if let Some(out) = flags.one("--out") {
        std::fs::write(out, &bytes).map_err(|e| anyhow::anyhow!("writing `{out}`: {e}"))?;
        println!("wrote {} bytes to {out}", bytes.len());
    } else {
        use std::io::Write as _;
        std::io::stdout()
            .write_all(&bytes)
            .map_err(|e| anyhow::anyhow!("writing stdout: {e}"))?;
    }
    Ok(())
}

async fn show(client: &mut CmisClient, flags: &Flags) -> anyhow::Result<()> {
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

async fn list(client: &mut CmisClient) -> anyhow::Result<()> {
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

async fn delete(client: &mut CmisClient, flags: &Flags) -> anyhow::Result<()> {
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

async fn proposals(client: &mut CmisClient) -> anyhow::Result<()> {
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
    println!("\nReview one with `ferrogate allowlist review --host <uuid>`.");
    Ok(())
}

async fn review(client: &mut CmisClient, flags: &Flags) -> anyhow::Result<()> {
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
    if !live.is_empty() {
        // A proposal is a full set: approving signs exactly the entries below and
        // replaces the live allowlist with them (it is not merged in). Say so up
        // front so the diff that follows reads correctly.
        println!("\napproving replaces the live allowlist with exactly the proposed set:");
    }
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
        println!(
            "\nwould be removed ({}) — live today, absent from the proposal:",
            dropped.len()
        );
        for e in dropped {
            println!("  - uid={:<7} bin_sha={}", fmt_uid(e.uid), e.bin_sha);
        }
        // The proposer should compose additively (live ∪ new); a stale or
        // non-additive proposal that omits operator-added entries shows up here.
        // Pruning is only correct when the proposer meant to drop these.
        println!(
            "  these drop on approval. Reject unless the pruning is intended — \
             an additive proposal would keep them."
        );
    }
    println!("\nApprove with `ferrogate allowlist approve --host {host_uuid}` or reject with `… reject --host {host_uuid}`.");
    Ok(())
}

async fn approve(client: &mut CmisClient, flags: &Flags) -> anyhow::Result<()> {
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

async fn reject(client: &mut CmisClient, flags: &Flags) -> anyhow::Result<()> {
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
async fn fetch_proposals(client: &mut CmisClient) -> anyhow::Result<Vec<PendingProposal>> {
    let resp = client
        .list_proposals(ListProposalsRequest {})
        .await
        .map_err(rpc_err)?
        .into_inner();
    Ok(resp.items)
}

/// Fetch the pending proposal for one host (`None` when none pending).
async fn fetch_proposal(
    client: &mut CmisClient,
    host_uuid: &str,
) -> anyhow::Result<Option<PendingProposal>> {
    Ok(fetch_proposals(client)
        .await?
        .into_iter()
        .find(|p| p.host_uuid == host_uuid))
}

/// Push entries to CMIS and return `(issued_at, not_after, new_entry_count)`.
async fn put(
    client: &mut CmisClient,
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
async fn fetch_bytes(client: &mut CmisClient, host_uuid: &str) -> anyhow::Result<Option<Vec<u8>>> {
    let resp = client
        .get_allowlist(GetAllowlistRequest {
            host_uuid: host_uuid.to_string(),
            accept_formats: Vec::new(),
        })
        .await
        .map_err(rpc_err)?
        .into_inner();
    Ok((!resp.signed_allowlist.is_empty()).then_some(resp.signed_allowlist))
}

/// Fetch and decode the allowlist body for a host (`None` when none stored).
async fn fetch_doc(
    client: &mut CmisClient,
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
        self.values
            .get(key)
            .and_then(|v| v.last())
            .map(String::as_str)
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
                let cert = CertificateDer::pem_slice_iter(&pem)
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
        anyhow::bail!(
            "bin_sha must be 48 bytes (SHA-384), got {} bytes",
            raw.len()
        );
    }
    Ok(s.to_lowercase())
}
