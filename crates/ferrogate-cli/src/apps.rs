//! `ferrogate admin apps …`: the application approval ledger from the
//! command line (F19 §5.4, §7.5).
//!
//! Every action maps onto one `ferrogate.admin.v1.Admin` RPC (`update` reads
//! the approval first for its `row_version`). The arguments are parsed into a
//! [`Command`] **before** any sign-in, so a typo never costs a TOTP code.
//! Decisions and edits need a recent step-up (the shared dispatcher in
//! [`crate::admin`] handles `step_up_required`); a direct registration carries
//! a fresh per-operation TOTP proof, and so does `approve --self`.
//!
//! Every string the server returns (paths, user names, notes, versions) is
//! personal or untrusted data and goes through [`printable`] before it reaches
//! the terminal.

use std::fmt::Write as _;

use ferro_proto::admin_v1::approve_app_request_request::Choice;
use ferro_proto::admin_v1::{
    AdminRegisterApplicationRequest, AppBinaryDesc, AppBinaryInfo, AppRequestInfo, AppUser,
    ApprovalInfo, ApprovalTerms, ApproveAppRequestRequest, DenyAppRequestRequest,
    GetAppRequestRequest, GetApprovalRequest, ListAppRequestsRequest, ListApprovalsRequest,
    PageRequest, RevokeApprovalRequest, SetLineageAutoUpdateFrozenRequest, UpdateApprovalRequest,
};

use crate::admin::{flag_value, flag_values, has_flag, printable, proof, Admin, Prompter};
use crate::rpc_err;

/// Default number of items a listing prints.
const DEFAULT_LIMIT: usize = 50;
/// Most items asked of the server per page.
const MAX_PAGE_SIZE: usize = 100;
/// Flag bit 0 of a binary: the path is writable only by privileged users.
const FLAG_PATH_PROTECTED: u32 = 1;

/// The usage text of `ferrogate admin apps`.
pub(crate) fn usage() -> &'static str {
    "ferrogate admin apps — application approvals (F19)\n\
     \n\
     \x20 apps requests [--state pending|approved|auto|denied|expired]... [--host <uuid>]\n\
     \x20               [--text <q>] [--limit N]\n\
     \x20 apps request <request_id>\n\
     \x20 apps approve <request_id> [--policy manual|auto] [--continuity anchored|path-user]\n\
     \x20               [--any-user --confirm-any-user] [--any-path]\n\
     \x20               [--expires-at <unix> | --no-expiry] [--note <text>]\n\
     \x20               [--reuse <approval_id>] [--also-revoke <approval_id>... --revoke-reason <code>]\n\
     \x20               [--self]        (--self: approving a request you registered; needs a TOTP code)\n\
     \x20 apps deny <request_id> --reason-code <n> [--message <text>]\n\
     \x20 apps approvals [--state active|expired|revoked]... [--host <uuid>] [--lineage <id>]\n\
     \x20               [--include-superseded] [--limit N]\n\
     \x20 apps approval <approval_id>\n\
     \x20 apps update <approval_id> [--policy manual|auto] [--continuity anchored|path-user]\n\
     \x20               [--expires-at <unix> | --no-expiry] [--note <text> | --clear-note]\n\
     \x20               [--narrow-user] [--narrow-path]\n\
     \x20 apps revoke <approval_id> --reason-code <n>\n\
     \x20 apps freeze|unfreeze <lineage_id>   stop or resume automatic updates of a lineage\n\
     \x20 apps register --host <uuid> --path <canonical path> --sha384 <hex>\n\
     \x20               --platform linux|macos|windows --user <name> --uid <n> [--sid <S-1-...>]\n\
     \x20               [--user-kind unix|windows] [--size <bytes>] [--format elf|macho|pe|other]\n\
     \x20               [--version <declared>] [--reason <text>] [--path-protected]\n\
     \x20               plus the terms flags of `approve` (needs a TOTP code)"
}

// ---- argument parsing ------------------------------------------------------------

/// Splits `args` into positional arguments, rejecting any `--flag` that is not
/// listed. `valued` flags consume the next argument, `switches` stand alone.
fn positionals(args: &[String], valued: &[&str], switches: &[&str]) -> anyhow::Result<Vec<String>> {
    let mut out = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if valued.contains(&a.as_str()) {
            if it.next().is_none() {
                anyhow::bail!("{a} needs a value\n\n{}", usage());
            }
        } else if switches.contains(&a.as_str()) {
        } else if a.starts_with("--") {
            anyhow::bail!("unknown option {a}\n\n{}", usage());
        } else {
            out.push(a.clone());
        }
    }
    Ok(out)
}

/// The single positional `what` of an action.
fn one_positional(pos: Vec<String>, what: &str) -> anyhow::Result<String> {
    let mut it = pos.into_iter();
    match (it.next(), it.next()) {
        (Some(v), None) => Ok(v),
        _ => anyhow::bail!("expected exactly one {what}\n\n{}", usage()),
    }
}

fn number<T: std::str::FromStr>(args: &[String], name: &str) -> anyhow::Result<Option<T>> {
    flag_value(args, name)
        .map(|v| v.parse::<T>())
        .transpose()
        .map_err(|_| anyhow::anyhow!("{name} must be a number"))
}

fn required<T>(v: Option<T>, name: &str) -> anyhow::Result<T> {
    v.ok_or_else(|| anyhow::anyhow!("{name} is required\n\n{}", usage()))
}

/// Request state code of a `--state` value.
fn request_state_code(name: &str) -> anyhow::Result<u32> {
    Ok(match name {
        "pending" => 1,
        "approved" => 2,
        "auto" | "auto_approved" | "auto-approved" => 3,
        "denied" => 4,
        "expired" => 5,
        other => anyhow::bail!(
            "unknown request state `{other}` (pending, approved, auto, denied, expired)"
        ),
    })
}

/// Name of a request state code.
fn request_state_name(code: u32) -> &'static str {
    match code {
        1 => "pending",
        2 => "approved",
        3 => "auto_approved",
        4 => "denied",
        5 => "expired",
        _ => "?",
    }
}

/// Approval state code of a `--state` value.
fn approval_state_code(name: &str) -> anyhow::Result<u32> {
    Ok(match name {
        "active" => 1,
        "expired" => 2,
        "revoked" => 3,
        other => anyhow::bail!("unknown approval state `{other}` (active, expired, revoked)"),
    })
}

/// Name of an approval state code.
fn approval_state_name(code: u32) -> &'static str {
    match code {
        1 => "active",
        2 => "expired",
        3 => "revoked",
        _ => "?",
    }
}

/// Update-policy code of a `--policy` value.
fn policy_code(name: &str) -> anyhow::Result<u32> {
    Ok(match name {
        "manual" => 1,
        "auto" => 2,
        other => anyhow::bail!("unknown policy `{other}` (manual, auto)"),
    })
}

fn policy_name(code: u32) -> &'static str {
    match code {
        1 => "manual",
        2 => "auto",
        _ => "?",
    }
}

/// Continuity code of a `--continuity` value.
fn continuity_code(name: &str) -> anyhow::Result<u32> {
    Ok(match name {
        "anchored" => 1,
        "path-user" | "path_user_only" => 2,
        other => anyhow::bail!("unknown continuity `{other}` (anchored, path-user)"),
    })
}

fn continuity_name(code: u32) -> &'static str {
    match code {
        1 => "anchored",
        2 => "path-user",
        _ => "?",
    }
}

fn platform_code(name: &str) -> anyhow::Result<u32> {
    Ok(match name {
        "linux" => 1,
        "macos" => 2,
        "windows" => 3,
        other => anyhow::bail!("unknown platform `{other}` (linux, macos, windows)"),
    })
}

fn format_code(name: &str) -> anyhow::Result<u32> {
    Ok(match name {
        "elf" => 1,
        "macho" => 2,
        "pe" => 3,
        "other" => 9,
        other => anyhow::bail!("unknown format `{other}` (elf, macho, pe, other)"),
    })
}

fn user_kind_code(name: &str) -> anyhow::Result<u32> {
    Ok(match name {
        "unix" => 1,
        "windows" => 2,
        other => anyhow::bail!("unknown user kind `{other}` (unix, windows)"),
    })
}

/// A SHA-384 as 96 lowercase hex characters (uppercase input is accepted and
/// lowercased).
fn sha384_hex(input: &str) -> anyhow::Result<String> {
    let s = input.to_ascii_lowercase();
    if s.len() == 96
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        Ok(s)
    } else {
        anyhow::bail!("--sha384 must be 96 hexadecimal characters (SHA-384)")
    }
}

/// The terms flags shared by `approve` and `register`.
const TERMS_VALUED: [&str; 4] = ["--policy", "--continuity", "--expires-at", "--note"];
const TERMS_SWITCHES: [&str; 3] = ["--any-user", "--confirm-any-user", "--any-path"];

/// Builds the [`ApprovalTerms`] of the terms flags in `args`.
fn build_terms(args: &[String]) -> anyhow::Result<ApprovalTerms> {
    let any_user = has_flag(args, "--any-user");
    if any_user && !has_flag(args, "--confirm-any-user") {
        anyhow::bail!("--any-user approves every user of the host: add --confirm-any-user");
    }
    if has_flag(args, "--confirm-any-user") && !any_user {
        anyhow::bail!("--confirm-any-user only goes with --any-user");
    }
    let expires_at = number::<i64>(args, "--expires-at")?;
    let no_expiry = has_flag(args, "--no-expiry");
    if no_expiry && expires_at.is_some() {
        anyhow::bail!("--no-expiry and --expires-at exclude each other");
    }
    Ok(ApprovalTerms {
        user_scope: if any_user { 2 } else { 1 },
        path_match: if has_flag(args, "--any-path") { 2 } else { 1 },
        update_policy: flag_value(args, "--policy")
            .map(|v| policy_code(&v))
            .transpose()?
            .unwrap_or(1),
        continuity: flag_value(args, "--continuity")
            .map(|v| continuity_code(&v))
            .transpose()?
            .unwrap_or(1),
        expires_at: expires_at.unwrap_or(0),
        no_expiry,
        note: flag_value(args, "--note").unwrap_or_default(),
        confirm_any_user: any_user,
    })
}

/// A parsed `apps` action.
#[derive(Debug)]
enum Command {
    Requests {
        states: Vec<u32>,
        host: String,
        text: String,
        limit: usize,
    },
    Request(String),
    Approve(Box<ApproveRequestArgs>),
    Deny {
        request_id: String,
        reason_code: u32,
        message: String,
    },
    Approvals {
        states: Vec<u32>,
        host: String,
        lineage: String,
        include_superseded: bool,
        limit: usize,
    },
    Approval(String),
    Update(Box<UpdateArgs>),
    Revoke {
        approval_id: String,
        reason_code: u32,
    },
    Freeze {
        lineage_id: String,
        frozen: bool,
    },
    Register(Box<RegisterArgs>),
}

/// `apps approve` arguments.
#[derive(Debug)]
struct ApproveRequestArgs {
    request_id: String,
    choice: Choice,
    also_revoke: Vec<String>,
    revoke_reason: u32,
    own_request: bool,
}

/// `apps update` arguments (they mirror the request flags one to one).
#[derive(Debug)]
#[allow(clippy::struct_excessive_bools)]
struct UpdateArgs {
    approval_id: String,
    update_policy: Option<u32>,
    continuity: Option<u32>,
    expires_at: Option<i64>,
    clear_expiry: bool,
    note: Option<String>,
    clear_note: bool,
    narrow_user: bool,
    narrow_path: bool,
}

/// `apps register` arguments.
#[derive(Debug)]
struct RegisterArgs {
    host: String,
    binary: AppBinaryDesc,
    user: AppUser,
    reason: String,
    terms: ApprovalTerms,
}

fn limit(args: &[String]) -> anyhow::Result<usize> {
    match number::<usize>(args, "--limit")? {
        Some(0) => anyhow::bail!("--limit must be at least 1"),
        Some(n) => Ok(n),
        None => Ok(DEFAULT_LIMIT),
    }
}

/// Parses `apps <action> …` without touching the network.
#[allow(clippy::too_many_lines)] // one arm per action.
fn parse(args: &[String]) -> anyhow::Result<Command> {
    let Some(action) = args.first() else {
        anyhow::bail!("apps needs an action\n\n{}", usage());
    };
    let rest = &args[1..];
    match action.as_str() {
        "requests" => {
            let pos = positionals(rest, &["--state", "--host", "--text", "--limit"], &[])?;
            if !pos.is_empty() {
                anyhow::bail!("requests takes no argument\n\n{}", usage());
            }
            Ok(Command::Requests {
                states: flag_values(rest, "--state")
                    .iter()
                    .map(|s| request_state_code(s))
                    .collect::<anyhow::Result<_>>()?,
                host: flag_value(rest, "--host").unwrap_or_default(),
                text: flag_value(rest, "--text").unwrap_or_default(),
                limit: limit(rest)?,
            })
        }
        "request" => Ok(Command::Request(one_positional(
            positionals(rest, &[], &[])?,
            "request_id",
        )?)),
        "approve" => {
            let pos = positionals(
                rest,
                &[
                    "--policy",
                    "--continuity",
                    "--expires-at",
                    "--note",
                    "--reuse",
                    "--also-revoke",
                    "--revoke-reason",
                ],
                &[
                    "--any-user",
                    "--confirm-any-user",
                    "--any-path",
                    "--no-expiry",
                    "--self",
                ],
            )?;
            let request_id = one_positional(pos, "request_id")?;
            let choice = if let Some(id) = flag_value(rest, "--reuse") {
                let terms_given = ["--policy", "--continuity", "--expires-at", "--note"]
                    .iter()
                    .any(|f| flag_value(rest, f).is_some())
                    || ["--any-user", "--any-path", "--no-expiry"]
                        .iter()
                        .any(|f| has_flag(rest, f));
                if terms_given {
                    anyhow::bail!(
                        "--reuse takes no terms flags: the existing approval's terms apply"
                    );
                }
                Choice::ReuseApprovalId(id)
            } else {
                Choice::Terms(build_terms(rest)?)
            };
            let also_revoke = flag_values(rest, "--also-revoke");
            let revoke_reason = number::<u32>(rest, "--revoke-reason")?.unwrap_or(0);
            if !also_revoke.is_empty() && revoke_reason == 0 {
                anyhow::bail!("--also-revoke needs --revoke-reason <code> (non-zero)");
            }
            Ok(Command::Approve(Box::new(ApproveRequestArgs {
                request_id,
                choice,
                also_revoke,
                revoke_reason,
                own_request: has_flag(rest, "--self"),
            })))
        }
        "deny" => {
            let request_id = one_positional(
                positionals(rest, &["--reason-code", "--message"], &[])?,
                "request_id",
            )?;
            let reason_code = required(number::<u32>(rest, "--reason-code")?, "--reason-code")?;
            if reason_code == 0 {
                anyhow::bail!("--reason-code must be non-zero");
            }
            Ok(Command::Deny {
                request_id,
                reason_code,
                message: flag_value(rest, "--message").unwrap_or_default(),
            })
        }
        "approvals" => {
            let pos = positionals(
                rest,
                &["--state", "--host", "--lineage", "--limit"],
                &["--include-superseded"],
            )?;
            if !pos.is_empty() {
                anyhow::bail!("approvals takes no argument\n\n{}", usage());
            }
            Ok(Command::Approvals {
                states: flag_values(rest, "--state")
                    .iter()
                    .map(|s| approval_state_code(s))
                    .collect::<anyhow::Result<_>>()?,
                host: flag_value(rest, "--host").unwrap_or_default(),
                lineage: flag_value(rest, "--lineage").unwrap_or_default(),
                include_superseded: has_flag(rest, "--include-superseded"),
                limit: limit(rest)?,
            })
        }
        "approval" => Ok(Command::Approval(one_positional(
            positionals(rest, &[], &[])?,
            "approval_id",
        )?)),
        "update" => parse_update(rest),
        "revoke" => {
            let approval_id =
                one_positional(positionals(rest, &["--reason-code"], &[])?, "approval_id")?;
            let reason_code = required(number::<u32>(rest, "--reason-code")?, "--reason-code")?;
            if reason_code == 0 {
                anyhow::bail!("--reason-code must be non-zero");
            }
            Ok(Command::Revoke {
                approval_id,
                reason_code,
            })
        }
        "freeze" | "unfreeze" => Ok(Command::Freeze {
            lineage_id: one_positional(positionals(rest, &[], &[])?, "lineage_id")?,
            frozen: action == "freeze",
        }),
        "register" => parse_register(rest),
        other => anyhow::bail!("unknown apps action: {other}\n\n{}", usage()),
    }
}

fn parse_update(rest: &[String]) -> anyhow::Result<Command> {
    let pos = positionals(
        rest,
        &["--policy", "--continuity", "--expires-at", "--note"],
        &[
            "--no-expiry",
            "--clear-note",
            "--narrow-user",
            "--narrow-path",
        ],
    )?;
    let approval_id = one_positional(pos, "approval_id")?;
    let expires_at = number::<i64>(rest, "--expires-at")?;
    let clear_expiry = has_flag(rest, "--no-expiry");
    if clear_expiry && expires_at.is_some() {
        anyhow::bail!("--no-expiry and --expires-at exclude each other");
    }
    let note = flag_value(rest, "--note");
    let clear_note = has_flag(rest, "--clear-note");
    if clear_note && note.is_some() {
        anyhow::bail!("--note and --clear-note exclude each other");
    }
    let update = UpdateArgs {
        approval_id,
        update_policy: flag_value(rest, "--policy")
            .map(|v| policy_code(&v))
            .transpose()?,
        continuity: flag_value(rest, "--continuity")
            .map(|v| continuity_code(&v))
            .transpose()?,
        expires_at,
        clear_expiry,
        note,
        clear_note,
        narrow_user: has_flag(rest, "--narrow-user"),
        narrow_path: has_flag(rest, "--narrow-path"),
    };
    if update.update_policy.is_none()
        && update.continuity.is_none()
        && update.expires_at.is_none()
        && !update.clear_expiry
        && update.note.is_none()
        && !update.clear_note
        && !update.narrow_user
        && !update.narrow_path
    {
        anyhow::bail!("apps update needs at least one change\n\n{}", usage());
    }
    Ok(Command::Update(Box::new(update)))
}

fn parse_register(rest: &[String]) -> anyhow::Result<Command> {
    let mut valued = vec![
        "--host",
        "--path",
        "--sha384",
        "--platform",
        "--uid",
        "--user",
        "--sid",
        "--user-kind",
        "--size",
        "--format",
        "--version",
        "--reason",
    ];
    valued.extend(TERMS_VALUED);
    let mut switches = vec!["--path-protected", "--no-expiry"];
    switches.extend(TERMS_SWITCHES);
    if !positionals(rest, &valued, &switches)?.is_empty() {
        anyhow::bail!("register takes no positional argument\n\n{}", usage());
    }
    let host = required(flag_value(rest, "--host"), "--host")?;
    uuid::Uuid::parse_str(&host).map_err(|_| anyhow::anyhow!("--host must be a UUID"))?;
    let platform = platform_code(&required(flag_value(rest, "--platform"), "--platform")?)?;
    let user_kind = match flag_value(rest, "--user-kind") {
        Some(k) => user_kind_code(&k)?,
        None if platform == 3 => 2,
        None => 1,
    };
    let uid = number::<i64>(rest, "--uid")?;
    let sid = flag_value(rest, "--sid").unwrap_or_default();
    if user_kind == 1 && uid.is_none() {
        anyhow::bail!("--uid is required for a unix user");
    }
    if user_kind == 2 && uid.is_none() && sid.is_empty() {
        anyhow::bail!("a windows user needs --sid (or --uid, the RID)");
    }
    let format = match flag_value(rest, "--format") {
        Some(f) => format_code(&f)?,
        None => match platform {
            1 => 1,
            2 => 2,
            _ => 3,
        },
    };
    Ok(Command::Register(Box::new(RegisterArgs {
        host,
        binary: AppBinaryDesc {
            canonical_path: required(flag_value(rest, "--path"), "--path")?,
            platform,
            sha384: sha384_hex(&required(flag_value(rest, "--sha384"), "--sha384")?)?,
            size: number::<u64>(rest, "--size")?.unwrap_or(0),
            format,
            declared_version: flag_value(rest, "--version").unwrap_or_default(),
            flags: if has_flag(rest, "--path-protected") {
                FLAG_PATH_PROTECTED
            } else {
                0
            },
            ..AppBinaryDesc::default()
        },
        user: AppUser {
            kind: user_kind,
            uid,
            sid,
            name: required(flag_value(rest, "--user"), "--user")?,
        },
        reason: flag_value(rest, "--reason").unwrap_or_default(),
        terms: build_terms(rest)?,
    })))
}

/// Checks `apps <action> …` before signing in (no network, no prompt).
pub(crate) fn validate(args: &[String]) -> anyhow::Result<()> {
    parse(args).map(|_| ())
}

// ---- printing --------------------------------------------------------------------

/// A unix time, or `never` for 0.
fn when(t: i64) -> String {
    if t == 0 {
        "never".to_string()
    } else {
        format!("{t} (unix)")
    }
}

/// An operating-system user, ready for the terminal.
fn user_label(u: Option<&AppUser>) -> String {
    let Some(u) = u else {
        return "-".to_string();
    };
    let mut s = printable(&u.name);
    if let Some(uid) = u.uid {
        let _ = write!(s, " (uid {uid})");
    }
    if !u.sid.is_empty() {
        let _ = write!(s, " ({})", printable(&u.sid));
    }
    s
}

fn request_origin_name(code: u32) -> &'static str {
    match code {
        1 => "self",
        2 => "assisted",
        3 => "admin_direct",
        4 => "observed",
        _ => "?",
    }
}

fn approval_origin_name(code: u32) -> &'static str {
    match code {
        1 => "manual",
        2 => "auto_update",
        3 => "admin_direct",
        4 => "legacy_import",
        _ => "?",
    }
}

fn change_kind_name(code: u32) -> &'static str {
    match code {
        1 => "created",
        2 => "updated",
        3 => "expired",
        4 => "revoked",
        5 => "renewed",
        _ => "?",
    }
}

/// One line of a request listing.
fn request_line(r: &AppRequestInfo) -> String {
    format!(
        "{}  {:<13} {}  {}  {}  {}  flags=0x{:x}",
        printable(&r.request_id),
        request_state_name(r.state),
        printable(&r.host_uuid),
        printable(&r.display_version),
        user_label(r.target_user.as_ref()),
        printable(&r.canonical_path),
        r.flags
    )
}

/// One line of an approval listing.
fn approval_line(a: &ApprovalInfo) -> String {
    format!(
        "{}  {:<7} {}  r{}  {}  {}  policy={}  expires {}",
        printable(&a.approval_id),
        approval_state_name(a.state),
        printable(&a.host_uuid),
        a.revision,
        user_label(a.user.as_ref()),
        printable(&a.canonical_path),
        policy_name(a.update_policy),
        when(a.expires_at)
    )
}

fn print_binary(b: &AppBinaryInfo) {
    println!("binary:");
    println!("  sha384:           {}", printable(&b.bin_sha));
    println!("  revision:         {}", b.revision);
    println!("  display_version:  {}", printable(&b.display_version));
    println!("  size:             {}", b.file_size);
    if b.signer_kind != 0 {
        println!(
            "  signer:           {} {} ({})",
            printable(&b.signer_id),
            printable(&b.signer_subject),
            if b.signer_valid { "valid" } else { "not valid" }
        );
    } else {
        println!("  signer:           none");
    }
}

fn print_request(r: &AppRequestInfo) {
    println!("request_id:         {}", printable(&r.request_id));
    println!("state:              {}", request_state_name(r.state));
    println!(
        "kind/origin:        {} / {}",
        if r.kind == 2 { "update" } else { "register" },
        request_origin_name(r.origin)
    );
    println!("host:               {}", printable(&r.host_uuid));
    println!("lineage:            {}", printable(&r.lineage_id));
    println!("path:               {}", printable(&r.canonical_path));
    println!("user:               {}", user_label(r.target_user.as_ref()));
    println!("display_version:    {}", printable(&r.display_version));
    println!("flags:              0x{:x}", r.flags);
    if !r.auto_downgrade_reason.is_empty() {
        println!(
            "auto_downgrade:     {}",
            printable(&r.auto_downgrade_reason)
        );
    }
    if !r.reason.is_empty() {
        println!("reason:             {}", printable(&r.reason));
    }
    println!("submitted_at:       {}", when(r.submitted_at));
    println!("pending_expires_at: {}", when(r.pending_expires_at));
    if r.decided_at != 0 {
        println!(
            "decision:           {} at {} by {} (reason code {}) {}",
            request_state_name(r.state),
            when(r.decided_at),
            printable(&r.decided_by_admin_id),
            r.decision_reason_code,
            printable(&r.decision_message)
        );
    }
    if !r.resulting_approval_id.is_empty() {
        println!(
            "approval:           {}{}",
            printable(&r.resulting_approval_id),
            if r.same_actor_approved {
                " (approved by the same actor)"
            } else {
                ""
            }
        );
    }
}

fn print_approval(a: &ApprovalInfo) {
    println!("approval_id:        {}", printable(&a.approval_id));
    println!("state:              {}", approval_state_name(a.state));
    println!("origin:             {}", approval_origin_name(a.origin));
    println!("host:               {}", printable(&a.host_uuid));
    println!("lineage:            {}", printable(&a.lineage_id));
    println!("path:               {}", printable(&a.canonical_path));
    println!(
        "path_match:         {}",
        if a.path_match == 2 { "any" } else { "exact" }
    );
    println!(
        "user_scope:         {}",
        if a.user_scope == 2 {
            "any user".to_string()
        } else {
            user_label(a.user.as_ref())
        }
    );
    println!("bin_sha:            {}", printable(&a.bin_sha));
    println!("revision:           {}", a.revision);
    println!("policy:             {}", policy_name(a.update_policy));
    println!("continuity:         {}", continuity_name(a.continuity));
    println!("created_at:         {}", when(a.created_at));
    println!("expires_at:         {}", when(a.expires_at));
    println!("approved_by:        {}", printable(&a.approved_by_admin_id));
    if !a.note.is_empty() {
        println!("note:               {}", printable(&a.note));
    }
    if !a.superseded_by.is_empty() {
        println!("superseded_by:      {}", printable(&a.superseded_by));
    }
    if a.revoked_at != 0 {
        println!(
            "revoked:            {} by {} (reason code {})",
            when(a.revoked_at),
            printable(&a.revoked_by_admin_id),
            a.revoke_reason_code
        );
    }
    println!("row_version:        {}", a.row_version);
}

// ---- execution -------------------------------------------------------------------

/// A fresh idempotency key (UUID v4: 36 characters of `[0-9a-f-]`).
fn idempotency_key() -> String {
    uuid::Uuid::new_v4().to_string()
}

fn page(remaining: usize, token: &str) -> Option<PageRequest> {
    Some(PageRequest {
        page_size: u32::try_from(remaining.min(MAX_PAGE_SIZE)).unwrap_or(1),
        page_token: token.to_string(),
    })
}

/// Runs `ferrogate admin apps <action>` on a signed-in admin client.
pub(crate) async fn run(
    admin: &mut Admin,
    args: &[String],
    prompter: &Prompter,
) -> anyhow::Result<()> {
    match parse(args)? {
        Command::Requests {
            states,
            host,
            text,
            limit,
        } => list_requests(admin, states, host, text, limit).await,
        Command::Request(id) => show_request(admin, id).await,
        Command::Approve(a) => approve(admin, *a, prompter).await,
        Command::Deny {
            request_id,
            reason_code,
            message,
        } => {
            let r = admin
                .deny_app_request(DenyAppRequestRequest {
                    idempotency_key: idempotency_key(),
                    request_id,
                    reason_code,
                    message,
                })
                .await
                .map_err(rpc_err)?
                .into_inner();
            if let Some(req) = r.request {
                println!(
                    "request {} {}",
                    printable(&req.request_id),
                    request_state_name(req.state)
                );
            }
            Ok(())
        }
        Command::Approvals {
            states,
            host,
            lineage,
            include_superseded,
            limit,
        } => list_approvals(admin, states, host, lineage, include_superseded, limit).await,
        Command::Approval(id) => show_approval(admin, id).await,
        Command::Update(u) => update(admin, *u).await,
        Command::Revoke {
            approval_id,
            reason_code,
        } => {
            let r = admin
                .revoke_approval(RevokeApprovalRequest {
                    idempotency_key: idempotency_key(),
                    approval_id,
                    reason_code,
                    expected_row_version: 0,
                })
                .await
                .map_err(rpc_err)?
                .into_inner();
            if let Some(a) = r.approval {
                println!(
                    "approval {} {} (allowlist generation {})",
                    printable(&a.approval_id),
                    approval_state_name(a.state),
                    r.allowlist_generation
                );
            }
            Ok(())
        }
        Command::Freeze { lineage_id, frozen } => {
            admin
                .set_lineage_auto_update_frozen(SetLineageAutoUpdateFrozenRequest {
                    idempotency_key: idempotency_key(),
                    lineage_id: lineage_id.clone(),
                    frozen,
                })
                .await
                .map_err(rpc_err)?;
            println!(
                "automatic updates of lineage {} {}",
                printable(&lineage_id),
                if frozen { "frozen" } else { "resumed" }
            );
            Ok(())
        }
        Command::Register(r) => register(admin, *r, prompter).await,
    }
}

async fn list_requests(
    admin: &mut Admin,
    states: Vec<u32>,
    host: String,
    text: String,
    limit: usize,
) -> anyhow::Result<()> {
    let mut printed = 0usize;
    let mut token = String::new();
    while printed < limit {
        let resp = admin
            .list_app_requests(ListAppRequestsRequest {
                states: states.clone(),
                host_uuid: host.clone(),
                text: text.clone(),
                page: page(limit - printed, &token),
                ..ListAppRequestsRequest::default()
            })
            .await
            .map_err(rpc_err)?
            .into_inner();
        for r in resp.items.iter().take(limit - printed) {
            println!("{}", request_line(r));
            printed += 1;
        }
        if resp.next_page_token.is_empty() || resp.items.is_empty() {
            break;
        }
        token = resp.next_page_token;
    }
    Ok(())
}

async fn show_request(admin: &mut Admin, request_id: String) -> anyhow::Result<()> {
    let r = admin
        .get_app_request(GetAppRequestRequest { request_id })
        .await
        .map_err(rpc_err)?
        .into_inner();
    if let Some(req) = &r.request {
        print_request(req);
    }
    if let Some(b) = &r.binary {
        print_binary(b);
    }
    println!(
        "lineage auto-update: {}",
        if r.lineage_auto_update_frozen {
            "frozen"
        } else {
            "allowed"
        }
    );
    println!("lineage approvals:");
    for a in &r.lineage_approvals {
        println!(
            "  {}  {:<7} r{}  policy={}  expires {}",
            printable(&a.approval_id),
            approval_state_name(a.state),
            a.revision,
            policy_name(a.update_policy),
            when(a.expires_at)
        );
    }
    Ok(())
}

async fn approve(
    admin: &mut Admin,
    a: ApproveRequestArgs,
    prompter: &Prompter,
) -> anyhow::Result<()> {
    let mfa = if a.own_request {
        proof(prompter.secret("TOTP code (fresh second factor to approve your own request)")?)
    } else {
        None
    };
    let r = admin
        .approve_app_request(ApproveAppRequestRequest {
            idempotency_key: idempotency_key(),
            request_id: a.request_id,
            choice: Some(a.choice),
            also_revoke_approval_ids: a.also_revoke,
            also_revoke_reason_code: a.revoke_reason,
            proof: mfa,
        })
        .await
        .map_err(rpc_err)?
        .into_inner();
    if let Some(ap) = &r.approval {
        println!("approved: {}", printable(&ap.approval_id));
        println!("expires_at: {}", when(ap.expires_at));
    }
    println!("allowlist generation: {}", r.allowlist_generation);
    for id in &r.revoked_approval_ids {
        println!("revoked: {}", printable(id));
    }
    if r.same_actor {
        println!("same actor: you both registered and approved this request");
    }
    Ok(())
}

async fn list_approvals(
    admin: &mut Admin,
    states: Vec<u32>,
    host: String,
    lineage: String,
    include_superseded: bool,
    limit: usize,
) -> anyhow::Result<()> {
    let mut printed = 0usize;
    let mut token = String::new();
    while printed < limit {
        let resp = admin
            .list_approvals(ListApprovalsRequest {
                states: states.clone(),
                host_uuid: host.clone(),
                lineage_id: lineage.clone(),
                include_superseded,
                page: page(limit - printed, &token),
                ..ListApprovalsRequest::default()
            })
            .await
            .map_err(rpc_err)?
            .into_inner();
        for a in resp.items.iter().take(limit - printed) {
            println!("{}", approval_line(a));
            printed += 1;
        }
        if resp.next_page_token.is_empty() || resp.items.is_empty() {
            break;
        }
        token = resp.next_page_token;
    }
    Ok(())
}

async fn show_approval(admin: &mut Admin, approval_id: String) -> anyhow::Result<()> {
    let r = admin
        .get_approval(GetApprovalRequest { approval_id })
        .await
        .map_err(rpc_err)?
        .into_inner();
    if let Some(a) = &r.approval {
        print_approval(a);
    }
    if let Some(b) = &r.binary {
        print_binary(b);
    }
    println!("revisions:");
    for v in &r.revisions {
        let by = if v.changed_by_admin_id.is_empty() {
            "system".to_string()
        } else {
            printable(&v.changed_by_admin_id)
        };
        println!(
            "  v{}  {:<8} {}  by {by}",
            v.row_version,
            change_kind_name(v.change_kind),
            when(v.changed_at)
        );
    }
    Ok(())
}

async fn update(admin: &mut Admin, u: UpdateArgs) -> anyhow::Result<()> {
    let current = admin
        .get_approval(GetApprovalRequest {
            approval_id: u.approval_id.clone(),
        })
        .await
        .map_err(rpc_err)?
        .into_inner()
        .approval
        .ok_or_else(|| anyhow::anyhow!("no approval {}", printable(&u.approval_id)))?;
    let r = admin
        .update_approval(UpdateApprovalRequest {
            idempotency_key: idempotency_key(),
            approval_id: u.approval_id,
            expected_row_version: current.row_version,
            update_policy: u.update_policy,
            continuity: u.continuity,
            expires_at: u.expires_at,
            clear_expiry: u.clear_expiry,
            note: u.note,
            clear_note: u.clear_note,
            narrow_to_exact_user: u.narrow_user,
            narrow_to_exact_path: u.narrow_path,
        })
        .await
        .map_err(rpc_err)?
        .into_inner();
    if let Some(a) = &r.approval {
        print_approval(a);
    }
    println!("allowlist generation: {}", r.allowlist_generation);
    Ok(())
}

async fn register(admin: &mut Admin, r: RegisterArgs, prompter: &Prompter) -> anyhow::Result<()> {
    let code = prompter.secret("TOTP code (fresh second factor for the direct registration)")?;
    let resp = admin
        .admin_register_application(AdminRegisterApplicationRequest {
            idempotency_key: idempotency_key(),
            proof: proof(code),
            host_uuid: r.host,
            binary: Some(r.binary),
            target_user: Some(r.user),
            reason: r.reason,
            terms: Some(r.terms),
        })
        .await
        .map_err(rpc_err)?
        .into_inner();
    if let Some(req) = &resp.request {
        println!("request: {}", printable(&req.request_id));
    }
    match (&resp.approval, resp.queued, resp.deduplicated) {
        (Some(a), _, true) => println!("already approved by {}", printable(&a.approval_id)),
        (Some(a), _, false) => {
            println!("approval: {}", printable(&a.approval_id));
            println!("expires_at: {}", when(a.expires_at));
        }
        (None, true, _) => println!("queued for another approver (strict separation of duties)"),
        (None, false, _) => {}
    }
    if resp.allowlist_generation != 0 {
        println!("allowlist generation: {}", resp.allowlist_generation);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(s: &str) -> Vec<String> {
        s.split_whitespace().map(str::to_string).collect()
    }

    #[test]
    fn state_names_parse_and_unknown_ones_are_refused() {
        assert_eq!(request_state_code("pending").unwrap(), 1);
        assert_eq!(request_state_code("auto").unwrap(), 3);
        assert_eq!(request_state_code("expired").unwrap(), 5);
        assert!(request_state_code("nope").is_err());
        assert_eq!(approval_state_code("revoked").unwrap(), 3);
        assert!(approval_state_code("pending").is_err());
        assert_eq!(request_state_name(4), "denied");
        assert_eq!(approval_state_name(1), "active");
        assert_eq!(approval_state_name(9), "?");
    }

    #[test]
    fn terms_default_to_the_narrowest_choice() {
        let t = build_terms(&args("--note x")).unwrap();
        assert_eq!(
            (t.user_scope, t.path_match, t.update_policy, t.continuity),
            (1, 1, 1, 1)
        );
        assert_eq!(
            (t.expires_at, t.no_expiry, t.note.as_str()),
            (0, false, "x")
        );
        assert!(!t.confirm_any_user);
    }

    #[test]
    fn terms_flags_map_to_codes() {
        let t = build_terms(&args(
            "--policy auto --continuity path-user --any-user --confirm-any-user --any-path --expires-at 99",
        ))
        .unwrap();
        assert_eq!(
            (t.user_scope, t.path_match, t.update_policy, t.continuity),
            (2, 2, 2, 2)
        );
        assert_eq!(t.expires_at, 99);
        assert!(t.confirm_any_user);
        assert!(build_terms(&args("--no-expiry")).unwrap().no_expiry);
    }

    #[test]
    fn terms_refuse_unconfirmed_any_user_and_conflicts() {
        assert!(build_terms(&args("--any-user")).is_err());
        assert!(build_terms(&args("--confirm-any-user")).is_err());
        assert!(build_terms(&args("--no-expiry --expires-at 5")).is_err());
        assert!(build_terms(&args("--policy sometimes")).is_err());
        assert!(build_terms(&args("--expires-at soon")).is_err());
    }

    #[test]
    fn the_sha384_is_validated_and_lowercased() {
        let good = "ab".repeat(48);
        assert_eq!(sha384_hex(&good).unwrap(), good);
        assert_eq!(sha384_hex(&good.to_uppercase()).unwrap(), good);
        assert!(sha384_hex(&"ab".repeat(47)).is_err());
        assert!(sha384_hex(&"zz".repeat(48)).is_err());
        assert!(sha384_hex("").is_err());
    }

    #[test]
    fn unknown_actions_and_flags_are_refused_before_any_sign_in() {
        assert!(validate(&args("")).is_err());
        assert!(validate(&args("frobnicate")).is_err());
        assert!(validate(&args("requests --bogus 1")).is_err());
        assert!(validate(&args("requests --state")).is_err());
        assert!(validate(&args("request")).is_err());
        assert!(validate(&args("request a b")).is_err());
        assert!(validate(&args("revoke abc")).is_err());
        assert!(validate(&args("revoke abc --reason-code 0")).is_err());
        assert!(validate(&args("deny abc --reason-code 3")).is_ok());
        assert!(validate(&args("update abc")).is_err());
        assert!(validate(&args("update abc --note a --clear-note")).is_err());
        assert!(validate(&args("update abc --narrow-user")).is_ok());
        assert!(validate(&args("freeze lin")).is_ok());
    }

    #[test]
    fn approve_rules() {
        assert!(matches!(
            parse(&args("approve r1 --reuse a1")).unwrap(),
            Command::Approve(a) if matches!(a.choice, Choice::ReuseApprovalId(_))
        ));
        assert!(parse(&args("approve r1 --reuse a1 --policy auto")).is_err());
        assert!(parse(&args("approve r1 --also-revoke a2")).is_err());
        let Command::Approve(a) = parse(&args(
            "approve r1 --also-revoke a2 --also-revoke a3 --revoke-reason 2 --self",
        ))
        .unwrap() else {
            panic!("approve")
        };
        assert_eq!(
            (a.also_revoke.len(), a.revoke_reason, a.own_request),
            (2, 2, true)
        );
    }

    #[test]
    fn register_builds_the_binary_and_user() {
        let sha = "cd".repeat(48);
        let line = format!(
            "register --host 11111111-1111-8111-8111-111111111111 --path /opt/t --sha384 {sha} \
             --platform linux --uid 1000 --user alice --path-protected --version 1.2"
        );
        let Command::Register(r) = parse(&args(&line)).unwrap() else {
            panic!("register")
        };
        assert_eq!(r.binary.flags, 1);
        assert_eq!((r.binary.platform, r.binary.format), (1, 1));
        assert_eq!((r.user.kind, r.user.uid), (1, Some(1000)));
        assert_eq!(r.binary.declared_version, "1.2");

        let win = line
            .replace("linux", "windows")
            .replace("--uid 1000", "--sid S-1-5-21-1");
        let Command::Register(r) = parse(&args(&win)).unwrap() else {
            panic!("register")
        };
        assert_eq!((r.user.kind, r.binary.format), (2, 3));

        assert!(parse(&args(&line.replace("--uid 1000", ""))).is_err());
        assert!(parse(&args(&line.replace("--host 11111111", "--host zzz"))).is_err());
        assert!(parse(&args(&line.replace(&sha, "abc"))).is_err());
        assert!(parse(&args(&line.replace("--user alice", ""))).is_err());
    }

    #[test]
    fn listings_default_to_fifty_items() {
        let Command::Requests { limit, .. } = parse(&args("requests")).unwrap() else {
            panic!("requests")
        };
        assert_eq!(limit, 50);
        assert!(parse(&args("requests --limit 0")).is_err());
        let Command::Approvals { states, .. } =
            parse(&args("approvals --state active --state revoked")).unwrap()
        else {
            panic!("approvals")
        };
        assert_eq!(states, vec![1, 3]);
    }

    #[test]
    fn idempotency_keys_fit_the_server_rule() {
        let k = idempotency_key();
        assert!((1..=60).contains(&k.len()));
        assert!(k.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'));
        assert_ne!(k, idempotency_key());
    }
}
