//! `mia app register | status | list` — application registration from the
//! command line (feature F19 §7.7).
//!
//! `register` and `status` are clients of the running daemon's helper socket
//! (helper protocol v2): they run unprivileged, as the user asking. For
//! `register --exe` the CLI opens the file **itself** and passes the open
//! descriptor with `SCM_RIGHTS`, so the daemon only ever hashes what the user
//! could open. `list` reads this host's verified allowlist (and, as root, the
//! local request ledger) offline.
//!
//! Exit status of `register` (and `status` for a single id): 0 approved,
//! 3 pending or queued, 4 denied (or expired/refused), 1 error, 2 usage.

use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::time::Duration;

use std::fmt::Write as _;

use anyhow::Context as _;
use mia_helper_proto::{
    format_id, parse_id, HelperFrame, HelperOp, LocalRequestStatus, LocalState, RegErrorCode,
    RegistrationResp, UserSel, ID_LEN,
};

use crate::config::Config;

const USAGE: &str = "\
usage: mia app register --exe <path> [--for-user <name|uid|SID>] [--reason <text>] [--json]
       mia app status [<request-id>…] [--json]
       mia app list [--json]
common: [-e|--environment <env>] [--config <path>]";

/// Exit: approved.
pub const EXIT_APPROVED: i32 = 0;
/// Exit: error.
pub const EXIT_ERROR: i32 = 1;
/// Exit: usage.
pub const EXIT_USAGE: i32 = 2;
/// Exit: pending or queued.
pub const EXIT_PENDING: i32 = 3;
/// Exit: denied, expired or refused.
pub const EXIT_DENIED: i32 = 4;

/// How long the daemon may take to identify a large binary.
#[cfg(unix)]
const REPLY_TIMEOUT: Duration = Duration::from_secs(180);

/// A parsed `mia app` command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppArgs {
    /// The subcommand.
    pub command: AppCommand,
    /// `--json`.
    pub json: bool,
    /// `--environment`.
    pub environment: Option<String>,
    /// `--config`.
    pub config: Option<PathBuf>,
}

/// The `mia app` subcommands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppCommand {
    /// `register --exe <path>`.
    Register {
        /// The executable.
        exe: PathBuf,
        /// `--for-user`.
        for_user: Option<UserSel>,
        /// `--reason`.
        reason: Option<String>,
    },
    /// `status [ids…]`.
    Status {
        /// Local or CMIS request ids.
        ids: Vec<[u8; ID_LEN]>,
    },
    /// `list`.
    List,
    /// `--help`.
    Help,
}

/// Parse `mia app` arguments (everything after `app`).
pub fn parse(args: &[String]) -> Result<AppArgs, String> {
    let mut it = args.iter();
    let sub = it.next().map(String::as_str);
    let mut json = false;
    let mut environment = None;
    let mut config = None;
    let mut exe = None;
    let mut for_user = None;
    let mut reason = None;
    let mut ids = Vec::new();
    if matches!(sub, None | Some("-h" | "--help" | "help")) {
        return Ok(AppArgs {
            command: AppCommand::Help,
            json,
            environment,
            config,
        });
    }
    while let Some(arg) = it.next() {
        let mut value = |name: &str| {
            it.next()
                .cloned()
                .ok_or_else(|| format!("{name} requires a value"))
        };
        match arg.as_str() {
            "--json" => json = true,
            "-e" | "--environment" => {
                let env = value("--environment")?;
                crate::config::validate_environment(&env).map_err(|e| e.to_string())?;
                environment = Some(env);
            }
            "--config" => config = Some(PathBuf::from(value("--config")?)),
            "--exe" if sub == Some("register") => exe = Some(PathBuf::from(value("--exe")?)),
            "--for-user" if sub == Some("register") => {
                for_user = Some(user_sel(&value("--for-user")?));
            }
            "--reason" if sub == Some("register") => {
                let r = value("--reason")?;
                if r.chars().count() > mia_helper_proto::MAX_REASON_CHARS {
                    return Err("--reason is longer than 200 characters".into());
                }
                reason = Some(r);
            }
            "-h" | "--help" => {
                return Ok(AppArgs {
                    command: AppCommand::Help,
                    json,
                    environment,
                    config,
                })
            }
            id if sub == Some("status") && !id.starts_with('-') => {
                ids.push(parse_id(id).ok_or_else(|| format!("not a request id: {id}"))?);
                if ids.len() > mia_helper_proto::MAX_STATUS_IDS {
                    return Err("at most 50 request ids".into());
                }
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    if environment.is_some() && config.is_some() {
        return Err("--environment and --config are mutually exclusive".into());
    }
    let command = match sub {
        Some("register") => AppCommand::Register {
            exe: exe.ok_or("register requires --exe <path>")?,
            for_user,
            reason,
        },
        Some("status") => AppCommand::Status { ids },
        Some("list") => AppCommand::List,
        Some(other) => return Err(format!("unknown subcommand: app {other}")),
        None => AppCommand::Help,
    };
    Ok(AppArgs {
        command,
        json,
        environment,
        config,
    })
}

/// `--for-user`: digits are a uid, `S-…` a SID, anything else a name.
fn user_sel(v: &str) -> UserSel {
    if let Ok(uid) = v.parse::<u32>() {
        UserSel::Uid(uid)
    } else if v.len() > 2 && v[..2].eq_ignore_ascii_case("S-") {
        UserSel::Sid(v.to_string())
    } else {
        UserSel::Name(v.to_string())
    }
}

/// Run `mia app …` and return the exit status.
#[must_use]
pub fn run(args: &[String]) -> i32 {
    let parsed = match parse(args) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("mia app: {e}\n\n{USAGE}");
            return EXIT_USAGE;
        }
    };
    match execute(&parsed) {
        Ok(code) => code,
        Err(e) => {
            if parsed.json {
                println!("{}", serde_json::json!({ "error": format!("{e:#}") }));
            } else {
                eprintln!("mia app: {e:#}");
            }
            EXIT_ERROR
        }
    }
}

fn execute(args: &AppArgs) -> anyhow::Result<i32> {
    if args.command == AppCommand::Help {
        println!("{USAGE}");
        return Ok(EXIT_APPROVED);
    }
    let (config, _) = Config::load(args.config.as_deref(), args.environment.as_deref())?;
    match &args.command {
        AppCommand::Register {
            exe,
            for_user,
            reason,
        } => register(&config, exe, for_user.clone(), reason.clone(), args.json),
        AppCommand::Status { ids } => status(&config, ids, args.json),
        AppCommand::List => list(&config, args.json),
        AppCommand::Help => Ok(EXIT_APPROVED),
    }
}

fn socket(config: &Config) -> anyhow::Result<PathBuf> {
    config
        .helper_socket()
        .context("the helper API is switched off for this environment (helper.enable = false)")
}

fn register(
    config: &Config,
    exe: &Path,
    for_user: Option<UserSel>,
    reason: Option<String>,
    json: bool,
) -> anyhow::Result<i32> {
    // Open the file as the invoking user: the daemon hashes this descriptor.
    let file =
        std::fs::File::open(exe).with_context(|| format!("cannot open {}", exe.display()))?;
    let op = HelperOp::RegisterFile {
        client_request_id: mia_helper_proto::uuid_v4(crate::host_api::random_bytes()),
        path: exe.display().to_string(),
        for_user,
        reason,
    };
    let resp = exchange(&socket(config)?, &HelperFrame::new(op), Some(&file))?;
    Ok(report_registration(&resp, json))
}

fn status(config: &Config, ids: &[[u8; ID_LEN]], json: bool) -> anyhow::Result<i32> {
    let op = HelperOp::RequestStatus {
        request_ids: ids.to_vec(),
    };
    let resp = exchange(&socket(config)?, &HelperFrame::new(op), None)?;
    match resp {
        RegistrationResp::Status(items) => {
            if json {
                let rows: Vec<_> = items.iter().map(status_json).collect();
                println!("{}", serde_json::Value::Array(rows));
            } else if items.is_empty() {
                println!("no registration requests");
            } else {
                for s in &items {
                    println!("{}", status_line(s));
                }
            }
            Ok(match items.as_slice() {
                [only] if ids.len() == 1 => exit_for(only.state),
                _ => EXIT_APPROVED,
            })
        }
        other => Ok(report_registration(&other, json)),
    }
}

/// Print a registration reply and map it to the exit status.
fn report_registration(resp: &RegistrationResp, json: bool) -> i32 {
    match resp {
        RegistrationResp::Submitted {
            request_id,
            local_id,
            state,
            revision,
            approval_id,
            retry_after,
        } => {
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "local_id": format_id(local_id),
                        "request_id": request_id.as_ref().map(format_id),
                        "state": state.as_str(),
                        "revision": revision,
                        "approval_id": approval_id.as_ref().map(format_id),
                        "retry_after": retry_after,
                    })
                );
            } else {
                let mut line = format!("request {}: {}", format_id(local_id), state.as_str());
                if let Some(r) = request_id {
                    let _ = write!(line, " (CMIS request {})", format_id(r));
                }
                if let Some(rev) = revision {
                    let _ = write!(line, ", revision r{rev}");
                }
                println!("{line}");
                if *state == LocalState::Queued {
                    println!("  queued on this host; it is sent when CMIS accepts requests");
                }
            }
            exit_for(*state)
        }
        RegistrationResp::AlreadyApproved { approval_id } => {
            if json {
                println!(
                    "{}",
                    serde_json::json!({ "state": "approved", "approval_id": format_id(approval_id) })
                );
            } else {
                println!("already approved (approval {})", format_id(approval_id));
            }
            EXIT_APPROVED
        }
        RegistrationResp::Status(_) => EXIT_ERROR,
        RegistrationResp::Error { code, retry_after } => {
            if json {
                println!(
                    "{}",
                    serde_json::json!({ "error": code.as_str(), "retry_after": retry_after })
                );
            } else {
                eprintln!("mia app: {}", error_text(*code, *retry_after));
            }
            EXIT_ERROR
        }
    }
}

fn error_text(code: RegErrorCode, retry_after: Option<u32>) -> String {
    let what = match code {
        RegErrorCode::PermissionDenied => "permission denied",
        RegErrorCode::RegistrationDisabled => "registration is switched off on this host",
        RegErrorCode::ServerUnsupported => "not supported by this agent or its CMIS",
        RegErrorCode::FileNotEligible => {
            "the file cannot be registered (not a readable, executable regular file)"
        }
        RegErrorCode::FileTooLarge => "the file is larger than registration.max_file_size_mib",
        RegErrorCode::RateLimited => "too many registration requests",
        RegErrorCode::MalformedRequest => "malformed request",
        RegErrorCode::Internal => "internal error in the agent",
    };
    match retry_after {
        Some(s) => format!("{what}; retry in {s} s"),
        None => what.to_string(),
    }
}

/// The exit status for a request state.
#[must_use]
pub const fn exit_for(state: LocalState) -> i32 {
    match state {
        LocalState::Approved | LocalState::AutoApproved => EXIT_APPROVED,
        LocalState::Queued | LocalState::Pending => EXIT_PENDING,
        LocalState::Denied | LocalState::Expired | LocalState::Refused => EXIT_DENIED,
    }
}

fn status_line(s: &LocalRequestStatus) -> String {
    let mut line = format!(
        "{}  {:<13} {}",
        format_id(&s.local_id),
        s.state.as_str(),
        s.path
    );
    if let Some(rev) = s.revision {
        let _ = write!(line, "  r{rev}");
    }
    if let Some(m) = &s.deny_message {
        let _ = write!(line, "  — {}", printable(m));
    }
    line
}

fn status_json(s: &LocalRequestStatus) -> serde_json::Value {
    serde_json::json!({
        "local_id": format_id(&s.local_id),
        "request_id": s.request_id.as_ref().map(format_id),
        "state": s.state.as_str(),
        "revision": s.revision,
        "approval_id": s.approval_id.as_ref().map(format_id),
        "path": s.path,
        "updated_at": s.updated_at,
        "deny_reason_code": s.deny_reason_code,
        "deny_message": s.deny_message,
    })
}

/// Text from CMIS or the ledger, with control characters (terminal escapes)
/// replaced.
fn printable(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { '\u{fffd}' } else { c })
        .collect()
}

/// One request/response exchange on the helper socket, passing `file`'s
/// descriptor with the frame on Unix.
fn exchange(
    endpoint: &Path,
    frame: &HelperFrame,
    file: Option<&std::fs::File>,
) -> anyhow::Result<RegistrationResp> {
    let bytes = mia_helper_proto::encode_frame(frame)?;
    #[cfg(unix)]
    {
        use std::io::Write as _;
        let mut stream = std::os::unix::net::UnixStream::connect(endpoint)
            .with_context(|| format!("cannot reach the agent at {}", endpoint.display()))?;
        stream.set_read_timeout(Some(REPLY_TIMEOUT))?;
        stream.set_write_timeout(Some(Duration::from_secs(10)))?;
        let sent = send_with_fd(&stream, &bytes, file)?;
        stream.write_all(&bytes[sent..])?;
        read_reply(&mut stream)
    }
    #[cfg(windows)]
    {
        use std::io::Write as _;
        let _ = file; // Windows opens the file under the client's token (follow-up).
        let mut pipe = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(endpoint)
            .with_context(|| format!("cannot reach the agent at {}", endpoint.display()))?;
        pipe.write_all(&bytes)?;
        read_reply(&mut pipe)
    }
}

fn read_reply<R: std::io::Read>(r: &mut R) -> anyhow::Result<RegistrationResp> {
    match mia_helper_proto::read_frame(r) {
        Ok(resp) => Ok(resp),
        Err(mia_helper_proto::ProtoError::Io(e))
            if e.kind() == std::io::ErrorKind::UnexpectedEof =>
        {
            anyhow::bail!(
                "the agent closed the connection without answering: it predates app registration \
                 (helper protocol v2); upgrade mia"
            )
        }
        Err(e) => Err(e.into()),
    }
}

/// Send the start of `bytes` with `file`'s descriptor attached; returns how
/// many bytes went out.
#[cfg(unix)]
fn send_with_fd(
    stream: &std::os::unix::net::UnixStream,
    bytes: &[u8],
    file: Option<&std::fs::File>,
) -> anyhow::Result<usize> {
    use rustix::net::{SendAncillaryBuffer, SendAncillaryMessage, SendFlags};
    use std::mem::MaybeUninit;
    use std::os::fd::AsFd as _;
    let Some(file) = file else { return Ok(0) };
    let fds = [file.as_fd()];
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut control = SendAncillaryBuffer::new(&mut space);
    anyhow::ensure!(
        control.push(SendAncillaryMessage::ScmRights(&fds)),
        "internal: control buffer too small"
    );
    let sent = rustix::net::sendmsg(
        stream,
        &[std::io::IoSlice::new(bytes)],
        &mut control,
        SendFlags::empty(),
    )
    .context("sending the request")?;
    Ok(sent)
}

fn list(config: &Config, json: bool) -> anyhow::Result<i32> {
    use crate::helper::allowlist::Allowlist;
    let key_path = config
        .allowlist_key()
        .context("allowlist.key is not configured; nothing can verify the allowlist")?;
    let key = ferro_crypto::composite::CompositePublicKey::from_concat_bytes(
        &crate::system_dir::read_trusted(key_path)
            .with_context(|| format!("reading {}", key_path.display()))?,
    )
    .map_err(|e| anyhow::anyhow!("allowlist.key unparseable: {e}"))?;
    let synced = crate::allowlist_sync::synced_body_path(&config.allowlist_state_path());
    let body_path = if config.allowlist_sync_enabled() && synced.exists() {
        synced
    } else {
        config.allowlist_path()
    };
    let bytes = crate::system_dir::read_trusted(&body_path)
        .with_context(|| format!("reading {}", body_path.display()))?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX));
    let allowlist = Allowlist::load(&bytes, &key, now, config.allowlist_max_age())
        .map_err(|e| anyhow::anyhow!("{} does not verify: {e}", body_path.display()))?;
    let ledger = crate::registration::ledger::read_only(&config.registration_ledger_path());
    let path_of = |approval: &[u8; ID_LEN]| -> Option<String> {
        ledger
            .as_ref()
            .ok()?
            .iter()
            .find(|e| e.approval_id.as_ref() == Some(approval))
            .map(|e| e.path.clone())
    };
    let rows: Vec<serde_json::Value> = match allowlist.entries_v2() {
        Some(entries) => entries
            .iter()
            .map(|e| {
                serde_json::json!({
                    "approval_id": format_id(&e.approval_id),
                    "bin_sha": e.bin_sha,
                    "uid": e.uid,
                    "path_constrained": e.path_hash.is_some(),
                    "sid_constrained": e.user_sid_hash.is_some(),
                    "expires_at": e.expires_at,
                    "path": path_of(&e.approval_id),
                })
            })
            .collect(),
        None => allowlist
            .rules()
            .iter()
            .map(|r| {
                serde_json::json!({
                    "bin_sha": r.bin_sha.map_or_else(|| "*".to_string(), hex::encode),
                    "uids": match &r.uids {
                        crate::helper::allowlist::RuleUids::Any => serde_json::json!("any"),
                        crate::helper::allowlist::RuleUids::Only(u) => serde_json::json!(u),
                    },
                })
            })
            .collect(),
    };
    if json {
        println!(
            "{}",
            serde_json::json!({
                "source": body_path.display().to_string(),
                "format": allowlist.format(),
                "generation": allowlist.generation(),
                "not_after": allowlist.not_after(),
                "entries": rows,
                "ledger_readable": ledger.is_ok(),
            })
        );
        return Ok(EXIT_APPROVED);
    }
    print_list(&body_path, &allowlist, &rows);
    if ledger.is_err() {
        println!("(local request paths need root: the request ledger is not readable)");
    }
    Ok(EXIT_APPROVED)
}

/// The text form of `mia app list`.
fn print_list(
    body_path: &Path,
    allowlist: &crate::helper::allowlist::Allowlist,
    rows: &[serde_json::Value],
) {
    println!(
        "{} (format v{}{}), expires at {} — {} entr{}",
        body_path.display(),
        allowlist.format(),
        allowlist
            .generation()
            .map_or_else(String::new, |g| format!(", generation {g}")),
        allowlist.not_after(),
        rows.len(),
        if rows.len() == 1 { "y" } else { "ies" }
    );
    for row in rows {
        let sha = row["bin_sha"].as_str().unwrap_or("");
        let prefix = &sha[..sha.len().min(16)];
        let mut line = match row.get("approval_id").and_then(|v| v.as_str()) {
            Some(id) => format!("  {id}  {prefix}…"),
            None => format!("  {prefix}…"),
        };
        if let Some(uid) = row.get("uid").and_then(serde_json::Value::as_u64) {
            let _ = write!(line, "  uid {uid}");
        }
        if let Some(uids) = row.get("uids") {
            let _ = write!(line, "  uids {uids}");
        }
        if row["path_constrained"].as_bool() == Some(true) {
            line.push_str("  path-bound");
        }
        if row["sid_constrained"].as_bool() == Some(true) {
            line.push_str("  user-SID-bound");
        }
        if let Some(exp) = row.get("expires_at").and_then(serde_json::Value::as_i64) {
            let _ = write!(line, "  expires {exp}");
        }
        if let Some(p) = row.get("path").and_then(|v| v.as_str()) {
            let _ = write!(line, "  {}", printable(p));
        }
        println!("{line}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn register_parses_its_options() {
        let p = parse(&args(&[
            "register",
            "--exe",
            "/opt/tool",
            "--for-user",
            "alice",
            "--reason",
            "build agent",
            "--json",
            "-e",
            "prod",
        ]))
        .unwrap();
        assert_eq!(
            p.command,
            AppCommand::Register {
                exe: PathBuf::from("/opt/tool"),
                for_user: Some(UserSel::Name("alice".into())),
                reason: Some("build agent".into()),
            }
        );
        assert!(p.json);
        assert_eq!(p.environment.as_deref(), Some("prod"));
        assert_eq!(user_sel("1001"), UserSel::Uid(1001));
        assert_eq!(
            user_sel("S-1-5-21-1-2-3-1001"),
            UserSel::Sid("S-1-5-21-1-2-3-1001".into())
        );
    }

    #[test]
    fn status_and_list_parse() {
        let id = "01234567-89ab-cdef-0123-456789abcdef";
        let p = parse(&args(&["status", id, "--json"])).unwrap();
        assert_eq!(
            p.command,
            AppCommand::Status {
                ids: vec![parse_id(id).unwrap()]
            }
        );
        assert_eq!(
            parse(&args(&["status"])).unwrap().command,
            AppCommand::Status { ids: vec![] }
        );
        assert_eq!(parse(&args(&["list"])).unwrap().command, AppCommand::List);
        assert_eq!(parse(&args(&[])).unwrap().command, AppCommand::Help);
        assert_eq!(
            parse(&args(&["register", "--help"])).unwrap().command,
            AppCommand::Help
        );
    }

    #[test]
    fn usage_errors_are_reported() {
        for bad in [
            &["register"][..],
            &["register", "--exe"],
            &["register", "--exe", "/x", "--bogus"],
            &["status", "not-an-id"],
            &["list", "--exe", "/x"],
            &["frobnicate"],
            &["list", "-e", "../etc"],
            &["list", "-e", "prod", "--config", "/x.toml"],
        ] {
            assert!(parse(&args(bad)).is_err(), "{bad:?}");
        }
        let long = "x".repeat(201);
        assert!(parse(&args(&["register", "--exe", "/x", "--reason", &long])).is_err());
    }

    #[test]
    fn states_map_to_the_documented_exit_codes() {
        assert_eq!(exit_for(LocalState::Approved), 0);
        assert_eq!(exit_for(LocalState::AutoApproved), 0);
        assert_eq!(exit_for(LocalState::Queued), 3);
        assert_eq!(exit_for(LocalState::Pending), 3);
        assert_eq!(exit_for(LocalState::Denied), 4);
        assert_eq!(exit_for(LocalState::Expired), 4);
        assert_eq!(exit_for(LocalState::Refused), 4);
        assert_eq!(printable("a\u{1b}[31mb"), "a\u{fffd}[31mb");
    }
}
