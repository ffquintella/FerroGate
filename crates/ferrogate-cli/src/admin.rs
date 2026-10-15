//! `ferrogate admin …` and the admin session behind every authenticated
//! command (feature F20 §12).
//!
//! - Secrets (password, TOTP code, session token) are prompted **without
//!   echo** on a terminal and held in [`Zeroizing`] buffers; when standard
//!   input is not a terminal they are read one per line from it (scripted
//!   use, like `--password-stdin` elsewhere).
//! - The session token lives in memory. It is written to disk **only** with
//!   the opt-in `--session-file <path>` (or `$FERROGATE_SESSION_FILE`): mode
//!   `0600`, never through a symlink, removed on `admin logout`. Put it on a
//!   tmpfs such as `$XDG_RUNTIME_DIR`. Without a session file every
//!   authenticated command signs in, runs, and signs out.
//! - Every call goes to the admin listener (`--admin-endpoint`, default
//!   `https://127.0.0.1:8444`) over the pinned hybrid-PQC transport, with an
//!   optional client certificate for mTLS (`--client-cert`/`--client-key`).
//! - Sensitive commands that hit `step_up_required` re-verify the second
//!   factor (`BeginStepUp`/`StepUp`), adopt the rotated token, and retry once.
//! - The server-issued **device token** (F20 §6, the norm's "cookie": it
//!   selects the throttle bucket and authenticates nothing) is kept in a
//!   `0600` file — `--device-file`, `$FERROGATE_DEVICE_FILE`, default
//!   `~/.config/ferrogate/admin-device.token`; an empty value disables it — so
//!   attacks on the account counter cannot lock this administrator out.

use std::io::{BufRead as _, IsTerminal as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use ferro_proto::admin_v1::admin_client::AdminClient;
use ferro_proto::admin_v1::{
    login_request::SecondFactor, mfa_proof, BeginEnrollmentRequest, BeginLoginRequest,
    BeginStepUpRequest, ChangePasswordRequest, ClientInfo, CompleteEnrollmentRequest,
    CreateAdminAccountRequest, ListAdminAccountsRequest, ListAdminGroupsRequest,
    ListMyFactorsRequest, ListMySessionsRequest, LoginRequest, LogoutRequest, MfaProof,
    RemoveFactorRequest, ResetAdminCredentialsRequest, RevokeSessionRequest,
    SetAdminAccountStateRequest, StepUpRequest, UpdateAdminAccountRequest, WhoAmIRequest,
};
use tonic::metadata::{Ascii, MetadataValue};
use tonic::service::interceptor::InterceptedService;
use tonic::service::Interceptor;
use tonic::transport::Channel;
use zeroize::Zeroizing;

use crate::{apps, migration, rpc_err, CmisError};

/// Default admin listener.
pub(crate) const DEFAULT_ADMIN_ENDPOINT: &str = "https://127.0.0.1:8444";
/// Client kind reported to CMIS (3 = CLI).
const CLIENT_KIND_CLI: u32 = 3;

pub(crate) fn usage() -> &'static str {
    "ferrogate admin — administrator sign-in and account management (F20)\n\
     \n\
     usage: ferrogate [--admin-endpoint <url>] [--session-file <path>] admin <subcommand>\n\
     \n\
     subcommands:\n\
     \x20 login                         sign in (username, password, TOTP); with\n\
     \x20                               --session-file the session is kept for later commands\n\
     \x20 logout                        end the session in --session-file and delete the file\n\
     \x20 whoami                        show the signed-in administrator\n\
     \x20 sessions [revoke <ref> [--account <admin_id>]]\n\
     \x20                               list or end sessions\n\
     \x20 passwd                        change your password (needs a fresh TOTP code)\n\
     \x20 bootstrap --token-file <path> create the first administrator on a fresh CMIS\n\
     \x20                               (run on the CMIS node that wrote the token)\n\
     \x20 enroll --token-file <path>    redeem an enrollment or reset token (TOTP)\n\
     \x20 accounts [list]               list administrator accounts\n\
     \x20 accounts create <username> --group <g>... [--display-name <n>] [--ttl <secs>]\n\
     \x20 accounts set-groups <admin_id> --group <g>...\n\
     \x20 accounts disable|enable <admin_id>\n\
     \x20 accounts reset <admin_id> [--password] [--mfa]\n\
     \x20 groups                        list groups and their permissions\n\
     \x20 factors [list]                list your second factors (TOTP, FIDO2 keys)\n\
     \x20 factors remove <factor_id>    remove one (needs a TOTP code; the last factor\n\
     \x20                               stays). FIDO2 keys are added from the tray client\n\
     \x20 apps <action>                 application approvals (F19); actions:\n\
     \x20                               requests, request, approve, deny, approvals,\n\
     \x20                               approval, update, revoke, freeze, unfreeze, register\n\
     \x20                               (`apps help` shows every flag)\n\
     \x20 migrate-allowlists [--dry-run]  import every legacy allowlist entry as an\n\
     \x20                               approval (legacy, no expiry); --dry-run only reports\n\
     \x20 set-allowlist-mode legacy|approvals [--yes] [--allow-unimported]\n\
     \x20                               switch the cluster's allowlist mode (F19 §11);\n\
     \x20                               going back to legacy asks for confirmation\n\
     \n\
     Secrets are prompted without echo; when stdin is not a terminal they are\n\
     read one per line from stdin. The session token is never printed."
}

// ---- prompting ---------------------------------------------------------------

/// Reads answers from the terminal (no echo for secrets) or, when stdin is not
/// a terminal, one line per answer from stdin.
pub(crate) struct Prompter {
    tty: bool,
}

impl Prompter {
    pub(crate) fn new() -> Self {
        Self {
            tty: std::io::stdin().is_terminal(),
        }
    }

    fn line(&self, label: &str) -> anyhow::Result<Zeroizing<String>> {
        if !self.tty {
            let mut buf = Zeroizing::new(String::new());
            let n = std::io::stdin().lock().read_line(&mut buf)?;
            if n == 0 {
                anyhow::bail!("no input for {label} (stdin closed)");
            }
            let trimmed = Zeroizing::new(buf.trim_end_matches(['\r', '\n']).to_string());
            return Ok(trimmed);
        }
        unreachable!("tty prompts go through `text` and `secret`")
    }

    pub(crate) fn text(&self, label: &str) -> anyhow::Result<String> {
        if self.tty {
            return inquire::Text::new(label)
                .prompt()
                .map_err(|e| anyhow::anyhow!("{label}: {e}"));
        }
        Ok(self.line(label)?.to_string())
    }

    pub(crate) fn secret(&self, label: &str) -> anyhow::Result<Zeroizing<String>> {
        if self.tty {
            return inquire::Password::new(label)
                .without_confirmation()
                .with_display_mode(inquire::PasswordDisplayMode::Hidden)
                .prompt()
                .map(Zeroizing::new)
                .map_err(|e| anyhow::anyhow!("{label}: {e}"));
        }
        self.line(label)
    }

    /// Whether answers come from a terminal (else one line each from stdin).
    pub(crate) fn is_tty(&self) -> bool {
        self.tty
    }

    /// A yes/no question on the terminal, defaulting to no. Without a
    /// terminal the answer is no: callers ask for an explicit flag instead.
    pub(crate) fn confirm(&self, label: &str) -> anyhow::Result<bool> {
        if !self.tty {
            return Ok(false);
        }
        inquire::Confirm::new(label)
            .with_default(false)
            .prompt()
            .map_err(|e| anyhow::anyhow!("{label}: {e}"))
    }

    /// A new password, typed twice on a terminal.
    pub(crate) fn new_password(&self) -> anyhow::Result<Zeroizing<String>> {
        let first = self.secret("New password (at least 24 characters)")?;
        if self.tty {
            let again = self.secret("Repeat the new password")?;
            if *first != *again {
                anyhow::bail!("the passwords differ");
            }
        }
        Ok(first)
    }
}

// ---- session and bearer -----------------------------------------------------

/// Adds `authorization: Bearer <token>` to every call while a session exists.
#[derive(Clone, Default)]
pub(crate) struct Bearer(Option<Arc<RwLock<Zeroizing<String>>>>);

impl Bearer {
    pub(crate) fn none() -> Self {
        Self(None)
    }
}

impl Interceptor for Bearer {
    fn call(&mut self, mut req: tonic::Request<()>) -> Result<tonic::Request<()>, tonic::Status> {
        if let Some(token) = &self.0 {
            let guard = token
                .read()
                .map_err(|_| tonic::Status::internal("session lock"))?;
            let header = Zeroizing::new(format!("Bearer {}", guard.as_str()));
            let mut value: MetadataValue<Ascii> = header
                .parse()
                .map_err(|_| tonic::Status::internal("session token is not ASCII"))?;
            value.set_sensitive(true);
            req.metadata_mut().insert("authorization", value);
        }
        Ok(req)
    }
}

/// An admin session: the token (shared with the [`Bearer`] interceptor) and,
/// when opted in, the file it is kept in.
pub(crate) struct Session {
    token: Arc<RwLock<Zeroizing<String>>>,
    file: Option<PathBuf>,
    /// Signed in by this process only; sign out when done.
    ephemeral: bool,
}

impl Session {
    fn new(token: Zeroizing<String>, file: Option<PathBuf>, ephemeral: bool) -> Self {
        Self {
            token: Arc::new(RwLock::new(token)),
            file,
            ephemeral,
        }
    }

    pub(crate) fn bearer(&self) -> Bearer {
        Bearer(Some(Arc::clone(&self.token)))
    }

    /// Adopt a rotated token (step-up, password change) and persist it.
    fn replace(&self, token: Zeroizing<String>) -> anyhow::Result<()> {
        if let Some(path) = &self.file {
            write_session_file(path, &token)?;
        }
        *self
            .token
            .write()
            .map_err(|_| anyhow::anyhow!("session lock poisoned"))? = token;
        Ok(())
    }
}

/// Write the session token to `path`: a fresh `0600` file, never through a
/// symlink or onto anything but a regular file.
pub(crate) fn write_session_file(path: &Path, token: &str) -> anyhow::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_file() => std::fs::remove_file(path)?,
        Ok(_) => anyhow::bail!("session file {} is not a regular file", path.display()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(path)
        .map_err(|e| anyhow::anyhow!("creating session file {}: {e}", path.display()))?;
    f.write_all(token.as_bytes())?;
    f.write_all(b"\n")?;
    f.sync_all()?;
    Ok(())
}

/// Read a session token, refusing a file readable by group or others.
pub(crate) fn read_session_file(path: &Path) -> anyhow::Result<Zeroizing<String>> {
    let meta = std::fs::symlink_metadata(path)
        .map_err(|e| anyhow::anyhow!("session file {}: {e}", path.display()))?;
    if !meta.file_type().is_file() {
        anyhow::bail!("session file {} is not a regular file", path.display());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if meta.permissions().mode() & 0o077 != 0 {
            anyhow::bail!(
                "session file {} is readable by group or others; refusing it",
                path.display()
            );
        }
    }
    let text = Zeroizing::new(std::fs::read_to_string(path)?);
    let token = Zeroizing::new(text.trim().to_string());
    if !token.starts_with("fgas_") {
        anyhow::bail!(
            "session file {} does not hold a session token",
            path.display()
        );
    }
    Ok(token)
}

// ---- connection --------------------------------------------------------------

/// Typed admin client carrying the session (if any).
pub(crate) type Admin = AdminClient<InterceptedService<Channel, Bearer>>;

fn client_info() -> Option<ClientInfo> {
    Some(ClientInfo {
        kind: CLIENT_KIND_CLI,
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

pub(crate) fn proof(code: Zeroizing<String>) -> Option<MfaProof> {
    Some(MfaProof {
        f: Some(mfa_proof::F::TotpCode(code.to_string())),
        nonce: Vec::new(),
    })
}

/// `true` when `err` is CMIS saying a fresh second factor is needed.
pub(crate) fn needs_step_up(err: &anyhow::Error) -> bool {
    err.chain().any(|e| {
        e.downcast_ref::<CmisError>().is_some_and(|c| {
            c.0.code() == tonic::Code::FailedPrecondition && c.0.message() == "step_up_required"
        })
    })
}

/// The per-user default device-token file.
pub(crate) fn default_device_file() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .filter(|h| !h.is_empty())
        .map(|h| PathBuf::from(h).join(".config/ferrogate/admin-device.token"))
}

fn read_device_token(path: Option<&Path>) -> String {
    let Some(meta) = path.and_then(|p| std::fs::symlink_metadata(p).ok()) else {
        return String::new();
    };
    if !meta.file_type().is_file() {
        return String::new();
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if meta.permissions().mode() & 0o077 != 0 {
            return String::new();
        }
    }
    path.and_then(|p| std::fs::read_to_string(p).ok())
        .map(|t| t.trim().to_string())
        .unwrap_or_default()
}

fn store_device_token(path: Option<&Path>, token: &str) {
    let Some(path) = path.filter(|_| !token.is_empty()) else {
        return;
    };
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    if let Err(e) = write_session_file(path, token) {
        eprintln!(
            "warning: could not keep the device token in {}: {e}",
            path.display()
        );
    }
}

/// Sign in interactively. Returns the session token (never printed).
pub(crate) async fn sign_in(
    channel: Channel,
    prompter: &Prompter,
    device_file: Option<&Path>,
) -> anyhow::Result<Zeroizing<String>> {
    let mut admin = AdminClient::with_interceptor(channel, Bearer::none());
    let device_token = read_device_token(device_file);
    let username = prompter.text("Username")?;
    let begin = admin
        .begin_login(BeginLoginRequest {
            username: username.clone(),
            device_token: device_token.clone(),
            client: client_info(),
        })
        .await
        .map_err(rpc_err)?
        .into_inner();
    let password = prompter.secret("Password")?;
    let code = prompter.secret("TOTP code")?;
    let resp = admin
        .login(LoginRequest {
            login_nonce: begin.login_nonce,
            username,
            password: password.to_string(),
            second_factor: Some(SecondFactor::TotpCode(code.to_string())),
            device_token,
            client: client_info(),
        })
        .await
        .map_err(rpc_err)?
        .into_inner();
    drop((password, code));
    store_device_token(device_file, &resp.device_token);
    if resp.password_change_required {
        eprintln!(
            "warning: your password has expired; run `ferrogate admin passwd` before anything else"
        );
    }
    Ok(Zeroizing::new(resp.session_token))
}

/// The session for an authenticated command: from `--session-file` when it
/// exists, else a fresh interactive sign-in that ends with the command.
pub(crate) async fn session_for_command(
    channel: Channel,
    session_file: Option<&Path>,
    device_file: Option<&Path>,
    prompter: &Prompter,
) -> anyhow::Result<Session> {
    if let Some(path) = session_file {
        if path.exists() {
            return Ok(Session::new(
                read_session_file(path)?,
                Some(path.to_path_buf()),
                false,
            ));
        }
    }
    let token = sign_in(channel, prompter, device_file).await?;
    Ok(Session::new(token, None, true))
}

/// Re-verify the second factor; adopt the rotated token.
pub(crate) async fn step_up(
    channel: Channel,
    session: &Session,
    prompter: &Prompter,
) -> anyhow::Result<()> {
    let mut admin = AdminClient::with_interceptor(channel, session.bearer());
    let begin = admin
        .begin_step_up(BeginStepUpRequest {})
        .await
        .map_err(rpc_err)?
        .into_inner();
    let code = prompter.secret("TOTP code (step-up for a sensitive operation)")?;
    let resp = admin
        .step_up(StepUpRequest {
            stepup_nonce: begin.stepup_nonce,
            proof: proof(code),
        })
        .await
        .map_err(rpc_err)?
        .into_inner();
    session.replace(Zeroizing::new(resp.session_token))
}

/// End an ephemeral session (best effort).
pub(crate) async fn finish(channel: Channel, session: &Session) {
    if session.ephemeral {
        let mut admin = AdminClient::with_interceptor(channel, session.bearer());
        if let Err(e) = admin.logout(LogoutRequest {}).await {
            eprintln!("warning: sign-out failed: {}", e.message());
        }
    }
}

// ---- `ferrogate admin …` -------------------------------------------------------

/// Arguments shared by the admin subcommands.
pub(crate) struct AdminArgs<'a> {
    pub(crate) channel: Channel,
    pub(crate) session_file: Option<&'a Path>,
    pub(crate) device_file: Option<&'a Path>,
    pub(crate) prompter: &'a Prompter,
}

pub(crate) fn flag_values(args: &[String], name: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == name {
            if let Some(v) = it.next() {
                out.push(v.clone());
            }
        }
    }
    out
}

pub(crate) fn flag_value(args: &[String], name: &str) -> Option<String> {
    flag_values(args, name).pop()
}

pub(crate) fn has_flag(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

/// Dispatch `ferrogate admin <sub>`.
pub(crate) async fn run(a: AdminArgs<'_>, sub: &str, args: &[String]) -> anyhow::Result<()> {
    match sub {
        "login" => login(a).await,
        "logout" => logout(a).await,
        "bootstrap" => enroll(a, args, true).await,
        "enroll" => enroll(a, args, false).await,
        "whoami" | "sessions" | "passwd" | "accounts" | "groups" | "factors" | "apps"
        | "migrate-allowlists" | "set-allowlist-mode" => {
            if matches!(sub, "migrate-allowlists" | "set-allowlist-mode") {
                if matches!(
                    args.first().map(String::as_str),
                    Some("help" | "-h" | "--help")
                ) {
                    println!("{}", migration::USAGE);
                    return Ok(());
                }
                // Typos are caught before a sign-in costs a TOTP code.
                migration::parse(sub, args)?;
            }
            if sub == "apps" {
                if matches!(
                    args.first().map(String::as_str),
                    Some("help" | "-h" | "--help")
                ) {
                    println!("{}", apps::usage());
                    return Ok(());
                }
                // Typos are caught before a sign-in costs a TOTP code.
                apps::validate(args)?;
            }
            let session =
                session_for_command(a.channel.clone(), a.session_file, a.device_file, a.prompter)
                    .await?;
            let result = authenticated(&a, &session, sub, args).await;
            let result = match result {
                Err(e) if needs_step_up(&e) => {
                    step_up(a.channel.clone(), &session, a.prompter).await?;
                    authenticated(&a, &session, sub, args).await
                }
                other => other,
            };
            finish(a.channel.clone(), &session).await;
            result
        }
        "help" | "-h" | "--help" => {
            println!("{}", usage());
            Ok(())
        }
        other => anyhow::bail!("unknown admin subcommand: {other}\n\n{}", usage()),
    }
}

async fn login(a: AdminArgs<'_>) -> anyhow::Result<()> {
    let token = sign_in(a.channel.clone(), a.prompter, a.device_file).await?;
    let session = Session::new(token, None, a.session_file.is_none());
    let mut admin = AdminClient::with_interceptor(a.channel.clone(), session.bearer());
    let who = admin
        .who_am_i(WhoAmIRequest {})
        .await
        .map_err(rpc_err)?
        .into_inner();
    println!("signed in as {} ({})", who.username, who.admin_id);
    println!("groups: {}", who.groups.join(", "));
    if let Some(path) = a.session_file {
        write_session_file(
            path,
            &session.token.read().map_err(|_| anyhow::anyhow!("lock"))?,
        )?;
        println!(
            "session kept in {} (0600); `ferrogate admin logout` ends it",
            path.display()
        );
    } else {
        println!("no --session-file given: credentials verified, signing out");
        finish(a.channel, &session).await;
    }
    Ok(())
}

async fn logout(a: AdminArgs<'_>) -> anyhow::Result<()> {
    let path = a.session_file.ok_or_else(|| {
        anyhow::anyhow!("logout needs --session-file (or $FERROGATE_SESSION_FILE)")
    })?;
    let token = read_session_file(path)?;
    let session = Session::new(token, None, false);
    let mut admin = AdminClient::with_interceptor(a.channel, session.bearer());
    let result = admin.logout(LogoutRequest {}).await;
    // Remove the file whatever the server said: the token must not linger.
    std::fs::remove_file(path)?;
    result.map_err(rpc_err)?;
    println!("signed out; {} removed", path.display());
    Ok(())
}

async fn enroll(a: AdminArgs<'_>, args: &[String], bootstrap: bool) -> anyhow::Result<()> {
    let path = flag_value(args, "--token-file")
        .ok_or_else(|| anyhow::anyhow!("--token-file <path> is required"))?;
    let token = Zeroizing::new(
        std::fs::read_to_string(&path)
            .map_err(|e| anyhow::anyhow!("reading {path}: {e}"))?
            .trim()
            .to_string(),
    );
    let mut admin = AdminClient::with_interceptor(a.channel, Bearer::none());
    let begin = admin
        .begin_enrollment(BeginEnrollmentRequest {
            enrollment_token: token.to_string(),
        })
        .await
        .map_err(rpc_err)?
        .into_inner();
    if bootstrap && !begin.username_choosable {
        anyhow::bail!("this is not a bootstrap token; use `ferrogate admin enroll`");
    }
    let (username, display_name) = if begin.username_choosable {
        (
            a.prompter.text("Username ([a-z0-9._-], 3-64)")?,
            a.prompter.text("Display name")?,
        )
    } else {
        println!("enrolling account {}", begin.username);
        (String::new(), String::new())
    };
    // A reset that kept the password ignores this value server-side.
    let password = a.prompter.new_password()?;
    if begin.totp_provisioning_uri.is_empty() {
        println!("your existing TOTP authenticator stays enrolled");
    } else {
        println!("add this account to your TOTP authenticator app (shown once):");
        println!("  {}", begin.totp_provisioning_uri);
    }
    let code = a.prompter.secret("TOTP code from the authenticator")?;
    let resp = admin
        .complete_enrollment(CompleteEnrollmentRequest {
            enrollment_token: token.to_string(),
            username,
            display_name,
            password: password.to_string(),
            totp_code: code.to_string(),
            // FIDO2 keys are registered from the tray admin client (F22).
            webauthn_attestation: None,
        })
        .await
        .map_err(rpc_err)?
        .into_inner();
    println!("enrolled administrator {}", resp.admin_id);
    if bootstrap {
        println!("bootstrap complete: every admin action now requires `ferrogate admin login`");
    }
    Ok(())
}

async fn authenticated(
    a: &AdminArgs<'_>,
    session: &Session,
    sub: &str,
    args: &[String],
) -> anyhow::Result<()> {
    let mut admin: Admin = AdminClient::with_interceptor(a.channel.clone(), session.bearer());
    match sub {
        "whoami" => {
            let w = admin
                .who_am_i(WhoAmIRequest {})
                .await
                .map_err(rpc_err)?
                .into_inner();
            println!("admin_id:            {}", w.admin_id);
            println!("username:            {}", w.username);
            println!("display_name:        {}", w.display_name);
            println!("groups:              {}", w.groups.join(", "));
            println!("permissions:         {}", w.permissions.join(", "));
            println!("aal:                 {}", w.aal);
            println!("password_expires_at: {} (unix)", w.password_expires_at);
            println!("restricted:          {}", w.restricted);
            Ok(())
        }
        "sessions" => sessions(&mut admin, args).await,
        "passwd" => passwd(&mut admin, session, a.prompter).await,
        "accounts" => accounts(&mut admin, args, a.prompter).await,
        "factors" => factors(&mut admin, args, a.prompter).await,
        "apps" => apps::run(&mut admin, args, a.prompter).await,
        "migrate-allowlists" | "set-allowlist-mode" => {
            migration::run(&mut admin, migration::parse(sub, args)?, a.prompter).await
        }
        "groups" => {
            let g = admin
                .list_admin_groups(ListAdminGroupsRequest {})
                .await
                .map_err(rpc_err)?
                .into_inner();
            for group in g.groups {
                println!(
                    "{}{}",
                    group.name,
                    if group.builtin { " (built-in)" } else { "" }
                );
                for p in group.permissions {
                    println!("    {p}");
                }
            }
            Ok(())
        }
        _ => unreachable!("dispatched above"),
    }
}

async fn sessions(admin: &mut Admin, args: &[String]) -> anyhow::Result<()> {
    if args.first().map(String::as_str) == Some("revoke") {
        let session_ref = args.get(1).ok_or_else(|| {
            anyhow::anyhow!("sessions revoke <session_ref> [--account <admin_id>]")
        })?;
        admin
            .revoke_session(RevokeSessionRequest {
                session_ref: session_ref.clone(),
                admin_id: flag_value(args, "--account").unwrap_or_default(),
            })
            .await
            .map_err(rpc_err)?;
        println!("session {session_ref} revoked");
        return Ok(());
    }
    let s = admin
        .list_my_sessions(ListMySessionsRequest {})
        .await
        .map_err(rpc_err)?
        .into_inner();
    for x in s.sessions {
        println!(
            "{}{}  from {}  created {}  last seen {}  aal {}",
            x.session_ref,
            if x.current { " (this)" } else { "" },
            x.source_ip,
            x.created_at,
            x.last_seen_at,
            x.aal
        );
    }
    Ok(())
}

/// A server-provided string made safe for a terminal: control characters
/// (including ANSI/OSC escape introducers) and bidi overrides removed
/// (F20 §12).
pub(crate) fn printable(text: &str) -> String {
    text.chars()
        .filter(|c| {
            !c.is_control() && !matches!(*c, '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
        })
        .collect()
}

/// `admin factors [list]` and `admin factors remove <factor_id>`. Adding a
/// factor is the tray admin client's job (F20 §5, F22 §3a); the CLI has no
/// authenticator access.
async fn factors(admin: &mut Admin, args: &[String], prompter: &Prompter) -> anyhow::Result<()> {
    match args.first().map_or("list", String::as_str) {
        "list" => {
            let f = admin
                .list_my_factors(ListMyFactorsRequest {})
                .await
                .map_err(rpc_err)?
                .into_inner();
            for x in f.factors {
                let method = match x.method {
                    1 => "totp",
                    2 => "fido2",
                    _ => "?",
                };
                println!(
                    "{}  {method}  {}  created {}  last used {}",
                    printable(&x.factor_id),
                    printable(&x.label),
                    x.created_at,
                    x.last_used_at
                );
            }
            Ok(())
        }
        "remove" => {
            let id = args
                .get(1)
                .ok_or_else(|| anyhow::anyhow!("factors remove <factor_id>"))?;
            let code = prompter.secret("TOTP code (proof of a factor you keep)")?;
            admin
                .remove_factor(RemoveFactorRequest {
                    idempotency_key: String::new(),
                    factor_id: id.clone(),
                    proof: proof(code),
                })
                .await
                .map_err(rpc_err)?;
            println!(
                "factor {} removed; your other sessions were ended",
                printable(id)
            );
            Ok(())
        }
        other => anyhow::bail!("unknown factors action: {other}\n\n{}", usage()),
    }
}

async fn passwd(admin: &mut Admin, session: &Session, prompter: &Prompter) -> anyhow::Result<()> {
    let current = prompter.secret("Current password")?;
    let new = prompter.new_password()?;
    let code = prompter.secret("TOTP code")?;
    let resp = admin
        .change_password(ChangePasswordRequest {
            current_password: current.to_string(),
            new_password: new.to_string(),
            proof: proof(code),
        })
        .await
        .map_err(rpc_err)?
        .into_inner();
    session.replace(Zeroizing::new(resp.session_token))?;
    println!(
        "password changed; it expires at {} (unix); your other sessions were ended",
        resp.password_expires_at
    );
    Ok(())
}

async fn account_row_version(admin: &mut Admin, admin_id: &str) -> anyhow::Result<u64> {
    let list = admin
        .list_admin_accounts(ListAdminAccountsRequest {})
        .await
        .map_err(rpc_err)?
        .into_inner();
    list.accounts
        .into_iter()
        .find(|x| x.admin_id == admin_id)
        .map(|x| x.row_version)
        .ok_or_else(|| anyhow::anyhow!("no account {admin_id}"))
}

#[allow(clippy::too_many_lines)] // one arm per `accounts` action.
async fn accounts(admin: &mut Admin, args: &[String], prompter: &Prompter) -> anyhow::Result<()> {
    let action = args.first().map_or("list", String::as_str);
    let target = || {
        args.get(1)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("accounts {action} needs an admin_id"))
    };
    match action {
        "list" => {
            let list = admin
                .list_admin_accounts(ListAdminAccountsRequest {})
                .await
                .map_err(rpc_err)?
                .into_inner();
            for x in list.accounts {
                let state = match x.state {
                    1 => "pending",
                    2 => "active",
                    3 => "disabled",
                    _ => "?",
                };
                println!(
                    "{}  {:<24} {:<9} {}",
                    x.admin_id,
                    x.username,
                    state,
                    x.groups.join(",")
                );
            }
            Ok(())
        }
        "create" => {
            let username = target()?;
            let groups = flag_values(args, "--group");
            let ttl = flag_value(args, "--ttl")
                .map(|v| v.parse::<i64>())
                .transpose()
                .map_err(|_| anyhow::anyhow!("--ttl must be seconds"))?
                .unwrap_or(0);
            let code = prompter.secret("TOTP code")?;
            let resp = admin
                .create_admin_account(CreateAdminAccountRequest {
                    idempotency_key: String::new(),
                    username,
                    display_name: flag_value(args, "--display-name").unwrap_or_default(),
                    groups,
                    proof: proof(code),
                    enrollment_ttl_secs: ttl,
                })
                .await
                .map_err(rpc_err)?
                .into_inner();
            println!("created account {} (pending enrollment)", resp.admin_id);
            println!("enrollment token (shown once; deliver it over a second channel after");
            println!(
                "verifying the person's identity; expires at {} unix):",
                resp.enrollment_expires_at
            );
            println!("  {}", resp.enrollment_token);
            Ok(())
        }
        "set-groups" => {
            let id = target()?;
            let version = account_row_version(admin, &id).await?;
            let code = prompter.secret("TOTP code")?;
            admin
                .update_admin_account(UpdateAdminAccountRequest {
                    idempotency_key: String::new(),
                    admin_id: id.clone(),
                    expected_row_version: version,
                    display_name: None,
                    replace_groups: true,
                    groups: flag_values(args, "--group"),
                    proof: proof(code),
                })
                .await
                .map_err(rpc_err)?;
            println!("groups of {id} replaced; their sessions were ended");
            Ok(())
        }
        "disable" | "enable" => {
            let id = target()?;
            let code = prompter.secret("TOTP code")?;
            admin
                .set_admin_account_state(SetAdminAccountStateRequest {
                    idempotency_key: String::new(),
                    admin_id: id.clone(),
                    state: if action == "disable" { 3 } else { 2 },
                    proof: proof(code),
                })
                .await
                .map_err(rpc_err)?;
            println!("account {id} {action}d");
            Ok(())
        }
        "reset" => {
            let id = target()?;
            let (password, mfa) = (has_flag(args, "--password"), has_flag(args, "--mfa"));
            let code = prompter.secret("TOTP code")?;
            let resp = admin
                .reset_admin_credentials(ResetAdminCredentialsRequest {
                    idempotency_key: String::new(),
                    admin_id: id.clone(),
                    reset_password: password || !mfa,
                    reset_mfa: mfa,
                    proof: proof(code),
                })
                .await
                .map_err(rpc_err)?
                .into_inner();
            println!("credentials of {id} reset; reset token (shown once, second channel):");
            println!("  {}", resp.enrollment_token);
            Ok(())
        }
        other => anyhow::bail!("unknown accounts action: {other}\n\n{}", usage()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_session_file_is_private_and_never_follows_a_symlink() {
        let dir =
            std::env::temp_dir().join(format!("ferrogate-cli-session-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("session");
        let token = format!("fgas_{}", "A".repeat(43));
        write_session_file(&path, &token).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(
                read_session_file(&path).is_err(),
                "group/world-readable refused"
            );
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert_eq!(read_session_file(&path).unwrap().as_str(), token);

        #[cfg(unix)]
        {
            let link = dir.join("link");
            std::os::unix::fs::symlink(&path, &link).unwrap();
            assert!(
                write_session_file(&link, &token).is_err(),
                "symlink refused"
            );
            assert!(read_session_file(&link).is_err());
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_bearer_header_is_added_only_with_a_session() {
        let mut none = Bearer::none();
        let req = none.call(tonic::Request::new(())).unwrap();
        assert!(req.metadata().get("authorization").is_none());

        let session = Session::new(Zeroizing::new("fgas_abc".into()), None, true);
        let mut b = session.bearer();
        let req = b.call(tonic::Request::new(())).unwrap();
        assert_eq!(
            req.metadata().get("authorization").unwrap(),
            "Bearer fgas_abc"
        );
        session.replace(Zeroizing::new("fgas_def".into())).unwrap();
        let req = b.call(tonic::Request::new(())).unwrap();
        assert_eq!(
            req.metadata().get("authorization").unwrap(),
            "Bearer fgas_def",
            "rotation is seen"
        );
    }

    #[test]
    fn step_up_is_recognised_from_the_status() {
        let e = rpc_err(tonic::Status::failed_precondition("step_up_required"));
        assert!(needs_step_up(&e));
        let e = rpc_err(tonic::Status::failed_precondition("tls_required"));
        assert!(!needs_step_up(&e));
    }
}
