//! The `ferrogate` CLI against a CMIS with the F20 admin listener: bootstrap
//! the first administrator, sign in with a session file, run the allowlist
//! admin commands, sign out, and see the old session refused.
//!
//! Secrets are fed on stdin (the CLI reads them one per line when stdin is not
//! a terminal). The server runs on a controlled clock so the test can compute
//! the TOTP codes the authenticator app would show.

#![allow(clippy::large_futures, clippy::too_many_lines)]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;

use cmis::admin::authz::AdminAuthz;
use cmis::admin::clock::{Clock, ManualClock};
use cmis::admin::keys::AdminKeys;
use cmis::admin::password::PasswordParams;
use cmis::admin::{AdminConfig, AdminState};
use cmis::credential::{CredentialError, CredentialMaker, WrappedCredential};
use cmis::{CmisConfig, CmisState};
use ferro_attest::{RimStore, TpmQuoteVerifier, VendorTrustStore};
use ferro_audit::{AuditLog, AuditStore, InProcessSigner, LocalDiskWormStore};
use ferro_crypto::pin::SpkiPin;
use ferro_crypto::tls::ProviderMode;
use ferro_svid::Issuer;
use rustls_pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::net::TcpListener;
use tokio::process::Command;

const PASSWORD: &str = "Tr0ub4dor&3-Correct!Horse_Battery";
const T0: i64 = 1_791_936_000;

struct NoCredentialMaker;
impl CredentialMaker for NoCredentialMaker {
    fn make_credential(
        &self,
        _ek_pub: &[u8],
        _aik_pub: &[u8],
        _secret: &[u8],
    ) -> Result<WrappedCredential, CredentialError> {
        Err(CredentialError::Wrap("unused".to_string()))
    }
}

struct Cmis {
    main: SocketAddr,
    admin: SocketAddr,
    pin: SpkiPin,
    clock: Arc<ManualClock>,
    state: Arc<AdminState>,
    dir: PathBuf,
}

impl Drop for Cmis {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

async fn spawn_cmis(tag: &str) -> Cmis {
    let dir = std::env::temp_dir().join(format!(
        "ferrogate-cli-admin-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let store: Arc<dyn AuditStore> = Arc::new(LocalDiskWormStore::open(dir.join("audit")).unwrap());
    let (signer, _pk) = InProcessSigner::generate("audit-cli-admin").unwrap();
    let cluster = Arc::new(
        ferro_raft::Cluster::start_single_node(dir.join("raft").to_string_lossy().into_owned())
            .await
            .unwrap(),
    );
    let cmis = Arc::new(CmisState::new(
        Issuer::generate("kid-cli-admin", "ferrogate.test").unwrap(),
        TpmQuoteVerifier::new(VendorTrustStore::default(), RimStore::new()),
        Box::new(NoCredentialMaker),
        CmisConfig::default(),
        AuditLog::new(store, Arc::new(signer)).unwrap(),
        cluster,
    ));
    let clock = Arc::new(ManualClock::new(T0));
    let config = AdminConfig {
        password_params: PasswordParams {
            m_cost_kib: 64,
            t_cost: 1,
            p_cost: 1,
        },
        trust_domain: "ferrogate.test".into(),
        bootstrap_token_file: dir.join("bootstrap.token"),
        ..AdminConfig::default()
    };
    let state = AdminState::new(
        Arc::clone(&cmis),
        config,
        AdminKeys::from_material(&[5; 32], &[6; 32]),
        Arc::clone(&clock) as Arc<dyn Clock>,
    )
    .await
    .unwrap();
    let authz = Arc::new(AdminAuthz::new(Arc::clone(&state)));

    let ck = rcgen::generate_simple_self_signed(vec!["cmis.test.ferrogate.invalid".to_string()])
        .unwrap();
    let pin = SpkiPin::from_certificate_der(ck.cert.der().as_ref()).unwrap();
    let tls = ferro_crypto::transport::server_config(
        ProviderMode::HybridOnly,
        vec![ck.cert.der().clone()],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.signing_key.serialize_der())),
    )
    .unwrap();
    let main_l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let admin_l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (main, admin) = (main_l.local_addr().unwrap(), admin_l.local_addr().unwrap());
    tokio::spawn(cmis::server::serve_main(
        main_l,
        Some(Arc::clone(&tls)),
        Arc::clone(&cmis),
        Some(Arc::clone(&authz)),
        true,
    ));
    tokio::spawn(cmis::server::serve_admin(admin_l, tls, cmis, authz));
    Cmis {
        main,
        admin,
        pin,
        clock,
        state,
        dir,
    }
}

impl Cmis {
    /// Run `ferrogate <args>` with `stdin` lines; returns (success, stdout, stderr).
    async fn run(&self, args: &[&str], stdin: &[&str]) -> (bool, String, String) {
        let mut full: Vec<String> = vec![
            "--endpoint".into(),
            format!("https://{}", self.main),
            "--admin-endpoint".into(),
            format!("https://{}", self.admin),
            "--spki-pin".into(),
            self.pin.to_hex(),
        ];
        full.extend(args.iter().map(|a| (*a).to_string()));
        let mut child = Command::new(env!("CARGO_BIN_EXE_ferrogate"))
            .args(&full)
            .env_remove("FERROGATE_SESSION_FILE")
            // Never touch the developer's real ~/.config.
            .env("FERROGATE_DEVICE_FILE", self.dir.join("device.token"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn ferrogate");
        let mut input = child.stdin.take().unwrap();
        for line in stdin {
            input.write_all(line.as_bytes()).await.unwrap();
            input.write_all(b"\n").await.unwrap();
        }
        drop(input);
        let out = child.wait_with_output().await.unwrap();
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }

    /// The TOTP code at the server's current time for `secret`.
    fn code(&self, secret: &[u8]) -> String {
        cmis::admin::totp::code_at(secret, cmis::admin::totp::step_at(self.clock.now()))
    }

    /// Bootstrap `root.admin` through the CLI; returns its TOTP secret.
    async fn bootstrap(&self) -> Vec<u8> {
        cmis::admin::bootstrap::arm(&self.state).await.unwrap();
        let token_file = self.dir.join("bootstrap.token");
        // Drive the CLI like the operator: answer the prompts, read the
        // otpauth:// URI it prints, and type the authenticator's code.
        let mut child = Command::new(env!("CARGO_BIN_EXE_ferrogate"))
            .args([
                "--admin-endpoint",
                &format!("https://{}", self.admin),
                "--spki-pin",
                &self.pin.to_hex(),
                "admin",
                "bootstrap",
                "--token-file",
                token_file.to_str().unwrap(),
            ])
            .env("FERROGATE_DEVICE_FILE", self.dir.join("device.token"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn ferrogate");
        let mut input = child.stdin.take().unwrap();
        for line in ["root.admin", "Root Admin", PASSWORD] {
            input
                .write_all(format!("{line}\n").as_bytes())
                .await
                .unwrap();
        }
        let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
        let mut printed = String::new();
        let uri = loop {
            let line = lines
                .next_line()
                .await
                .unwrap()
                .expect("CLI printed the URI");
            printed.push_str(&line);
            if let Some(i) = line.find("otpauth://") {
                break line[i..].to_string();
            }
        };
        assert!(
            uri.starts_with("otpauth://totp/FerroGate:admin?secret="),
            "{uri}"
        );
        let secret = secret_from_uri(&uri);
        input
            .write_all(format!("{}\n", self.code(&secret)).as_bytes())
            .await
            .unwrap();
        drop(input);
        while let Some(line) = lines.next_line().await.unwrap() {
            printed.push_str(&line);
        }
        let out = child.wait_with_output().await.unwrap();
        assert!(
            out.status.success(),
            "bootstrap: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(printed.contains("bootstrap complete"), "{printed}");
        assert!(!printed.contains(PASSWORD));
        secret
    }

    /// Sign in with a session file (advancing one TOTP step first).
    async fn login(&self, secret: &[u8], session: &Path) {
        self.clock.advance(30);
        let code = self.code(secret);
        let (ok, stdout, stderr) = self
            .run(
                &[
                    "admin",
                    "login",
                    "--session-file",
                    session.to_str().unwrap(),
                ],
                &["root.admin", PASSWORD, &code],
            )
            .await;
        assert!(ok, "login: {stderr}");
        assert!(stdout.contains("signed in as root.admin"), "{stdout}");
    }
}

/// The base32 secret of an `otpauth://` URI.
fn secret_from_uri(uri: &str) -> Vec<u8> {
    const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let start = uri.find("secret=").unwrap() + "secret=".len();
    let end = uri[start..].find('&').map_or(uri.len(), |i| start + i);
    let (mut out, mut buf, mut bits) = (Vec::new(), 0u32, 0u32);
    for c in uri[start..end].bytes() {
        let v = u32::try_from(A.iter().position(|&x| x == c).unwrap()).unwrap();
        buf = (buf << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((buf >> bits) & 0xff).unwrap());
        }
    }
    out
}

#[tokio::test]
async fn bootstrap_login_allowlist_logout_and_the_old_session_is_refused() {
    let cmis = spawn_cmis("flow").await;
    let secret = cmis.bootstrap().await;
    let session = cmis.dir.join("session");
    cmis.login(&secret, &session).await;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&session).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "session file is private");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let device = cmis.dir.join("device.token");
        let mode = std::fs::metadata(&device).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "the device token is kept privately");
        assert!(std::fs::read_to_string(&device)
            .unwrap()
            .starts_with("fgdt_"));
    }
    let token = std::fs::read_to_string(&session).unwrap();
    let s = session.to_str().unwrap();

    let host = "11111111-1111-8111-8111-111111111111";
    let bin_sha = hex::encode([0xAA; 48]);
    let (ok, stdout, stderr) = cmis
        .run(
            &[
                "--session-file",
                s,
                "allowlist",
                "set",
                "--host",
                host,
                "--entry",
                &format!("1000:{bin_sha}"),
                "--ttl",
                "3600",
            ],
            &[],
        )
        .await;
    assert!(ok, "allowlist set: {stderr}");
    assert!(stdout.contains("set allowlist"), "{stdout}");
    assert!(
        !stdout.contains(token.trim()) && !stderr.contains(token.trim()),
        "token never printed"
    );

    // `show` is a public read on the main endpoint.
    let (ok, stdout, _) = cmis.run(&["allowlist", "show", "--host", host], &[]).await;
    assert!(ok && stdout.contains("uid=1000"), "{stdout}");
    let (ok, stdout, stderr) = cmis
        .run(&["--session-file", s, "allowlist", "list"], &[])
        .await;
    assert!(ok && stdout.contains(host), "list: {stdout} {stderr}");
    let (ok, stdout, _) = cmis
        .run(&["--session-file", s, "admin", "whoami"], &[])
        .await;
    assert!(
        ok && stdout.contains("ferrogate-platform-operators"),
        "{stdout}"
    );

    // Keep a copy of the token, then sign out.
    let stale = cmis.dir.join("stale-session");
    std::fs::copy(&session, &stale).unwrap();
    let (ok, _, stderr) = cmis
        .run(&["--session-file", s, "admin", "logout"], &[])
        .await;
    assert!(ok, "logout: {stderr}");
    assert!(!session.exists(), "logout removes the session file");

    let (ok, _, stderr) = cmis
        .run(
            &[
                "--session-file",
                stale.to_str().unwrap(),
                "allowlist",
                "list",
            ],
            &[],
        )
        .await;
    assert!(!ok);
    assert!(stderr.contains("session_invalid"), "{stderr}");

    // Without a session the CLI signs in; with nothing on stdin it stops.
    let (ok, _, stderr) = cmis.run(&["list-svids"], &[]).await;
    assert!(!ok && stderr.contains("no input"), "{stderr}");
}

#[tokio::test]
async fn allowlist_set_show_list_get_delete_roundtrip() {
    let cmis = spawn_cmis("crud").await;
    let secret = cmis.bootstrap().await;
    let session = cmis.dir.join("session");
    cmis.login(&secret, &session).await;
    let s = session.to_str().unwrap();
    let host = "11111111-1111-8111-8111-111111111111";
    let bin_sha = hex::encode([0xAA; 48]);

    let (ok, _, stderr) = cmis
        .run(
            &[
                "--session-file",
                s,
                "allowlist",
                "set",
                "--host",
                host,
                "--entry",
                &format!("1000:{bin_sha}"),
                "--ttl",
                "3600",
            ],
            &[],
        )
        .await;
    assert!(ok, "set: {stderr}");
    let (ok, stdout, _) = cmis.run(&["allowlist", "show", "--host", host], &[]).await;
    assert!(
        ok && stdout.contains(&bin_sha) && stdout.contains("uid=1000"),
        "{stdout}"
    );

    // get --out writes signed CBOR the MIA verifier accepts.
    let cbor = cmis.dir.join("al.cbor");
    let (ok, _, stderr) = cmis
        .run(
            &[
                "allowlist",
                "get",
                "--host",
                host,
                "--out",
                cbor.to_str().unwrap(),
            ],
            &[],
        )
        .await;
    assert!(ok, "get: {stderr}");
    let signed = ferro_svid::allowlist::decode(&std::fs::read(&cbor).unwrap()).unwrap();
    let doc = ferro_svid::allowlist::decode_body(&signed.body).unwrap();
    assert_eq!(doc.entries[0].uid, Some(1000));

    // Wildcard uid (ADR-0002).
    let (ok, _, stderr) = cmis
        .run(
            &[
                "--session-file",
                s,
                "allowlist",
                "set",
                "--host",
                host,
                "--entry",
                &bin_sha,
                "--ttl",
                "3600",
            ],
            &[],
        )
        .await;
    assert!(ok, "wildcard set: {stderr}");
    let (_, stdout, _) = cmis.run(&["allowlist", "show", "--host", host], &[]).await;
    assert!(stdout.contains("uid=*"), "{stdout}");

    let (ok, stdout, _) = cmis
        .run(
            &["--session-file", s, "allowlist", "delete", "--host", host],
            &[],
        )
        .await;
    assert!(ok && stdout.contains("deleted"), "{stdout}");
    let (ok, _, _) = cmis.run(&["allowlist", "show", "--host", host], &[]).await;
    assert!(!ok, "show after delete must fail");

    // After the step-up window a write asks for a fresh TOTP code, rotates
    // the session and retries.
    cmis.clock.advance(301);
    let code = cmis.code(&secret);
    let (ok, _, stderr) = cmis
        .run(
            &[
                "--session-file",
                s,
                "allowlist",
                "set",
                "--host",
                host,
                "--entry",
                &bin_sha,
            ],
            &[&code],
        )
        .await;
    assert!(ok, "set after step-up: {stderr}");
}

#[tokio::test]
async fn the_admin_endpoint_must_be_tls() {
    let out = Command::new(env!("CARGO_BIN_EXE_ferrogate"))
        .args(["--admin-endpoint", "http://127.0.0.1:9", "list-svids"])
        .stdin(Stdio::null())
        .output()
        .await
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("must be https"));
}

/// `ferrogate admin factors`: list the caller's factors (server strings are
/// printed without control characters) and remove one with a TOTP proof;
/// the last factor stays. FIDO2 enrollment itself is the tray's (F22).
#[tokio::test]
async fn factors_list_and_remove_with_a_totp_proof() {
    let cmis = spawn_cmis("factors").await;
    let secret = cmis.bootstrap().await;
    let session = cmis.dir.join("session");
    cmis.login(&secret, &session).await;
    let s = session.to_str().unwrap();

    let admin_id = cmis
        .state
        .cluster()
        .admin_account_by_username("root.admin")
        .await
        .unwrap()
        .unwrap()
        .admin_id;
    let credential_id = vec![0x42; 32];
    cmis.state
        .cluster()
        .admin_add_webauthn_credential(&ferro_raft::admin::WebAuthnCredentialRow {
            credential_id: credential_id.clone(),
            admin_id,
            cose_public_key: vec![0xa0],
            sign_count: 0,
            aaguid: None,
            label: Some("Lost\u{1b}[31m key".into()),
            created_at: T0,
            last_used_at: None,
        })
        .await
        .unwrap();
    let key_id = cmis::admin::factors::factor_id(&credential_id);

    let (ok, stdout, stderr) = cmis
        .run(&["--session-file", s, "admin", "factors"], &[])
        .await;
    assert!(ok, "factors: {stderr}");
    assert!(
        stdout.contains("totp") && stdout.contains(&key_id),
        "{stdout}"
    );
    assert!(stdout.contains("Lost[31m key"), "{stdout}");
    assert!(
        !stdout.contains('\u{1b}'),
        "no escape sequence reaches the terminal"
    );

    cmis.clock.advance(30);
    let (ok, stdout, stderr) = cmis
        .run(
            &["--session-file", s, "admin", "factors", "remove", &key_id],
            &[&cmis.code(&secret)],
        )
        .await;
    assert!(ok, "remove: {stderr}");
    assert!(stdout.contains("removed"), "{stdout}");

    cmis.clock.advance(30);
    let (ok, _, stderr) = cmis
        .run(
            &["--session-file", s, "admin", "factors", "remove", "totp"],
            &[&cmis.code(&secret)],
        )
        .await;
    assert!(!ok && stderr.contains("last_factor"), "{stderr}");
}

/// `ferrogate admin apps`: register an application directly (fresh TOTP
/// proof), list it, revoke it and read the revoked state back with its
/// revision history. A typo is refused before any sign-in prompt.
#[tokio::test]
async fn apps_register_list_revoke_and_show_the_history() {
    let cmis = spawn_cmis("apps").await;
    let secret = cmis.bootstrap().await;
    let session = cmis.dir.join("session");
    cmis.login(&secret, &session).await;
    let s = session.to_str().unwrap();
    let host = "22222222-2222-8222-8222-222222222222";
    let sha = hex::encode([0xBB; 48]);

    // Parsed before the sign-in: no stdin needed to learn it is a typo.
    let (ok, _, stderr) = cmis
        .run(&["--session-file", s, "admin", "apps", "frobnicate"], &[])
        .await;
    assert!(!ok && stderr.contains("unknown apps action"), "{stderr}");
    let (ok, _, stderr) = cmis
        .run(
            &[
                "admin", "apps", "register", "--host", host, "--sha384", "abc",
            ],
            &[],
        )
        .await;
    assert!(!ok && stderr.contains("is required"), "{stderr}");

    cmis.clock.advance(30);
    let (ok, stdout, stderr) = cmis
        .run(
            &[
                "--session-file",
                s,
                "admin",
                "apps",
                "register",
                "--host",
                host,
                "--path",
                "/opt/tool/bin/tool",
                "--sha384",
                &sha,
                "--platform",
                "linux",
                "--uid",
                "1000",
                "--user",
                "alice",
                "--size",
                "2048",
                "--version",
                "2.1.0",
                "--reason",
                "line-of-business tool",
            ],
            &[&cmis.code(&secret)],
        )
        .await;
    assert!(ok, "register: {stderr}");
    let id_after = |text: &str, key: &str| -> String {
        text.lines()
            .find_map(|l| l.strip_prefix(key))
            .unwrap_or_else(|| panic!("no `{key}` in {text}"))
            .trim()
            .to_string()
    };
    let approval_id = id_after(&stdout, "approval: ");
    let request_id = id_after(&stdout, "request: ");
    assert!(
        !approval_id.is_empty() && !request_id.is_empty(),
        "{stdout}"
    );

    // Registering the same binary again is covered by the active approval.
    cmis.clock.advance(30);
    let (ok, stdout, stderr) = cmis
        .run(
            &[
                "--session-file",
                s,
                "admin",
                "apps",
                "register",
                "--host",
                host,
                "--path",
                "/opt/tool/bin/tool",
                "--sha384",
                &sha.to_uppercase(),
                "--platform",
                "linux",
                "--uid",
                "1000",
                "--user",
                "alice",
            ],
            &[&cmis.code(&secret)],
        )
        .await;
    assert!(ok, "second register: {stderr}");
    assert!(
        stdout.contains(&format!("already approved by {approval_id}")),
        "{stdout}"
    );

    let (ok, stdout, stderr) = cmis
        .run(
            &[
                "--session-file",
                s,
                "admin",
                "apps",
                "approvals",
                "--host",
                host,
            ],
            &[],
        )
        .await;
    assert!(ok, "approvals: {stderr}");
    assert!(
        stdout.contains(&approval_id) && stdout.contains("active") && stdout.contains("alice"),
        "{stdout}"
    );
    let (ok, stdout, stderr) = cmis
        .run(
            &[
                "--session-file",
                s,
                "admin",
                "apps",
                "requests",
                "--state",
                "approved",
            ],
            &[],
        )
        .await;
    assert!(ok, "requests: {stderr}");
    assert!(
        stdout.contains(&request_id) && stdout.contains("/opt/tool/bin/tool"),
        "{stdout}"
    );
    let (ok, stdout, stderr) = cmis
        .run(
            &["--session-file", s, "admin", "apps", "request", &request_id],
            &[],
        )
        .await;
    assert!(ok, "request: {stderr}");
    assert!(
        stdout.contains(&sha) && stdout.contains(&approval_id),
        "{stdout}"
    );

    // The revoke is a decision: it needs a recent step-up, so a code is on
    // stdin in case the server asks for one.
    cmis.clock.advance(30);
    let (ok, stdout, stderr) = cmis
        .run(
            &[
                "--session-file",
                s,
                "admin",
                "apps",
                "revoke",
                &approval_id,
                "--reason-code",
                "2",
            ],
            &[&cmis.code(&secret)],
        )
        .await;
    assert!(ok, "revoke: {stderr}");
    assert!(stdout.contains("revoked"), "{stdout}");

    let (ok, stdout, stderr) = cmis
        .run(
            &[
                "--session-file",
                s,
                "admin",
                "apps",
                "approval",
                &approval_id,
            ],
            &[],
        )
        .await;
    assert!(ok, "approval: {stderr}");
    assert!(
        stdout.contains("state:              revoked") && stdout.contains("created"),
        "{stdout}"
    );
    assert!(stdout.contains("revisions:"), "{stdout}");
    assert!(
        stdout
            .lines()
            .any(|l| l.contains("revoked") && l.contains("by ")),
        "{stdout}"
    );
}

/// F19 §11 through the CLI (M38): dry run, import (idempotent), the switch
/// to approvals (refused until imported), `allowlist add|remove` mapped onto
/// the approval RPCs, the read-only legacy writes, and the confirmed
/// rollback.
#[tokio::test]
async fn migrate_allowlists_switch_modes_and_map_the_allowlist_commands() {
    let cmis = spawn_cmis("migrate").await;
    let secret = cmis.bootstrap().await;
    let session = cmis.dir.join("session");
    cmis.login(&secret, &session).await;
    let s = session.to_str().unwrap();
    let host = "33333333-3333-8333-8333-333333333333";
    let sha = hex::encode([0xCC; 48]);
    let sha2 = hex::encode([0xDD; 48]);

    // Typos are refused before any sign-in (no stdin needed).
    let (ok, _, stderr) = cmis
        .run(&["admin", "set-allowlist-mode", "sideways"], &[])
        .await;
    assert!(!ok && stderr.contains("unknown allowlist mode"), "{stderr}");
    let (ok, _, stderr) = cmis
        .run(&["admin", "migrate-allowlists", "--force"], &[])
        .await;
    assert!(!ok && stderr.contains("unknown option --force"), "{stderr}");

    let (ok, _, stderr) = cmis
        .run(
            &[
                "--session-file",
                s,
                "allowlist",
                "set",
                "--host",
                host,
                "--entry",
                &format!("1000:{sha}"),
            ],
            &[],
        )
        .await;
    assert!(ok, "set: {stderr}");

    let (ok, stdout, stderr) = cmis
        .run(
            &[
                "--session-file",
                s,
                "admin",
                "migrate-allowlists",
                "--dry-run",
            ],
            &[],
        )
        .await;
    assert!(ok, "dry run: {stderr}");
    assert!(stdout.contains("dry run: nothing was written"), "{stdout}");
    assert!(
        stdout.contains(&format!("host {host}: 1 to create")),
        "{stdout}"
    );
    assert!(stdout.contains("legacy, no expiry"), "{stdout}");

    // Not imported yet: the switch is refused.
    let (ok, _, stderr) = cmis
        .run(
            &[
                "--session-file",
                s,
                "admin",
                "set-allowlist-mode",
                "approvals",
            ],
            &[],
        )
        .await;
    assert!(!ok && stderr.contains("migrate-allowlists"), "{stderr}");

    let (ok, stdout, stderr) = cmis
        .run(&["--session-file", s, "admin", "migrate-allowlists"], &[])
        .await;
    assert!(ok, "import: {stderr}");
    assert!(stdout.contains("1 approvals created"), "{stdout}");
    let (ok, stdout, _) = cmis
        .run(&["--session-file", s, "admin", "migrate-allowlists"], &[])
        .await;
    assert!(
        ok && stdout.contains("0 approvals created, 1 already imported"),
        "{stdout}"
    );

    let (ok, stdout, stderr) = cmis
        .run(
            &[
                "--session-file",
                s,
                "admin",
                "set-allowlist-mode",
                "approvals",
            ],
            &[],
        )
        .await;
    assert!(ok, "switch: {stderr}");
    assert!(
        stdout.contains("allowlist mode: legacy -> approvals"),
        "{stdout}"
    );
    let (ok, stdout, _) = cmis
        .run(
            &[
                "--session-file",
                s,
                "admin",
                "set-allowlist-mode",
                "approvals",
            ],
            &[],
        )
        .await;
    assert!(ok && stdout.contains("already approvals"), "{stdout}");

    // The legacy writes are read-only now, with a hint.
    let (ok, _, stderr) = cmis
        .run(
            &[
                "--session-file",
                s,
                "allowlist",
                "set",
                "--host",
                host,
                "--entry",
                &format!("1000:{sha}"),
            ],
            &[],
        )
        .await;
    assert!(!ok && stderr.contains("approvals mode"), "{stderr}");

    // `add` registers one binary (fresh TOTP code); `remove` revokes.
    let (ok, _, stderr) = cmis
        .run(
            &[
                "--session-file",
                s,
                "allowlist",
                "add",
                "--host",
                host,
                "--entry",
                &format!("1001:{sha2}"),
            ],
            &[],
        )
        .await;
    assert!(!ok && stderr.contains("needs --path"), "{stderr}");
    cmis.clock.advance(30);
    let (ok, stdout, stderr) = cmis
        .run(
            &[
                "--session-file",
                s,
                "allowlist",
                "add",
                "--host",
                host,
                "--entry",
                &format!("1001:{sha2}"),
                "--path",
                "/opt/tool/bin/tool",
                "--platform",
                "linux",
                "--user",
                "bob",
                "--any-path",
            ],
            &[&cmis.code(&secret)],
        )
        .await;
    assert!(ok, "add: {stderr}");
    assert!(stdout.contains("approval: "), "{stdout}");
    let (ok, _, stderr) = cmis
        .run(
            &[
                "--session-file",
                s,
                "allowlist",
                "remove",
                "--host",
                host,
                "--uid",
                "1000",
            ],
            &[],
        )
        .await;
    assert!(!ok && stderr.contains("--reason-code"), "{stderr}");
    let (ok, stdout, stderr) = cmis
        .run(
            &[
                "--session-file",
                s,
                "allowlist",
                "remove",
                "--host",
                host,
                "--uid",
                "1000",
                "--reason-code",
                "3",
            ],
            &[],
        )
        .await;
    assert!(
        !ok && stderr.contains("--yes"),
        "no terminal, no --yes: {stderr}"
    );
    assert!(stdout.contains("approvals to revoke"), "{stdout}");
    let (ok, stdout, stderr) = cmis
        .run(
            &[
                "--session-file",
                s,
                "allowlist",
                "remove",
                "--host",
                host,
                "--uid",
                "1000",
                "--reason-code",
                "3",
                "--yes",
            ],
            &[],
        )
        .await;
    assert!(ok, "remove: {stderr}");
    assert_eq!(stdout.matches("revoked approval").count(), 1, "{stdout}");

    // A rollback shows what changes and needs confirmation (--yes without a
    // terminal).
    let (ok, stdout, stderr) = cmis
        .run(
            &["--session-file", s, "admin", "set-allowlist-mode", "legacy"],
            &[],
        )
        .await;
    assert!(!ok && stderr.contains("--yes"), "{stderr}");
    assert!(
        stdout.contains("1 approval(s) created since the switch")
            && stdout.contains("1 legacy import(s) revoked or expired"),
        "{stdout}"
    );
    let (ok, stdout, stderr) = cmis
        .run(
            &[
                "--session-file",
                s,
                "admin",
                "set-allowlist-mode",
                "legacy",
                "--yes",
            ],
            &[],
        )
        .await;
    assert!(ok, "rollback: {stderr}");
    assert!(
        stdout.contains("allowlist mode: approvals -> legacy"),
        "{stdout}"
    );

    // The preserved legacy body is served again.
    let (ok, stdout, _) = cmis.run(&["allowlist", "show", "--host", host], &[]).await;
    assert!(
        ok && stdout.contains(&sha) && stdout.contains("uid=1000"),
        "{stdout}"
    );
}
