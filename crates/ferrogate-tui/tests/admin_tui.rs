//! `ferrogate-tui` end to end: the headless [`App`] driven by keys, its
//! commands executed by the real client ([`AdminConnection`]) over the pinned
//! hybrid-PQC TLS admin listener of an in-process CMIS.
//!
//! The CMIS is the F19/F20 test harness of `crates/cmis/tests/support`
//! (included by path, so both suites exercise the same server set-up) on a
//! controlled clock, served by `cmis::server::serve_admin` behind a TLS
//! listener with a fresh certificate whose SPKI pin the TUI is given.
//!
//! Covered: login → list → approve with a forced step-up (the retry reuses
//! the idempotency key, the server audits exactly one approval); deny, edit
//! against a concurrent edit (`ABORTED` → reload → asked again), revoke with
//! the typed short id and freeze, each audited once by the server; the
//! single-step add with a fresh TOTP code even inside the step-up window
//! (approved by default, a wrong code changes nothing, strict SoD leaves the
//! request pending); a wrong pin refused before any credential is sent; a
//! viewer refused by the server even when the client is forced; a server
//! that completes the handshake and never answers meets the RPC deadline.

#![allow(
    clippy::large_futures,
    clippy::too_many_lines,
    clippy::missing_panics_doc
)]

#[path = "../../cmis/tests/support/mod.rs"]
mod support;

use std::collections::VecDeque;
use std::sync::Arc;

use cmis::admin::authz::paths;
use ferro_audit::AuditEvent;
use ferro_crypto::pin::SpkiPin;
use ferro_crypto::tls::ProviderMode;
use ferro_proto::admin_v1::admin_server::Admin as _;
use ferro_proto::admin_v1::{
    approve_app_request_request::Choice, AdminRegisterApplicationRequest, ApprovalTerms,
    ApproveAppRequestRequest, GetAppRequestRequest, ListAppRequestsRequest, ListApprovalsRequest,
    UpdateApprovalRequest,
};
use ferro_proto::v1::machine_identity_server::MachineIdentity as _;
use ferrogate_tui::app::dialogs::{short_id, DialogKind};
use ferrogate_tui::app::{App, Modal, Msg, Phase, Screen};
use ferrogate_tui::client::{AdminConnection, ClientConfig, Cmd, Mutation, Op, Reply};
use ferrogate_tui::input::Key;
use rustls_pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use support::hosts::{approvals_mode, mint_host, Host};
use support::{Admin1, Harness};
use tokio::net::TcpListener;

const PATH: &str = "/opt/tool/bin/tool";

/// An in-process CMIS behind a real TLS admin listener.
struct Server {
    h: Harness,
    endpoint: String,
    pin: SpkiPin,
    root: Admin1,
    root_token: String,
}

/// The SPKI pin of a fresh, unrelated certificate (a wrong pin).
fn unrelated_pin() -> SpkiPin {
    let ck = rcgen::generate_simple_self_signed(vec!["elsewhere.invalid".to_string()]).unwrap();
    SpkiPin::from_certificate_der(ck.cert.der().as_ref()).unwrap()
}

async fn server(tag: &str, strict: bool) -> Server {
    let h = support::harness_with(tag, |c| c.strict_sod = strict).await;
    approvals_mode(&h.cmis).await;
    let ck = rcgen::generate_simple_self_signed(vec!["cmis.test.ferrogate.invalid".to_string()])
        .unwrap();
    let pin = SpkiPin::from_certificate_der(ck.cert.der().as_ref()).unwrap();
    let tls = ferro_crypto::transport::server_config(
        ProviderMode::HybridOnly,
        vec![ck.cert.der().clone()],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.signing_key.serialize_der())),
    )
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(cmis::server::serve_admin(
        listener,
        tls,
        Arc::clone(&h.cmis),
        Arc::clone(&h.authz),
    ));
    let root = support::bootstrap(&h, "root-admin").await;
    let root_token = h.login(&root).await;
    Server {
        h,
        endpoint: format!("https://{addr}"),
        pin,
        root,
        root_token,
    }
}

impl Server {
    async fn account(&self, name: &str, group: &str) -> Admin1 {
        self.h
            .create_and_enroll(&self.root, &self.root_token, name, &[group])
            .await
    }

    /// A host-submitted pending request (as MIA would send it).
    async fn submit(&self, host: &Host, sha: u8) -> String {
        let doc = host.app_doc(PATH, [sha; 48], 1000, "alice", 0);
        self.h
            .mi
            .submit_app_request(tonic::Request::new(host.submit(&doc)))
            .await
            .unwrap()
            .into_inner()
            .request_id
    }

    fn events(&self, want: fn(&AuditEvent) -> bool) -> usize {
        self.h.audit_events().iter().filter(|e| want(e)).count()
    }
}

/// The TUI without a terminal: keys in, commands through the real client.
struct Tui {
    app: App,
    conn: AdminConnection,
    /// Idempotency keys of every mutation and step-up retry sent.
    keys_sent: Vec<String>,
    /// Replies seen, for assertions.
    replies: Vec<Reply>,
}

impl Tui {
    fn new(s: &Server, pin: SpkiPin) -> Self {
        let mut app = App::new(&s.endpoint, &pin.to_hex(), 0, true);
        app.update(Msg::Tick {
            mono: 0,
            unix: s.h.clock_now(),
        });
        Self {
            app,
            conn: AdminConnection::new(ClientConfig {
                endpoint: s.endpoint.clone(),
                pins: vec![pin],
                device_token_path: None,
                connect_timeout: ferrogate_tui::client::CONNECT_TIMEOUT,
                rpc_timeout: ferrogate_tui::client::RPC_TIMEOUT,
            }),
            keys_sent: Vec::new(),
            replies: Vec::new(),
        }
    }

    /// Run commands (and the commands their replies produce) to completion.
    async fn pump(&mut self, cmds: Vec<Cmd>) {
        let mut queue: VecDeque<Cmd> = cmds.into();
        while let Some(cmd) = queue.pop_front() {
            match &cmd {
                Cmd::Mutate(m) | Cmd::StepUp { retry: m, .. } => {
                    self.keys_sent.push(m.idempotency_key().to_string());
                }
                Cmd::Register { req, .. } => self.keys_sent.push(req.idempotency_key.clone()),
                _ => {}
            }
            for reply in self.conn.handle(cmd).await {
                self.replies.push(reply.clone());
                queue.extend(self.app.update(Msg::Reply(reply)));
            }
        }
    }

    async fn key(&mut self, k: Key) {
        let cmds = self.app.update(Msg::Key(k));
        self.pump(cmds).await;
    }

    async fn text(&mut self, s: &str) {
        for c in s.chars() {
            self.key(Key::Char(c)).await;
        }
    }

    /// Keep the TUI's clock on the server's controlled clock.
    fn sync_clock(&mut self, h: &Harness) {
        self.app.update(Msg::Tick {
            mono: 1,
            unix: h.clock_now(),
        });
    }

    async fn login(&mut self, s: &Server, who: &Admin1) {
        self.text(&who.username).await;
        self.key(Key::Enter).await;
        self.text(support::PASSWORD).await;
        self.key(Key::Enter).await;
        let code = s.h.fresh_code(who);
        self.sync_clock(&s.h);
        self.text(&code).await;
        self.key(Key::Enter).await;
    }

    fn message_title(&self) -> Option<String> {
        match &self.app.modal {
            Some(Modal::Message { title, .. }) => Some(title.clone()),
            _ => None,
        }
    }

    /// Assert the outcome modal's title; on a mismatch show what the TUI
    /// shows and the last replies, so a failure names its cause.
    fn expect_title(&self, want: &str) {
        let got = self.message_title();
        if got.as_deref() != Some(want) {
            let shown = match &self.app.modal {
                Some(Modal::Message { title, lines }) => format!("{title}: {lines:?}"),
                Some(Modal::Dialog(d)) => format!("dialog {:?} at {:?}", d.kind, d.stage),
                Some(Modal::StepUp { error, .. }) => format!("step-up prompt ({error:?})"),
                Some(Modal::RegisterTotp { error, .. }) => format!("add TOTP prompt ({error:?})"),
                Some(_) => "another modal".to_string(),
                None => "no modal".to_string(),
            };
            let tail = &self.replies[self.replies.len().saturating_sub(3)..];
            panic!(
                "expected \"{want}\", the TUI shows {shown}; status {:?}; last replies {tail:?}",
                self.app.status
            );
        }
    }
}

fn manual_terms() -> ApprovalTerms {
    ApprovalTerms::default()
}

#[tokio::test]
async fn login_list_and_approve_with_a_step_up_that_reuses_the_key() {
    let s = server("tui-approve", false).await;
    let approver = s.account("approver.one", "ferrogate-approvers").await;
    let host = mint_host(&s.h.cmis.issuer, 0x61, "p1");
    let request_id = s.submit(&host, 1).await;

    let mut tui = Tui::new(&s, s.pin);
    tui.login(&s, &approver).await;
    assert!(matches!(tui.app.phase, Phase::Main), "signed in");
    assert!(tui.conn.has_session());
    assert!(tui.app.can("app_request.approve"), "WhoAmI permissions");

    tui.text("2").await;
    assert_eq!(tui.app.screen, Screen::Requests);
    assert_eq!(tui.app.requests.items.len(), 1);
    assert_eq!(tui.app.requests.items[0].request_id, request_id);

    // Past the step-up window: the server will ask for a fresh code.
    s.h.clock.advance(301);
    tui.sync_clock(&s.h);
    tui.text("a").await;
    let Some(Modal::Dialog(d)) = &tui.app.modal else {
        panic!("the approve dialog opens");
    };
    assert_eq!(d.kind, DialogKind::Approve);
    assert_eq!(d.form.choice("policy"), 0, "manual by default");
    tui.key(Key::Enter).await;
    tui.text("y").await;
    assert!(
        matches!(tui.app.modal, Some(Modal::StepUp { .. })),
        "step_up_required opens the TOTP prompt"
    );
    assert_eq!(
        s.events(|e| matches!(e, AuditEvent::AppRequestApproved { .. })),
        0
    );
    let code = s.h.fresh_code(&approver);
    tui.sync_clock(&s.h);
    tui.text(&code).await;
    tui.key(Key::Enter).await;
    assert_eq!(tui.keys_sent.len(), 2, "the first try and the one retry");
    assert_eq!(tui.keys_sent[0], tui.keys_sent[1], "same idempotency key");
    tui.expect_title("Approved");
    let Some(Modal::Message { lines, .. }) = &tui.app.modal else {
        panic!()
    };
    assert!(lines[0].contains("host generation"), "{lines:?}");
    assert_eq!(
        s.events(|e| matches!(e, AuditEvent::AppRequestApproved { .. })),
        1,
        "exactly one approval audited"
    );
    assert_eq!(s.events(|e| matches!(e, AuditEvent::AdminStepUp { .. })), 1);
    // The list refreshed after the mutation: nothing pending any more.
    tui.key(Key::Esc).await;
    tui.key(Key::Esc).await;
    tui.text("r").await;
    assert!(tui.app.requests.items.is_empty(), "no pending request left");

    // Lock: the server session is ended and the token wiped.
    tui.key(Key::CtrlL).await;
    assert!(matches!(tui.app.phase, Phase::Login(_)));
    assert!(!tui.conn.has_session());
    assert_eq!(s.events(|e| matches!(e, AuditEvent::AdminLogout { .. })), 1);
}

/// Select the listed request `id` and press `k` on it.
async fn on_request(tui: &mut Tui, id: &str, k: char) {
    let idx = tui
        .app
        .requests
        .items
        .iter()
        .position(|r| r.request_id == id)
        .unwrap_or_else(|| panic!("request {id} is listed"));
    tui.app.requests.selected = idx;
    tui.text(&k.to_string()).await;
}

/// Review the open dialog (`Enter`) and confirm it (`y`).
async fn review_and_confirm(tui: &mut Tui) {
    tui.key(Key::Enter).await;
    let Some(Modal::Dialog(d)) = &tui.app.modal else {
        panic!("a dialog is open");
    };
    assert_eq!(
        d.stage,
        ferrogate_tui::app::dialogs::Stage::Review,
        "{:?}",
        d.form
            .fields
            .iter()
            .filter_map(|f| f.error.clone())
            .collect::<Vec<_>>()
    );
    tui.text("y").await;
}

#[tokio::test]
async fn deny_edit_revoke_and_freeze_go_end_to_end() {
    let s = server("tui-flows", false).await;
    let approver = s.account("approver.five", "ferrogate-approvers").await;
    let host = mint_host(&s.h.cmis.issuer, 0x65, "p1");
    let to_deny = s.submit(&host, 2).await;
    let to_approve = {
        let doc = host.app_doc("/opt/other/bin/other", [5; 48], 1000, "alice", 0);
        s.h.mi
            .submit_app_request(tonic::Request::new(host.submit(&doc)))
            .await
            .unwrap()
            .into_inner()
            .request_id
    };

    let mut tui = Tui::new(&s, s.pin);
    tui.login(&s, &approver).await;
    tui.text("2").await;
    assert_eq!(tui.app.requests.items.len(), 2);

    // Deny, with a reason code and a message (inside the step-up window).
    on_request(&mut tui, &to_deny, 'd').await;
    let Some(Modal::Dialog(d)) = &mut tui.app.modal else {
        panic!("the deny dialog opens");
    };
    assert_eq!(d.kind, DialogKind::Deny);
    d.form.set_choice("reason", 4); // security_risk
    d.form.focus_on("message");
    d.form.paste("Not on the software list.");
    review_and_confirm(&mut tui).await;
    tui.expect_title("Denied");
    assert_eq!(
        s.events(|e| matches!(e, AuditEvent::AppRequestDenied { .. })),
        1
    );
    let denied =
        s.h.call(
            &s.root_token,
            paths::GET_APP_REQUEST,
            GetAppRequestRequest {
                request_id: to_deny.clone(),
            },
            |svc, r| Box::pin(async move { svc.get_app_request(r).await }),
        )
        .await
        .unwrap()
        .request
        .unwrap();
    assert_eq!(
        (denied.state, denied.decision_reason_code),
        (4, 5),
        "DENIED with security_risk"
    );
    assert_eq!(denied.decision_message, "Not on the software list.");
    // Back to the list: it was reloaded after the mutation.
    tui.key(Key::Esc).await;
    tui.key(Key::Esc).await;
    assert_eq!(tui.app.screen, Screen::Requests);
    assert_eq!(tui.app.requests.items.len(), 1, "the denied one left");

    // Approve the other one, then open its approval.
    on_request(&mut tui, &to_approve, 'a').await;
    review_and_confirm(&mut tui).await;
    tui.expect_title("Approved");
    tui.key(Key::Esc).await;
    tui.text("3").await;
    assert_eq!(tui.app.approvals.items.len(), 1);
    tui.key(Key::Enter).await;
    assert_eq!(tui.app.screen, Screen::ApprovalDetail);
    let approval = tui
        .app
        .approval_detail
        .as_ref()
        .and_then(|d| d.approval.clone())
        .unwrap();

    // Someone else edits the approval meanwhile.
    let other = s.h.login(&approver).await;
    s.h.call(
        &other,
        paths::UPDATE_APPROVAL,
        UpdateApprovalRequest {
            idempotency_key: uuid_key(),
            approval_id: approval.approval_id.clone(),
            expected_row_version: approval.row_version,
            note: Some("changed elsewhere".into()),
            ..UpdateApprovalRequest::default()
        },
        |svc, r| Box::pin(async move { svc.update_approval(r).await }),
    )
    .await
    .unwrap();
    tui.sync_clock(&s.h);

    // The TUI's edit is based on the old row version: ABORTED, reload, ask
    // again showing what changed.
    tui.text("e").await;
    let Some(Modal::Dialog(d)) = &mut tui.app.modal else {
        panic!("the edit dialog opens");
    };
    assert_eq!(d.kind, DialogKind::Edit);
    d.form.set_choice("expires", 2); // 90 days from now
    review_and_confirm(&mut tui).await;
    let Some(Modal::Dialog(d)) = &mut tui.app.modal else {
        panic!("the edit is asked again: {:?}", tui.message_title());
    };
    let notice = d.notice.clone().unwrap_or_default();
    assert!(notice.contains("changed elsewhere"), "{notice}");
    assert_eq!(
        s.events(|e| matches!(e, AuditEvent::ApprovalUpdated { .. })),
        1,
        "only the concurrent edit so far"
    );
    d.form.set_choice("expires", 2);
    review_and_confirm(&mut tui).await;
    tui.expect_title("Updated");
    assert_eq!(
        s.events(|e| matches!(e, AuditEvent::ApprovalUpdated { .. })),
        2
    );
    tui.key(Key::Esc).await;
    let edited = tui
        .app
        .approval_detail
        .as_ref()
        .and_then(|d| d.approval.clone())
        .unwrap();
    assert_eq!(edited.row_version, approval.row_version + 2, "reloaded");
    assert_eq!(edited.note, "changed elsewhere", "the other edit is kept");
    assert!(edited.expires_at > tui.app.unix + 89 * 86_400);

    // Revoke: a wrong short id is refused inline, the right one sends.
    tui.text("x").await;
    let Some(Modal::Dialog(d)) = &mut tui.app.modal else {
        panic!("the revoke dialog opens");
    };
    assert_eq!(d.kind, DialogKind::Revoke);
    d.form.focus_on("confirm");
    d.form.paste("A-00000000");
    tui.key(Key::Enter).await;
    let Some(Modal::Dialog(d)) = &mut tui.app.modal else {
        panic!()
    };
    assert_eq!(d.stage, ferrogate_tui::app::dialogs::Stage::Form);
    assert!(tui.replies.iter().all(|r| !matches!(
        r,
        Reply::Mutated(m) if matches!(**m, ferrogate_tui::client::Mutated::Revoked(_))
    )));
    d.form.focus_on("confirm");
    for _ in 0..16 {
        d.form.handle(Key::Backspace);
    }
    d.form.paste(&short_id("A", &approval.approval_id));
    review_and_confirm(&mut tui).await;
    tui.expect_title("Revoked");
    assert_eq!(
        s.events(|e| matches!(e, AuditEvent::ApprovalRevoked { .. })),
        1
    );
    tui.key(Key::Esc).await;
    let revoked = tui
        .app
        .approval_detail
        .as_ref()
        .and_then(|d| d.approval.clone())
        .unwrap();
    assert_eq!(revoked.state, 3, "REVOKED, kept in history");

    // Freeze the lineage's auto-updates.
    tui.text("z").await;
    let Some(Modal::Dialog(d)) = &tui.app.modal else {
        panic!("the freeze dialog opens");
    };
    assert_eq!(d.kind, DialogKind::Freeze);
    review_and_confirm(&mut tui).await;
    tui.expect_title("Frozen");
    assert_eq!(
        s.events(|e| matches!(e, AuditEvent::LineageAutoUpdateFrozen { .. })),
        1
    );
    assert_eq!(
        tui.keys_sent
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len(),
        tui.keys_sent.len(),
        "every new operation has its own idempotency key"
    );
}

async fn fill_add_dialog(tui: &mut Tui, host: &Host, sha: u8) {
    tui.text("A").await;
    let Some(Modal::Dialog(d)) = &mut tui.app.modal else {
        panic!("A opens the add dialog");
    };
    assert_eq!(d.kind, DialogKind::Register);
    let sha_hex = hex::encode([sha; 48]);
    for (k, v) in [
        ("host", host.uuid.as_str()),
        ("path", PATH),
        ("sha", sha_hex.as_str()),
        ("uid", "1000"),
        ("user", "alice"),
        ("version", "2.1.0"),
    ] {
        d.form.focus_on(k);
        d.form.paste(v);
    }
    tui.key(Key::Enter).await;
    let Some(Modal::Dialog(d)) = &tui.app.modal else {
        panic!()
    };
    let review = d.review_lines(tui.app.unix).join("\n");
    assert!(review.contains("YOUR ASSERTION"), "{review}");
    assert!(review.contains("registers AND approves"), "{review}");
    assert!(review.contains("CMIS_ADMIN_STRICT_SOD"), "{review}");
}

#[tokio::test]
async fn add_application_asks_a_fresh_code_and_is_approved_in_one_step() {
    let s = server("tui-add", false).await;
    let approver = s.account("approver.two", "ferrogate-approvers").await;
    let host = mint_host(&s.h.cmis.issuer, 0x62, "p1");

    let mut tui = Tui::new(&s, s.pin);
    tui.login(&s, &approver).await;
    // Just signed in: the step-up window is valid, yet the add asks a code.
    tui.text("2").await;
    fill_add_dialog(&mut tui, &host, 7).await;
    tui.text("y").await;
    assert!(
        matches!(tui.app.modal, Some(Modal::RegisterTotp { .. })),
        "a fresh TOTP prompt even within the step-up window"
    );
    assert!(tui.keys_sent.is_empty(), "nothing sent before the code");

    // A wrong code changes nothing; the retry reuses the key.
    let good = s.h.fresh_code(&approver);
    let wrong = if good == "000000" { "000001" } else { "000000" };
    tui.sync_clock(&s.h);
    tui.text(wrong).await;
    tui.key(Key::Enter).await;
    assert!(matches!(tui.app.modal, Some(Modal::RegisterTotp { .. })));
    assert!(matches!(
        tui.replies.last(),
        Some(Reply::Failed(op, e)) if matches!(**op, Op::Register(_)) && e.code == tonic::Code::Unauthenticated
    ));
    assert_eq!(
        s.events(|e| matches!(e, AuditEvent::AppApprovedBySameActor { .. })),
        0
    );
    let code = s.h.fresh_code(&approver);
    tui.sync_clock(&s.h);
    tui.text(&code).await;
    tui.key(Key::Enter).await;
    assert_eq!(tui.keys_sent.len(), 2);
    assert_eq!(tui.keys_sent[0], tui.keys_sent[1], "same idempotency key");
    tui.expect_title("Registered and approved");
    assert_eq!(
        s.events(|e| matches!(e, AuditEvent::AppApprovedBySameActor { .. })),
        1,
        "exactly one same-actor approval audited"
    );
    let approvals =
        s.h.call(
            &s.root_token,
            paths::LIST_APPROVALS,
            ListApprovalsRequest {
                host_uuid: host.uuid.clone(),
                states: vec![1],
                ..ListApprovalsRequest::default()
            },
            |svc, r| Box::pin(async move { svc.list_approvals(r).await }),
        )
        .await
        .unwrap();
    assert_eq!(approvals.items.len(), 1, "the approval is ACTIVE");
    assert_eq!(approvals.items[0].origin, 3, "admin_direct");
    let requests =
        s.h.call(
            &s.root_token,
            paths::LIST_APP_REQUESTS,
            ListAppRequestsRequest {
                host_uuid: host.uuid.clone(),
                states: vec![2],
                ..ListAppRequestsRequest::default()
            },
            |svc, r| Box::pin(async move { svc.list_app_requests(r).await }),
        )
        .await
        .unwrap();
    assert_eq!(requests.items.len(), 1, "the request is APPROVED");
}

#[tokio::test]
async fn under_strict_sod_the_add_stays_pending_for_another_approver() {
    let s = server("tui-add-strict", true).await;
    let approver = s.account("approver.three", "ferrogate-approvers").await;
    let host = mint_host(&s.h.cmis.issuer, 0x63, "p1");

    let mut tui = Tui::new(&s, s.pin);
    tui.login(&s, &approver).await;
    tui.text("2").await;
    fill_add_dialog(&mut tui, &host, 9).await;
    tui.text("y").await;
    let code = s.h.fresh_code(&approver);
    tui.sync_clock(&s.h);
    tui.text(&code).await;
    tui.key(Key::Enter).await;
    tui.expect_title("Queued for another approver");
    // Under the strict policy the bootstrap operator is no approver; read the
    // ledger as the approver (a second session).
    let token = s.h.login(&approver).await;
    let pending =
        s.h.call(
            &token,
            paths::LIST_APP_REQUESTS,
            ListAppRequestsRequest {
                host_uuid: host.uuid.clone(),
                states: vec![1],
                ..ListAppRequestsRequest::default()
            },
            |svc, r| Box::pin(async move { svc.list_app_requests(r).await }),
        )
        .await
        .unwrap();
    assert_eq!(pending.items.len(), 1, "PENDING under strict SoD");
    assert_eq!(pending.items[0].origin, 3, "admin_direct");
    assert_eq!(
        s.events(|e| matches!(e, AuditEvent::AppApprovedBySameActor { .. })),
        0
    );
}

#[tokio::test]
async fn a_wrong_pin_is_refused_before_any_credential_is_sent() {
    let s = server("tui-pin", false).await;
    let approver = s.account("approver.four", "ferrogate-approvers").await;
    let before = s.h.audit_events().len();
    let mut tui = Tui::new(&s, unrelated_pin());
    tui.login(&s, &approver).await;
    let Phase::Login(l) = &tui.app.phase else {
        panic!("still signed out");
    };
    let error = l.error.clone().unwrap_or_default();
    assert!(error.contains("nothing was sent"), "{error}");
    assert!(!tui.conn.has_session());
    let after = s.h.audit_events();
    assert_eq!(after.len(), before, "the server saw no login attempt");
}

#[tokio::test]
async fn a_viewer_is_refused_by_the_server_even_when_the_client_is_forced() {
    let s = server("tui-viewer", false).await;
    let viewer = s.account("viewer.one", "ferrogate-viewers").await;
    let host = mint_host(&s.h.cmis.issuer, 0x64, "p1");
    let request_id = s.submit(&host, 3).await;

    let mut tui = Tui::new(&s, s.pin);
    tui.login(&s, &viewer).await;
    assert!(matches!(tui.app.phase, Phase::Main));
    tui.text("2").await;
    assert_eq!(tui.app.requests.items.len(), 1, "a viewer may list");
    tui.text("a").await;
    assert!(tui.app.modal.is_none(), "the key is refused locally");
    tui.text("A").await;
    assert!(tui.app.modal.is_none());

    // Forced past the client: the server decides.
    let replies = tui
        .conn
        .handle(Cmd::Mutate(Mutation::Approve(ApproveAppRequestRequest {
            idempotency_key: uuid_key(),
            request_id: request_id.clone(),
            choice: Some(Choice::Terms(manual_terms())),
            also_revoke_approval_ids: vec![],
            also_revoke_reason_code: 0,
            proof: None,
        })))
        .await;
    let [Reply::Failed(_, e)] = &replies[..] else {
        panic!("{replies:?}");
    };
    assert_eq!(
        (e.code, e.reason.as_str()),
        (tonic::Code::PermissionDenied, "permission_denied")
    );
    let mut code = ferrogate_tui::secret::Secret::new();
    for c in s.h.fresh_code(&viewer).chars() {
        code.push(c);
    }
    let replies = tui
        .conn
        .handle(Cmd::Register {
            req: Box::new(AdminRegisterApplicationRequest {
                idempotency_key: uuid_key(),
                host_uuid: host.uuid.clone(),
                ..AdminRegisterApplicationRequest::default()
            }),
            totp: code,
        })
        .await;
    let [Reply::Failed(_, e)] = &replies[..] else {
        panic!("{replies:?}");
    };
    assert_eq!(e.code, tonic::Code::PermissionDenied);
    assert_eq!(
        s.events(|e| matches!(
            e,
            AuditEvent::AppRequestApproved { .. } | AuditEvent::AppApprovedBySameActor { .. }
        )),
        0
    );
}

fn uuid_key() -> String {
    uuid::Uuid::new_v4().to_string()
}

#[tokio::test]
async fn a_server_that_never_answers_meets_the_rpc_deadline() {
    use tokio_stream::StreamExt as _;
    // A pinned hybrid-PQC TLS listener that completes the handshake and then
    // never speaks HTTP/2.
    let ck = rcgen::generate_simple_self_signed(vec!["hung.test.ferrogate.invalid".to_string()])
        .unwrap();
    let pin = SpkiPin::from_certificate_der(ck.cert.der().as_ref()).unwrap();
    let tls = ferro_crypto::transport::server_config(
        ProviderMode::HybridOnly,
        vec![ck.cert.der().clone()],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ck.signing_key.serialize_der())),
    )
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let mut incoming = std::pin::pin!(cmis::transport::tls_incoming(listener, tls));
        let mut held = Vec::new();
        while let Some(conn) = incoming.next().await {
            held.push(conn);
        }
    });
    let mut conn = AdminConnection::new(ClientConfig {
        endpoint: format!("https://{addr}"),
        pins: vec![pin],
        device_token_path: None,
        connect_timeout: std::time::Duration::from_secs(5),
        rpc_timeout: std::time::Duration::from_millis(300),
    });
    let started = std::time::Instant::now();
    let mut password = ferrogate_tui::secret::Secret::new();
    password.push('p');
    let mut totp = ferrogate_tui::secret::Secret::new();
    for c in "123456".chars() {
        totp.push(c);
    }
    let replies = conn
        .handle(Cmd::Login {
            username: "u".into(),
            password,
            totp,
        })
        .await;
    let [Reply::LoginFailed(ferrogate_tui::client::LoginError::Other(e))] = &replies[..] else {
        panic!("{replies:?}");
    };
    assert_eq!(e.code, tonic::Code::DeadlineExceeded);
    assert!(started.elapsed() < std::time::Duration::from_secs(3));
    assert!(!conn.has_session());
    // The client task is free again: the next command runs (and redials).
    let replies = conn
        .handle(Cmd::Query(ferrogate_tui::client::Query::WhoAmI))
        .await;
    let [Reply::Failed(_, e)] = &replies[..] else {
        panic!("{replies:?}");
    };
    assert_eq!(e.code, tonic::Code::DeadlineExceeded);
    // Ending the session never waits on this server.
    let started = std::time::Instant::now();
    assert!(matches!(
        &conn.handle(Cmd::Logout).await[..],
        [Reply::LoggedOut]
    ));
    assert!(started.elapsed() < std::time::Duration::from_secs(1));
}

#[tokio::test]
async fn a_logout_through_the_session_handle_ends_the_server_session() {
    let s = server("tui-logout-task", false).await;
    let approver = s.account("approver.six", "ferrogate-approvers").await;
    let (client, mut replies) = ferrogate_tui::client::spawn(ClientConfig {
        endpoint: s.endpoint.clone(),
        pins: vec![s.pin],
        device_token_path: None,
        connect_timeout: ferrogate_tui::client::CONNECT_TIMEOUT,
        rpc_timeout: ferrogate_tui::client::RPC_TIMEOUT,
    });
    let mut password = ferrogate_tui::secret::Secret::new();
    for c in support::PASSWORD.chars() {
        password.push(c);
    }
    let mut totp = ferrogate_tui::secret::Secret::new();
    for c in s.h.fresh_code(&approver).chars() {
        totp.push(c);
    }
    assert!(client.send(Cmd::Login {
        username: approver.username.clone(),
        password,
        totp,
    }));
    let reply = replies.recv().await;
    assert!(matches!(reply, Some(Reply::LoggedIn(_))), "{reply:?}");
    // Lock: the token leaves the slot at once and the logout task (its own
    // connection) ends the session on the server.
    assert!(client.send(Cmd::Logout));
    let reply = replies.recv().await;
    assert!(matches!(reply, Some(Reply::LoggedOut)), "{reply:?}");
    assert_eq!(s.events(|e| matches!(e, AuditEvent::AdminLogout { .. })), 1);
    client.shutdown(std::time::Duration::from_secs(1)).await;
}
