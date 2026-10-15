//! Headless transition tests of the state machine: keys, permission gating,
//! filter validation, dialog defaults, review content, the step-up retry with
//! the same idempotency key, the fresh TOTP of a direct add, idle lock,
//! session end and quit.

use ferro_appid::flags::RiskFlags;
use ferro_proto::admin_v1::{
    AdminRegisterApplicationResponse, AppUser, ApproveAppRequestResponse, ListAppRequestsResponse,
    WhoAmIResponse,
};

use super::*;
use crate::client::{Mutated, Op, RpcError};

const PIN: &str = "abababababababababababababababababababababababababababababababababababababababababababababababab";

fn new_app() -> App {
    App::new("https://127.0.0.1:8444", PIN, 30, false)
}

fn key(app: &mut App, k: Key) -> Vec<Cmd> {
    app.update(Msg::Key(k))
}

fn typed(app: &mut App, text: &str) -> Vec<Cmd> {
    let mut out = Vec::new();
    for c in text.chars() {
        out.extend(app.update(Msg::Key(Key::Char(c))));
    }
    out
}

fn reply(app: &mut App, r: Reply) -> Vec<Cmd> {
    app.update(Msg::Reply(r))
}

fn tick(app: &mut App, mono: u64) -> Vec<Cmd> {
    app.update(Msg::Tick {
        mono,
        unix: 1_791_936_000 + i64::try_from(mono).unwrap(),
    })
}

fn status_text(app: &App) -> String {
    app.status
        .as_ref()
        .map(|(_, t)| t.clone())
        .unwrap_or_default()
}

/// Sign in with `permissions`; returns the app on the dashboard.
fn signed_in(permissions: &[&str]) -> App {
    let mut app = new_app();
    tick(&mut app, 0);
    typed(&mut app, "jsilva");
    assert!(
        key(&mut app, Key::Enter).is_empty(),
        "Enter moves to the password"
    );
    typed(&mut app, "correct horse battery staple!!");
    key(&mut app, Key::Enter);
    typed(&mut app, "123456");
    let cmds = key(&mut app, Key::Enter);
    let [Cmd::Login {
        username,
        password,
        totp,
    }] = &cmds[..]
    else {
        panic!("one Login command");
    };
    assert_eq!(username, "jsilva");
    assert_eq!(password.expose(), "correct horse battery staple!!");
    assert_eq!(totp.expose(), "123456");
    let Phase::Login(l) = &app.phase else {
        panic!()
    };
    assert!(
        l.form.secret("password").unwrap().is_empty(),
        "the form no longer holds the password"
    );
    let cmds = reply(
        &mut app,
        Reply::LoggedIn(LoginInfo {
            idle_timeout_secs: 900,
            aal: 2,
            password_change_required: false,
            admin_id: "adm-1".into(),
            display_name: "J. Silva".into(),
            groups: vec!["ferrogate-approvers".into()],
        }),
    );
    assert!(matches!(app.phase, Phase::Main));
    assert!(matches!(
        &cmds[..],
        [
            Cmd::Query(Query::WhoAmI),
            Cmd::Query(Query::Dashboard { .. })
        ]
    ));
    reply(
        &mut app,
        Reply::WhoAmI(Box::new(WhoAmIResponse {
            username: "jsilva".into(),
            permissions: permissions.iter().map(|p| (*p).to_string()).collect(),
            groups: vec!["ferrogate-approvers".into()],
            aal: 2,
            ..WhoAmIResponse::default()
        })),
    );
    app
}

const APPROVER: [&str; 7] = [
    perm::REQUEST_LIST,
    "app_request.read",
    perm::APPROVAL_LIST,
    "approval.read",
    perm::APPROVE,
    perm::DENY,
    perm::DIRECT_REGISTER,
];
const VIEWER: [&str; 4] = [
    perm::REQUEST_LIST,
    "app_request.read",
    perm::APPROVAL_LIST,
    "approval.read",
];

fn request(flags: u32) -> AppRequestInfo {
    AppRequestInfo {
        request_id: "0192a9f1-0000-7000-8000-00000000a1b2".into(),
        host_uuid: "11111111-2222-3333-4444-555555555555".into(),
        lineage_id: "lin-1".into(),
        canonical_path: "/usr/local/bin/backup-agent".into(),
        bin_sha: "ab".repeat(48),
        revision: 4,
        state: 1,
        flags,
        display_version: "r4".into(),
        target_user: Some(AppUser {
            kind: 1,
            uid: Some(993),
            sid: String::new(),
            name: "backup".into(),
        }),
        ..AppRequestInfo::default()
    }
}

/// Open the Requests screen with one row.
fn with_requests(app: &mut App, flags: u32) {
    let cmds = typed(app, "2");
    let [Cmd::Query(Query::Requests { seq, req })] = &cmds[..] else {
        panic!("2 loads the requests");
    };
    assert_eq!(req.states, vec![1], "pending by default");
    let seq = *seq;
    reply(
        app,
        Reply::Requests(
            seq,
            ListAppRequestsResponse {
                items: vec![request(flags)],
                next_page_token: "next-1".into(),
            },
        ),
    );
    assert_eq!(app.screen, Screen::Requests);
}

/// From the Requests list, `a` loads the request and opens the dialog.
fn open_approve(app: &mut App, flags: u32) {
    let cmds = typed(app, "a");
    let [Cmd::Query(Query::Request { seq, id })] = &cmds[..] else {
        panic!("a loads the request first");
    };
    assert_eq!(id, "0192a9f1-0000-7000-8000-00000000a1b2");
    let seq = *seq;
    reply(
        app,
        Reply::Request(
            seq,
            Box::new(GetAppRequestResponse {
                request: Some(request(flags)),
                ..GetAppRequestResponse::default()
            }),
        ),
    );
    assert!(matches!(app.modal, Some(Modal::Dialog(_))), "dialog opened");
}

fn mutate_key(cmds: &[Cmd]) -> String {
    match cmds {
        [Cmd::Mutate(m)] => m.idempotency_key().to_string(),
        _ => panic!("expected one mutation"),
    }
}

#[test]
fn login_needs_every_field_and_reports_failures_generically() {
    let mut app = new_app();
    typed(&mut app, "jsilva");
    key(&mut app, Key::Tab);
    key(&mut app, Key::Tab);
    typed(&mut app, "12345");
    assert!(
        key(&mut app, Key::Enter).is_empty(),
        "no password, short code"
    );
    let Phase::Login(l) = &app.phase else {
        panic!()
    };
    assert!(l.error.is_some());

    let mut app = signed_in(&[]);
    // Lock, then a failed sign-in shows one generic line.
    key(&mut app, Key::CtrlL);
    let Phase::Login(_) = &app.phase else {
        panic!()
    };
    reply(&mut app, Reply::LoginFailed(LoginError::Rejected));
    let Phase::Login(l) = &app.phase else {
        panic!()
    };
    assert_eq!(
        l.error.as_deref(),
        Some("Sign-in failed. Check the username, password and code.")
    );
}

#[test]
fn a_throttled_login_waits_for_the_countdown() {
    let mut app = new_app();
    tick(&mut app, 10);
    reply(&mut app, Reply::LoginFailed(LoginError::Throttled(60)));
    let Phase::Login(l) = &app.phase else {
        panic!()
    };
    assert_eq!(l.throttled_until, Some(70));
    let Phase::Login(l) = &mut app.phase else {
        panic!()
    };
    for (k, v) in [("username", "u"), ("password", "p"), ("totp", "123456")] {
        l.form.focus_on(k);
        l.form.paste(v);
    }
    assert!(
        key(&mut app, Key::Enter).is_empty(),
        "refused while throttled"
    );
    tick(&mut app, 70);
    let Phase::Login(l) = &app.phase else {
        panic!()
    };
    assert!(l.throttled_until.is_none());
    assert!(matches!(
        &key(&mut app, Key::Enter)[..],
        [Cmd::Login { .. }]
    ));
}

#[test]
fn an_expired_password_forces_the_change_first() {
    let mut app = new_app();
    typed(&mut app, "u");
    key(&mut app, Key::Enter);
    typed(&mut app, "p");
    key(&mut app, Key::Enter);
    typed(&mut app, "123456");
    key(&mut app, Key::Enter);
    let cmds = reply(
        &mut app,
        Reply::LoggedIn(LoginInfo {
            idle_timeout_secs: 900,
            aal: 2,
            password_change_required: true,
            admin_id: String::new(),
            display_name: String::new(),
            groups: vec![],
        }),
    );
    assert!(cmds.is_empty(), "nothing but the change is allowed");
    assert!(matches!(app.phase, Phase::ChangePassword(_)));
    // Screen keys do nothing here.
    assert!(typed(&mut app, "2").is_empty());
    let Phase::ChangePassword(p) = &mut app.phase else {
        panic!()
    };
    p.form.focus = 0;
    p.form.paste("old-password");
    p.form.focus = 1;
    p.form.paste("a-new-password-of-24-chars!");
    p.form.focus = 2;
    p.form.paste("a-new-password-of-24-chars?");
    p.form.focus = 3;
    p.form.paste("654321");
    assert!(key(&mut app, Key::Enter).is_empty());
    let Phase::ChangePassword(p) = &mut app.phase else {
        panic!()
    };
    assert_eq!(p.error.as_deref(), Some("The two new passwords differ."));
    p.form.focus = 2;
    p.form.paste("x");
    p.form.focus = 2;
    for _ in 0..30 {
        p.form.handle(Key::Backspace);
    }
    p.form.paste("a-new-password-of-24-chars!");
    p.form.focus = 3;
    let cmds = key(&mut app, Key::Enter);
    assert!(matches!(&cmds[..], [Cmd::ChangePassword { .. }]));
    let cmds = reply(&mut app, Reply::PasswordChanged(0));
    assert!(matches!(app.phase, Phase::Main));
    assert!(matches!(&cmds[..], [Cmd::Query(Query::WhoAmI), _]));
}

#[test]
fn screen_keys_switch_and_load() {
    let mut app = signed_in(&APPROVER);
    let cmds = typed(&mut app, "3");
    assert_eq!(app.screen, Screen::Approvals);
    let [Cmd::Query(Query::Approvals { req, .. })] = &cmds[..] else {
        panic!()
    };
    assert_eq!(req.states, vec![1], "active by default");
    typed(&mut app, "4");
    assert_eq!(app.screen, Screen::Hosts);
    let cmds = typed(&mut app, "6");
    assert!(matches!(&cmds[..], [Cmd::Query(Query::Sessions)]));
    let cmds = typed(&mut app, "5");
    assert!(cmds.is_empty(), "no account.list: nothing requested");
    key(&mut app, Key::Tab);
    assert_eq!(app.screen, Screen::Sessions);
    key(&mut app, Key::Tab);
    assert_eq!(app.screen, Screen::Dashboard);
    key(&mut app, Key::BackTab);
    assert_eq!(app.screen, Screen::Sessions);
    typed(&mut app, "?");
    assert!(matches!(app.modal, Some(Modal::Help)));
    key(&mut app, Key::Esc);
    assert!(app.modal.is_none());
}

#[test]
fn keys_needing_a_permission_are_refused_with_the_reason() {
    let mut app = signed_in(&VIEWER);
    with_requests(&mut app, 0);
    assert!(typed(&mut app, "a").is_empty());
    assert!(status_text(&app).contains("requires app_request.approve"));
    assert!(typed(&mut app, "d").is_empty());
    assert!(status_text(&app).contains("requires app_request.deny"));
    assert!(typed(&mut app, "A").is_empty());
    assert!(status_text(&app).contains("requires app.direct_register"));
    assert!(app.modal.is_none());
    // Reading is allowed.
    assert!(matches!(
        &key(&mut app, Key::Enter)[..],
        [Cmd::Query(Query::Request { .. })]
    ));
}

#[test]
fn lists_page_with_server_tokens_and_drop_stale_replies() {
    let mut app = signed_in(&APPROVER);
    with_requests(&mut app, 0);
    let cmds = typed(&mut app, "n");
    let [Cmd::Query(Query::Requests { seq, req })] = &cmds[..] else {
        panic!()
    };
    assert_eq!(req.page.as_ref().unwrap().page_token, "next-1");
    assert_eq!(app.requests.page(), 2);
    let newest = *seq;
    // A reply to an older query is ignored.
    reply(
        &mut app,
        Reply::Requests(newest - 1, ListAppRequestsResponse::default()),
    );
    assert_eq!(app.requests.items.len(), 1);
    reply(
        &mut app,
        Reply::Requests(newest, ListAppRequestsResponse::default()),
    );
    assert_eq!(app.requests.items.len(), 0);
    let cmds = typed(&mut app, "p");
    let [Cmd::Query(Query::Requests { req, .. })] = &cmds[..] else {
        panic!()
    };
    assert_eq!(req.page.as_ref().unwrap().page_token, "");
    let cmds = typed(&mut app, "s");
    let [Cmd::Query(Query::Requests { req, .. })] = &cmds[..] else {
        panic!()
    };
    assert!(req.ascending, "s toggles the order");
}

#[test]
fn the_filter_panel_validates_inline_and_sends_structured_fields() {
    let mut app = signed_in(&APPROVER);
    with_requests(&mut app, 0);
    typed(&mut app, "f");
    let Some(Modal::Filters { form, .. }) = &mut app.modal else {
        panic!("f opens the panel")
    };
    form.focus_on("sha");
    form.paste("xyz");
    assert!(
        key(&mut app, Key::Enter).is_empty(),
        "invalid: nothing sent"
    );
    let Some(Modal::Filters { form, .. }) = &mut app.modal else {
        panic!("still open")
    };
    assert!(form.field("sha").unwrap().error.is_some());
    form.focus_on("sha");
    for _ in 0..3 {
        form.handle(Key::Backspace);
    }
    form.paste("ABCDEF01");
    form.focus_on("path");
    form.paste("zoom");
    let cmds = key(&mut app, Key::Enter);
    let [Cmd::Query(Query::Requests { req, .. })] = &cmds[..] else {
        panic!()
    };
    assert_eq!(req.bin_sha_prefix, "abcdef01");
    assert_eq!(req.path_contains, "zoom");
    assert!(app.modal.is_none());

    // Free-text search, bounded at 128 characters.
    typed(&mut app, "/");
    let Some(Modal::Search { form, .. }) = &mut app.modal else {
        panic!()
    };
    form.paste(&"z".repeat(300));
    let cmds = key(&mut app, Key::Enter);
    let [Cmd::Query(Query::Requests { req, .. })] = &cmds[..] else {
        panic!()
    };
    assert_eq!(req.text.len(), 128);
    // c clears every filter.
    let cmds = typed(&mut app, "c");
    let [Cmd::Query(Query::Requests { req, .. })] = &cmds[..] else {
        panic!()
    };
    assert!(req.text.is_empty() && req.path_contains.is_empty());
}

#[test]
fn approve_uses_safe_defaults_and_the_step_up_retry_reuses_the_key_once() {
    let mut app = signed_in(&APPROVER);
    with_requests(
        &mut app,
        RiskFlags::UNSIGNED | RiskFlags::USER_WRITABLE_PATH,
    );
    open_approve(
        &mut app,
        RiskFlags::UNSIGNED | RiskFlags::USER_WRITABLE_PATH,
    );
    let Some(Modal::Dialog(d)) = &app.modal else {
        panic!()
    };
    assert_eq!(
        d.form.choice("policy"),
        0,
        "manual: not protected, unsigned"
    );
    assert_eq!(d.form.choice("scope"), 0);
    assert_eq!(d.warnings(), vec!["user-writable path", "unsigned"]);
    // Esc sends nothing.
    assert!(key(&mut app, Key::Esc).is_empty());
    assert!(app.modal.is_none());
    assert_eq!(app.screen, Screen::RequestDetail);
    key(&mut app, Key::Esc);
    assert_eq!(app.screen, Screen::Requests);
    open_approve(&mut app, 0);
    assert!(
        key(&mut app, Key::Enter).is_empty(),
        "Enter goes to the review"
    );
    let Some(Modal::Dialog(d)) = &app.modal else {
        panic!()
    };
    assert_eq!(d.stage, dialogs::Stage::Review);
    let review = d.review_lines(app.unix).join("\n");
    assert!(
        review.contains("Update policy:  manual each time"),
        "{review}"
    );
    assert!(
        review.contains("User scope:     this user only"),
        "{review}"
    );
    let cmds = typed(&mut app, "y");
    let first_key = mutate_key(&cmds);
    let Cmd::Mutate(m) = &cmds[0] else { panic!() };
    let m = m.clone();

    // The server asks for a step-up: the TOTP modal appears.
    let cmds = reply(
        &mut app,
        Reply::Failed(
            Box::new(Op::Mutation(m.clone())),
            RpcError {
                code: tonic::Code::FailedPrecondition,
                reason: "step_up_required".into(),
                field: None,
                retry_after: None,
            },
        ),
    );
    assert!(cmds.is_empty());
    assert!(matches!(app.modal, Some(Modal::StepUp { .. })));
    typed(&mut app, "654321");
    let cmds = key(&mut app, Key::Enter);
    let [Cmd::StepUp { totp, retry }] = &cmds[..] else {
        panic!("one StepUp")
    };
    assert_eq!(totp.expose(), "654321");
    assert_eq!(
        retry.idempotency_key(),
        first_key,
        "the retry reuses the key"
    );
    assert_eq!(retry, &m, "and the exact request");

    // The server asks again right after the step-up: no loop.
    let until = app.unix + 300;
    reply(&mut app, Reply::SteppedUp(until));
    let cmds = reply(
        &mut app,
        Reply::Failed(
            Box::new(Op::Mutation(m)),
            RpcError {
                code: tonic::Code::FailedPrecondition,
                reason: "step_up_required".into(),
                field: None,
                retry_after: None,
            },
        ),
    );
    assert!(cmds.is_empty(), "nothing more is sent");
    let Some(Modal::Message { lines, .. }) = &app.modal else {
        panic!()
    };
    assert!(lines[0].contains("nothing more was sent"));
    assert!(app.pending.is_none());
}

#[test]
fn a_wrong_step_up_code_asks_again_for_the_same_operation() {
    let mut app = signed_in(&APPROVER);
    with_requests(&mut app, 0);
    open_approve(&mut app, 0);
    key(&mut app, Key::Enter);
    let cmds = typed(&mut app, "y");
    let k = mutate_key(&cmds);
    let Cmd::Mutate(m) = &cmds[0] else { panic!() };
    let m = m.clone();
    let step_up = RpcError {
        code: tonic::Code::FailedPrecondition,
        reason: "step_up_required".into(),
        field: None,
        retry_after: None,
    };
    reply(
        &mut app,
        Reply::Failed(Box::new(Op::Mutation(m.clone())), step_up),
    );
    typed(&mut app, "111111");
    key(&mut app, Key::Enter);
    reply(
        &mut app,
        Reply::Failed(
            Box::new(Op::StepUp(m)),
            RpcError {
                code: tonic::Code::Unauthenticated,
                reason: "invalid_credentials".into(),
                field: None,
                retry_after: None,
            },
        ),
    );
    let Some(Modal::StepUp { error, .. }) = &app.modal else {
        panic!()
    };
    assert_eq!(error.as_deref(), Some("The code was not accepted."));
    typed(&mut app, "222222");
    let cmds = key(&mut app, Key::Enter);
    let [Cmd::StepUp { retry, .. }] = &cmds[..] else {
        panic!()
    };
    assert_eq!(retry.idempotency_key(), k);
    // Success refreshes and reports the approval.
    let cmds = reply(
        &mut app,
        Reply::Mutated(Box::new(Mutated::Approved(ApproveAppRequestResponse {
            approval: Some(ApprovalInfo {
                approval_id: "0193-0000-0000-00000000c0de".into(),
                ..ApprovalInfo::default()
            }),
            allowlist_generation: 7,
            ..ApproveAppRequestResponse::default()
        }))),
    );
    assert!(!cmds.is_empty(), "refreshes after a mutation");
    let Some(Modal::Message { lines, .. }) = &app.modal else {
        panic!()
    };
    assert!(lines[0].contains("A-0000C0DE"), "{lines:?}");
    assert!(lines[0].contains("generation 7"));
    assert!(lines[1].contains("within 5 minutes"));
}

#[test]
fn a_direct_add_always_asks_for_a_fresh_code_and_reuses_its_key() {
    let mut app = signed_in(&APPROVER);
    // A valid step-up window does not replace the per-operation code.
    app.session.as_mut().unwrap().step_up_until = Some(app.unix + 300);
    with_requests(&mut app, 0);
    typed(&mut app, "A");
    let Some(Modal::Dialog(d)) = &mut app.modal else {
        panic!("A opens the add dialog")
    };
    assert_eq!(d.kind, dialogs::DialogKind::Register);
    for (k, v) in [
        ("host", "11111111-2222-3333-4444-555555555555"),
        ("path", "/opt/tool/bin/tool"),
        ("uid", "1000"),
        ("user", "alice"),
    ] {
        d.form.focus_on(k);
        d.form.paste(v);
    }
    d.form.focus_on("sha");
    d.form.paste(&"0123456789abcdef".repeat(6));
    assert!(key(&mut app, Key::Enter).is_empty());
    let Some(Modal::Dialog(d)) = &app.modal else {
        panic!()
    };
    assert_eq!(d.stage, dialogs::Stage::Review);
    let cmds = typed(&mut app, "y");
    assert!(cmds.is_empty(), "y asks for the code, it does not send");
    assert!(matches!(app.modal, Some(Modal::RegisterTotp { .. })));
    typed(&mut app, "123123");
    let cmds = key(&mut app, Key::Enter);
    let [Cmd::Register { req, totp }] = &cmds[..] else {
        panic!("one Register")
    };
    assert_eq!(totp.expose(), "123123");
    assert!(req.proof.is_none(), "the client task adds the proof");
    let first = req.idempotency_key.clone();
    let req = req.clone();
    // A wrong code: asked again, same key.
    reply(
        &mut app,
        Reply::Failed(
            Box::new(Op::Register(req)),
            RpcError {
                code: tonic::Code::Unauthenticated,
                reason: "invalid_credentials".into(),
                field: None,
                retry_after: None,
            },
        ),
    );
    assert!(matches!(app.modal, Some(Modal::RegisterTotp { .. })));
    typed(&mut app, "321321");
    let cmds = key(&mut app, Key::Enter);
    let [Cmd::Register { req, .. }] = &cmds[..] else {
        panic!()
    };
    assert_eq!(req.idempotency_key, first);
    // Strict SoD: the outcome says it is queued.
    reply(
        &mut app,
        Reply::Registered(Box::new(AdminRegisterApplicationResponse {
            request: Some(request(0)),
            queued: true,
            ..AdminRegisterApplicationResponse::default()
        })),
    );
    let Some(Modal::Message { title, lines }) = &app.modal else {
        panic!()
    };
    assert_eq!(title, "Queued for another approver");
    assert!(lines[0].contains("PENDING"));
}

#[test]
fn edit_aborted_reloads_shows_the_change_and_asks_again() {
    let mut app = signed_in(&["approval.read", perm::APPROVAL_LIST, perm::UPDATE]);
    let old = ApprovalInfo {
        approval_id: "0191c2aa-0000-7000-8000-00000000beef".into(),
        lineage_id: "lin".into(),
        canonical_path: "/opt/tool".into(),
        state: 1,
        update_policy: 1,
        continuity: 1,
        user_scope: 1,
        path_match: 1,
        note: "first".into(),
        row_version: 3,
        expires_at: 1_800_000_000,
        ..ApprovalInfo::default()
    };
    app.approval_detail = Some(Box::new(GetApprovalResponse {
        approval: Some(old.clone()),
        ..GetApprovalResponse::default()
    }));
    app.screen = Screen::ApprovalDetail;
    typed(&mut app, "e");
    let Some(Modal::Dialog(d)) = &mut app.modal else {
        panic!("e opens the edit dialog")
    };
    d.form.set_choice("policy", 1);
    key(&mut app, Key::Enter);
    let cmds = typed(&mut app, "y");
    let [Cmd::Mutate(m @ Mutation::Update(u))] = &cmds[..] else {
        panic!()
    };
    assert_eq!(u.expected_row_version, 3);
    // The operator opens another approval while the edit is in flight.
    app.approval_detail = Some(Box::new(GetApprovalResponse {
        approval: Some(ApprovalInfo {
            approval_id: "another".into(),
            note: "unrelated".into(),
            ..ApprovalInfo::default()
        }),
        ..GetApprovalResponse::default()
    }));
    let cmds = reply(
        &mut app,
        Reply::Failed(
            Box::new(Op::Mutation(m.clone())),
            RpcError {
                code: tonic::Code::Aborted,
                reason: "row_version_mismatch".into(),
                field: None,
                retry_after: None,
            },
        ),
    );
    let [Cmd::Query(Query::Approval { seq, id })] = &cmds[..] else {
        panic!("reloads the approval")
    };
    assert_eq!(id, &old.approval_id);
    let seq = *seq;
    let mut new = old.clone();
    new.note = "changed by someone".into();
    new.row_version = 4;
    reply(
        &mut app,
        Reply::Approval(
            seq,
            Box::new(GetApprovalResponse {
                approval: Some(new),
                ..GetApprovalResponse::default()
            }),
        ),
    );
    let Some(Modal::Dialog(d)) = &app.modal else {
        panic!("asks again")
    };
    let notice = d.notice.clone().unwrap();
    assert!(
        notice.contains("note: first → changed by someone"),
        "{notice}"
    );
    let Ctx::Edit { approval } = &d.ctx else {
        panic!()
    };
    assert_eq!(approval.row_version, 4, "based on the new row version");
}

use dialogs::Ctx;

#[test]
fn revoke_needs_the_typed_short_id() {
    let mut app = signed_in(&["approval.read", perm::REVOKE]);
    app.approval_detail = Some(Box::new(GetApprovalResponse {
        approval: Some(ApprovalInfo {
            approval_id: "0191c2aa-0000-7000-8000-00000000beef".into(),
            state: 1,
            row_version: 2,
            ..ApprovalInfo::default()
        }),
        ..GetApprovalResponse::default()
    }));
    app.screen = Screen::ApprovalDetail;
    typed(&mut app, "x");
    assert!(key(&mut app, Key::Enter).is_empty(), "no id typed");
    let Some(Modal::Dialog(d)) = &mut app.modal else {
        panic!()
    };
    d.form.focus_on("confirm");
    d.form.paste("a-0000beef");
    key(&mut app, Key::Enter);
    let cmds = typed(&mut app, "y");
    assert!(matches!(&cmds[..], [Cmd::Mutate(Mutation::Revoke(_))]));
}

#[test]
fn idle_lock_wipes_the_display_and_logs_out() {
    let mut app = signed_in(&APPROVER);
    with_requests(&mut app, 0);
    tick(&mut app, 869);
    assert!(matches!(app.phase, Phase::Main), "not yet: 900 - 30 s");
    typed(&mut app, "j"); // activity resets the countdown
    tick(&mut app, 1_700);
    assert!(matches!(app.phase, Phase::Main));
    let cmds = tick(&mut app, 869 + 870 + 1);
    assert!(matches!(&cmds[..], [Cmd::Logout]), "locks and logs out");
    let Phase::Login(l) = &app.phase else {
        panic!()
    };
    assert!(l.notice.as_deref().unwrap().contains("inactivity"));
    assert!(app.take_clear(), "the screen is cleared");
    assert_eq!(app.requests.items.len(), 0, "records dropped");
    assert!(app.session.is_none());
    // A late reply to a read sent before the lock is dropped.
    let seq = app.requests.seq;
    reply(
        &mut app,
        Reply::Requests(
            seq,
            ListAppRequestsResponse {
                items: vec![request(0)],
                next_page_token: String::new(),
            },
        ),
    );
    assert_eq!(app.requests.items.len(), 0);
}

#[test]
fn ctrl_l_locks_now_and_session_end_returns_to_login() {
    let mut app = signed_in(&APPROVER);
    let cmds = key(&mut app, Key::CtrlL);
    assert!(matches!(&cmds[..], [Cmd::Logout]));
    assert!(matches!(app.phase, Phase::Login(_)));

    let mut app = signed_in(&APPROVER);
    with_requests(&mut app, 0);
    reply(&mut app, Reply::SessionEnded);
    let Phase::Login(l) = &app.phase else {
        panic!()
    };
    assert_eq!(l.notice.as_deref(), Some("Session ended. Sign in again."));
    assert_eq!(app.requests.items.len(), 0);
}

#[test]
fn quit_asks_then_logs_out_before_exiting() {
    let mut app = signed_in(&APPROVER);
    assert!(typed(&mut app, "q").is_empty());
    assert!(matches!(app.modal, Some(Modal::ConfirmQuit)));
    assert!(typed(&mut app, "n").is_empty());
    assert!(app.modal.is_none());
    typed(&mut app, "q");
    let cmds = typed(&mut app, "y");
    assert!(matches!(&cmds[..], [Cmd::Logout]));
    assert!(app.is_quitting() && !app.should_quit());
    reply(&mut app, Reply::LoggedOut);
    assert!(app.should_quit());

    let mut app = signed_in(&APPROVER);
    let cmds = key(&mut app, Key::CtrlC);
    assert!(
        matches!(&cmds[..], [Cmd::Logout]),
        "Ctrl-C logs out at once"
    );
    assert!(app.is_quitting());
}

#[test]
fn a_quit_during_the_sign_in_never_shows_the_new_session() {
    let mut app = new_app();
    tick(&mut app, 0);
    let Phase::Login(l) = &mut app.phase else {
        panic!()
    };
    for (k, v) in [("username", "u"), ("password", "p"), ("totp", "123456")] {
        l.form.focus_on(k);
        l.form.paste(v);
    }
    assert!(matches!(
        &key(&mut app, Key::Enter)[..],
        [Cmd::Login { .. }]
    ));
    // Ctrl-C while the sign-in is in flight: the Logout is queued behind it.
    assert!(matches!(&key(&mut app, Key::CtrlC)[..], [Cmd::Logout]));
    let cmds = reply(
        &mut app,
        Reply::LoggedIn(LoginInfo {
            idle_timeout_secs: 900,
            aal: 2,
            password_change_required: false,
            admin_id: String::new(),
            display_name: "J. Silva".into(),
            groups: vec!["ferrogate-approvers".into()],
        }),
    );
    assert!(
        cmds.is_empty(),
        "no WhoAmI or dashboard for a session being ended"
    );
    assert!(matches!(app.phase, Phase::Login(_)));
    reply(&mut app, Reply::LoggedOut);
    assert!(app.should_quit());
}

#[test]
fn auto_refresh_reloads_the_open_list_when_nothing_is_in_flight() {
    let mut app = signed_in(&APPROVER);
    with_requests(&mut app, 0);
    // The dashboard query from the login is still counted in flight.
    app.in_flight = 0;
    let cmds = tick(&mut app, 31);
    assert!(matches!(&cmds[..], [Cmd::Query(Query::Requests { .. })]));
    let cmds = tick(&mut app, 40);
    assert!(cmds.is_empty(), "a request is in flight");
}

#[test]
fn a_paste_goes_into_the_focused_field_only() {
    let mut app = new_app();
    let mut s = Secret::new();
    for c in "jsilva".chars() {
        s.push(c);
    }
    app.update(Msg::Paste(s));
    let Phase::Login(l) = &app.phase else {
        panic!()
    };
    assert_eq!(l.form.text("username"), "jsilva");
}

#[test]
fn the_password_change_screen_also_locks_when_idle() {
    let mut app = new_app();
    tick(&mut app, 0);
    let Phase::Login(l) = &mut app.phase else {
        panic!()
    };
    for (k, v) in [("username", "u"), ("password", "p"), ("totp", "123456")] {
        l.form.focus_on(k);
        l.form.paste(v);
    }
    assert!(matches!(
        &key(&mut app, Key::Enter)[..],
        [Cmd::Login { .. }]
    ));
    reply(
        &mut app,
        Reply::LoggedIn(LoginInfo {
            idle_timeout_secs: 900,
            aal: 2,
            password_change_required: true,
            admin_id: String::new(),
            display_name: String::new(),
            groups: vec![],
        }),
    );
    assert!(tick(&mut app, 869).is_empty());
    let cmds = tick(&mut app, 870);
    assert!(matches!(&cmds[..], [Cmd::Logout]));
    assert!(matches!(app.phase, Phase::Login(_)));
}

#[test]
fn a_hostile_idle_timeout_can_neither_disable_nor_overflow_the_lock() {
    for (server_idle, lock_at) in [(i64::MAX, 1_770), (i64::MIN, 10), (0, 10), (900, 870)] {
        let mut app = signed_in(&APPROVER);
        app.session.as_mut().unwrap().idle_timeout_secs = server_idle;
        assert!(matches!(app.phase, Phase::Main));
        tick(&mut app, lock_at - 1);
        assert!(matches!(app.phase, Phase::Main), "{server_idle}");
        tick(&mut app, lock_at);
        assert!(matches!(app.phase, Phase::Login(_)), "{server_idle}");
    }
    let mut app = new_app();
    reply(
        &mut app,
        Reply::LoginFailed(LoginError::Throttled(u64::MAX)),
    );
    let Phase::Login(l) = &app.phase else {
        panic!()
    };
    assert_eq!(l.throttled_until, Some(3_600), "capped, no overflow");
}
