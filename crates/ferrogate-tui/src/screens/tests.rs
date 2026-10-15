//! Render tests on ratatui's `TestBackend` at 80×24 (the supported minimum):
//! every main screen and modal draws its content, untrusted strings arrive
//! inert, secrets are masked, and a smaller terminal gets the notice.

use ferro_proto::admin_v1::{
    AppRequestInfo, AppUser, ApprovalInfo, GetAppRequestResponse, GetApprovalResponse,
};
use ratatui::backend::TestBackend;
use ratatui::style::Color;
use ratatui::Terminal;

use super::*;
use crate::app::dialogs::Dialog;
use crate::app::{LoginScreen, Modal, Msg, SessionView};
use crate::client::DashboardCounts;
use crate::input::Key;

const PIN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const HOSTILE: &str =
    "/opt/\u{1b}]52;c;ZXZpbA==\u{7}\u{1b}[2J\u{202E}gpj.exe/\u{200B}tool\u{9b}31m";

fn render(app: &App, w: u16, h: u16) -> (String, ratatui::buffer::Buffer) {
    let mut t = Terminal::new(TestBackend::new(w, h)).unwrap();
    t.draw(|f| draw(app, f)).unwrap();
    let buf = t.backend().buffer().clone();
    let mut text = String::new();
    for y in 0..h {
        for x in 0..w {
            text.push_str(buf[(x, y)].symbol());
        }
        text.push('\n');
    }
    (text, buf)
}

/// No cell carries a control character (the sanitiser's guarantee, end to
/// end through ratatui).
fn assert_inert(text: &str) {
    assert!(
        !text
            .chars()
            .any(|c| c != '\n' && (c.is_control() || ('\u{202A}'..='\u{202E}').contains(&c))),
        "control character on screen"
    );
}

fn main_app(perms: &[&str]) -> App {
    let mut app = App::new("https://cmis-1:8444", PIN, 30, false);
    app.update(Msg::Tick {
        mono: 0,
        unix: 1_791_936_000,
    });
    app.phase = Phase::Main;
    app.session = Some(SessionView {
        username: "jsilva".into(),
        display_name: "J. Silva".into(),
        groups: vec!["ferrogate-approvers".into()],
        permissions: perms.iter().map(|p| (*p).to_string()).collect(),
        aal: 2,
        idle_timeout_secs: 900,
        step_up_until: Some(1_791_936_000 + 190),
    });
    app
}

fn hostile_request() -> AppRequestInfo {
    AppRequestInfo {
        request_id: "0192ab3c-0000-7000-8000-000000001234".into(),
        host_uuid: "deadbeef-2222-3333-4444-555555555555".into(),
        lineage_id: "lin".into(),
        canonical_path: HOSTILE.into(),
        bin_sha: "ab".repeat(48),
        revision: 3,
        state: 1,
        flags: ferro_appid::flags::RiskFlags::UNSIGNED
            | ferro_appid::flags::RiskFlags::USER_WRITABLE_PATH,
        display_version: "6.2.1 (r3)".into(),
        reason: "need it\u{1b}[31m now".into(),
        target_user: Some(AppUser {
            kind: 1,
            uid: Some(1000),
            sid: String::new(),
            name: "jsouza\u{1b}]8;;http://x\u{7}".into(),
        }),
        submitted_at: 1_791_936_000 - 7_200,
        ..AppRequestInfo::default()
    }
}

#[test]
fn the_login_screen_shows_endpoint_and_pin_and_masks_the_password() {
    let mut app = App::new("https://127.0.0.1:8444", PIN, 30, false);
    for c in "jsilva".chars() {
        app.update(Msg::Key(Key::Char(c)));
    }
    app.update(Msg::Key(Key::Tab));
    for c in "hunter2-secret".chars() {
        app.update(Msg::Key(Key::Char(c)));
    }
    let (text, _) = render(&app, 80, 24);
    assert!(text.contains("FerroGate admin — sign in"), "{text}");
    assert!(text.contains("https://127.0.0.1:8444"));
    assert!(
        text.contains("01234567…89abcdef"),
        "pin fingerprint: {text}"
    );
    assert!(text.contains("jsilva"));
    assert!(!text.contains("hunter2"), "the password is never drawn");
    assert!(text.contains("••••••••••••••"));
    assert!(text.contains("Not enrolled? Use the tray admin client"));
    assert_inert(&text);

    app.phase = Phase::Login(LoginScreen {
        throttled_until: Some(45),
        ..std_login()
    });
    let (text, _) = render(&app, 80, 24);
    assert!(text.contains("try again in 45 s"), "{text}");
}

fn std_login() -> LoginScreen {
    let app = App::new("https://x:1", PIN, 0, false);
    match app.phase {
        Phase::Login(l) => l,
        _ => unreachable!(),
    }
}

#[test]
fn a_terminal_below_80x24_gets_the_notice() {
    let app = main_app(&[]);
    let (text, _) = render(&app, 79, 24);
    assert!(text.contains("Terminal too small"), "{text}");
    let (text, _) = render(&app, 80, 23);
    assert!(text.contains("Terminal too small"));
    let (text, _) = render(&app, 80, 24);
    assert!(!text.contains("Terminal too small"));
}

#[test]
fn the_dashboard_shows_the_header_tabs_and_counts() {
    let mut app = main_app(&["app_request.list"]);
    app.dashboard = Some(DashboardCounts {
        pending: Some((12, false)),
        auto_approved_24h: Some((200, true)),
        expiring_14d: None,
        legacy_no_expiry: Some((0, false)),
    });
    let (text, _) = render(&app, 80, 24);
    assert!(
        text.contains("FerroGate · cmis-1:8444 · jsilva (approver) · AAL2"),
        "{text}"
    );
    assert!(text.contains("idle 14:30"), "{text}");
    assert!(text.contains("step-up ✓ 3:10"), "{text}");
    assert!(text.contains("1 Dashboard"));
    assert!(text.contains("6 Sessions"));
    assert!(text.contains("Pending requests"));
    assert!(text.contains("12"));
    assert!(text.contains("200+"));
    assert!(text.contains("— (not permitted)"));
    assert_inert(&text);
}

#[test]
fn the_request_list_renders_hostile_strings_inert_and_flags_the_row() {
    let mut app = main_app(&["app_request.list"]);
    app.screen = Screen::Requests;
    app.requests.items = vec![hostile_request()];
    app.requests.loaded = true;
    let (text, _) = render(&app, 80, 24);
    assert_inert(&text);
    assert!(text.contains("ID"), "{text}");
    assert!(text.contains("00001234"), "id tail: {text}");
    assert!(text.contains("⚠PENDING"), "{text}");
    assert!(text.contains('…'), "the path is cut in the middle: {text}");
    assert!(text.contains("⚠ user-writable path · unsigned"), "{text}");
    assert!(text.contains("2h"), "age");
    // Keys the viewer lacks are marked.
    assert!(text.contains("a approve✗"), "{text}");
}

#[test]
fn the_request_detail_shows_the_full_escaped_values() {
    let mut app = main_app(&["app_request.read", "app_request.approve"]);
    app.screen = Screen::RequestDetail;
    app.request_detail = Some(Box::new(GetAppRequestResponse {
        request: Some(hostile_request()),
        lineage_auto_update_frozen: true,
        ..GetAppRequestResponse::default()
    }));
    let (text, _) = render(&app, 80, 24);
    assert_inert(&text);
    assert!(
        text.contains("\\x1b]52;c;ZXZpbA==\\x07"),
        "OSC 52 shown, inert: {text}"
    );
    assert!(text.contains("⟨U+202E⟩gpj.exe"), "{text}");
    assert!(text.contains("⟨U+200B⟩"), "{text}");
    assert!(
        text.contains("abababababababab…"),
        "abbreviated hash: {text}"
    );
    app.full_hash = true;
    let (text, _) = render(&app, 80, 24);
    assert!(text.contains(&"ab".repeat(29)), "full hash with h: {text}");
    assert!(!text.contains("(h: show all)"));
}

#[test]
fn the_approval_list_and_detail_render() {
    let mut app = main_app(&["approval.list", "approval.read"]);
    let a = ApprovalInfo {
        approval_id: "0191c2aa-0000-7000-8000-00000000beef".into(),
        host_uuid: "deadbeef-2222-3333-4444-555555555555".into(),
        lineage_id: "lin".into(),
        canonical_path: "/usr/local/bin/backup-agent".into(),
        bin_sha: "cd".repeat(48),
        revision: 4,
        state: 1,
        user_scope: 2,
        update_policy: 2,
        expires_at: 1_791_936_000 + 30 * 86_400,
        declared_version: "1.2".into(),
        note: "ok\u{1b}[5m".into(),
        row_version: 3,
        ..ApprovalInfo::default()
    };
    app.screen = Screen::Approvals;
    app.approvals.items = vec![a.clone()];
    app.approvals.loaded = true;
    let (text, _) = render(&app, 80, 24);
    assert!(
        text.contains("0000BEEF") || text.contains("0000beef"),
        "{text}"
    );
    assert!(text.contains("ACTIVE"));
    assert!(text.contains("2026-11-13"), "{text}");
    assert!(text.contains("auto"));
    app.screen = Screen::ApprovalDetail;
    app.approval_detail = Some(Box::new(GetApprovalResponse {
        approval: Some(a),
        lineage_approvals: vec![],
        ..GetApprovalResponse::default()
    }));
    let (text, _) = render(&app, 80, 24);
    assert_inert(&text);
    assert!(text.contains("A-0000BEEF"), "{text}");
    assert!(text.contains("any user ⚠"));
    assert!(text.contains("ok\\x1b[5m"), "{text}");
    assert!(text.contains("e edit✗"), "no approval.update: {text}");
}

#[test]
fn hosts_accounts_and_sessions_explain_what_is_missing() {
    let mut app = main_app(&[]);
    app.screen = Screen::Hosts;
    let (text, _) = render(&app, 80, 24);
    assert!(text.contains("not available on this server"), "{text}");
    app.screen = Screen::Accounts;
    let (text, _) = render(&app, 80, 24);
    assert!(text.contains("Requires an account administrator"), "{text}");
    app.screen = Screen::Sessions;
    let (text, _) = render(&app, 80, 24);
    assert!(text.contains("SESSION"), "{text}");
}

#[test]
fn the_approve_dialog_and_its_review_fit_80x24() {
    let mut app = main_app(&["app_request.approve"]);
    app.screen = Screen::RequestDetail;
    let detail = GetAppRequestResponse {
        request: Some(hostile_request()),
        ..GetAppRequestResponse::default()
    };
    app.modal = Some(Modal::Dialog(Box::new(Dialog::approve(&detail).unwrap())));
    let (text, _) = render(&app, 80, 24);
    assert_inert(&text);
    assert!(text.contains("Update policy"), "{text}");
    assert!(
        text.contains("◀ Manual approval for every new binary ▶"),
        "{text}"
    );
    assert!(text.contains("⚠ user-writable path · unsigned"), "{text}");
    assert!(text.contains("Enter review"));
    app.update(Msg::Key(Key::Enter));
    let (text, _) = render(&app, 80, 24);
    assert!(
        text.contains("Review — nothing is sent until you press y"),
        "{text}"
    );
    assert!(text.contains("manual each time"), "{text}");
    assert!(text.contains("y: confirm"), "{text}");
}

#[test]
fn the_add_review_states_the_outcome_and_scrolls() {
    let mut app = main_app(&["app.direct_register", "app_request.approve"]);
    let mut d = Dialog::register(true);
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
    d.form.paste(&"0f".repeat(48));
    d.on_key(Key::Enter, app.unix);
    app.modal = Some(Modal::Dialog(Box::new(d)));
    let mut seen = String::new();
    for _ in 0..30 {
        let (text, _) = render(&app, 80, 24);
        seen.push_str(&text);
        app.update(Msg::Key(Key::Down));
    }
    assert!(seen.contains("registers AND approves"), "{seen}");
    assert!(seen.contains("YOUR ASSERTION"), "{seen}");
    assert!(seen.contains("fresh TOTP"), "{seen}");
    assert!(seen.contains("↓ more below"), "the review says it scrolls");
}

#[test]
fn monochrome_draws_no_colour() {
    let mut app = main_app(&["app_request.list"]);
    app.monochrome = true;
    app.screen = Screen::Requests;
    app.requests.items = vec![hostile_request()];
    app.requests.loaded = true;
    app.status = Some((crate::app::Level::Warn, "refused".into()));
    let (_, buf) = render(&app, 80, 24);
    for cell in buf.content() {
        assert_eq!(cell.fg, Color::Reset);
        assert_eq!(cell.bg, Color::Reset);
    }
}

#[test]
fn modals_render_inert_messages_and_masked_codes() {
    let mut app = main_app(&[]);
    app.modal = Some(Modal::Message {
        title: "Refused\u{1b}[2J".into(),
        lines: vec!["refused: bad\u{1b}]52;c;x\u{7}".into()],
    });
    let (text, _) = render(&app, 80, 24);
    assert_inert(&text);
    assert!(text.contains("Refused\\x1b[2J"), "{text}");
    let mut form = crate::app::form::Form::new(vec![crate::app::form::Field::secret(
        "totp",
        "TOTP code",
        true,
        8,
    )]);
    form.paste("987654");
    app.modal = Some(Modal::StepUp { form, error: None });
    let (text, _) = render(&app, 80, 24);
    assert!(text.contains("••••••"), "{text}");
    assert!(!text.contains("987654"));
    app.modal = Some(Modal::Help);
    let (text, _) = render(&app, 80, 24);
    assert!(text.contains("Ctrl-L"), "{text}");
}
