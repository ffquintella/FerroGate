//! Dashboard, Requests, Approvals, Hosts, Accounts and Sessions.

use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use super::{short, Theme};
use crate::app::filters::{warning_flags, APPROVAL_STATES, REQUEST_STATES};
use crate::app::{perm, App, ListView};
use crate::client::Count;
use crate::sanitize::{truncate_end, truncate_middle};
use crate::timefmt;

/// One column: header, width (0 = takes the rest), middle-ellipsis.
struct Col {
    head: &'static str,
    width: usize,
    middle: bool,
}

const fn col(head: &'static str, width: usize) -> Col {
    Col {
        head,
        width,
        middle: false,
    }
}

/// Lay out `cols` in `total` columns: fixed widths, the flexible one gets the
/// rest.
fn widths(cols: &[Col], total: usize) -> Vec<usize> {
    let fixed: usize = cols.iter().map(|c| c.width).sum::<usize>() + cols.len().saturating_sub(1);
    let flex = total.saturating_sub(fixed).max(6);
    cols.iter()
        .map(|c| if c.width == 0 { flex } else { c.width })
        .collect()
}

/// A table row: every cell sanitised and fitted.
fn row(cols: &[Col], w: &[usize], cells: &[String]) -> String {
    let mut out = String::new();
    for (i, ((c, width), cell)) in cols.iter().zip(w).zip(cells).enumerate() {
        if i > 0 {
            out.push(' ');
        }
        let fitted = if c.middle {
            truncate_middle(cell, *width)
        } else {
            truncate_end(cell, *width)
        };
        let pad = width.saturating_sub(crate::sanitize::width(&fitted));
        out.push_str(&fitted);
        out.push_str(&" ".repeat(pad));
    }
    out
}

fn header(cols: &[Col], w: &[usize]) -> String {
    let cells: Vec<String> = cols.iter().map(|c| c.head.to_string()).collect();
    row(cols, w, &cells)
}

/// The first visible row so that `selected` is on screen.
fn offset(selected: usize, visible: usize) -> usize {
    if visible == 0 {
        0
    } else {
        selected.saturating_sub(visible - 1)
    }
}

fn list_status<T>(list: &ListView<T>, shown: usize) -> String {
    let mut s = format!("{shown} shown · page {}", list.page());
    if !list.next_token.is_empty() {
        s.push_str(" · more (n)");
    }
    s.push_str(if list.ascending {
        " · oldest first"
    } else {
        " · newest first"
    });
    if list.loading {
        s.push_str(" · loading…");
    }
    s
}

fn figure(c: Option<Count>) -> String {
    match c {
        None => "loading…".to_string(),
        Some(None) => "— (not permitted)".to_string(),
        Some(Some((n, true))) => format!("{n}+"),
        Some(Some((n, false))) => n.to_string(),
    }
}

/// The dashboard.
pub(super) fn dashboard(app: &App, area: Rect, frame: &mut Frame<'_>) {
    let theme = Theme::of(app);
    let d = app.dashboard.as_ref();
    let mut lines = vec![
        Line::from(format!(
            "{:<34}{}",
            "Pending requests",
            figure(d.map(|d| d.pending))
        )),
        Line::from(format!(
            "{:<34}{}",
            "Auto-approved in the last 24 h",
            figure(d.map(|d| d.auto_approved_24h))
        )),
        Line::from(format!(
            "{:<34}{}",
            "Approvals expiring within 14 days",
            figure(d.map(|d| d.expiring_14d))
        )),
        Line::from(format!(
            "{:<34}{}",
            "Legacy approvals without expiry",
            figure(d.map(|d| d.legacy_no_expiry))
        )),
        Line::from(Span::styled(
            format!(
                "{:<34}{}",
                "Hosts with sync failures", "not exposed by this server"
            ),
            theme.muted(),
        )),
        Line::from(""),
    ];
    if let Some(s) = &app.session {
        let who = format!(
            "Signed in as {} ({}) · {}",
            s.username,
            if s.display_name.is_empty() {
                "—"
            } else {
                &s.display_name
            },
            s.role()
        );
        lines.push(Line::from(truncate_end(&who, usize::from(area.width))));
        lines.extend(super::kv("Groups", &s.groups.join(", "), area.width));
        lines.extend(super::kv(
            "Permissions",
            &if s.permissions.is_empty() {
                "loading…".to_string()
            } else {
                s.permissions.join(", ")
            },
            area.width,
        ));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "Counts stop at one page (200); \"200+\" means more.",
        theme.muted(),
    )));
    frame.render_widget(Paragraph::new(lines), area);
}

const REQUEST_COLS: [Col; 8] = [
    col("ID", 8),
    col("STATE", 8),
    col("HOST", 8),
    Col {
        head: "APP (path)",
        width: 0,
        middle: true,
    },
    col("VERSION", 12),
    col("USER", 8),
    col("KIND", 4),
    col("AGE", 4),
];

fn request_state(code: u32) -> &'static str {
    REQUEST_STATES
        .get(code.wrapping_sub(1) as usize)
        .copied()
        .unwrap_or("?")
}

/// The request list.
pub(super) fn requests(app: &App, area: Rect, frame: &mut Frame<'_>) {
    let theme = Theme::of(app);
    let list = &app.requests;
    let width = usize::from(area.width);
    let w = widths(&REQUEST_COLS, width);
    let mut lines = Vec::new();
    let search = if app.request_filters.text.is_empty() {
        String::new()
    } else {
        format!("/ {}   ", app.request_filters.text)
    };
    lines.push(Line::from(truncate_end(
        &format!(
            "{search}{}   {}",
            app.request_filters.summary(),
            list_status(list, list.items.len())
        ),
        width,
    )));
    lines.push(Line::styled(header(&REQUEST_COLS, &w), theme.title()));
    let visible = usize::from(area.height).saturating_sub(4);
    if let Some(e) = &list.error {
        lines.push(Line::styled(
            truncate_end(&format!("✗ {e}"), width),
            theme.error(),
        ));
    } else if list.items.is_empty() {
        lines.push(Line::styled(
            if list.loaded {
                "No request matches."
            } else {
                "Loading…"
            },
            theme.muted(),
        ));
    }
    let start = offset(list.selected, visible);
    for (i, r) in list.items.iter().enumerate().skip(start).take(visible) {
        let user = r
            .target_user
            .as_ref()
            .map(|u| u.name.clone())
            .unwrap_or_default();
        let kind = if r.kind == 2 { "upd" } else { "reg" };
        let flag = if warning_flags(r.flags).is_empty() {
            ""
        } else {
            "⚠"
        };
        let cells = [
            short(&r.request_id),
            format!("{flag}{}", request_state(r.state)).to_uppercase(),
            r.host_uuid.clone(),
            r.canonical_path.clone(),
            r.display_version.clone(),
            user,
            kind.to_string(),
            timefmt::age(app.unix, r.submitted_at),
        ];
        let text = row(&REQUEST_COLS, &w, &cells);
        lines.push(if i == list.selected {
            Line::styled(text, theme.selected())
        } else {
            Line::from(text)
        });
    }
    // The selected row's risk flags.
    if let Some(r) = list.items.get(list.selected) {
        let flags = warning_flags(r.flags);
        let used = lines.len();
        for _ in used..usize::from(area.height).saturating_sub(1) {
            lines.push(Line::from(""));
        }
        if !flags.is_empty() {
            lines.push(Line::styled(
                truncate_end(&format!("  ⚠ {}", flags.join(" · ")), width),
                theme.warn(),
            ));
        }
    }
    frame.render_widget(Paragraph::new(lines), area);
}

const APPROVAL_COLS: [Col; 9] = [
    col("ID", 8),
    col("STATE", 8),
    col("HOST", 8),
    Col {
        head: "APP (path)",
        width: 0,
        middle: true,
    },
    col("VERSION", 10),
    col("SCOPE", 5),
    col("POLICY", 6),
    col("EXPIRES", 10),
    col("", 2),
];

/// The approval list.
pub(super) fn approvals(app: &App, area: Rect, frame: &mut Frame<'_>) {
    let theme = Theme::of(app);
    let list = &app.approvals;
    let width = usize::from(area.width);
    let w = widths(&APPROVAL_COLS, width);
    let mut lines = Vec::new();
    let search = if app.approval_filters.text.is_empty() {
        String::new()
    } else {
        format!("/ {}   ", app.approval_filters.text)
    };
    lines.push(Line::from(truncate_end(
        &format!(
            "{search}{}   {}",
            app.approval_filters.summary(),
            list_status(list, list.items.len())
        ),
        width,
    )));
    lines.push(Line::styled(header(&APPROVAL_COLS, &w), theme.title()));
    let visible = usize::from(area.height).saturating_sub(3);
    if let Some(e) = &list.error {
        lines.push(Line::styled(
            truncate_end(&format!("✗ {e}"), width),
            theme.error(),
        ));
    } else if list.items.is_empty() {
        lines.push(Line::styled(
            if list.loaded {
                "No approval matches."
            } else {
                "Loading…"
            },
            theme.muted(),
        ));
    }
    let start = offset(list.selected, visible);
    for (i, a) in list.items.iter().enumerate().skip(start).take(visible) {
        let state = APPROVAL_STATES
            .get(a.state.wrapping_sub(1) as usize)
            .copied()
            .unwrap_or("?");
        let version = if a.declared_version.is_empty() {
            format!("r{}", a.revision)
        } else {
            format!("{} (r{})", a.declared_version, a.revision)
        };
        let cells = [
            short(&a.approval_id),
            state.to_uppercase(),
            a.host_uuid.clone(),
            a.canonical_path.clone(),
            version,
            if a.user_scope == 2 { "any" } else { "user" }.to_string(),
            if a.update_policy == 2 {
                "auto"
            } else {
                "manual"
            }
            .to_string(),
            if a.expires_at == 0 {
                "never".to_string()
            } else {
                timefmt::date(a.expires_at)
            },
            if a.superseded_by.is_empty() { "" } else { "S" }.to_string(),
        ];
        let text = row(&APPROVAL_COLS, &w, &cells);
        lines.push(if i == list.selected {
            Line::styled(text, theme.selected())
        } else {
            Line::from(text)
        });
    }
    frame.render_widget(Paragraph::new(lines), area);
}

/// Hosts: no `ListHosts` RPC on the server yet.
pub(super) fn hosts(area: Rect, frame: &mut Frame<'_>) {
    let lines = vec![
        Line::from("Hosts are not available on this server."),
        Line::from(""),
        Line::from("The ListHosts RPC is not implemented by CMIS yet (deferred in M37)."),
        Line::from("Requests and approvals show each host's UUID; filter by it with f."),
    ];
    frame.render_widget(Paragraph::new(lines), area);
}

/// Administrator accounts (read-only here).
pub(super) fn accounts(app: &App, area: Rect, frame: &mut Frame<'_>) {
    let theme = Theme::of(app);
    if !app.can(perm::ACCOUNT_LIST) {
        frame.render_widget(
            Paragraph::new(vec![Line::styled(
                "Requires an account administrator (account.list).",
                theme.muted(),
            )]),
            area,
        );
        return;
    }
    let cols = [
        col("USERNAME", 18),
        col("STATE", 8),
        col("GROUPS", 0),
        col("LAST LOGIN", 16),
        col("PW EXPIRES", 10),
    ];
    let w = widths(&cols, usize::from(area.width));
    let mut lines = vec![Line::styled(header(&cols, &w), theme.title())];
    match &app.accounts {
        None => lines.push(Line::styled("Loading…", theme.muted())),
        Some(list) => {
            for a in list.iter().take(usize::from(area.height).saturating_sub(3)) {
                let state = match a.state {
                    1 => "pending",
                    2 => "active",
                    3 => "disabled",
                    _ => "?",
                };
                let cells = [
                    a.username.clone(),
                    state.to_string(),
                    a.groups.join(","),
                    timefmt::datetime(a.last_login_at),
                    if a.password_expires_at == 0 {
                        "—".to_string()
                    } else {
                        timefmt::date(a.password_expires_at)
                    },
                ];
                lines.push(Line::from(row(&cols, &w, &cells)));
            }
        }
    }
    lines.push(Line::styled(
        "Creating, disabling and resetting accounts: ferrogate admin accounts (CLI).",
        theme.muted(),
    ));
    frame.render_widget(Paragraph::new(lines), area);
}

/// The administrator's own sessions.
pub(super) fn sessions(app: &App, area: Rect, frame: &mut Frame<'_>) {
    let theme = Theme::of(app);
    let cols = [
        col("SESSION", 10),
        col("CREATED", 16),
        col("LAST SEEN", 16),
        col("FROM", 0),
        col("CLIENT", 6),
        col("AAL", 3),
    ];
    let w = widths(&cols, usize::from(area.width));
    let mut lines = vec![Line::styled(header(&cols, &w), theme.title())];
    match &app.sessions {
        None => lines.push(Line::styled("Loading…", theme.muted())),
        Some(list) => {
            for s in list.iter().take(usize::from(area.height).saturating_sub(3)) {
                let client = match s.client_kind {
                    1 => "tui",
                    2 => "tray",
                    3 => "cli",
                    _ => "?",
                };
                let cells = [
                    format!(
                        "{}{}",
                        short(&s.session_ref),
                        if s.current { "*" } else { "" }
                    ),
                    timefmt::datetime(s.created_at),
                    timefmt::datetime(s.last_seen_at),
                    s.source_ip.clone(),
                    client.to_string(),
                    s.aal.to_string(),
                ];
                lines.push(Line::from(row(&cols, &w, &cells)));
            }
        }
    }
    lines.push(Line::styled(
        "* this session. Revoking sessions: ferrogate admin sessions revoke (CLI).",
        theme.muted(),
    ));
    frame.render_widget(Paragraph::new(lines), area);
}
