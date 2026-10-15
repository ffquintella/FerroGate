//! Request and approval detail views: every field, wrapped and sanitised,
//! with the lineage history.

use std::fmt::Write as _;

use ferro_proto::admin_v1::{AppBinaryInfo, AppUser};
use ratatui::layout::Rect;
use ratatui::text::Line;
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use super::{kv, short, Theme};
use crate::app::dialogs::{short_id, user_label, DENY_REASONS, REVOKE_REASONS};
use crate::app::filters::{
    warning_flags, APPROVAL_ORIGINS, APPROVAL_STATES, REQUEST_ORIGINS, REQUEST_STATES,
};
use crate::app::App;
use crate::sanitize;
use crate::timefmt;

fn name<'a>(table: &[&'a str], code: u32) -> &'a str {
    usize::try_from(code)
        .ok()
        .and_then(|c| c.checked_sub(1))
        .and_then(|i| table.get(i))
        .copied()
        .unwrap_or("—")
}

fn hash(app: &App, sha: &str) -> String {
    if app.full_hash || sha.len() <= 24 {
        sha.to_string()
    } else {
        format!(
            "{}…{}  (h: show all)",
            sha.get(..16).unwrap_or(sha),
            sha.get(sha.len().saturating_sub(8)..).unwrap_or("")
        )
    }
}

fn user(u: Option<&AppUser>) -> String {
    let kind = match u.map(|u| u.kind) {
        Some(2) => "windows",
        Some(1) => "unix",
        _ => "",
    };
    format!("{} {kind}", user_label(u)).trim_end().to_string()
}

fn binary_lines(b: &AppBinaryInfo, width: u16, out: &mut Vec<Line<'static>>) {
    let version = if b.declared_version.is_empty() {
        format!("r{}", b.revision)
    } else {
        format!(
            "{} (r{}, source {})",
            b.declared_version, b.revision, b.version_source
        )
    };
    out.extend(kv("Version", &version, width));
    if !b.product_name.is_empty() {
        out.extend(kv("Product", &b.product_name, width));
    }
    if !b.bundle_id.is_empty() {
        out.extend(kv("Bundle", &b.bundle_id, width));
    }
    if !b.package_name.is_empty() {
        out.extend(kv("Package", &b.package_name, width));
    }
    let signer = match b.signer_kind {
        0 => "none (unsigned)".to_string(),
        k => format!(
            "{} {} — {} ({})",
            if k == 1 { "authenticode" } else { "apple" },
            b.signer_id,
            b.signer_subject,
            if b.signer_valid { "valid" } else { "NOT valid" }
        ),
    };
    out.extend(kv("Signer", &signer, width));
    out.extend(kv(
        "Size / first seen",
        &format!(
            "{} bytes · {}",
            b.file_size,
            timefmt::datetime(b.first_seen_at)
        ),
        width,
    ));
}

/// One request with its lineage history.
#[allow(clippy::too_many_lines)] // one block per field group of F21 §3.
pub(super) fn request(app: &App, area: Rect, frame: &mut Frame<'_>) {
    let theme = Theme::of(app);
    let Some(d) = &app.request_detail else {
        frame.render_widget(Paragraph::new("Loading…"), area);
        return;
    };
    let Some(r) = &d.request else {
        frame.render_widget(Paragraph::new("No request."), area);
        return;
    };
    let w = area.width;
    let mut lines: Vec<Line<'static>> = Vec::new();
    lines.extend(kv(
        "Request",
        &format!("{}  {}", short_id("R", &r.request_id), r.request_id),
        w,
    ));
    lines.extend(kv(
        "State",
        &format!(
            "{} · {} · origin {}",
            name(&REQUEST_STATES, r.state).to_uppercase(),
            if r.kind == 2 { "update" } else { "register" },
            name(&REQUEST_ORIGINS, r.origin)
        ),
        w,
    ));
    lines.extend(kv(
        "Host",
        &format!("{} · tier {}", r.host_uuid, r.host_tier),
        w,
    ));
    lines.extend(kv("Path", &r.canonical_path, w));
    lines.extend(kv("SHA-384", &hash(app, &r.bin_sha), w));
    if let Some(b) = &d.binary {
        binary_lines(b, w, &mut lines);
    } else {
        lines.extend(kv("Version", &r.display_version, w));
    }
    lines.extend(kv("User", &user(r.target_user.as_ref()), w));
    let requester = match (
        &r.requester_user_name,
        r.requester_uid,
        &r.requested_by_admin_id,
    ) {
        (_, _, admin) if !admin.is_empty() => format!("administrator {}", short(admin)),
        (n, Some(uid), _) => format!("{n} ({uid})"),
        (n, None, _) => n.clone(),
    };
    lines.extend(kv("Requester", &requester, w));
    lines.extend(kv(
        "Submitted",
        &format!(
            "{} · pending until {}",
            timefmt::datetime(r.submitted_at),
            timefmt::datetime(r.pending_expires_at)
        ),
        w,
    ));
    if !r.reason.is_empty() {
        lines.extend(kv("Reason", &r.reason, w));
    }
    let flags = warning_flags(r.flags);
    if !flags.is_empty() {
        for l in kv("Flags", &format!("⚠ {}", flags.join(" · ")), w) {
            lines.push(l.style(theme.warn()));
        }
    }
    if r.flags & ferro_appid::flags::RiskFlags::PATH_PROTECTED != 0 {
        lines.extend(kv("Path protection", "writable only by administrators", w));
    }
    if !r.auto_downgrade_reason.is_empty() {
        lines.extend(kv("Auto-downgrade", &r.auto_downgrade_reason, w));
    }
    if r.decided_at != 0 {
        let reason = if r.state == 4 {
            format!(" · reason {}", name(&DENY_REASONS, r.decision_reason_code))
        } else {
            String::new()
        };
        lines.extend(kv(
            "Decision",
            &format!(
                "{} by {}{reason}{}",
                timefmt::datetime(r.decided_at),
                if r.decided_by_admin_id.is_empty() {
                    "policy".to_string()
                } else {
                    short(&r.decided_by_admin_id)
                },
                if r.same_actor_approved {
                    " · same actor"
                } else {
                    ""
                }
            ),
            w,
        ));
        if !r.decision_message.is_empty() {
            lines.extend(kv("Message", &r.decision_message, w));
        }
        if !r.resulting_approval_id.is_empty() {
            lines.extend(kv("Approval", &short_id("A", &r.resulting_approval_id), w));
        }
    }
    lines.push(Line::from(""));
    lines.push(Line::styled(
        format!(
            "Lineage {}{}",
            short(&r.lineage_id),
            if d.lineage_auto_update_frozen {
                "  ❄ auto-update frozen"
            } else {
                ""
            }
        ),
        theme.title(),
    ));
    for b in &d.lineage_binaries {
        let approvals: Vec<String> = d
            .lineage_approvals
            .iter()
            .filter(|a| a.bin_sha == b.bin_sha)
            .map(|a| {
                format!(
                    "{} {}",
                    short_id("A", &a.approval_id),
                    name(&APPROVAL_STATES, a.state)
                )
            })
            .collect();
        let requests: Vec<String> = d
            .lineage_requests
            .iter()
            .filter(|q| q.bin_sha == b.bin_sha)
            .map(|q| {
                format!(
                    "{} {}",
                    short_id("R", &q.request_id),
                    name(&REQUEST_STATES, q.state)
                )
            })
            .collect();
        let line = format!(
            "  r{:<3} {}  {}  {}  {}",
            b.revision,
            b.bin_sha.get(..8).unwrap_or(&b.bin_sha),
            b.display_version,
            requests.join(", "),
            approvals.join(", ")
        );
        lines.push(Line::from(sanitize::truncate_end(&line, usize::from(w))));
    }
    let skip = usize::from(app.scroll).min(lines.len().saturating_sub(1));
    frame.render_widget(
        Paragraph::new(lines.into_iter().skip(skip).collect::<Vec<_>>()),
        area,
    );
}

/// One approval with its revision history and lineage.
#[allow(clippy::too_many_lines)] // one block per field group of F21 §3.
pub(super) fn approval(app: &App, area: Rect, frame: &mut Frame<'_>) {
    let theme = Theme::of(app);
    let Some(d) = &app.approval_detail else {
        frame.render_widget(Paragraph::new("Loading…"), area);
        return;
    };
    let Some(a) = &d.approval else {
        frame.render_widget(Paragraph::new("No approval."), area);
        return;
    };
    let w = area.width;
    let mut lines: Vec<Line<'static>> = Vec::new();
    lines.extend(kv(
        "Approval",
        &format!("{}  {}", short_id("A", &a.approval_id), a.approval_id),
        w,
    ));
    let mut state = name(&APPROVAL_STATES, a.state).to_uppercase();
    if !a.superseded_by.is_empty() {
        let _ = write!(
            state,
            " · superseded by {}",
            short_id("A", &a.superseded_by)
        );
    }
    lines.extend(kv("State", &state, w));
    lines.extend(kv("Origin", name(&APPROVAL_ORIGINS, a.origin), w));
    lines.extend(kv("Host", &a.host_uuid, w));
    lines.extend(kv("Path", &a.canonical_path, w));
    lines.extend(kv("SHA-384", &hash(app, &a.bin_sha), w));
    if let Some(b) = &d.binary {
        binary_lines(b, w, &mut lines);
    } else {
        lines.extend(kv("Revision", &format!("r{}", a.revision), w));
    }
    lines.extend(kv(
        "User scope",
        &if a.user_scope == 2 {
            "any user ⚠".to_string()
        } else {
            format!("this user only · {}", user(a.user.as_ref()))
        },
        w,
    ));
    lines.extend(kv(
        "Path match",
        if a.path_match == 2 {
            "any path"
        } else {
            "exact path"
        },
        w,
    ));
    lines.extend(kv(
        "Update policy",
        if a.update_policy == 2 {
            "auto-update (same path + same user)"
        } else {
            "manual each time"
        },
        w,
    ));
    lines.extend(kv(
        "Continuity",
        if a.continuity == 2 {
            "path + user only ⚠"
        } else {
            "anchored"
        },
        w,
    ));
    lines.extend(kv(
        "Created / expires",
        &format!(
            "{} · {}",
            timefmt::datetime(a.created_at),
            if a.expires_at == 0 {
                "no expiry".to_string()
            } else {
                timefmt::datetime(a.expires_at)
            }
        ),
        w,
    ));
    lines.extend(kv(
        "Approved by",
        &if a.approved_by_admin_id.is_empty() {
            "policy or import".to_string()
        } else {
            short(&a.approved_by_admin_id)
        },
        w,
    ));
    if !a.source_request_id.is_empty() {
        lines.extend(kv("From request", &short_id("R", &a.source_request_id), w));
    }
    if !a.parent_approval_id.is_empty() {
        lines.extend(kv("Parent", &short_id("A", &a.parent_approval_id), w));
    }
    if a.revoked_at != 0 {
        lines.extend(kv(
            "Revoked",
            &format!(
                "{} by {} · reason {}",
                timefmt::datetime(a.revoked_at),
                short(&a.revoked_by_admin_id),
                if a.revoke_reason_code == 1000 {
                    "legacy_entry_removed"
                } else {
                    name(&REVOKE_REASONS, a.revoke_reason_code)
                }
            ),
            w,
        ));
    }
    if !a.note.is_empty() {
        lines.extend(kv("Note", &a.note, w));
    }
    lines.extend(kv("Row version", &a.row_version.to_string(), w));
    lines.push(Line::from(""));
    lines.push(Line::styled("Revisions", theme.title()));
    for r in &d.revisions {
        let kind = match r.change_kind {
            1 => "created",
            2 => "updated",
            3 => "expired",
            4 => "revoked",
            5 => "renewed",
            _ => "?",
        };
        let by = if r.changed_by_admin_id.is_empty() {
            "system".to_string()
        } else {
            short(&r.changed_by_admin_id)
        };
        let what = match (&r.before, &r.after) {
            (Some(b), Some(a)) => {
                let mut parts = Vec::new();
                if b.update_policy != a.update_policy {
                    parts.push("policy");
                }
                if b.continuity != a.continuity {
                    parts.push("continuity");
                }
                if b.expires_at != a.expires_at {
                    parts.push("expiry");
                }
                if b.user_scope != a.user_scope {
                    parts.push("user scope");
                }
                if b.path_match != a.path_match {
                    parts.push("path match");
                }
                if b.state != a.state {
                    parts.push("state");
                }
                parts.join(", ")
            }
            _ => String::new(),
        };
        let line = format!(
            "  v{:<3} {}  {kind:<8} by {by}  {what}",
            r.row_version,
            timefmt::datetime(r.changed_at)
        );
        lines.push(Line::from(sanitize::truncate_end(&line, usize::from(w))));
    }
    lines.push(Line::from(""));
    lines.push(Line::styled(
        format!("Lineage {}", short(&a.lineage_id)),
        theme.title(),
    ));
    for l in &d.lineage_approvals {
        let marker = if l.approval_id == a.approval_id {
            "▶"
        } else {
            " "
        };
        let line = format!(
            " {marker} r{:<3} {} {}{}",
            l.revision,
            short_id("A", &l.approval_id),
            name(&APPROVAL_STATES, l.state),
            if l.parent_approval_id.is_empty() {
                String::new()
            } else {
                format!(" ← {}", short_id("A", &l.parent_approval_id))
            }
        );
        lines.push(Line::from(sanitize::truncate_end(&line, usize::from(w))));
    }
    let skip = usize::from(app.scroll).min(lines.len().saturating_sub(1));
    frame.render_widget(
        Paragraph::new(lines.into_iter().skip(skip).collect::<Vec<_>>()),
        area,
    );
}
