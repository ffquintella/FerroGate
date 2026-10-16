//! Modals: forms, dialogs (form, wide confirmation, review), TOTP prompts,
//! messages, help.

use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Clear, Paragraph};
use ratatui::Frame;

use super::Theme;
use crate::app::dialogs::{Dialog, Stage};
use crate::app::filters::FLAG_NAMES;
use crate::app::form::{FieldKind, Form};
use crate::app::{App, Modal};
use crate::sanitize;

/// A centred rectangle of at most `w`×`h` inside `area`.
pub(super) fn centered(area: Rect, w: u16, h: u16) -> Rect {
    let w = w.min(area.width.saturating_sub(2)).max(10);
    let h = h.min(area.height.saturating_sub(2)).max(5);
    Rect {
        x: area.x + (area.width.saturating_sub(w)) / 2,
        y: area.y + (area.height.saturating_sub(h)) / 2,
        width: w,
        height: h,
    }
}

const LABEL: usize = 18;

/// The form as lines, and the index of the focused field's first line.
#[allow(clippy::too_many_lines)] // one arm per field kind.
pub(super) fn form_lines(form: &Form, width: u16, theme: Theme) -> (Vec<Line<'static>>, usize) {
    let width = usize::from(width);
    let value_width = width.saturating_sub(LABEL + 3).max(8);
    let mut out = Vec::new();
    let mut focus_line = 0;
    for (i, f) in form.fields.iter().enumerate() {
        let focused = i == form.focus;
        if focused {
            focus_line = out.len();
        }
        let marker = if focused { "▶ " } else { "  " };
        let label = sanitize::truncate_end(&f.label, LABEL);
        let head = format!("{marker}{label:<LABEL$} ");
        let label_style = if focused {
            theme.focus()
        } else {
            ratatui::style::Style::default()
        };
        let mut rows: Vec<Vec<Span<'static>>> = Vec::new();
        match &f.kind {
            FieldKind::Text { value, .. } => {
                let cursor = if focused { "▏" } else { "" };
                // Show the end of a long value while typing.
                let clean = sanitize::display(value);
                let room = value_width.saturating_sub(3);
                let shown = if sanitize::width(&clean) > room {
                    let tail: String = {
                        let chars: Vec<char> = clean.chars().collect();
                        let mut acc = String::new();
                        for c in chars.iter().rev() {
                            if sanitize::width(&acc) + 1 > room.saturating_sub(1) {
                                break;
                            }
                            acc.insert(0, *c);
                        }
                        acc
                    };
                    format!("…{tail}")
                } else {
                    clean
                };
                rows.push(vec![Span::raw(format!("[{shown}{cursor}]"))]);
            }
            FieldKind::Secret { value, .. } => {
                let dots = "•".repeat(value.char_count().min(value_width.saturating_sub(3)));
                let cursor = if focused { "▏" } else { "" };
                rows.push(vec![Span::raw(format!("[{dots}{cursor}]"))]);
            }
            FieldKind::Choice { options, selected } => {
                let opt = options.get(*selected).map_or("", String::as_str);
                rows.push(vec![Span::raw(sanitize::truncate_end(
                    &format!("◀ {opt} ▶  ({}/{})", selected + 1, options.len()),
                    value_width,
                ))]);
            }
            FieldKind::Multi {
                options,
                checked,
                cursor,
            } => {
                let mut row: Vec<Span<'static>> = Vec::new();
                let mut used = 0;
                for (j, (opt, on)) in options.iter().zip(checked).enumerate() {
                    let pointer = if focused && j == *cursor { "›" } else { " " };
                    let item = sanitize::truncate_end(
                        &format!("{pointer}[{}] {opt} ", if *on { "x" } else { " " }),
                        value_width,
                    );
                    let w = sanitize::width(&item);
                    if used + w > value_width && !row.is_empty() {
                        rows.push(std::mem::take(&mut row));
                        used = 0;
                    }
                    used += w;
                    let style = if focused && j == *cursor {
                        theme.selected()
                    } else {
                        ratatui::style::Style::default()
                    };
                    row.push(Span::styled(item, style));
                }
                if !row.is_empty() {
                    rows.push(row);
                }
            }
            FieldKind::Toggle { on } => {
                rows.push(vec![Span::raw(if *on { "[x]" } else { "[ ]" })]);
            }
        }
        for (k, mut row) in rows.into_iter().enumerate() {
            let lead = if k == 0 {
                Span::styled(head.clone(), label_style)
            } else {
                Span::raw(" ".repeat(LABEL + 3))
            };
            row.insert(0, lead);
            if k == 0 {
                if let Some(h) = &f.hint {
                    row.push(Span::styled(
                        format!("  {}", sanitize::display(h)),
                        theme.muted(),
                    ));
                }
            }
            out.push(Line::from(row));
        }
        if let Some(e) = &f.error {
            out.push(Line::styled(
                sanitize::truncate_end(&format!("{}✗ {e}", " ".repeat(LABEL + 3)), width),
                theme.error(),
            ));
        }
    }
    (out, focus_line)
}

/// Keep the focused part of `lines` within `height`.
pub(super) fn window(lines: Vec<Line<'static>>, focus: usize, height: usize) -> Vec<Line<'static>> {
    if lines.len() <= height || height == 0 {
        return lines;
    }
    let start = focus.saturating_sub(height / 2).min(lines.len() - height);
    lines.into_iter().skip(start).take(height).collect()
}

fn wrapped(text: &str, width: u16) -> Vec<Line<'static>> {
    sanitize::wrap(text, usize::from(width))
        .into_iter()
        .map(Line::from)
        .collect()
}

fn frame_box(frame: &mut Frame<'_>, rect: Rect, title: &str, theme: Theme) -> Rect {
    frame.render_widget(Clear, rect);
    let block = Block::bordered().title(Span::styled(
        format!(
            " {} ",
            sanitize::truncate_end(title, usize::from(rect.width).saturating_sub(4))
        ),
        theme.title(),
    ));
    let inner = block.inner(rect);
    frame.render_widget(block, rect);
    inner
}

/// Draw `modal` over `area`.
pub(super) fn draw(app: &App, modal: &Modal, area: Rect, frame: &mut Frame<'_>) {
    let theme = Theme::of(app);
    match modal {
        Modal::Help => help(app, area, frame),
        Modal::ConfirmQuit => {
            let inner = frame_box(frame, centered(area, 50, 6), "Quit", theme);
            frame.render_widget(
                Paragraph::new(vec![
                    Line::from("Sign out and quit?"),
                    Line::from(""),
                    Line::from("y: sign out and quit · n / Esc: stay"),
                ]),
                inner,
            );
        }
        Modal::Search { form, .. } => {
            let inner = frame_box(frame, centered(area, 70, 6), "Search", theme);
            let (lines, _) = form_lines(form, inner.width, theme);
            let mut lines = lines;
            lines.push(Line::styled(
                "Matched by the server in paths, products, users and versions. Esc: cancel",
                theme.muted(),
            ));
            frame.render_widget(Paragraph::new(lines), inner);
        }
        Modal::Filters { form, .. } => {
            let inner = frame_box(frame, centered(area, 78, 22), "Filters", theme);
            let (lines, focus) = form_lines(form, inner.width, theme);
            let height = usize::from(inner.height).saturating_sub(1);
            let mut lines = window(lines, focus, height);
            lines.push(Line::styled(
                "Tab next · Space/←→ change · Enter apply · Esc cancel",
                theme.muted(),
            ));
            frame.render_widget(Paragraph::new(lines), inner);
        }
        Modal::Dialog(d) => dialog(app, d, area, frame),
        Modal::StepUp { form, error } => totp(
            frame,
            area,
            theme,
            "Step-up",
            "This operation needs a fresh second factor (the server's step-up window has passed). It is sent again once, with the same idempotency key.",
            form,
            error.as_deref(),
        ),
        Modal::RegisterTotp { form, error } => totp(
            frame,
            area,
            theme,
            "Fresh TOTP code for this add",
            "Every direct add needs its own TOTP code, even within the step-up window. A wrong code changes nothing.",
            form,
            error.as_deref(),
        ),
        Modal::Message { title, lines } => {
            let inner = frame_box(frame, centered(area, 70, 12), title, theme);
            let mut out = Vec::new();
            for l in lines {
                out.extend(wrapped(l, inner.width));
            }
            out.push(Line::from(""));
            out.push(Line::styled("Enter: close", theme.muted()));
            frame.render_widget(Paragraph::new(out), inner);
        }
    }
}

fn totp(
    frame: &mut Frame<'_>,
    area: Rect,
    theme: Theme,
    title: &str,
    explain: &str,
    form: &Form,
    error: Option<&str>,
) {
    let inner = frame_box(frame, centered(area, 64, 11), title, theme);
    let mut lines = wrapped(explain, inner.width);
    lines.push(Line::from(""));
    lines.extend(form_lines(form, inner.width, theme).0);
    if let Some(e) = error {
        lines.push(Line::styled(
            sanitize::truncate_end(&format!("✗ {e}"), usize::from(inner.width)),
            theme.error(),
        ));
    }
    lines.push(Line::styled("Enter: send · Esc: cancel", theme.muted()));
    frame.render_widget(Paragraph::new(lines), inner);
}

fn dialog(app: &App, d: &Dialog, area: Rect, frame: &mut Frame<'_>) {
    let theme = Theme::of(app);
    let inner = frame_box(frame, centered(area, 78, 22), &d.title, theme);
    let height = usize::from(inner.height);
    match d.stage {
        Stage::Form => {
            let mut head = Vec::new();
            if let Some(n) = &d.notice {
                for l in wrapped(&format!("⚠ {n}"), inner.width) {
                    head.push(l.style(theme.warn()));
                }
            }
            let warnings = d.warnings();
            if !warnings.is_empty() {
                head.push(Line::styled(
                    sanitize::truncate_end(
                        &format!("⚠ {}", warnings.join(" · ")),
                        usize::from(inner.width),
                    ),
                    theme.warn(),
                ));
            }
            let (lines, focus) = form_lines(&d.form, inner.width, theme);
            let room = height.saturating_sub(head.len() + 1);
            let mut out = head;
            out.extend(window(lines, focus, room));
            out.push(Line::styled(
                "Tab next · Space/←→ change · Enter review · Esc cancel",
                theme.muted(),
            ));
            frame.render_widget(Paragraph::new(out), inner);
        }
        Stage::WideConfirm => {
            let mut out = Vec::new();
            for l in d.wide_lines() {
                out.extend(wrapped(&l, inner.width));
            }
            for l in &mut out {
                *l = l.clone().style(theme.warn());
            }
            frame.render_widget(Paragraph::new(out), inner);
        }
        Stage::Review => {
            let mut body = Vec::new();
            for l in d.review_lines(app.unix) {
                body.extend(wrapped(&l, inner.width));
            }
            let room = height.saturating_sub(2);
            let max_skip = body.len().saturating_sub(room);
            let skip = usize::from(d.scroll).min(max_skip);
            let more = skip < max_skip;
            let mut out = vec![Line::styled(
                "Review — nothing is sent until you press y",
                theme.title(),
            )];
            out.extend(body.into_iter().skip(skip).take(room));
            out.push(Line::styled(
                if more {
                    "↓ more below (↑↓ scroll) · y: confirm · Backspace: back · Esc: cancel"
                } else {
                    "y: confirm · Backspace: back · Esc: cancel"
                },
                if more { theme.warn() } else { theme.muted() },
            ));
            frame.render_widget(Paragraph::new(out), inner);
        }
    }
}

fn help(app: &App, area: Rect, frame: &mut Frame<'_>) {
    let theme = Theme::of(app);
    let inner = frame_box(frame, centered(area, 78, 22), "Help", theme);
    let mut lines: Vec<Line<'static>> = [
        "1–6 / Tab  switch screen        ?  help        Ctrl-L  lock now        q  quit",
        "Lists      ↑↓ j k  move   PgUp PgDn   g G  first/last   Enter  open   r  refresh",
        "           /  search (≤ 128)   f  filters   s  sort   n p  page   c  clear filters",
        "Requests   a  approve   d  deny   A  add application by hash and path",
        "Request    h  full hash   l  lineage approvals   z  freeze/unfreeze lineage",
        "Approval   e  edit   x  revoke (type the short id)   z  freeze/unfreeze   h  hash",
        "Dialogs    Tab  next field   Space ←→  change   Enter  review   y  confirm   Esc  cancel",
        "",
        "Policies: manual = every new binary is reviewed; auto-update = same path and user,",
        "with anchored continuity (protected path or same signer) unless path+user only.",
        "Keys marked ✗ need a permission your groups do not grant; the server decides.",
        "",
        "Flags:",
    ]
    .iter()
    .map(|s| Line::from(*s))
    .collect();
    let names: Vec<&str> = FLAG_NAMES.iter().map(|(_, n)| *n).collect();
    lines.extend(wrapped(&names.join(" · "), inner.width));
    frame.render_widget(Paragraph::new(lines), inner);
}
