//! Pure view functions (F21 §3): `fn(&App, Rect, &mut Frame)`, no state, no
//! I/O. Every server-supplied string reaches the frame only through
//! [`crate::sanitize`]; ratatui then draws plain spans and interprets no
//! markup.
//!
//! Colours supplement text and are never the only signal: errors carry `✗`,
//! warnings `⚠`, the focused field `▶`, the selected row is reversed. With
//! `NO_COLOR` or `--monochrome` only modifiers (bold, reverse, dim) are used.
//! Below 80×24 the views draw a "terminal too small" notice instead.

use std::fmt::Write as _;

mod detail;
mod lists;
mod login;
mod modal;

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Paragraph};
use ratatui::Frame;

use crate::app::{perm, App, Level, Phase, Screen, TABS};
use crate::sanitize;
use crate::timefmt;

/// Smallest supported terminal.
pub const MIN_WIDTH: u16 = 80;
/// Smallest supported terminal.
pub const MIN_HEIGHT: u16 = 24;

/// Styles, with or without colour.
#[derive(Debug, Clone, Copy)]
pub struct Theme {
    mono: bool,
}

impl Theme {
    /// The theme for `app`.
    #[must_use]
    pub fn of(app: &App) -> Self {
        Self {
            mono: app.monochrome,
        }
    }

    fn pick(self, mono: Style, colour: Style) -> Style {
        if self.mono {
            mono
        } else {
            colour
        }
    }

    /// Titles and the header.
    #[must_use]
    pub fn title(self) -> Style {
        self.pick(
            Style::default().add_modifier(Modifier::BOLD),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
    }

    /// The selected row or tab.
    #[must_use]
    pub fn selected(self) -> Style {
        Style::default().add_modifier(Modifier::REVERSED)
    }

    /// Warnings (always with `⚠` in the text).
    #[must_use]
    pub fn warn(self) -> Style {
        self.pick(
            Style::default().add_modifier(Modifier::BOLD),
            Style::default().fg(Color::Yellow),
        )
    }

    /// Errors (always with `✗` in the text).
    #[must_use]
    pub fn error(self) -> Style {
        self.pick(
            Style::default().add_modifier(Modifier::BOLD),
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        )
    }

    /// Hints and disabled keys.
    #[must_use]
    pub fn muted(self) -> Style {
        self.pick(
            Style::default().add_modifier(Modifier::DIM),
            Style::default().fg(Color::DarkGray),
        )
    }

    /// The focused form field.
    #[must_use]
    pub fn focus(self) -> Style {
        Style::default().add_modifier(Modifier::BOLD)
    }
}

/// Draw the whole UI.
pub fn draw(app: &App, frame: &mut Frame<'_>) {
    let area = frame.area();
    if area.width < MIN_WIDTH || area.height < MIN_HEIGHT {
        too_small(area, frame);
        return;
    }
    match &app.phase {
        Phase::Login(l) => login::login(app, l, area, frame),
        Phase::ChangePassword(p) => login::change_password(app, p, area, frame),
        Phase::Main => main(app, area, frame),
    }
}

fn too_small(area: Rect, frame: &mut Frame<'_>) {
    let text = vec![
        Line::from("Terminal too small."),
        Line::from(format!(
            "ferrogate-tui needs at least {MIN_WIDTH}×{MIN_HEIGHT}; this one is {}×{}.",
            area.width, area.height
        )),
        Line::from("Resize the window (nothing is shown until then)."),
    ];
    frame.render_widget(Paragraph::new(text), area);
}

fn main(app: &App, area: Rect, frame: &mut Frame<'_>) {
    let [header, tabs, body, hints, status] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Min(5),
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .areas(area);
    let theme = Theme::of(app);
    frame.render_widget(
        Paragraph::new(Line::styled(header_text(app, header.width), theme.title())),
        header,
    );
    frame.render_widget(Paragraph::new(tab_line(app, theme)), tabs);
    let title = match app.screen {
        Screen::RequestDetail => "Request".to_string(),
        Screen::ApprovalDetail => "Approval".to_string(),
        s => TABS[s.tab()].to_string(),
    };
    let block = Block::bordered().title(Span::styled(format!(" {title} "), theme.title()));
    let inner = block.inner(body);
    frame.render_widget(block, body);
    match app.screen {
        Screen::Dashboard => lists::dashboard(app, inner, frame),
        Screen::Requests => lists::requests(app, inner, frame),
        Screen::Approvals => lists::approvals(app, inner, frame),
        Screen::RequestDetail => detail::request(app, inner, frame),
        Screen::ApprovalDetail => detail::approval(app, inner, frame),
        Screen::Hosts => lists::hosts(inner, frame),
        Screen::Accounts => lists::accounts(app, inner, frame),
        Screen::Sessions => lists::sessions(app, inner, frame),
    }
    frame.render_widget(Paragraph::new(hint_line(app, theme, hints.width)), hints);
    frame.render_widget(
        Paragraph::new(status_line(app, theme, status.width)),
        status,
    );
    if let Some(m) = &app.modal {
        modal::draw(app, m, area, frame);
    }
}

/// The header: endpoint, administrator, role, AAL, idle countdown, step-up.
/// On a narrow terminal "admin" and then the role are dropped before the
/// line is cut, so the countdowns stay visible.
fn header_text(app: &App, width: u16) -> String {
    let host = app
        .endpoint
        .strip_prefix("https://")
        .unwrap_or(&app.endpoint);
    let Some(sess) = &app.session else {
        return sanitize::truncate_end(&format!("FerroGate admin · {host}"), usize::from(width));
    };
    let mut tail = format!(" · AAL{}", sess.aal);
    if let Some(left) = app.idle_left() {
        let _ = write!(tail, " · idle {}", timefmt::clock(left));
    }
    match sess.step_up_until {
        Some(until) if until > app.unix => {
            let _ = write!(
                tail,
                " · step-up ✓ {}",
                timefmt::clock(until.saturating_sub(app.unix))
            );
        }
        _ => tail.push_str(" · step-up —"),
    }
    let candidates = [
        format!(
            "FerroGate admin · {host} · {} ({}){tail}",
            sess.username,
            sess.role()
        ),
        format!(
            "FerroGate · {host} · {} ({}){tail}",
            sess.username,
            sess.role()
        ),
        format!("FerroGate · {host} · {}{tail}", sess.username),
    ];
    let max = usize::from(width);
    let pick = candidates
        .iter()
        .map(|c| sanitize::display(c))
        .find(|c| sanitize::width(c) <= max)
        .unwrap_or_else(|| sanitize::display(&candidates[2]));
    sanitize::truncate_end(&pick, max)
}

fn tab_line(app: &App, theme: Theme) -> Line<'static> {
    let mut spans = Vec::new();
    for (i, name) in TABS.iter().enumerate() {
        let mut label = format!(" {} {name}", i + 1);
        if i == 1 && app.requests.loaded {
            let _ = write!(label, " ({})", app.requests.items.len());
        }
        label.push(' ');
        let style = if app.screen.tab() == i {
            theme.selected()
        } else {
            Style::default()
        };
        spans.push(Span::styled(label, style));
    }
    spans.push(Span::styled("   ? help", theme.muted()));
    Line::from(spans)
}

/// A key hint, greyed out (with the reason) when the session lacks the
/// permission.
fn hint(app: &App, theme: Theme, text: &str, permission: Option<&str>) -> Span<'static> {
    match permission {
        Some(p) if !app.can(p) => Span::styled(format!("{text}✗ "), theme.muted()),
        _ => Span::raw(format!("{text} ")),
    }
}

fn hint_line(app: &App, theme: Theme, width: u16) -> Line<'static> {
    let h = |t: &str, p: Option<&str>| hint(app, theme, t, p);
    let spans = match app.screen {
        Screen::Requests => vec![
            h("⏎ open ·", None),
            h("a approve", Some(perm::APPROVE)),
            h("· d deny", Some(perm::DENY)),
            h("· A add", Some(perm::DIRECT_REGISTER)),
            h(
                "· / search · f filter · s sort · n/p page · c clear · r · q",
                None,
            ),
        ],
        Screen::Approvals => vec![
            h("⏎ open ·", None),
            h("A add", Some(perm::DIRECT_REGISTER)),
            h(
                "· / search · f filter · s sort · n/p page · c clear · r refresh · q quit",
                None,
            ),
        ],
        Screen::RequestDetail => vec![
            h("a approve", Some(perm::APPROVE)),
            h("· d deny", Some(perm::DENY)),
            h("· z freeze", Some(perm::UPDATE)),
            h(
                "· h hash · l lineage · ↑↓ scroll · Esc back · r refresh",
                None,
            ),
        ],
        Screen::ApprovalDetail => vec![
            h("e edit", Some(perm::UPDATE)),
            h("· x revoke", Some(perm::REVOKE)),
            h("· z freeze", Some(perm::UPDATE)),
            h("· h hash · ↑↓ scroll · Esc back · r refresh", None),
        ],
        _ => vec![h(
            "1-6 screens · Tab next · r refresh · ? help · Ctrl-L lock · q quit",
            None,
        )],
    };
    // Keep what fits.
    let mut used = 0usize;
    let mut out = Vec::new();
    for s in spans {
        let w = sanitize::width(&s.content);
        if used + w > usize::from(width) {
            break;
        }
        used += w;
        out.push(s);
    }
    Line::from(out)
}

fn status_line(app: &App, theme: Theme, width: u16) -> Line<'static> {
    let mut spans = Vec::new();
    if app.in_flight > 0 {
        spans.push(Span::styled("⟳ working… ", theme.muted()));
    }
    if let Some((level, text)) = &app.status {
        let (style, prefix) = match level {
            Level::Info => (Style::default(), ""),
            Level::Warn => (theme.warn(), "⚠ "),
        };
        spans.push(Span::styled(
            sanitize::truncate_end(
                &format!("{prefix}{text}"),
                usize::from(width).saturating_sub(12),
            ),
            style,
        ));
    }
    Line::from(spans)
}

/// `label: value` lines with the value wrapped (sanitised) to `width`.
pub(crate) fn kv(label: &str, value: &str, width: u16) -> Vec<Line<'static>> {
    const LABEL: usize = 18;
    let avail = usize::from(width).saturating_sub(LABEL + 1).max(8);
    let mut out = Vec::new();
    for (i, chunk) in sanitize::wrap(value, avail).into_iter().enumerate() {
        let head = if i == 0 {
            format!("{label:<LABEL$} ")
        } else {
            " ".repeat(LABEL + 1)
        };
        out.push(Line::from(format!("{head}{chunk}")));
    }
    out
}

/// The tail of an id (what the lists show).
pub(crate) fn short(id: &str) -> String {
    let chars: Vec<char> = id.chars().filter(char::is_ascii_alphanumeric).collect();
    chars[chars.len().saturating_sub(8)..].iter().collect()
}

#[cfg(test)]
mod tests;
