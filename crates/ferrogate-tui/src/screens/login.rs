//! Sign-in and forced password change.

use ratatui::layout::Rect;
use ratatui::text::Line;
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use super::modal::{centered, form_lines};
use super::Theme;
use crate::app::{App, LoginScreen, PasswordScreen};
use crate::sanitize;

/// The sign-in screen: endpoint and pin (read-only), username, password
/// (masked), TOTP code, one generic error line or the throttle countdown.
pub(super) fn login(app: &App, l: &LoginScreen, area: Rect, frame: &mut Frame<'_>) {
    let theme = Theme::of(app);
    let rect = centered(area, 72, 18);
    let block = ratatui::widgets::Block::bordered().title(ratatui::text::Span::styled(
        " FerroGate admin — sign in ",
        theme.title(),
    ));
    let inner = block.inner(rect);
    frame.render_widget(block, rect);
    let width = usize::from(inner.width);
    let mut lines = vec![
        Line::from(sanitize::truncate_end(
            &format!("Endpoint    {}", app.endpoint),
            width,
        )),
        Line::from(sanitize::truncate_end(
            &format!("Server pin  {} (SPKI SHA-384)", app.pin_hint),
            width,
        )),
        Line::from(""),
    ];
    lines.extend(form_lines(&l.form, inner.width, theme).0);
    lines.push(Line::from(""));
    if let Some(n) = &l.notice {
        lines.push(Line::styled(sanitize::truncate_end(n, width), theme.warn()));
    }
    if let Some(until) = l.throttled_until {
        lines.push(Line::styled(
            format!(
                "✗ Too many attempts: try again in {} s.",
                until.saturating_sub(app.mono)
            ),
            theme.error(),
        ));
    } else if let Some(e) = &l.error {
        for chunk in sanitize::wrap(&format!("✗ {e}"), width) {
            lines.push(Line::styled(chunk, theme.error()));
        }
    }
    if l.busy {
        lines.push(Line::styled("⟳ signing in…", theme.muted()));
    }
    lines.push(Line::styled(
        "Not enrolled? Use the tray admin client (mia-tray-admin).",
        theme.muted(),
    ));
    lines.push(Line::styled(
        "Enter: next / sign in · Tab: move · Esc: quit",
        theme.muted(),
    ));
    frame.render_widget(Paragraph::new(lines), inner);
}

/// The forced password change after sign-in with an expired password.
pub(super) fn change_password(app: &App, p: &PasswordScreen, area: Rect, frame: &mut Frame<'_>) {
    let theme = Theme::of(app);
    let rect = centered(area, 72, 16);
    let block = ratatui::widgets::Block::bordered().title(ratatui::text::Span::styled(
        " Your password has expired — change it ",
        theme.title(),
    ));
    let inner = block.inner(rect);
    frame.render_widget(block, rect);
    let width = usize::from(inner.width);
    let mut lines = vec![
        Line::from("Nothing else is allowed until the password is changed."),
        Line::styled(
            "At least 24 characters; the server also rejects common and reused passwords.",
            theme.muted(),
        ),
        Line::from(""),
    ];
    lines.extend(form_lines(&p.form, inner.width, theme).0);
    lines.push(Line::from(""));
    if let Some(e) = &p.error {
        for chunk in sanitize::wrap(&format!("✗ {e}"), width) {
            lines.push(Line::styled(chunk, theme.error()));
        }
    }
    if p.busy {
        lines.push(Line::styled("⟳ changing…", theme.muted()));
    }
    lines.push(Line::styled(
        "Enter: next / change · Ctrl-L: lock · Esc: sign out and quit",
        theme.muted(),
    ));
    frame.render_widget(Paragraph::new(lines), inner);
}
