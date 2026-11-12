//! The one notification layer (F23 §3): every message the tray or the
//! admin client shows — OS notification, menu line, window status bar — is
//! a [`Notice`], formatted here and nowhere else.
//!
//! Notices carry tray-composed, localised text only: never a code, secret,
//! token, path or user name. [`NoticeCenter`] keeps the in-app history and
//! rate-limits OS delivery with [`crate::alerts::RateLimiter`].

use std::collections::VecDeque;

use serde::{Deserialize, Serialize};

use crate::alerts::{Alert, AlertKind, Policy, RateLimiter};
use crate::i18n::{count, fill, Lang, Msg};
use crate::model::WindowKind;
use crate::text::display_safe;

/// The title of every OS notification.
pub const TITLE: &str = "FerroGate";
/// Longest subtitle kept, in characters.
pub const MAX_SUBTITLE: usize = 64;
/// Longest body kept, in characters.
pub const MAX_BODY: usize = 300;
/// Notices kept for the in-app history.
pub const HISTORY: usize = 20;

/// What kind of message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NoticeKind {
    /// Neutral information (an action started).
    Info,
    /// Something finished well.
    Success,
    /// Needs attention soon.
    Warning,
    /// Failed, or broken now.
    Error,
    /// Application requests wait for a decision.
    ApprovalPending,
}

/// How insistent the OS notification is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Urgency {
    /// Informational.
    Low,
    /// Ordinary.
    Normal,
    /// Needs a person (approvals, errors): stays until dismissed where the
    /// platform supports it.
    Critical,
}

impl NoticeKind {
    /// The kind's name (also the accessible text beside its glyph).
    #[must_use]
    pub fn label(self) -> Msg {
        match self {
            Self::Info => Msg::NoticeKindInfo,
            Self::Success => Msg::NoticeKindSuccess,
            Self::Warning => Msg::NoticeKindWarning,
            Self::Error => Msg::NoticeKindError,
            Self::ApprovalPending => Msg::NoticeKindApproval,
        }
    }

    /// A glyph so the kind never rests on colour alone.
    #[must_use]
    pub fn glyph(self) -> &'static str {
        match self {
            Self::Info => "ℹ",
            Self::Success => "✔",
            Self::Warning => "⚠",
            Self::Error => "✖",
            Self::ApprovalPending => "➜",
        }
    }

    /// The urgency: critical only when a person must act.
    #[must_use]
    pub fn urgency(self) -> Urgency {
        match self {
            Self::Info | Self::Success => Urgency::Low,
            Self::Warning => Urgency::Normal,
            Self::Error | Self::ApprovalPending => Urgency::Critical,
        }
    }
}

/// A notice's group: a newer notice of the same tag replaces the older one
/// on platforms that can.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Tag {
    /// The agent's state changed.
    State,
    /// A tray action ran.
    Action,
    /// Pending application requests.
    Approvals,
}

/// What activating a notice opens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Target {
    /// The main window at a tab.
    Window(WindowKind),
    /// The administrator client's requests (never a decision).
    Approvals,
}

/// A button on the OS notification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoticeAction {
    /// Open the target.
    Open,
    /// Open the approvals to review them (never approves).
    Review,
    /// Close it.
    Dismiss,
}

impl NoticeAction {
    /// The identifier sent to the platform.
    #[must_use]
    pub fn id(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Review => "review",
            Self::Dismiss => "dismiss",
        }
    }

    /// Parse a platform identifier (closed set).
    #[must_use]
    pub fn from_id(id: &str) -> Option<Self> {
        [Self::Open, Self::Review, Self::Dismiss]
            .into_iter()
            .find(|a| a.id() == id)
    }

    /// The button's label.
    #[must_use]
    pub fn label(self, lang: Lang) -> &'static str {
        match self {
            Self::Open => Msg::NoticeOpen.text(lang),
            Self::Review => Msg::NoticeReview.text(lang),
            Self::Dismiss => Msg::NoticeDismiss.text(lang),
        }
    }
}

/// How a person answered an OS notification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response {
    /// The body was clicked.
    Default,
    /// A button, by identifier.
    Action(String),
    /// Closed or expired.
    Closed,
}

/// One message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Notice {
    /// Its kind.
    pub kind: NoticeKind,
    /// Its group.
    pub tag: Tag,
    /// The environment or app it is about (`None`: the tray itself).
    pub subtitle: Option<String>,
    /// One or two short, plain sentences.
    pub body: String,
    /// What activating it opens.
    pub target: Option<Target>,
    /// Unix seconds when it was raised.
    pub at: i64,
}

impl Notice {
    /// A notice with its texts bounded and made inert.
    #[must_use]
    pub fn new(
        kind: NoticeKind,
        tag: Tag,
        subtitle: Option<&str>,
        body: &str,
        target: Option<Target>,
        at: i64,
    ) -> Self {
        Self {
            kind,
            tag,
            subtitle: subtitle
                .map(|s| display_safe(s, MAX_SUBTITLE))
                .filter(|s| !s.is_empty()),
            body: display_safe(body, MAX_BODY),
            target,
            at,
        }
    }

    /// A state alert for the environment labelled `env` whose state title is
    /// `state`; it opens the main window.
    #[must_use]
    pub fn from_alert(alert: &Alert, env: &str, state: Msg, lang: Lang, now: i64) -> Self {
        let (kind, body) = match alert.kind {
            AlertKind::BecameUnhealthy => {
                let kind = if alert.state.severity() >= 3 {
                    NoticeKind::Error
                } else {
                    NoticeKind::Warning
                };
                let body = fill(
                    Msg::NoticeUnhealthy.text(lang),
                    &[("state", state.text(lang))],
                );
                (kind, body)
            }
            AlertKind::SvidExpiring => (
                NoticeKind::Warning,
                Msg::NoticeSvidExpiring.text(lang).to_string(),
            ),
            AlertKind::CrlStale => (
                NoticeKind::Warning,
                Msg::NoticeCrlStale.text(lang).to_string(),
            ),
        };
        Self::new(
            kind,
            Tag::State,
            Some(env),
            &body,
            Some(Target::Window(WindowKind::Status)),
            now,
        )
    }

    /// An action's progress or result: `ok` is `None` while it runs.
    #[must_use]
    pub fn action(
        action: &str,
        outcome: &str,
        ok: Option<bool>,
        env: Option<&str>,
        lang: Lang,
        now: i64,
    ) -> Self {
        let kind = match ok {
            None => NoticeKind::Info,
            Some(true) => NoticeKind::Success,
            Some(false) => NoticeKind::Error,
        };
        let body = fill(
            Msg::NoticeAction.text(lang),
            &[("action", action), ("outcome", outcome)],
        );
        Self::new(
            kind,
            Tag::Action,
            env,
            &body,
            Some(Target::Window(WindowKind::Recovery)),
            now,
        )
    }

    /// `n` application requests wait for a decision (a count only: no
    /// path, user or host).
    #[must_use]
    pub fn pending_approvals(n: u64, lang: Lang, now: i64) -> Self {
        let body = count(lang, n, Msg::NoticePendingOne, Msg::NoticePendingOther);
        Self::new(
            NoticeKind::ApprovalPending,
            Tag::Approvals,
            Some(Msg::NoticeAdminApp.text(lang)),
            &body,
            Some(Target::Approvals),
            now,
        )
    }

    /// The one-line form for the tray menu and the window's status bar.
    #[must_use]
    pub fn line(&self) -> String {
        match &self.subtitle {
            Some(s) => format!("{s} · {}", self.body),
            None => self.body.clone(),
        }
    }

    /// Title and subtitle for the OS: macOS shows a real subtitle; the
    /// others get `FerroGate · <subtitle>` as the summary.
    #[must_use]
    pub fn heading(&self, separate_subtitle: bool) -> (String, Option<String>) {
        match (&self.subtitle, separate_subtitle) {
            (Some(s), true) => (TITLE.to_string(), Some(s.clone())),
            (Some(s), false) => (format!("{TITLE} · {s}"), None),
            (None, _) => (TITLE.to_string(), None),
        }
    }

    /// The buttons to offer where the platform has them.
    #[must_use]
    pub fn actions(&self) -> Vec<NoticeAction> {
        match self.target {
            Some(Target::Approvals) => vec![NoticeAction::Review, NoticeAction::Dismiss],
            Some(Target::Window(_)) => vec![NoticeAction::Open, NoticeAction::Dismiss],
            None => Vec::new(),
        }
    }

    /// Where the person's `response` leads: the body or Open/Review go to
    /// the target, anything else nowhere. Nothing is ever decided here.
    #[must_use]
    pub fn activation(&self, response: &Response) -> Option<Target> {
        match response {
            Response::Default => self.target,
            Response::Action(id) => match NoticeAction::from_id(id)? {
                NoticeAction::Open => self.target,
                NoticeAction::Review => self.target.filter(|t| *t == Target::Approvals),
                NoticeAction::Dismiss => None,
            },
            Response::Closed => None,
        }
    }

    /// The single-line JSON form for the control pipe.
    #[must_use]
    pub fn to_wire(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    /// Parse [`Notice::to_wire`]'s output; the texts are bounded and made
    /// inert again (the pipe is not trusted more than the daemon).
    #[must_use]
    pub fn from_wire(json: &str) -> Option<Self> {
        let n: Self = serde_json::from_str(json).ok()?;
        Some(Self::new(
            n.kind,
            n.tag,
            n.subtitle.as_deref(),
            &n.body,
            n.target,
            n.at,
        ))
    }
}

/// The localised result of a finished action and whether it succeeded
/// (with the restart note for actions that apply on restart).
#[must_use]
pub fn outcome_text(
    action: crate::actions::Action,
    outcome: crate::actions::Outcome,
    lang: Lang,
) -> (String, bool) {
    let ok = outcome == crate::actions::Outcome::Succeeded;
    let label = outcome.label().text(lang);
    let text = if ok && action.applies_on_restart() {
        format!("{label}. {}", Msg::NoteRestartToApply.text(lang))
    } else {
        label.to_string()
    };
    (text, ok)
}

/// The in-app history plus the OS delivery rate limit.
#[derive(Debug, Clone)]
pub struct NoticeCenter {
    limiter: RateLimiter<(Tag, Option<String>, String)>,
    history: VecDeque<Notice>,
}

impl Default for NoticeCenter {
    fn default() -> Self {
        Self::new(Policy {
            dedup_secs: 60,
            burst: 6,
            window_secs: 10 * 60,
        })
    }
}

impl NoticeCenter {
    /// A center whose OS delivery follows `policy`.
    #[must_use]
    pub fn new(policy: Policy) -> Self {
        Self {
            limiter: RateLimiter::new(policy),
            history: VecDeque::new(),
        }
    }

    /// Record `notice`; `true` when it should also go to the OS (`os` asks
    /// for that; an identical notice inside the dedup window, or one past
    /// the burst budget, stays in-app only).
    pub fn push(&mut self, notice: Notice, os: bool) -> bool {
        let deliver = os
            && self.limiter.allow(
                &(notice.tag, notice.subtitle.clone(), notice.body.clone()),
                notice.at,
            );
        // A running action's line is replaced by its result.
        if let Some(last) = self.history.back() {
            if last.tag == notice.tag
                && last.kind == NoticeKind::Info
                && last.subtitle == notice.subtitle
            {
                self.history.pop_back();
            }
        }
        self.history.push_back(notice);
        while self.history.len() > HISTORY {
            self.history.pop_front();
        }
        deliver
    }

    /// The newest notice.
    #[must_use]
    pub fn latest(&self) -> Option<&Notice> {
        self.history.back()
    }

    /// Every notice kept, newest first.
    pub fn history(&self) -> impl Iterator<Item = &Notice> {
        self.history.iter().rev()
    }

    /// Forget the newest notice (the status bar's "Dismiss").
    pub fn dismiss_latest(&mut self) {
        self.history.pop_back();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mia_status_proto::AgentState;

    fn alert(kind: AlertKind, state: AgentState) -> Alert {
        Alert {
            kind,
            environment: Some("prod".into()),
            state,
        }
    }

    #[test]
    fn every_kind_and_message_is_localised() {
        let kinds = [
            NoticeKind::Info,
            NoticeKind::Success,
            NoticeKind::Warning,
            NoticeKind::Error,
            NoticeKind::ApprovalPending,
        ];
        for lang in Lang::ALL {
            for k in kinds {
                assert_ne!(k.label().text(lang), "");
            }
            for a in [
                NoticeAction::Open,
                NoticeAction::Review,
                NoticeAction::Dismiss,
            ] {
                assert_ne!(a.label(lang), "");
                assert_eq!(NoticeAction::from_id(a.id()), Some(a));
            }
            let pending = Notice::pending_approvals(3, lang, 0);
            assert!(pending.body.contains('3'), "{lang:?}: {}", pending.body);
            let state = Notice::from_alert(
                &alert(AlertKind::BecameUnhealthy, AgentState::NotEnrolled),
                "prod",
                Msg::StateNotEnrolled,
                lang,
                0,
            );
            assert!(state.body.starts_with(Msg::StateNotEnrolled.text(lang)));
        }
        // The three languages really differ.
        let en = Notice::pending_approvals(2, Lang::En, 0).body;
        let pt = Notice::pending_approvals(2, Lang::Pt, 0).body;
        let es = Notice::pending_approvals(2, Lang::Es, 0).body;
        assert!(en != pt && pt != es && en != es);
    }

    #[test]
    fn the_format_is_one_title_a_subtitle_and_a_short_body() {
        let n = Notice::from_alert(
            &alert(AlertKind::CrlStale, AgentState::CrlStale),
            "prod",
            Msg::StateCrlStale,
            Lang::En,
            10,
        );
        assert_eq!(n.kind, NoticeKind::Warning);
        assert_eq!(n.kind.urgency(), Urgency::Normal);
        assert_eq!(n.heading(true), ("FerroGate".into(), Some("prod".into())));
        assert_eq!(n.heading(false), ("FerroGate · prod".into(), None));
        assert_eq!(
            n.line(),
            "prod · The revocation list is stale, so token minting is paused."
        );
        assert_eq!(n.target, Some(Target::Window(WindowKind::Status)));
        // Broken states are errors and critical.
        let broken = Notice::from_alert(
            &alert(AlertKind::BecameUnhealthy, AgentState::PinMismatch),
            "prod",
            Msg::StatePinMismatch,
            Lang::En,
            10,
        );
        assert_eq!(broken.kind.urgency(), Urgency::Critical);
        // An action without an environment has no subtitle.
        let done = Notice::action("Restart the service", "done", Some(true), None, Lang::En, 0);
        assert_eq!(done.heading(true), ("FerroGate".into(), None));
        assert_eq!(done.line(), "Restart the service — done");
        assert_eq!(done.kind.urgency(), Urgency::Low);
    }

    #[test]
    fn hostile_text_is_bounded_and_inert() {
        let n = Notice::new(
            NoticeKind::Info,
            Tag::Action,
            Some("env\u{1b}[2J\u{202e}"),
            &format!("<b>x</b>\n{}", "y".repeat(1000)),
            None,
            0,
        );
        assert!(!n.line().contains('\u{1b}') && !n.line().contains('\n'));
        // The bound counts input characters; escapes add a few.
        assert!(n.body.chars().count() <= MAX_BODY + 8);
        // Round trip through the pipe re-sanitises.
        let mut raw = n.clone();
        raw.body = "a\u{202e}b".into();
        let back = Notice::from_wire(&raw.to_wire()).unwrap();
        assert!(!back.body.contains('\u{202e}'));
        assert_eq!(Notice::from_wire("{not json"), None);
    }

    #[test]
    fn approval_notices_only_ever_open_the_list() {
        let n = Notice::pending_approvals(1, Lang::En, 0);
        assert_eq!(n.kind.urgency(), Urgency::Critical);
        assert_eq!(
            n.actions(),
            vec![NoticeAction::Review, NoticeAction::Dismiss]
        );
        assert_eq!(n.activation(&Response::Default), Some(Target::Approvals));
        assert_eq!(
            n.activation(&Response::Action("review".into())),
            Some(Target::Approvals)
        );
        for other in ["dismiss", "approve", "", "open; rm -rf /"] {
            let to = n.activation(&Response::Action(other.into()));
            assert!(to.is_none() || other == "open", "{other}");
        }
        assert_eq!(n.activation(&Response::Closed), None);
        // "Review" on a non-approval notice leads nowhere.
        let s = Notice::action("x", "y", Some(true), None, Lang::En, 0);
        assert_eq!(s.activation(&Response::Action("review".into())), None);
        assert_eq!(
            s.activation(&Response::Action("open".into())),
            Some(Target::Window(WindowKind::Recovery))
        );
    }

    #[test]
    fn the_center_dedups_os_delivery_but_keeps_the_history() {
        let mut c = NoticeCenter::default();
        let a = Notice::action("Restart", "failed", Some(false), None, Lang::En, 0);
        assert!(c.push(a.clone(), true));
        let mut again = a.clone();
        again.at = 5;
        assert!(!c.push(again, true), "identical within a minute");
        assert_eq!(c.history().count(), 2);
        // A different body is shown.
        let b = Notice::action("Restart", "done", Some(true), None, Lang::En, 6);
        assert!(c.push(b.clone(), true));
        assert_eq!(c.latest(), Some(&b));
        // `os = false` never delivers.
        assert!(!c.push(Notice::pending_approvals(2, Lang::En, 7), false));
    }

    #[test]
    fn a_result_replaces_its_running_line_and_history_is_bounded() {
        let mut c = NoticeCenter::default();
        c.push(
            Notice::action("Start", "running…", None, None, Lang::En, 0),
            false,
        );
        c.push(
            Notice::action("Start", "done", Some(true), None, Lang::En, 1),
            true,
        );
        assert_eq!(c.history().count(), 1);
        assert_eq!(c.latest().unwrap().kind, NoticeKind::Success);
        for i in 0..50 {
            c.push(
                Notice::pending_approvals(i, Lang::En, i64::try_from(i).unwrap()),
                false,
            );
        }
        assert_eq!(c.history().count(), HISTORY);
        c.dismiss_latest();
        assert_eq!(c.history().count(), HISTORY - 1);
    }
}
