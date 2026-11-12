//! The OS side of the notification layer (F23 §3): freedesktop (D-Bus)
//! on Linux / BSD, toasts on Windows, Notification Center on macOS, all
//! through `notify-rust` behind [`deliver`]. Each notification waits for
//! its answer on a helper thread; a failure is only logged, because the
//! same notice is already in the menu line and the window's status bar.

use std::sync::mpsc;

use notify_rust::{Notification, NotificationResponse};

use crate::i18n::Lang;
#[cfg(not(target_os = "macos"))]
use crate::notice::Urgency;
use crate::notice::{Notice, Response, Target};

/// Map the platform's answer to ours.
fn response(r: &NotificationResponse) -> Response {
    match r {
        NotificationResponse::Default => Response::Default,
        NotificationResponse::Action(id) => Response::Action(id.clone()),
        NotificationResponse::Reply(_) | NotificationResponse::Closed(_) => Response::Closed,
    }
}

#[cfg(not(target_os = "macos"))]
fn urgency(u: Urgency) -> notify_rust::Urgency {
    match u {
        Urgency::Low => notify_rust::Urgency::Low,
        Urgency::Normal => notify_rust::Urgency::Normal,
        Urgency::Critical => notify_rust::Urgency::Critical,
    }
}

/// Show `notice`; where a click leads goes to `activated`.
pub(crate) fn deliver(notice: &Notice, lang: Lang, activated: mpsc::Sender<Target>) {
    let notice = notice.clone();
    std::thread::spawn(move || {
        let shown = build(&notice, lang)
            .show()
            .map_err(|e| e.to_string())
            .and_then(|handle| {
                remember(&notice, &handle);
                handle
                    .wait_for_response(|r: &NotificationResponse| {
                        if let Some(target) = notice.activation(&response(r)) {
                            let _ = activated.send(target);
                        }
                    })
                    .map_err(|e| e.to_string())
            });
        if let Err(e) = shown {
            tracing::warn!(error = %e, kind = ?notice.kind, "desktop notification failed; shown in the app only");
        }
    });
}

/// Linux / BSD: summary `FerroGate · <subtitle>`, markup-escaped body,
/// the installed icon, urgency, buttons, and the previous id of the tag.
#[cfg(all(unix, not(target_os = "macos")))]
fn build(notice: &Notice, lang: Lang) -> Notification {
    let (summary, _) = notice.heading(false);
    let mut n = Notification::new();
    n.appname(crate::i18n::Msg::AppName.text(lang))
        .summary(&summary)
        // freedesktop servers render a subset of HTML in the body.
        .body(&crate::text::escape_markup(&notice.body))
        .icon("ferrogate-mia")
        .urgency(urgency(notice.kind.urgency()))
        .hint(notify_rust::Hint::Custom(
            "x-dunst-stack-tag".into(),
            format!("ferrogate-{:?}", notice.tag),
        ));
    // "default" is the body click.
    n.action("default", crate::notice::NoticeAction::Open.label(lang));
    for a in notice.actions() {
        n.action(a.id(), a.label(lang));
    }
    if let Some(id) = previous_id(notice) {
        n.id(id);
    }
    n
}

/// Windows: a toast titled `FerroGate · <subtitle>` with buttons, under
/// FerroGate's AppUserModelID once the installer registered it.
#[cfg(windows)]
fn build(notice: &Notice, lang: Lang) -> Notification {
    let (summary, _) = notice.heading(false);
    let mut n = Notification::new();
    n.summary(&summary)
        .body(&notice.body)
        .urgency(urgency(notice.kind.urgency()));
    if windows_app_id_registered() {
        n.app_id(WINDOWS_APP_ID);
    }
    for a in notice.actions() {
        n.action(a.id(), a.label(lang));
    }
    n
}

/// macOS: title `FerroGate`, the environment or app as the subtitle,
/// click-to-open (no buttons), under the app bundle's identifier.
#[cfg(target_os = "macos")]
fn build(notice: &Notice, _lang: Lang) -> Notification {
    static BUNDLE: std::sync::Once = std::sync::Once::new();
    // Not from unit tests: it changes the process's notification identity.
    if cfg!(not(test)) {
        BUNDLE.call_once(|| {
            if let Err(e) = notify_rust::set_application(MACOS_BUNDLE_ID) {
                tracing::debug!(error = %e, "notifications use the default application");
            }
        });
    }
    let (title, subtitle) = notice.heading(true);
    let mut n = Notification::new();
    n.summary(&title).body(&notice.body);
    if let Some(s) = subtitle {
        n.subtitle(&s);
    }
    n
}

/// `CFBundleIdentifier` of "FerroGate MIA.app" (`dist/macos/Info.plist`).
#[cfg(target_os = "macos")]
const MACOS_BUNDLE_ID: &str = "com.ferrogate.mia-tray";

/// The AppUserModelID FerroGate's toasts use once it is registered.
#[cfg(windows)]
const WINDOWS_APP_ID: &str = "FerroGate.MIA";

/// Whether the per-user AppUserModelID registration exists (read only:
/// Windows drops toasts of an unregistered id).
#[cfg(windows)]
fn windows_app_id_registered() -> bool {
    winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER)
        .open_subkey("Software\\Classes\\AppUserModelId\\FerroGate.MIA")
        .is_ok()
}

/// The last server id per tag (Linux), so a repeat replaces it.
#[cfg(all(unix, not(target_os = "macos")))]
type Ids = std::sync::Mutex<std::collections::HashMap<crate::notice::Tag, u32>>;

#[cfg(all(unix, not(target_os = "macos")))]
fn ids() -> &'static Ids {
    static IDS: std::sync::OnceLock<Ids> = std::sync::OnceLock::new();
    IDS.get_or_init(Ids::default)
}

#[cfg(all(unix, not(target_os = "macos")))]
fn previous_id(notice: &Notice) -> Option<u32> {
    ids().lock().ok()?.get(&notice.tag).copied()
}

#[cfg(all(unix, not(target_os = "macos")))]
fn remember(notice: &Notice, handle: &notify_rust::NotificationHandle) {
    if let Ok(mut ids) = ids().lock() {
        ids.insert(notice.tag, handle.id());
    }
}

/// Windows and macOS cannot replace through `notify-rust`.
#[cfg(any(windows, target_os = "macos"))]
fn remember(_notice: &Notice, _handle: &notify_rust::NotificationHandle) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platform_answers_map_to_ours() {
        assert_eq!(response(&NotificationResponse::Default), Response::Default);
        assert_eq!(
            response(&NotificationResponse::Action("review".into())),
            Response::Action("review".into())
        );
        assert_eq!(
            response(&NotificationResponse::Reply("typed".into())),
            Response::Closed,
            "an inline reply never counts as an action"
        );
        assert_eq!(
            response(&NotificationResponse::Closed(
                notify_rust::CloseReason::Dismissed
            )),
            Response::Closed
        );
    }

    /// The platform notification is built from the notice alone.
    #[test]
    fn the_platform_notification_carries_only_the_notice_text() {
        let n = Notice::pending_approvals(2, Lang::En, 0);
        let built = format!("{:?}", build(&n, Lang::En));
        assert!(built.contains("FerroGate"));
        assert!(built.contains("2 application requests are waiting for a decision."));
    }
}
