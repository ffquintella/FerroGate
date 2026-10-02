//! Desktop notifications (`notify-rust`: D-Bus on Linux, Notification Center
//! on macOS, toast on Windows). Sent from a helper thread so a slow
//! notification daemon never stalls the tray; failures are logged only.

/// Show one notification. `title` and `body` are tray-composed text (state
/// titles, environment labels — validated, or escaped when the daemon
/// reported a name the shared rule rejects).
pub(crate) fn show(title: &str, body: &str) {
    let title = crate::text::display_safe(title, 120);
    let body = crate::text::display_safe(body, 300);
    // freedesktop notification servers render a subset of HTML in the body.
    #[cfg(all(unix, not(target_os = "macos")))]
    let body = crate::text::escape_markup(&body);
    std::thread::spawn(move || {
        if let Err(e) = notify_rust::Notification::new()
            .appname("FerroGate MIA")
            .summary(&title)
            .body(&body)
            .show()
        {
            tracing::warn!(error = %e, "desktop notification failed");
        }
    });
}
