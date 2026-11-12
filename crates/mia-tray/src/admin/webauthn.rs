//! The platform's FIDO2 authenticator for the admin client (F22 §3a).
//!
//! The protocol side — the request, the `clientDataJSON`, the RP ID check —
//! lives in `ferrogate_admin_client::webauthn` behind its `Authenticator`
//! trait. This module only picks the platform backend.

//! macOS and Linux (feature `fido2-hid`): CTAP2 over USB HID (`admin::ctap`,
//! Mozilla's `authenticator` crate). The key's touch, choice and PIN prompts
//! appear in the admin window through a [`KeyPrompt`], since raw HID has no
//! operating-system prompt.

//! Windows (feature `fido2-windows`): the Windows WebAuthn API
//! (`webauthn.dll`, `admin::winkey` over the `ferro-winwebauthn` FFI crate).
//! Windows shows its own dialog for the touch, PIN or biometric, so the PIN
//! never passes through this client; the [`KeyPrompt`] only arms and cancels.
//! Without `webauthn.dll` (or its API version 1), [`platform`] is `None` and
//! the window disables the key button with an explanation.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use ferrogate_admin_client::webauthn::Authenticator;
use tracing_subscriber::filter::{filter_fn, EnvFilter, FilterExt as _};
use tracing_subscriber::layer::Filter;
use tracing_subscriber::registry::LookupSpan;

use super::keyprompt::KeyPrompt;

/// The CTAP library's log target. Its `log` records, which the subscriber
/// forwards to `tracing`, carry credential ids, PIN hashes and raw HID
/// frames at debug and trace level.
pub const KEY_LIBRARY_TARGET: &str = "authenticator";

/// The security-key backend of this platform and the window's side of its
/// ceremonies.
#[derive(Clone)]
pub struct Platform {
    /// What the worker calls (blocking, off the UI and async threads).
    pub authenticator: Arc<dyn Authenticator>,
    /// Arms and cancels the key's ceremonies; on USB HID it also carries the
    /// touch, choice and PIN prompts the window shows (on Windows the system
    /// shows its own).
    pub prompt: Option<Arc<KeyPrompt>>,
    /// The admin window's native handle, for the system's dialog.
    parent: Arc<AtomicUsize>,
}

impl Platform {
    /// Parent the system's security-key dialog to the admin window (a
    /// Windows `HWND`; 0 or elsewhere: the foreground window, or unused).
    pub fn set_parent_window(&self, hwnd: usize) {
        self.parent.store(hwnd, Ordering::Relaxed);
    }
}

/// The security-key backend of this platform, when one is built in.
#[cfg(all(feature = "fido2-hid", any(target_os = "macos", target_os = "linux")))]
#[must_use]
pub fn platform() -> Option<Platform> {
    let prompt = KeyPrompt::new();
    let key = super::ctap::HidKey::new(Arc::clone(&prompt));
    Some(Platform {
        authenticator: Arc::new(key),
        prompt: Some(prompt),
        parent: Arc::new(AtomicUsize::new(0)),
    })
}

/// The security-key backend of this platform, when one is built in and
/// this Windows has `webauthn.dll`.
#[cfg(all(feature = "fido2-windows", windows))]
#[must_use]
pub fn platform() -> Option<Platform> {
    let dll = super::winkey::dll()?;
    let prompt = KeyPrompt::new();
    let parent = Arc::new(AtomicUsize::new(0));
    let key = super::winkey::WinKey::new(dll, Arc::clone(&prompt), Arc::clone(&parent));
    Some(Platform {
        authenticator: Arc::new(key),
        prompt: Some(prompt),
        parent,
    })
}

/// The security-key backend of this platform, when one is built in.
#[cfg(not(any(
    all(feature = "fido2-hid", any(target_os = "macos", target_os = "linux")),
    all(feature = "fido2-windows", windows)
)))]
#[must_use]
pub fn platform() -> Option<Platform> {
    None
}

/// Whether an event may reach the admin client's log: never one of the
/// CTAP library's, whatever `MIA_TRAY_LOG` asks for.
#[must_use]
pub fn may_log(meta: &tracing::Metadata<'_>) -> bool {
    let target = meta.target();
    target != KEY_LIBRARY_TARGET
        && !target
            .strip_prefix(KEY_LIBRARY_TARGET)
            .is_some_and(|rest| rest.starts_with("::"))
}

/// The admin client's log filter: `directives` (from `MIA_TRAY_LOG`, else
/// `info`) and [`may_log`].
pub fn log_filter<S>(directives: EnvFilter) -> impl Filter<S>
where
    S: tracing::Subscriber + for<'a> LookupSpan<'a>,
{
    directives.and(filter_fn(may_log))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::Mutex;

    use tracing_subscriber::layer::SubscriberExt as _;
    use tracing_subscriber::Layer as _;

    #[test]
    fn a_backend_is_claimed_exactly_where_one_is_built() {
        let hid = cfg!(all(
            feature = "fido2-hid",
            any(target_os = "macos", target_os = "linux")
        ));
        let windows = cfg!(all(feature = "fido2-windows", windows));
        let p = platform();
        if hid {
            assert!(p.is_some(), "USB HID is always offered");
        }
        if !hid && !windows {
            assert!(p.is_none(), "no backend built here");
        }
        // On Windows it depends on webauthn.dll being present.
        if let Some(p) = p {
            assert!(p.prompt.is_some(), "the window arms and cancels ceremonies");
            p.set_parent_window(0x1234);
            assert_eq!(p.parent.load(Ordering::Relaxed), 0x1234);
        }
    }

    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Vec<u8>>>);

    impl Write for Capture {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn the_key_library_never_reaches_the_log_whatever_the_directives() {
        let out = Capture::default();
        let writer = out.clone();
        let layer = tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .with_writer(move || writer.clone())
            .with_filter(log_filter(EnvFilter::new("trace,authenticator=trace")));
        let subscriber = tracing_subscriber::registry().with(layer);
        tracing::subscriber::with_default(subscriber, || {
            tracing::error!(target: "authenticator::ctap2::commands::client_pin", "pin_hash = 0x1234");
            tracing::trace!(target: "authenticator", "sending key_handle");
            tracing::info!(target: "authenticators_elsewhere", "kept too");
            tracing::info!(target: "mia_tray::admin", "kept");
        });
        let text = String::from_utf8(out.0.lock().unwrap().clone()).unwrap();
        assert!(text.contains("kept") && text.contains("kept too"), "{text}");
        assert!(
            !text.contains("pin_hash") && !text.contains("key_handle"),
            "{text}"
        );
    }
}
