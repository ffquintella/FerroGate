//! Process-wide failure detection for the UI loop.
//!
//! A panic in the client task or the input thread must stop the UI: the
//! hook from [`install`] first raises a flag, then restores the terminal.
//! The loop checks [`has_panicked`] before every frame and, once raised,
//! draws nothing more, ends the session and exits.

use std::sync::atomic::{AtomicBool, Ordering};

static PANICKED: AtomicBool = AtomicBool::new(false);

/// Install the panic hook: raise the flag, run `restore` (put the terminal
/// back), then the previous hook (which prints the message).
pub fn install(restore: fn()) {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        PANICKED.store(true, Ordering::SeqCst);
        restore();
        previous(info);
    }));
}

/// Whether any thread of the process panicked since [`install`].
#[must_use]
pub fn has_panicked() -> bool {
    PANICKED.load(Ordering::SeqCst)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    static RESTORED: AtomicUsize = AtomicUsize::new(0);

    fn restore() {
        RESTORED.fetch_add(1, Ordering::SeqCst);
    }

    #[test]
    fn a_panic_in_another_thread_raises_the_flag_and_restores_the_terminal() {
        let saved = std::panic::take_hook();
        install(restore);
        let joined = std::thread::spawn(|| panic!("client task failure (test)")).join();
        // Put the test harness's hook back before asserting.
        let _ = std::panic::take_hook();
        std::panic::set_hook(saved);
        assert!(joined.is_err());
        assert!(has_panicked(), "the UI loop sees the panic");
        assert!(
            RESTORED.load(Ordering::SeqCst) >= 1,
            "the terminal is restored"
        );
    }
}
