//! The window's side of a security-key ceremony over USB HID (F22 §3a, macOS
//! and Linux): what the key asks for — a touch, a choice between keys, its
//! PIN — and the PIN typed back. The CTAP2 backend runs on a blocking worker
//! thread, off the UI and the async runtime; [`KeyPrompt`] is the bridge.

//! Raw HID has no operating-system PIN prompt, so on these platforms (and
//! only there) the PIN is typed in the admin window: into a [`PinEntry`] (the
//! same fixed-capacity, wiped [`Secret`] buffer as the password, at most
//! [`MAX_PIN_BYTES`]), handed over by move, and wiped on submit, `Esc`,
//! sign-out, the idle lock and close. Views carry its length only; it is
//! never logged, written or formatted.

//! The window arms the prompt when it sends a command that uses the key and
//! cancels it on `Esc`, sign-out, the idle lock and close. A ceremony starts
//! only while armed, and a cancel ends every ceremony armed before it, so a
//! command the window gave up on can never ask for the PIN later. On Windows
//! only this arming and cancelling is used: the system shows its own dialog.

use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::Instant;

use serde::Serialize;

use super::secret::Secret;

/// Longest PIN accepted, in bytes (CTAP2: at most 63 bytes of UTF-8).
pub const MAX_PIN_BYTES: usize = 63;
/// Shortest PIN submitted, in characters (CTAP2: at least 4 code points).
pub const MIN_PIN_CHARS: usize = 4;

/// What the key needs from the administrator now. Holds no secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyAsk {
    /// Touch the key (it blinks).
    Touch,
    /// Several keys are connected: touch the one to use.
    ChooseKey,
    /// Type the key's PIN.
    Pin {
        /// The previous PIN was wrong.
        again: bool,
        /// PIN attempts the key says are left, when it says.
        retries: Option<u8>,
    },
}

impl KeyAsk {
    /// Whether this asks for the PIN.
    #[must_use]
    pub fn is_pin(self) -> bool {
        matches!(self, Self::Pin { .. })
    }
}

/// The PIN being typed in the window: masked (only its length is shown),
/// at most [`MAX_PIN_BYTES`], wiped on `clear`, `backspace` and drop.
pub struct PinEntry(Secret);

static_assertions::assert_not_impl_any!(PinEntry: std::fmt::Debug, std::fmt::Display, Clone);

impl Default for PinEntry {
    fn default() -> Self {
        Self::new()
    }
}

impl PinEntry {
    /// An empty entry.
    #[must_use]
    pub fn new() -> Self {
        Self(Secret::new())
    }

    /// Type or paste `text`; control characters and anything past
    /// [`MAX_PIN_BYTES`] are dropped (a character that does not fit whole is
    /// refused whole).
    pub fn type_text(&mut self, text: &str) {
        for c in text.chars() {
            if self.0.expose().len() + c.len_utf8() <= MAX_PIN_BYTES {
                self.0.push(c);
            }
        }
    }

    /// Delete the last character (its bytes are wiped).
    pub fn backspace(&mut self) {
        self.0.pop();
    }

    /// Wipe what was typed.
    pub fn clear(&mut self) {
        self.0.clear();
    }

    /// Characters typed (shown as that many mask dots).
    #[must_use]
    pub fn char_count(&self) -> usize {
        self.0.char_count()
    }

    /// Whether the PIN is long enough to send ([`MIN_PIN_CHARS`]).
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.0.char_count() >= MIN_PIN_CHARS
    }

    /// Move the PIN out, leaving an empty entry.
    #[must_use]
    pub fn take(&mut self) -> Secret {
        self.0.take()
    }
}

/// How a wait for the PIN ended.
pub enum PinAnswer {
    /// The administrator typed it (wiped when dropped).
    Pin(Secret),
    /// The window cancelled (`Esc`, sign-out, lock, close).
    Cancelled,
    /// Nobody answered before the request's deadline.
    TimedOut,
}

static_assertions::assert_not_impl_any!(PinAnswer: std::fmt::Debug, std::fmt::Display, Clone);

/// A ceremony the backend started ([`KeyPrompt::begin`]).
pub struct Ceremony {
    generation: u64,
}

#[derive(Default)]
struct State {
    /// Bumped by every [`KeyPrompt::arm`].
    generation: u64,
    /// The generation the window armed, while its key command is out.
    armed: Option<u64>,
    /// Ceremonies of this generation or older are cancelled.
    cancelled_upto: u64,
    /// What the key asks for, and for which ceremony.
    asking: Option<(u64, KeyAsk)>,
    /// The PIN the window typed, until the backend takes it.
    pin: Option<Secret>,
}

impl State {
    fn is_cancelled(&self, generation: u64) -> bool {
        generation <= self.cancelled_upto
    }
}

/// The bridge between a blocking key backend and the window (see the module
/// documentation). Shared as an `Arc` by the backend and the window.
pub struct KeyPrompt {
    state: Mutex<State>,
    changed: Condvar,
    wake: Mutex<Option<Arc<dyn Fn() + Send + Sync>>>,
}

static_assertions::assert_not_impl_any!(KeyPrompt: std::fmt::Debug, std::fmt::Display, Clone);

impl KeyPrompt {
    /// A prompt with nothing armed.
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(State::default()),
            changed: Condvar::new(),
            wake: Mutex::new(None),
        })
    }

    /// Call `wake` whenever the key asks for something new (the window
    /// repaints).
    pub fn set_wake(&self, wake: Arc<dyn Fn() + Send + Sync>) {
        *self.wake.lock().unwrap_or_else(PoisonError::into_inner) = Some(wake);
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Tell the waiting backend and the window that something changed (the
    /// state lock is not held here).
    fn changed(&self) {
        self.changed.notify_all();
        let wake = self
            .wake
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        if let Some(wake) = wake {
            wake();
        }
    }

    // ── The window's side ──────────────────────────────────────────────

    /// A command that uses the key is being sent: its ceremonies may start.
    pub fn arm(&self) {
        let mut s = self.lock();
        s.generation += 1;
        s.armed = Some(s.generation);
    }

    /// The armed command was answered: no new ceremony starts for it.
    pub fn disarm(&self) {
        let mut s = self.lock();
        s.armed = None;
        s.pin = None;
    }

    /// `Esc`, sign-out, the idle lock or close: end every ceremony armed so
    /// far, wipe a PIN not yet taken, and start no new one until the next
    /// [`KeyPrompt::arm`].
    pub fn cancel(&self) {
        {
            let mut s = self.lock();
            s.armed = None;
            s.cancelled_upto = s.generation;
            s.asking = None;
            s.pin = None;
        }
        self.changed();
    }

    /// What the key asks for now, if anything.
    #[must_use]
    pub fn asking(&self) -> Option<KeyAsk> {
        self.lock().asking.map(|(_, ask)| ask)
    }

    /// Hand the typed PIN to the waiting backend; `false` (and the PIN is
    /// wiped) when no PIN is being asked for.
    pub fn answer(&self, pin: Secret) -> bool {
        let taken = {
            let mut s = self.lock();
            match s.asking {
                Some((g, ask)) if ask.is_pin() && !s.is_cancelled(g) => {
                    s.pin = Some(pin);
                    true
                }
                _ => false,
            }
        };
        if taken {
            self.changed();
        }
        taken
    }

    // ── The backend's side ─────────────────────────────────────────────

    /// Start a ceremony; `None` when the window armed nothing or cancelled
    /// what it armed (nothing may be asked then).
    #[must_use]
    pub fn begin(&self) -> Option<Ceremony> {
        let s = self.lock();
        match s.armed {
            Some(g) if !s.is_cancelled(g) => Some(Ceremony { generation: g }),
            _ => None,
        }
    }

    /// Whether the window cancelled `ceremony`.
    #[must_use]
    pub fn cancelled(&self, ceremony: &Ceremony) -> bool {
        self.lock().is_cancelled(ceremony.generation)
    }

    /// Show `ask` for `ceremony` (not for a cancelled one).
    pub fn show(&self, ceremony: &Ceremony, ask: KeyAsk) {
        {
            let mut s = self.lock();
            if s.is_cancelled(ceremony.generation) {
                return;
            }
            s.asking = Some((ceremony.generation, ask));
            s.pin = None;
        }
        self.changed();
    }

    /// Ask for the PIN and wait until the window answers, cancels, or
    /// `deadline` passes.
    #[must_use]
    pub fn wait_pin(
        &self,
        ceremony: &Ceremony,
        again: bool,
        retries: Option<u8>,
        deadline: Instant,
    ) -> PinAnswer {
        let g = ceremony.generation;
        {
            let mut s = self.lock();
            if s.is_cancelled(g) {
                return PinAnswer::Cancelled;
            }
            s.pin = None;
            s.asking = Some((g, KeyAsk::Pin { again, retries }));
        }
        self.changed();
        let mut s = self.lock();
        loop {
            if s.is_cancelled(g) {
                return PinAnswer::Cancelled;
            }
            if let Some(pin) = s.pin.take() {
                // The key now checks it and may ask for a touch.
                s.asking = None;
                return PinAnswer::Pin(pin);
            }
            let now = Instant::now();
            if now >= deadline {
                s.asking = None;
                return PinAnswer::TimedOut;
            }
            s = self
                .changed
                .wait_timeout(s, deadline - now)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
    }

    /// The ceremony ended: whatever it showed goes (and a PIN not taken is
    /// wiped).
    pub fn finish(&self, ceremony: Ceremony) {
        {
            let mut s = self.lock();
            if matches!(s.asking, Some((g, _)) if g == ceremony.generation) {
                s.asking = None;
            }
            s.pin = None;
        }
        self.changed();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    fn secret(text: &str) -> Secret {
        let mut s = Secret::new();
        s.push_str(text);
        s
    }

    /// Poll `prompt` until it asks for a PIN (the backend runs on a thread).
    fn until_pin(prompt: &KeyPrompt) -> KeyAsk {
        for _ in 0..500 {
            if let Some(ask) = prompt.asking().filter(|a| a.is_pin()) {
                return ask;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        panic!("no PIN asked");
    }

    #[test]
    fn the_pin_entry_is_bounded_masked_and_moved_out() {
        let mut e = PinEntry::new();
        e.type_text("12\u{1b}3\n");
        assert_eq!(e.char_count(), 3, "controls dropped");
        assert!(!e.is_complete(), "CTAP2 needs four characters");
        e.type_text("4");
        assert!(e.is_complete());
        e.type_text(&"9".repeat(100));
        assert_eq!(e.char_count(), MAX_PIN_BYTES, "63 bytes at most");
        e.clear();
        for _ in 0..MAX_PIN_BYTES - 1 {
            e.type_text("a");
        }
        e.type_text("é");
        assert_eq!(
            e.char_count(),
            MAX_PIN_BYTES - 1,
            "a character that does not fit"
        );
        e.backspace();
        assert_eq!(e.char_count(), MAX_PIN_BYTES - 2);
        e.clear();
        e.type_text("2468");
        let pin = e.take();
        assert_eq!(pin.expose(), "2468");
        assert_eq!(e.char_count(), 0, "nothing left behind");
    }

    #[test]
    fn a_ceremony_starts_only_while_armed_and_a_cancel_is_final() {
        let p = KeyPrompt::new();
        assert!(p.begin().is_none(), "nothing armed");
        p.arm();
        let first = p.begin().expect("armed");
        p.cancel();
        assert!(p.cancelled(&first));
        assert!(p.begin().is_none(), "a cancel disarms");
        // A new command does not revive the cancelled ceremony.
        p.arm();
        assert!(p.cancelled(&first));
        let second = p.begin().expect("armed again");
        assert!(!p.cancelled(&second));
        p.show(&first, KeyAsk::Touch);
        assert_eq!(p.asking(), None, "a cancelled ceremony shows nothing");
        p.show(&second, KeyAsk::Touch);
        assert_eq!(p.asking(), Some(KeyAsk::Touch));
        p.finish(second);
        assert_eq!(p.asking(), None);
        p.disarm();
        assert!(p.begin().is_none());
    }

    #[test]
    fn the_typed_pin_reaches_the_waiting_backend_by_move() {
        let p = KeyPrompt::new();
        let woken = Arc::new(AtomicUsize::new(0));
        let w = Arc::clone(&woken);
        p.set_wake(Arc::new(move || {
            w.fetch_add(1, Ordering::SeqCst);
        }));
        assert!(!p.answer(secret("1234")), "no PIN asked yet");
        p.arm();
        let backend = Arc::clone(&p);
        let waiter = std::thread::spawn(move || {
            let c = backend.begin().unwrap();
            let deadline = Instant::now() + Duration::from_secs(10);
            match backend.wait_pin(&c, true, Some(2), deadline) {
                PinAnswer::Pin(pin) => pin.expose().to_string(),
                PinAnswer::Cancelled => "cancelled".into(),
                PinAnswer::TimedOut => "timed out".into(),
            }
        });
        assert_eq!(
            until_pin(&p),
            KeyAsk::Pin {
                again: true,
                retries: Some(2)
            }
        );
        assert!(woken.load(Ordering::SeqCst) > 0, "the window was woken");
        assert!(p.answer(secret("1234")));
        assert_eq!(waiter.join().unwrap(), "1234");
        assert_eq!(p.asking(), None, "the PIN prompt went with the answer");
        assert!(p.lock().pin.is_none(), "the bridge keeps no copy");
    }

    #[test]
    fn a_cancel_or_the_deadline_ends_the_wait_and_wipes_the_pin() {
        let p = KeyPrompt::new();
        p.arm();
        let backend = Arc::clone(&p);
        let waiter = std::thread::spawn(move || {
            let c = backend.begin().unwrap();
            let deadline = Instant::now() + Duration::from_secs(10);
            matches!(
                backend.wait_pin(&c, false, None, deadline),
                PinAnswer::Cancelled
            )
        });
        until_pin(&p);
        p.cancel();
        assert!(waiter.join().unwrap(), "cancelled");
        assert_eq!(p.asking(), None);
        assert!(!p.answer(secret("1234")), "too late: refused and wiped");
        assert!(p.lock().pin.is_none());

        p.arm();
        let c = p.begin().unwrap();
        let deadline = Instant::now() + Duration::from_millis(30);
        assert!(matches!(
            p.wait_pin(&c, false, None, deadline),
            PinAnswer::TimedOut
        ));
        assert_eq!(p.asking(), None, "nothing left on screen");
    }
}
