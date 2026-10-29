//! Buffers for the administrator's secrets (F22 §3, F20 §12).
//!
//! - [`Secret`] holds what the administrator types: a password or a TOTP
//!   code. It is allocated once with a fixed capacity, so typing never
//!   reallocates and leaves partial copies behind, and it is wiped on drop
//!   ([`Zeroizing`]).
//! - [`SessionToken`] holds the bearer token CMIS issues. It lives only in
//!   memory, never in the toolkit's state, a file, the clipboard or a log, and
//!   is wiped on logout, lock and exit.
//!
//! Neither type implements `Debug`, `Display` or `Clone`; the
//! `static_assertions` below make that a compile-time guarantee, so a stray
//! `{:?}` or an accidental copy cannot leak one.

use zeroize::{Zeroize as _, Zeroizing};

/// A secret typed by the administrator (password or TOTP code).
pub struct Secret(Zeroizing<String>);

impl Secret {
    /// Longest secret accepted, in bytes (the server's password limit is 256
    /// characters; this leaves room for multi-byte characters).
    pub const CAPACITY: usize = 1024;

    /// An empty buffer with its final capacity.
    #[must_use]
    pub fn new() -> Self {
        Self(Zeroizing::new(String::with_capacity(Self::CAPACITY)))
    }

    /// Append `c`; returns `false` (and keeps the buffer) when it is full or
    /// `c` is a control character.
    pub fn push(&mut self, c: char) -> bool {
        if c.is_control() || self.0.len() + c.len_utf8() > Self::CAPACITY {
            return false;
        }
        self.0.push(c);
        true
    }

    /// Remove the last character and wipe the byte(s) it occupied.
    ///
    /// `String::pop` only shortens the length, which would leave the removed
    /// character in the spare capacity, so the whole buffer is wiped and the
    /// kept text restored from a copy that is itself wiped when it drops.
    pub fn pop(&mut self) {
        if self.0.pop().is_none() {
            return;
        }
        let kept = Zeroizing::new(self.0.as_str().to_owned());
        // `String::zeroize` wipes the whole allocation and keeps its capacity.
        self.0.zeroize();
        self.0.push_str(&kept);
    }

    /// Wipe the contents.
    pub fn clear(&mut self) {
        self.0.zeroize();
    }

    /// Number of characters (shown as that many mask dots).
    #[must_use]
    pub fn char_count(&self) -> usize {
        self.0.chars().count()
    }

    /// Whether nothing was typed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The secret, for the one request that carries it.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Take the contents, leaving an empty buffer behind.
    #[must_use]
    pub fn take(&mut self) -> Self {
        std::mem::take(self)
    }

    /// Whether this is a well-formed TOTP code (6 to 8 ASCII digits).
    #[must_use]
    pub fn is_totp_code(&self) -> bool {
        (6..=8).contains(&self.0.len()) && self.0.bytes().all(|b| b.is_ascii_digit())
    }
}

impl Default for Secret {
    fn default() -> Self {
        Self::new()
    }
}

/// The admin session token (`fgas_…`), held only in memory.
pub struct SessionToken(Zeroizing<String>);

impl SessionToken {
    /// No session.
    #[must_use]
    pub fn none() -> Self {
        Self(Zeroizing::new(String::new()))
    }

    /// Adopt a token from a server response (the `String` is moved, not
    /// copied, and wiped when this value is dropped or replaced).
    #[must_use]
    pub fn from_server(token: String) -> Self {
        Self(Zeroizing::new(token))
    }

    /// Whether a session is held.
    #[must_use]
    pub fn is_set(&self) -> bool {
        !self.0.is_empty()
    }

    /// The token, for the `authorization` header only.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Forget the session now.
    pub fn clear(&mut self) {
        self.0.zeroize();
    }
}

impl Default for SessionToken {
    fn default() -> Self {
        Self::none()
    }
}

// Compile-time secret hygiene: no formatting, no implicit copies.
static_assertions::assert_not_impl_any!(Secret: std::fmt::Debug, std::fmt::Display, Clone);
static_assertions::assert_not_impl_any!(SessionToken: std::fmt::Debug, std::fmt::Display, Clone);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typing_never_reallocates_and_refuses_controls_and_overflow() {
        let mut s = Secret::new();
        let before = s.0.capacity();
        for _ in 0..Secret::CAPACITY {
            assert!(s.push('a'));
        }
        assert!(!s.push('a'), "full");
        assert_eq!(s.0.capacity(), before, "no reallocation");
        let mut t = Secret::new();
        assert!(!t.push('\u{1b}'));
        assert!(!t.push('\n'));
        assert!(t.is_empty());
    }

    #[test]
    fn a_multibyte_character_that_does_not_fit_is_refused_whole() {
        let mut s = Secret::new();
        for _ in 0..Secret::CAPACITY - 1 {
            assert!(s.push('a'));
        }
        assert!(!s.push('é'), "two bytes into one free byte");
        assert_eq!(s.char_count(), Secret::CAPACITY - 1);
    }

    #[test]
    fn pop_removes_one_character_and_keeps_the_capacity() {
        let mut s = Secret::new();
        let before = s.0.capacity();
        for c in "pa$$é".chars() {
            s.push(c);
        }
        s.pop();
        assert_eq!(s.expose(), "pa$$");
        s.pop();
        s.pop();
        s.pop();
        s.pop();
        s.pop();
        assert!(s.is_empty());
        assert_eq!(s.0.capacity(), before);
    }

    #[test]
    fn take_leaves_an_empty_buffer_and_clear_wipes() {
        let mut s = Secret::new();
        for c in "123456".chars() {
            s.push(c);
        }
        assert!(s.is_totp_code());
        let taken = s.take();
        assert!(s.is_empty());
        assert_eq!(taken.expose(), "123456");
        let mut t = taken;
        t.clear();
        assert!(t.is_empty());
    }

    #[test]
    fn totp_codes_are_six_to_eight_digits() {
        for (text, ok) in [
            ("12345", false),
            ("123456", true),
            ("12345678", true),
            ("123456789", false),
            ("12345a", false),
            ("", false),
        ] {
            let mut s = Secret::new();
            for c in text.chars() {
                s.push(c);
            }
            assert_eq!(s.is_totp_code(), ok, "{text:?}");
        }
    }

    #[test]
    fn a_token_is_cleared_on_demand() {
        let mut t = SessionToken::from_server("fgas_x".into());
        assert!(t.is_set());
        t.clear();
        assert!(!t.is_set());
        assert_eq!(t.expose(), "");
    }
}
