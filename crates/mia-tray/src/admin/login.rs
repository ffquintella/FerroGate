//! The login model (F22 §3): what the administrator has typed and how it is
//! wiped.
//!
//! The window never gives a secret to a text widget. It translates keystrokes
//! into [`LoginModel::type_text`] / [`LoginModel::backspace`] calls on the model, which owns the buffers;
//! the window draws only the [`LoginView`], which has no field that could hold
//! a secret (the mask is a character count). So the toolkit's text-edit state
//! (undo history, galley cache) never sees the password or the code.
//!
//! The buffers are wiped when the login is submitted, on `Esc`, when the
//! window is closed and when the client locks.

use serde::Serialize;
use zeroize::Zeroizing;

use super::secret::Secret;

/// Longest user name accepted, in bytes.
pub const MAX_USERNAME: usize = 128;

/// A login field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Field {
    /// The user name.
    Username,
    /// The password (masked).
    Password,
    /// The TOTP code (masked). Left empty when a security key is used.
    Code,
}

impl Field {
    /// The field after this one (`Tab`).
    #[must_use]
    pub fn next(self) -> Self {
        match self {
            Self::Username => Self::Password,
            Self::Password => Self::Code,
            Self::Code => Self::Username,
        }
    }
}

/// Why a login was not submitted. The wording shown for each is generic
/// (F20): it never says which part of a credential was wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LoginError {
    /// No user name.
    MissingUsername,
    /// No password.
    MissingPassword,
    /// A code was typed but it is not 6 to 8 digits.
    BadCode,
}

/// What the window draws. It holds **no secret**: the password and the code
/// appear only as their length, for the mask dots.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LoginView {
    /// The user name (not a secret).
    pub username: String,
    /// Characters in the password.
    pub password_len: usize,
    /// Characters in the code.
    pub code_len: usize,
    /// The focused field.
    pub focus: Field,
    /// Why the last submit was refused.
    pub error: Option<LoginError>,
    /// Whether the form is complete enough to submit.
    pub can_submit: bool,
}

/// The credentials of one login attempt, moved out of the model by
/// [`LoginModel::submit`]. They are wiped when this value drops.
pub struct Credentials {
    /// The user name.
    pub username: Zeroizing<String>,
    /// The password.
    pub password: Secret,
    /// The TOTP code, when one was typed (otherwise a security key is used).
    pub code: Option<Secret>,
}

static_assertions::assert_not_impl_any!(Credentials: std::fmt::Debug, std::fmt::Display, Clone);
static_assertions::assert_not_impl_any!(LoginModel: std::fmt::Debug, std::fmt::Display, Clone);

/// The login form's state.
pub struct LoginModel {
    username: Zeroizing<String>,
    password: Secret,
    code: Secret,
    focus: Field,
    error: Option<LoginError>,
}

impl Default for LoginModel {
    fn default() -> Self {
        Self::new()
    }
}

impl LoginModel {
    /// An empty form, focused on the user name.
    #[must_use]
    pub fn new() -> Self {
        Self {
            username: Zeroizing::new(String::with_capacity(MAX_USERNAME)),
            password: Secret::new(),
            code: Secret::new(),
            focus: Field::Username,
            error: None,
        }
    }

    /// Focus `field`.
    pub fn focus(&mut self, field: Field) {
        self.focus = field;
    }

    /// Type or paste `text` into the focused field; characters the field
    /// refuses (controls, anything past its capacity) are dropped. Takes a
    /// borrow so the window never has to copy what the toolkit delivered.
    pub fn type_text(&mut self, text: &str) {
        self.error = None;
        match self.focus {
            Field::Username => {
                for c in text.chars() {
                    if !c.is_control() && self.username.len() + c.len_utf8() <= MAX_USERNAME {
                        self.username.push(c);
                    }
                }
            }
            Field::Password => Self::push_all(&mut self.password, text),
            Field::Code => Self::push_all(&mut self.code, text),
        }
    }

    /// Delete the last character of the focused field.
    pub fn backspace(&mut self) {
        self.error = None;
        match self.focus {
            Field::Username => {
                self.username.pop();
            }
            Field::Password => self.password.pop(),
            Field::Code => self.code.pop(),
        }
    }

    fn push_all(secret: &mut Secret, text: &str) {
        for c in text.chars() {
            secret.push(c);
        }
    }

    /// `Esc`: wipe the password and the code, keep the user name.
    pub fn escape(&mut self) {
        self.password.clear();
        self.code.clear();
        self.error = None;
        self.focus = Field::Password;
    }

    /// The window is closing, or the client locked: wipe everything and
    /// return to the empty form.
    pub fn wipe(&mut self) {
        *self = Self::new();
    }

    /// Whether the form can be submitted.
    #[must_use]
    pub fn can_submit(&self) -> bool {
        self.check().is_ok()
    }

    fn check(&self) -> Result<(), LoginError> {
        if self.username.trim().is_empty() {
            Err(LoginError::MissingUsername)
        } else if self.password.is_empty() {
            Err(LoginError::MissingPassword)
        } else if !self.code.is_empty() && !self.code.is_totp_code() {
            Err(LoginError::BadCode)
        } else {
            Ok(())
        }
    }

    /// Submit: move the credentials out and leave the form empty (the user
    /// name included — the server's answer decides what is shown next).
    ///
    /// # Errors
    /// [`LoginError`] when the form is incomplete; nothing is wiped then.
    pub fn submit(&mut self) -> Result<Credentials, LoginError> {
        if let Err(e) = self.check() {
            self.error = Some(e);
            return Err(e);
        }
        let creds = Credentials {
            username: std::mem::take(&mut self.username),
            password: self.password.take(),
            code: (!self.code.is_empty()).then(|| self.code.take()),
        };
        self.wipe();
        Ok(creds)
    }

    /// What the window draws.
    #[must_use]
    pub fn view(&self) -> LoginView {
        LoginView {
            username: self.username.to_string(),
            password_len: self.password.char_count(),
            code_len: self.code.char_count(),
            focus: self.focus,
            error: self.error,
            can_submit: self.can_submit(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWORD: &str = "c0rrect-horse-Battery-staple";

    fn typed(model: &mut LoginModel, field: Field, text: &str) {
        model.focus(field);
        model.type_text(text);
    }

    fn filled() -> LoginModel {
        let mut m = LoginModel::new();
        typed(&mut m, Field::Username, "alice");
        typed(&mut m, Field::Password, PASSWORD);
        typed(&mut m, Field::Code, "123456");
        m
    }

    #[test]
    fn the_view_carries_lengths_never_secrets() {
        let m = filled();
        let json = serde_json::to_string(&m.view()).unwrap();
        assert!(!json.contains(PASSWORD));
        assert!(!json.contains("123456"));
        let v = m.view();
        assert_eq!(v.password_len, PASSWORD.chars().count());
        assert_eq!(v.code_len, 6);
        assert!(v.can_submit);
    }

    #[test]
    fn submit_moves_the_secrets_out_and_empties_the_form() {
        let mut m = filled();
        let creds = m.submit().expect("complete form");
        assert_eq!(&*creds.username, "alice");
        assert_eq!(creds.password.expose(), PASSWORD);
        assert_eq!(creds.code.as_ref().map(Secret::expose), Some("123456"));
        let v = m.view();
        assert_eq!(
            (v.username.as_str(), v.password_len, v.code_len),
            ("", 0, 0)
        );
        assert_eq!(v.focus, Field::Username);
        assert!(!v.can_submit);
    }

    #[test]
    fn a_login_by_security_key_carries_no_code() {
        let mut m = LoginModel::new();
        typed(&mut m, Field::Username, "alice");
        typed(&mut m, Field::Password, PASSWORD);
        let creds = m.submit().expect("complete form");
        assert!(creds.code.is_none());
    }

    #[test]
    fn an_incomplete_form_is_refused_with_a_generic_reason_and_keeps_the_input() {
        let mut m = LoginModel::new();
        typed(&mut m, Field::Password, PASSWORD);
        assert!(matches!(m.submit(), Err(LoginError::MissingUsername)));
        typed(&mut m, Field::Username, "alice");
        typed(&mut m, Field::Code, "12ab");
        assert!(matches!(m.submit(), Err(LoginError::BadCode)));
        let v = m.view();
        assert_eq!(v.error, Some(LoginError::BadCode));
        assert_eq!(v.password_len, PASSWORD.chars().count(), "nothing wiped");
        m.backspace();
        assert_eq!(m.view().error, None, "an edit clears the message");
    }

    #[test]
    fn escape_wipes_the_secrets_and_keeps_the_user_name() {
        let mut m = filled();
        m.escape();
        let v = m.view();
        assert_eq!(v.username, "alice");
        assert_eq!((v.password_len, v.code_len), (0, 0));
        assert_eq!(v.focus, Field::Password);
    }

    #[test]
    fn close_and_lock_wipe_everything() {
        let mut m = filled();
        m.wipe();
        let v = m.view();
        assert_eq!(v.username, "");
        assert_eq!((v.password_len, v.code_len), (0, 0));
    }

    #[test]
    fn editing_affects_only_the_focused_field() {
        let mut m = LoginModel::new();
        typed(&mut m, Field::Password, "abc");
        m.backspace();
        let v = m.view();
        assert_eq!(v.password_len, 2);
        assert_eq!((v.username.as_str(), v.code_len), ("", 0));
    }

    #[test]
    fn controls_and_overflow_are_dropped() {
        let mut m = LoginModel::new();
        typed(&mut m, Field::Username, "al\u{1b}[31mice\n");
        assert_eq!(m.view().username, "al[31mice");
        typed(&mut m, Field::Password, "pa\nss\t");
        assert_eq!(m.view().password_len, 4);
        m.focus(Field::Username);
        m.type_text(&"x".repeat(MAX_USERNAME * 2));
        assert_eq!(m.view().username.len(), MAX_USERNAME);
    }

    #[test]
    fn tab_cycles_the_fields() {
        assert_eq!(Field::Username.next(), Field::Password);
        assert_eq!(Field::Password.next(), Field::Code);
        assert_eq!(Field::Code.next(), Field::Username);
    }
}
