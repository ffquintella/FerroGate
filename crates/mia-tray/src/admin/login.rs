//! The login model (F22 §3): what the administrator has typed and how it is
//! wiped. Two stages: the user name (sent alone in `BeginLogin`, which says
//! which second factors the account may use here), then the password with a
//! TOTP code or a security key, as offered.

//! The window never gives a secret to a text widget: it hands keystrokes to
//! [`LoginModel::type_text`] / [`LoginModel::backspace`] and draws only the
//! [`LoginView`], whose masks are character counts. The buffers are wiped on
//! submit, `Esc`, close and lock.

use ferrogate_admin_client::client::Methods;
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
    /// The TOTP code (masked).
    Code,
}

/// Where the form is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    /// Typing the user name.
    Username,
    /// The server offered these methods for the user name: password plus a
    /// code and/or a key.
    Secrets(Methods),
}

/// How the administrator chose to prove the second factor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Submission {
    /// With the TOTP code typed in the form.
    Code,
    /// With a touch of a security key.
    SecurityKey,
}

/// Why a login was not submitted. The wording shown is generic (F20): it
/// never says which part of a credential was wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LoginError {
    /// No user name.
    MissingUsername,
    /// No password.
    MissingPassword,
    /// The code is not 6 to 8 digits.
    BadCode,
    /// That second factor is not offered for this account here.
    NotOffered,
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
    /// The stage, with the offered methods.
    pub stage: Stage,
    /// Why the last submit was refused.
    pub error: Option<LoginError>,
    /// Whether "Continue" (the user name stage) can be pressed.
    pub can_continue: bool,
    /// Whether the form can be submitted with the code.
    pub can_submit_code: bool,
    /// Whether the form can be submitted with a security key.
    pub can_submit_key: bool,
}

/// The credentials of one login attempt, moved out of the model by
/// [`LoginModel::submit`]. They are wiped when this value drops.
pub struct Credentials {
    /// The user name.
    pub username: Zeroizing<String>,
    /// The password.
    pub password: Secret,
    /// The TOTP code, for [`Submission::Code`].
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
    stage: Stage,
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
            stage: Stage::Username,
            error: None,
        }
    }

    /// Focus `field`, when this stage shows it.
    pub fn focus(&mut self, field: Field) {
        if self.fields().contains(&field) {
            self.focus = field;
        }
    }

    /// The fields this stage shows, in `Tab` order.
    #[must_use]
    pub fn fields(&self) -> Vec<Field> {
        match self.stage {
            Stage::Username => vec![Field::Username],
            Stage::Secrets(m) if m.totp => vec![Field::Password, Field::Code],
            Stage::Secrets(_) => vec![Field::Password],
        }
    }

    /// `Tab` (or `Shift-Tab` when `back`): the next field of this stage.
    pub fn tab(&mut self, back: bool) {
        let fields = self.fields();
        let at = fields.iter().position(|f| *f == self.focus).unwrap_or(0);
        let n = fields.len();
        let next = if back { (at + n - 1) % n } else { (at + 1) % n };
        self.focus = fields[next];
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
            Field::Password => self.password.push_str(text),
            Field::Code => self.code.push_str(text),
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

    /// `Esc`: wipe the password and the code, keep the user name and stage.
    pub fn escape(&mut self) {
        self.password.clear();
        self.code.clear();
        self.error = None;
        self.focus = match self.stage {
            Stage::Username => Field::Username,
            Stage::Secrets(_) => Field::Password,
        };
    }

    /// The window is closing, or the client locked: wipe everything and
    /// return to the empty form.
    pub fn wipe(&mut self) {
        *self = Self::new();
    }

    /// "Continue": the user name to ask the server about.
    ///
    /// # Errors
    /// [`LoginError::MissingUsername`].
    pub fn continue_with(&mut self) -> Result<String, LoginError> {
        let name = self.username.trim();
        if name.is_empty() {
            self.error = Some(LoginError::MissingUsername);
            return Err(LoginError::MissingUsername);
        }
        Ok(name.to_string())
    }

    /// The server offered `methods` for `username`: show the secrets stage
    /// (ignored when the form now holds another user name).
    pub fn offered(&mut self, username: &str, methods: Methods) {
        if self.username.trim() == username {
            // In place: the buffer keeps its capacity, no stray copy.
            self.username.clear();
            self.username.push_str(username);
            self.stage = Stage::Secrets(methods);
            self.focus = Field::Password;
            self.error = None;
        }
    }

    /// "Change user": back to the user name, the secrets wiped.
    pub fn back(&mut self) {
        self.password.clear();
        self.code.clear();
        self.stage = Stage::Username;
        self.focus = Field::Username;
        self.error = None;
    }

    fn check(&self, how: Submission) -> Result<(), LoginError> {
        let Stage::Secrets(methods) = self.stage else {
            return Err(LoginError::MissingUsername);
        };
        if self.username.trim().is_empty() {
            return Err(LoginError::MissingUsername);
        }
        match how {
            Submission::Code if !methods.totp => return Err(LoginError::NotOffered),
            Submission::SecurityKey if !methods.security_key => return Err(LoginError::NotOffered),
            _ => {}
        }
        if self.password.is_empty() {
            return Err(LoginError::MissingPassword);
        }
        if how == Submission::Code && !self.code.is_totp_code() {
            return Err(LoginError::BadCode);
        }
        Ok(())
    }

    /// Submit: move the credentials out and leave the form empty (the user
    /// name included — the server's answer decides what is shown next). A
    /// key submission wipes any typed code.
    ///
    /// # Errors
    /// [`LoginError`] when the form is incomplete; nothing is wiped then.
    pub fn submit(&mut self, how: Submission) -> Result<Credentials, LoginError> {
        if let Err(e) = self.check(how) {
            self.error = Some(e);
            return Err(e);
        }
        let creds = Credentials {
            username: std::mem::take(&mut self.username),
            password: self.password.take(),
            code: (how == Submission::Code).then(|| self.code.take()),
        };
        self.wipe();
        Ok(creds)
    }

    /// Return to the secrets stage for `username` after a refused sign-in
    /// (the secrets were wiped at submit and must be typed again).
    pub fn retry(&mut self, username: &str, methods: Methods) {
        self.wipe();
        self.username.push_str(username);
        self.offered(username, methods);
    }

    /// What the window draws.
    #[must_use]
    pub fn view(&self) -> LoginView {
        LoginView {
            username: self.username.to_string(),
            password_len: self.password.char_count(),
            code_len: self.code.char_count(),
            focus: self.focus,
            stage: self.stage,
            error: self.error,
            can_continue: self.stage == Stage::Username && !self.username.trim().is_empty(),
            can_submit_code: self.check(Submission::Code).is_ok(),
            can_submit_key: self.check(Submission::SecurityKey).is_ok(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWORD: &str = "c0rrect-horse-Battery-staple";
    const BOTH: Methods = Methods {
        totp: true,
        security_key: true,
    };
    const KEY_ONLY: Methods = Methods {
        totp: false,
        security_key: true,
    };

    fn typed(model: &mut LoginModel, field: Field, text: &str) {
        model.focus(field);
        model.type_text(text);
    }

    fn at_secrets(methods: Methods) -> LoginModel {
        let mut m = LoginModel::new();
        typed(&mut m, Field::Username, "alice");
        let name = m.continue_with().unwrap();
        m.offered(&name, methods);
        m
    }

    fn filled() -> LoginModel {
        let mut m = at_secrets(BOTH);
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
        assert!(v.can_submit_code && v.can_submit_key);
    }

    #[test]
    fn the_user_name_comes_first_and_the_offer_opens_the_secrets() {
        let mut m = LoginModel::new();
        assert_eq!(m.continue_with(), Err(LoginError::MissingUsername));
        assert_eq!(m.fields(), vec![Field::Username]);
        m.focus(Field::Password);
        assert_eq!(m.view().focus, Field::Username, "no password field yet");
        typed(&mut m, Field::Username, "  alice ");
        assert!(m.view().can_continue);
        assert_eq!(m.continue_with().unwrap(), "alice");
        m.offered("bob", BOTH);
        assert_eq!(m.view().stage, Stage::Username, "an offer for another name");
        m.offered("alice", BOTH);
        let v = m.view();
        assert_eq!((v.stage, v.focus), (Stage::Secrets(BOTH), Field::Password));
        assert_eq!(v.username, "alice");
        m.back();
        assert_eq!(m.view().stage, Stage::Username);
    }

    #[test]
    fn submit_moves_the_secrets_out_and_empties_the_form() {
        let mut m = filled();
        let creds = m.submit(Submission::Code).expect("complete form");
        assert_eq!(&*creds.username, "alice");
        assert_eq!(creds.password.expose(), PASSWORD);
        assert_eq!(creds.code.as_ref().map(Secret::expose), Some("123456"));
        let v = m.view();
        assert_eq!(
            (v.username.as_str(), v.password_len, v.code_len),
            ("", 0, 0)
        );
        assert_eq!((v.stage, v.focus), (Stage::Username, Field::Username));
    }

    #[test]
    fn a_login_by_security_key_carries_no_code() {
        let mut m = filled();
        let creds = m.submit(Submission::SecurityKey).expect("complete form");
        assert!(creds.code.is_none());
        assert_eq!(m.view().code_len, 0, "the typed code is wiped too");
    }

    #[test]
    fn under_the_fido2_policy_only_the_key_is_offered() {
        let mut m = at_secrets(KEY_ONLY);
        assert_eq!(m.fields(), vec![Field::Password], "no code field");
        typed(&mut m, Field::Password, PASSWORD);
        let v = m.view();
        assert!(!v.can_submit_code && v.can_submit_key);
        assert!(matches!(
            m.submit(Submission::Code),
            Err(LoginError::NotOffered)
        ));
        assert_eq!(m.view().password_len, PASSWORD.chars().count());
    }

    #[test]
    fn an_incomplete_form_is_refused_with_a_generic_reason_and_keeps_the_input() {
        let mut m = at_secrets(BOTH);
        assert!(matches!(
            m.submit(Submission::Code),
            Err(LoginError::MissingPassword)
        ));
        typed(&mut m, Field::Password, PASSWORD);
        typed(&mut m, Field::Code, "12ab");
        assert!(matches!(
            m.submit(Submission::Code),
            Err(LoginError::BadCode)
        ));
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
        assert_eq!(v.stage, Stage::Username);
    }

    #[test]
    fn a_refused_sign_in_returns_to_the_secrets_of_the_same_user() {
        let mut m = filled();
        let _ = m.submit(Submission::Code).unwrap();
        m.retry("alice", BOTH);
        let v = m.view();
        assert_eq!(
            (v.username.as_str(), v.stage),
            ("alice", Stage::Secrets(BOTH))
        );
        assert_eq!((v.password_len, v.code_len), (0, 0));
    }

    #[test]
    fn controls_and_overflow_are_dropped() {
        let mut m = LoginModel::new();
        typed(&mut m, Field::Username, "al\u{1b}[31mice\n");
        assert_eq!(m.view().username, "al[31mice");
        m.focus(Field::Username);
        m.type_text(&"x".repeat(MAX_USERNAME * 2));
        assert_eq!(m.view().username.len(), MAX_USERNAME);
        let mut s = at_secrets(BOTH);
        typed(&mut s, Field::Password, "pa\nss\t");
        assert_eq!(s.view().password_len, 4);
    }

    #[test]
    fn tab_cycles_the_fields_of_the_stage() {
        let mut m = at_secrets(BOTH);
        m.tab(false);
        assert_eq!(m.view().focus, Field::Code);
        m.tab(false);
        assert_eq!(m.view().focus, Field::Password);
        m.tab(true);
        assert_eq!(m.view().focus, Field::Code);
        let mut k = at_secrets(KEY_ONLY);
        k.tab(false);
        assert_eq!(k.view().focus, Field::Password);
    }
}
