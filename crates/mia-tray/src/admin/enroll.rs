//! The enrollment wizard (F22 §3a item 1), headless: redeem an enrollment
//! or reset token, set the password, and enroll a TOTP authenticator (QR
//! code shown once), a security key, or both. At least one factor is
//! required when the token offers them; both are recommended.

//! Like the login form, every secret (token, password, codes) sits in a
//! wiped [`Secret`] typed into by hand-drawn fields; [`EnrollView`] holds
//! lengths only, and the seed is reached only through
//! [`EnrollWizard::seed_display`]. Dropping the wizard wipes it all.

use ferrogate_admin_client::enroll::EnrollmentOffer;
use ferrogate_admin_client::webauthn::{clean_label, CreationRequest, WebAuthnAttestation};
use serde::Serialize;

use super::secret::Secret;
use super::seed::{SeedDisplay, ShownSeed};
use crate::text::display_safe;

/// Longest key label typed, in characters (CMIS's limit).
pub const MAX_LABEL: usize = 64;
/// Longest user or display name shown, in characters.
pub const MAX_NAME: usize = 64;

/// A wizard field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EnrollField {
    /// The enrollment token (masked).
    Token,
    /// The new password (masked).
    Password,
    /// The new password again (masked).
    Confirm,
    /// A TOTP code (masked).
    Code,
    /// The security key's label (plain text).
    Label,
}

/// Where the wizard is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EnrollStage {
    /// Typing the token.
    Token,
    /// The server answered: password and factors.
    Details,
}

/// Why the wizard did not go on (shown with the field it names).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EnrollError {
    /// No token typed.
    MissingToken,
    /// A bootstrap token: the first operator enrolls on the server host.
    BootstrapToken,
    /// The password is shorter than the policy's minimum.
    PasswordTooShort,
    /// The two passwords differ.
    PasswordMismatch,
    /// Neither a code nor a key: one factor at least.
    NoFactor,
    /// The code is not 6 to 8 digits.
    BadCode,
    /// No security-key support in this build on this platform.
    KeyUnavailable,
}

/// What the window draws. Holds no secret: masks are lengths.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[allow(clippy::struct_excessive_bools)] // A flat view model: one flag per control.
pub struct EnrollView {
    /// The stage.
    pub stage: EnrollStage,
    /// The focused field.
    pub focus: EnrollField,
    /// Characters in the token.
    pub token_len: usize,
    /// The account's user name (escaped).
    pub username: String,
    /// The account's display name (escaped).
    pub display_name: String,
    /// The policy's minimum password length.
    pub password_min_len: u32,
    /// Characters in the password.
    pub password_len: usize,
    /// Characters in the confirmation.
    pub confirm_len: usize,
    /// Characters in the code.
    pub code_len: usize,
    /// The key's label (escaped; not a secret).
    pub label: String,
    /// The token enrolls a TOTP authenticator (the QR code is shown).
    pub totp_offered: bool,
    /// The token enrolls a security key.
    pub key_offered: bool,
    /// A key was registered and waits for "Finish".
    pub key_registered: bool,
    /// A password-only reset: proven with the current authenticator's code.
    pub reset_only: bool,
    /// The seed is shown as text too.
    pub seed_text_shown: bool,
    /// Whether "Continue" can be pressed.
    pub can_continue: bool,
    /// Whether "Register security key" can be pressed.
    pub can_register_key: bool,
    /// Whether this build has a security-key backend here.
    pub key_available: bool,
    /// Whether "Finish" can be pressed.
    pub can_finish: bool,
    /// Why the last step was refused.
    pub error: Option<EnrollError>,
}

/// What `BeginEnrollment` offered, as the wizard keeps it.
struct Offer {
    username: String,
    display_name: String,
    min_len: u32,
    seed: Option<ShownSeed>,
    key: Option<CreationRequest>,
}

/// The credentials of one `CompleteEnrollment`, moved out of the wizard
/// (the token is a copy: a refused attempt can be retried).
pub struct Completion {
    /// The token.
    pub token: Secret,
    /// The new password.
    pub password: Secret,
    /// The code, when one was typed.
    pub code: Option<Secret>,
    /// The registered key.
    pub key: Option<WebAuthnAttestation>,
}

static_assertions::assert_not_impl_any!(Completion: std::fmt::Debug, std::fmt::Display, Clone);
static_assertions::assert_not_impl_any!(EnrollWizard: std::fmt::Debug, std::fmt::Display, Clone);

/// The wizard's state.
pub struct EnrollWizard {
    token: Secret,
    password: Secret,
    confirm: Secret,
    code: Secret,
    label: String,
    focus: EnrollField,
    stage: EnrollStage,
    offer: Option<Offer>,
    key: Option<WebAuthnAttestation>,
    key_available: bool,
    error: Option<EnrollError>,
}

/// A copy of `s` in a new wiped buffer (for one request).
fn copy(s: &Secret) -> Secret {
    let mut out = Secret::new();
    out.push_str(s.expose());
    out
}

impl EnrollWizard {
    /// An empty wizard on the token; `key_available` when this build has a
    /// security-key backend here.
    #[must_use]
    pub fn new(key_available: bool) -> Self {
        Self {
            token: Secret::new(),
            password: Secret::new(),
            confirm: Secret::new(),
            code: Secret::new(),
            label: String::new(),
            focus: EnrollField::Token,
            stage: EnrollStage::Token,
            offer: None,
            key: None,
            key_available,
            error: None,
        }
    }

    fn totp_offered(&self) -> bool {
        self.offer.as_ref().is_some_and(|o| o.seed.is_some())
    }

    fn key_offered(&self) -> bool {
        self.offer.as_ref().is_some_and(|o| o.key.is_some())
    }

    fn reset_only(&self) -> bool {
        self.offer.is_some() && !self.totp_offered() && !self.key_offered()
    }

    /// The fields shown now, in `Tab` order.
    #[must_use]
    pub fn fields(&self) -> Vec<EnrollField> {
        match self.stage {
            EnrollStage::Token => vec![EnrollField::Token],
            EnrollStage::Details => {
                let mut f = vec![EnrollField::Password, EnrollField::Confirm];
                if self.totp_offered() || self.reset_only() {
                    f.push(EnrollField::Code);
                }
                if self.key_offered() && self.key.is_none() {
                    f.push(EnrollField::Label);
                }
                f
            }
        }
    }

    /// Focus `field`, when shown.
    pub fn focus(&mut self, field: EnrollField) {
        if self.fields().contains(&field) {
            self.focus = field;
        }
    }

    /// `Tab` / `Shift-Tab`.
    pub fn tab(&mut self, back: bool) {
        let fields = self.fields();
        let at = fields.iter().position(|f| *f == self.focus).unwrap_or(0);
        let n = fields.len();
        let next = if back { (at + n - 1) % n } else { (at + 1) % n };
        self.focus = fields[next];
    }

    /// Typed or pasted text, for the focused field.
    pub fn type_text(&mut self, text: &str) {
        self.error = None;
        match self.focus {
            EnrollField::Token => self.token.push_str(text.trim()),
            EnrollField::Password => self.password.push_str(text),
            EnrollField::Confirm => self.confirm.push_str(text),
            EnrollField::Code => self.code.push_str(text),
            EnrollField::Label => {
                for c in text.chars().filter(|c| !c.is_control()) {
                    if self.label.chars().count() < MAX_LABEL {
                        self.label.push(c);
                    }
                }
            }
        }
    }

    /// `Backspace` in the focused field.
    pub fn backspace(&mut self) {
        self.error = None;
        match self.focus {
            EnrollField::Token => self.token.pop(),
            EnrollField::Password => self.password.pop(),
            EnrollField::Confirm => self.confirm.pop(),
            EnrollField::Code => self.code.pop(),
            EnrollField::Label => {
                self.label.pop();
            }
        }
    }

    /// `Esc`: wipe the typed secrets of this stage (the token is kept once
    /// the server has answered).
    pub fn escape(&mut self) {
        if self.stage == EnrollStage::Token {
            self.token.clear();
        }
        self.password.clear();
        self.confirm.clear();
        self.code.clear();
        self.error = None;
    }

    /// "Continue": a copy of the token for `BeginEnrollment`.
    ///
    /// # Errors
    /// [`EnrollError::MissingToken`].
    pub fn continue_with(&mut self) -> Result<Secret, EnrollError> {
        if self.stage != EnrollStage::Token || self.token.is_empty() {
            self.error = Some(EnrollError::MissingToken);
            return Err(EnrollError::MissingToken);
        }
        self.error = None;
        Ok(copy(&self.token))
    }

    /// The server's offer. A bootstrap token is refused (wiped, back to an
    /// empty token): the first operator enrolls with `ferrogate admin
    /// bootstrap` on the server host.
    pub fn offered(&mut self, offer: EnrollmentOffer) {
        if offer.username_choosable {
            *self = Self::new(self.key_available);
            self.error = Some(EnrollError::BootstrapToken);
            return;
        }
        self.offer = Some(Offer {
            username: display_safe(&offer.username, MAX_NAME),
            display_name: display_safe(&offer.display_name, MAX_NAME),
            min_len: offer.password_min_len,
            seed: offer.totp.map(ShownSeed::new),
            key: offer.key,
        });
        self.stage = EnrollStage::Details;
        self.focus = EnrollField::Password;
        self.error = None;
    }

    /// "Register security key": the request and label for the platform's key.
    ///
    /// # Errors
    /// [`EnrollError::KeyUnavailable`] without a backend; nothing is asked
    /// when no key is offered or one is registered already.
    pub fn register_key(&mut self) -> Result<(Box<CreationRequest>, String), EnrollError> {
        if !self.key_available {
            self.error = Some(EnrollError::KeyUnavailable);
            return Err(EnrollError::KeyUnavailable);
        }
        match (&self.offer, &self.key) {
            (Some(Offer { key: Some(req), .. }), None) => {
                Ok((Box::new(req.clone()), clean_label(&self.label)))
            }
            _ => Err(EnrollError::KeyUnavailable),
        }
    }

    /// The key answered: keep its registration for "Finish".
    pub fn key_registered(&mut self, attestation: WebAuthnAttestation) {
        if self.key_offered() {
            self.key = Some(attestation);
            if self.focus == EnrollField::Label {
                self.focus = EnrollField::Password;
            }
        }
    }

    fn check(&self) -> Result<(), EnrollError> {
        let Some(offer) = &self.offer else {
            return Err(EnrollError::MissingToken);
        };
        let min = usize::try_from(offer.min_len).unwrap_or(usize::MAX);
        if self.password.char_count() < min {
            return Err(EnrollError::PasswordTooShort);
        }
        if self.password.expose() != self.confirm.expose() {
            return Err(EnrollError::PasswordMismatch);
        }
        let typed = !self.code.is_empty();
        if typed && !self.code.is_totp_code() {
            return Err(EnrollError::BadCode);
        }
        if self.reset_only() && !typed {
            return Err(EnrollError::BadCode);
        }
        if !self.reset_only() && !typed && self.key.is_none() {
            return Err(EnrollError::NoFactor);
        }
        Ok(())
    }

    /// "Finish": move the password and code out (wiped here), copy the
    /// token and the key's registration.
    ///
    /// # Errors
    /// [`EnrollError`]; nothing is wiped then.
    pub fn finish(&mut self) -> Result<Completion, EnrollError> {
        if let Err(e) = self.check() {
            self.error = Some(e);
            return Err(e);
        }
        self.confirm.clear();
        self.error = None;
        // A refused attempt is typed again from the password.
        self.focus = EnrollField::Password;
        let code = if self.code.is_empty() {
            None
        } else {
            Some(self.code.take())
        };
        Ok(Completion {
            token: copy(&self.token),
            password: self.password.take(),
            code,
            key: self.key.clone(),
        })
    }

    /// Show or hide the seed as text.
    pub fn toggle_seed_text(&mut self) {
        if let Some(seed) = self.offer.as_mut().and_then(|o| o.seed.as_mut()) {
            seed.toggle_text();
        }
    }

    /// The seed to paint, while the wizard holds one.
    #[must_use]
    pub fn seed_display(&self) -> Option<SeedDisplay<'_>> {
        self.offer
            .as_ref()
            .and_then(|o| o.seed.as_ref())
            .map(ShownSeed::display)
    }

    /// Whether anything worth wiping is held (the idle lock closes it).
    #[must_use]
    pub fn holds_anything(&self) -> bool {
        !self.token.is_empty() || self.offer.is_some()
    }

    /// What the window draws.
    #[must_use]
    pub fn view(&self) -> EnrollView {
        let offer = self.offer.as_ref();
        let can_finish = self.stage == EnrollStage::Details && self.check().is_ok();
        EnrollView {
            stage: self.stage,
            focus: self.focus,
            token_len: self.token.char_count(),
            username: offer.map(|o| o.username.clone()).unwrap_or_default(),
            display_name: offer.map(|o| o.display_name.clone()).unwrap_or_default(),
            password_min_len: offer.map_or(0, |o| o.min_len),
            password_len: self.password.char_count(),
            confirm_len: self.confirm.char_count(),
            code_len: self.code.char_count(),
            label: display_safe(&self.label, MAX_LABEL),
            totp_offered: self.totp_offered(),
            key_offered: self.key_offered(),
            key_registered: self.key.is_some(),
            reset_only: self.reset_only(),
            seed_text_shown: offer
                .and_then(|o| o.seed.as_ref())
                .is_some_and(ShownSeed::text_shown),
            can_continue: self.stage == EnrollStage::Token && !self.token.is_empty(),
            can_register_key: self.key_offered() && self.key.is_none() && self.key_available,
            key_available: self.key_available,
            can_finish,
            error: self.error,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admin::seed::tests::{seed, SECRET, URI};
    use ferrogate_admin_client::webauthn::{creation_request, CreationOptions};

    const TOKEN: &str = "fgae_0123456789abcdef0123456789abcdef";
    const PASSWORD: &str = "Tr0ub4dor&3-Correct!Horse_Battery";
    const CODE: &str = "123456";

    fn request() -> CreationRequest {
        creation_request(&CreationOptions {
            challenge: vec![3; 32],
            rp_id: "ferrogate-admin.ferrogate.test".into(),
            rp_name: "FerroGate".into(),
            user_id: vec![4; 32],
            user_name: "new.person".into(),
            display_name: "New Person".into(),
            pub_key_cred_params: vec![-7],
            exclude_credential_ids: Vec::new(),
            user_verification: 1,
            attestation: 1,
        })
        .unwrap()
    }

    fn offer(totp: bool, key: bool) -> EnrollmentOffer {
        EnrollmentOffer {
            username: "new.person".into(),
            username_choosable: false,
            display_name: "New\u{1b}[2J Person".into(),
            password_min_len: 24,
            totp: totp.then(seed),
            key: key.then(request),
        }
    }

    fn attestation() -> WebAuthnAttestation {
        WebAuthnAttestation {
            credential_id: vec![9; 32],
            attestation_object: vec![1; 64],
            client_data_json: b"{}".to_vec(),
            transports: Vec::new(),
            label: "Desk key".into(),
        }
    }

    /// The wizard at the details stage for `offer`.
    fn at_details(offer: EnrollmentOffer, key_available: bool) -> EnrollWizard {
        let mut w = EnrollWizard::new(key_available);
        w.type_text(TOKEN);
        let token = w.continue_with().unwrap();
        assert_eq!(token.expose(), TOKEN);
        w.offered(offer);
        assert_eq!(w.view().stage, EnrollStage::Details);
        w
    }

    fn passwords(w: &mut EnrollWizard) {
        w.focus(EnrollField::Password);
        w.type_text(PASSWORD);
        w.tab(false);
        w.type_text(PASSWORD);
    }

    /// No secret in the serialised view.
    fn clean(w: &EnrollWizard) {
        let json = serde_json::to_string(&w.view()).unwrap();
        for secret in [TOKEN, PASSWORD, CODE, SECRET, URI, "JBSW"] {
            assert!(!json.contains(secret), "{secret} in {json}");
        }
    }

    #[test]
    fn totp_only_needs_the_code_and_moves_the_secrets_out() {
        let mut w = at_details(offer(true, false), false);
        let v = w.view();
        assert!(v.totp_offered && !v.key_offered && !v.reset_only);
        assert_eq!(v.username, "new.person");
        assert!(!v.display_name.contains('\u{1b}'), "escaped");
        assert!(w.seed_display().unwrap().qr.is_some());
        assert!(w.seed_display().unwrap().text.is_none(), "QR first");
        w.toggle_seed_text();
        assert!(w.seed_display().unwrap().text.is_some());
        passwords(&mut w);
        assert_eq!(w.finish().err(), Some(EnrollError::NoFactor));
        w.tab(false);
        w.type_text(CODE);
        clean(&w);
        let done = w.finish().unwrap();
        assert_eq!(done.token.expose(), TOKEN);
        assert_eq!(done.password.expose(), PASSWORD);
        assert_eq!(done.code.as_ref().map(Secret::expose), Some(CODE));
        assert!(done.key.is_none());
        let v = w.view();
        assert_eq!((v.password_len, v.confirm_len, v.code_len), (0, 0, 0));
        assert_eq!(v.token_len, TOKEN.len(), "kept for a retry");
    }

    #[test]
    fn a_key_only_enrollment_needs_a_backend_and_a_registered_key() {
        let mut without = at_details(offer(false, true), false);
        assert!(!without.view().can_register_key);
        assert_eq!(
            without.register_key().err(),
            Some(EnrollError::KeyUnavailable)
        );

        let mut w = at_details(offer(false, true), true);
        assert!(w.view().can_register_key);
        assert!(w.fields().contains(&EnrollField::Label));
        w.focus(EnrollField::Label);
        w.type_text("Desk\u{7} key");
        passwords(&mut w);
        assert_eq!(w.finish().err(), Some(EnrollError::NoFactor));
        let (req, label) = w.register_key().unwrap();
        assert_eq!(*req, request());
        assert_eq!(label, "Desk key");
        w.key_registered(attestation());
        let v = w.view();
        assert!(v.key_registered && !v.can_register_key);
        assert!(!w.fields().contains(&EnrollField::Label));
        let done = w.finish().unwrap();
        assert!(done.code.is_none());
        assert_eq!(done.key, Some(attestation()));
    }

    #[test]
    fn both_factors_go_together_and_the_password_is_checked_first() {
        let mut w = at_details(offer(true, true), true);
        w.focus(EnrollField::Password);
        w.type_text("short");
        w.tab(false);
        w.type_text("short");
        assert_eq!(w.finish().err(), Some(EnrollError::PasswordTooShort));
        w.escape();
        assert_eq!(w.view().password_len, 0);
        w.focus(EnrollField::Password);
        w.type_text(PASSWORD);
        w.tab(false);
        w.type_text("Tr0ub4dor&3-Correct!Horse_Batterx");
        assert_eq!(w.finish().err(), Some(EnrollError::PasswordMismatch));
        w.backspace();
        w.type_text("y");
        w.tab(false);
        w.type_text("12a456");
        assert_eq!(w.finish().err(), Some(EnrollError::BadCode));
        for _ in 0..6 {
            w.backspace();
        }
        w.type_text(CODE);
        w.key_registered(attestation());
        assert!(w.view().can_finish);
        let done = w.finish().unwrap();
        assert!(done.code.is_some() && done.key.is_some());
    }

    #[test]
    fn a_password_only_reset_asks_for_the_current_code() {
        let mut w = at_details(offer(false, false), true);
        let v = w.view();
        assert!(v.reset_only && !v.totp_offered && !v.key_offered);
        assert!(w.seed_display().is_none());
        passwords(&mut w);
        assert_eq!(w.finish().err(), Some(EnrollError::BadCode));
        w.tab(false);
        w.type_text(CODE);
        assert!(w.finish().is_ok());
    }

    #[test]
    fn a_bootstrap_token_is_refused_and_wiped() {
        let mut w = EnrollWizard::new(true);
        w.type_text(TOKEN);
        let _ = w.continue_with().unwrap();
        let mut bootstrap = offer(true, false);
        bootstrap.username_choosable = true;
        bootstrap.username = String::new();
        w.offered(bootstrap);
        let v = w.view();
        assert_eq!(v.stage, EnrollStage::Token);
        assert_eq!(v.error, Some(EnrollError::BootstrapToken));
        assert_eq!(v.token_len, 0);
        assert!(w.seed_display().is_none(), "the seed is dropped");
        assert_eq!(w.continue_with().err(), Some(EnrollError::MissingToken));
    }

    #[test]
    fn escape_on_the_token_wipes_it() {
        let mut w = EnrollWizard::new(false);
        w.type_text(&format!("  {TOKEN}\n"));
        assert_eq!(w.view().token_len, TOKEN.len(), "trimmed paste");
        clean(&w);
        w.escape();
        assert_eq!(w.view().token_len, 0);
        assert!(!w.holds_anything());
    }
}
