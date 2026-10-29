//! "My account → Second factors" (F22 §3a items 2 and 3), headless: the
//! account's factors, adding an authenticator app (QR code shown once) or a
//! security key, and removing one. Adding and removing take a fresh proof
//! of a factor the account already holds; the last one is never removed.

//! Under the FIDO2 tray policy, a session without a key is *restricted*:
//! the panel offers only "Register a security key", and the flow ends the
//! session once it is registered. Secrets live in wiped buffers; the view
//! holds lengths and escaped server text only.

use ferrogate_admin_client::client::Methods;
use ferrogate_admin_client::factors::{AddNonce, AddOffer, FactorInfo, FactorMethod};
use ferrogate_admin_client::webauthn::{clean_label, CreationRequest};
use serde::Serialize;

use super::login::Submission;
use super::secret::Secret;
use super::seed::{SeedDisplay, ShownSeed};
use super::session::{Cmd, FactorChoice};
use crate::text::display_safe;

/// Longest key label typed, in characters (CMIS's limit).
pub const MAX_LABEL: usize = 64;

/// A field of the panel's forms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FactorField {
    /// A code from the authenticator being added (masked).
    NewCode,
    /// A code proving a factor already held (masked).
    Proof,
    /// The new key's label (plain text).
    Label,
}

/// What the panel shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PanelMode {
    /// The list.
    List,
    /// Adding an authenticator app: QR code, its code, a proof.
    AddTotp,
    /// Adding a security key: label, a proof.
    AddKey,
    /// Confirming a removal with a proof.
    Remove,
}

/// Why the panel refused a step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PanelError {
    /// Removing the account's only factor.
    LastFactor,
    /// A code is not 6 to 8 digits.
    BadCode,
    /// No security-key support in this build on this platform.
    KeyUnavailable,
    /// That proof is not accepted for this account here.
    NotOffered,
}

/// One factor as shown (escaped).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FactorRow {
    /// The factor's id, as the server listed it.
    pub factor_id: String,
    /// What it is.
    pub method: FactorMethod,
    /// The holder's label (escaped).
    pub label: String,
    /// When it was added (Unix seconds; 0 unknown).
    pub created_at: i64,
    /// When it was last used (Unix seconds; 0 never or unknown).
    pub last_used_at: i64,
}

/// What the window draws. Holds no secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[allow(clippy::struct_excessive_bools)] // A flat view model: one flag per control.
pub struct FactorsView {
    /// The factors (once loaded).
    pub rows: Vec<FactorRow>,
    /// Whether the list arrived.
    pub loaded: bool,
    /// The FIDO2 policy holds this session to registering a key.
    pub restricted: bool,
    /// The form shown.
    pub mode: PanelMode,
    /// The label of the factor being removed (escaped).
    pub removing: Option<String>,
    /// Characters in the new authenticator's code.
    pub new_code_len: usize,
    /// Characters in the proof code.
    pub proof_len: usize,
    /// The new key's label (escaped).
    pub label: String,
    /// The focused field.
    pub focus: FactorField,
    /// A typed code may prove the account here.
    pub proof_by_code: bool,
    /// A security key may prove the account here.
    pub proof_by_key: bool,
    /// "Add an authenticator app" is possible.
    pub can_add_totp: bool,
    /// "Add a security key" is possible.
    pub can_add_key: bool,
    /// Whether this build has a security-key backend here.
    pub key_available: bool,
    /// The seed is shown as text too.
    pub seed_text_shown: bool,
    /// Why the last step was refused.
    pub error: Option<PanelError>,
}

enum Mode {
    List,
    AddTotp {
        nonce: AddNonce,
        seed: ShownSeed,
    },
    AddKey {
        nonce: AddNonce,
        request: Box<CreationRequest>,
    },
    Remove {
        factor_id: String,
    },
}

static_assertions::assert_not_impl_any!(FactorsPanel: std::fmt::Debug, std::fmt::Display, Clone);

/// The panel's state.
pub struct FactorsPanel {
    factors: Vec<FactorRow>,
    loaded: bool,
    restricted: bool,
    methods: Methods,
    key_available: bool,
    mode: Mode,
    new_code: Secret,
    proof: Secret,
    label: String,
    focus: FactorField,
    error: Option<PanelError>,
}

impl FactorsPanel {
    /// An empty panel; `methods` are the proofs the session may use,
    /// `restricted` under the FIDO2 policy without a key.
    #[must_use]
    pub fn new(restricted: bool, methods: Methods, key_available: bool) -> Self {
        Self {
            factors: Vec::new(),
            loaded: false,
            restricted,
            methods,
            key_available,
            mode: Mode::List,
            new_code: Secret::new(),
            proof: Secret::new(),
            label: String::new(),
            focus: FactorField::Proof,
            error: None,
        }
    }

    /// Whether the session is restricted to registering a key.
    #[must_use]
    pub fn restricted(&self) -> bool {
        self.restricted
    }

    /// The proofs the session may use changed (after a list).
    pub fn set_methods(&mut self, methods: Methods) {
        self.methods = methods;
    }

    /// The server's list.
    pub fn loaded(&mut self, factors: Vec<FactorInfo>) {
        self.factors = factors
            .into_iter()
            .map(|f| FactorRow {
                factor_id: f.factor_id,
                method: f.method,
                label: display_safe(&f.label, MAX_LABEL),
                created_at: f.created_at,
                last_used_at: f.last_used_at,
            })
            .collect();
        self.loaded = true;
    }

    fn has(&self, method: FactorMethod) -> bool {
        self.factors.iter().any(|f| f.method == method)
    }

    fn proof_by_code(&self) -> bool {
        self.methods.totp
    }

    fn proof_by_key(&self) -> bool {
        self.methods.security_key && self.key_available
    }

    /// Whether `method` may be added now.
    #[must_use]
    pub fn can_add(&self, method: FactorMethod) -> bool {
        if !matches!(self.mode, Mode::List) {
            return false;
        }
        match method {
            FactorMethod::Totp => {
                !self.restricted
                    && self.loaded
                    && !self.has(FactorMethod::Totp)
                    && self.proof_by_key()
            }
            FactorMethod::SecurityKey => {
                self.key_available && (self.proof_by_code() || self.proof_by_key())
            }
        }
    }

    /// The fields of the form shown, in `Tab` order.
    #[must_use]
    pub fn fields(&self) -> Vec<FactorField> {
        let proof = self.proof_by_code().then_some(FactorField::Proof);
        match self.mode {
            Mode::List => Vec::new(),
            Mode::AddTotp { .. } => vec![FactorField::NewCode],
            Mode::AddKey { .. } => [Some(FactorField::Label), proof]
                .into_iter()
                .flatten()
                .collect(),
            Mode::Remove { .. } => proof.into_iter().collect(),
        }
    }

    /// Focus `field`, when shown.
    pub fn focus(&mut self, field: FactorField) {
        if self.fields().contains(&field) {
            self.focus = field;
        }
    }

    /// `Tab` / `Shift-Tab`.
    pub fn tab(&mut self, back: bool) {
        let fields = self.fields();
        if fields.is_empty() {
            return;
        }
        let at = fields.iter().position(|f| *f == self.focus).unwrap_or(0);
        let n = fields.len();
        let next = if back { (at + n - 1) % n } else { (at + 1) % n };
        self.focus = fields[next];
    }

    /// Whether a form takes typing now.
    #[must_use]
    pub fn editing(&self) -> bool {
        !matches!(self.mode, Mode::List)
    }

    /// Typed or pasted text, for the focused field.
    pub fn type_text(&mut self, text: &str) {
        if !self.fields().contains(&self.focus) {
            return;
        }
        self.error = None;
        match self.focus {
            FactorField::NewCode => self.new_code.push_str(text),
            FactorField::Proof => self.proof.push_str(text),
            FactorField::Label => {
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
            FactorField::NewCode => self.new_code.pop(),
            FactorField::Proof => self.proof.pop(),
            FactorField::Label => {
                self.label.pop();
            }
        }
    }

    fn reset_form(&mut self) {
        self.new_code.clear();
        self.proof.clear();
        self.label.clear();
        self.error = None;
    }

    /// The server's add offer: show its form.
    pub fn offered(&mut self, nonce: AddNonce, offer: AddOffer) {
        self.reset_form();
        match offer {
            AddOffer::Totp(seed) => {
                self.mode = Mode::AddTotp {
                    nonce,
                    seed: ShownSeed::new(seed),
                };
                self.focus = FactorField::NewCode;
            }
            AddOffer::SecurityKey(request) => {
                self.mode = Mode::AddKey { nonce, request };
                self.focus = FactorField::Label;
            }
        }
    }

    /// "Remove" on a row: confirm with a proof.
    ///
    /// # Errors
    /// [`PanelError::LastFactor`] for the only factor (the server refuses it
    /// too); nothing happens in a restricted session.
    pub fn start_remove(&mut self, factor_id: &str) -> Result<(), PanelError> {
        if self.restricted || !matches!(self.mode, Mode::List) {
            return Ok(());
        }
        if self.factors.len() <= 1 {
            self.error = Some(PanelError::LastFactor);
            return Err(PanelError::LastFactor);
        }
        if self.factors.iter().any(|f| f.factor_id == factor_id) {
            self.reset_form();
            self.mode = Mode::Remove {
                factor_id: factor_id.to_string(),
            };
            self.focus = FactorField::Proof;
        }
        Ok(())
    }

    /// "Cancel" or `Esc`: back to the list, the form wiped (an offered seed
    /// with it: the next "Add" asks the server for a fresh one).
    pub fn cancel(&mut self) {
        self.reset_form();
        self.mode = Mode::List;
    }

    fn proof(&mut self, how: Submission) -> Result<FactorChoice, PanelError> {
        match how {
            Submission::Code if !self.proof_by_code() => Err(PanelError::NotOffered),
            Submission::Code if !self.proof.is_totp_code() => Err(PanelError::BadCode),
            Submission::Code => Ok(FactorChoice::Code(self.proof.take())),
            Submission::SecurityKey if !self.methods.security_key => Err(PanelError::NotOffered),
            Submission::SecurityKey if !self.key_available => Err(PanelError::KeyUnavailable),
            Submission::SecurityKey => {
                self.proof.clear();
                Ok(FactorChoice::SecurityKey)
            }
        }
    }

    /// Submit the form shown, proving the account with `how`. The form goes
    /// back to the list (the nonce is single use either way).
    ///
    /// # Errors
    /// [`PanelError`]; nothing is wiped or sent then.
    pub fn submit(&mut self, how: Submission) -> Result<Cmd, PanelError> {
        let checked = match &self.mode {
            Mode::List => return Err(PanelError::NotOffered),
            Mode::AddTotp { .. } if !self.new_code.is_totp_code() => Err(PanelError::BadCode),
            Mode::AddKey { .. } if !self.key_available => Err(PanelError::KeyUnavailable),
            _ => Ok(()),
        };
        let proof = checked.and_then(|()| self.proof(how));
        let proof = match proof {
            Ok(p) => p,
            Err(e) => {
                self.error = Some(e);
                return Err(e);
            }
        };
        let mode = std::mem::replace(&mut self.mode, Mode::List);
        let cmd = match mode {
            Mode::AddTotp { nonce, seed } => {
                drop(seed);
                Cmd::CompleteAddTotp {
                    nonce,
                    code: self.new_code.take(),
                    proof,
                }
            }
            Mode::AddKey { nonce, request } => Cmd::CompleteAddKey {
                nonce,
                request,
                label: clean_label(&self.label),
                proof,
            },
            Mode::Remove { factor_id } => Cmd::RemoveFactor { factor_id, proof },
            Mode::List => return Err(PanelError::NotOffered),
        };
        self.reset_form();
        Ok(cmd)
    }

    /// The default proof for `Enter`: a code when one may be typed (and
    /// the form has a proof field), else a key.
    #[must_use]
    pub fn default_submission(&self) -> Submission {
        if self.fields().contains(&FactorField::Proof) {
            Submission::Code
        } else {
            Submission::SecurityKey
        }
    }

    /// Show or hide the seed as text.
    pub fn toggle_seed_text(&mut self) {
        if let Mode::AddTotp { seed, .. } = &mut self.mode {
            seed.toggle_text();
        }
    }

    /// The seed to paint, while an authenticator app is being added.
    #[must_use]
    pub fn seed_display(&self) -> Option<SeedDisplay<'_>> {
        match &self.mode {
            Mode::AddTotp { seed, .. } => Some(seed.display()),
            _ => None,
        }
    }

    /// What the window draws.
    #[must_use]
    pub fn view(&self) -> FactorsView {
        let mode = match self.mode {
            Mode::List => PanelMode::List,
            Mode::AddTotp { .. } => PanelMode::AddTotp,
            Mode::AddKey { .. } => PanelMode::AddKey,
            Mode::Remove { .. } => PanelMode::Remove,
        };
        let removing = match &self.mode {
            Mode::Remove { factor_id } => self
                .factors
                .iter()
                .find(|f| &f.factor_id == factor_id)
                .map(|f| f.label.clone()),
            _ => None,
        };
        let seed_text_shown = matches!(&self.mode, Mode::AddTotp { seed, .. } if seed.text_shown());
        FactorsView {
            rows: self.factors.clone(),
            loaded: self.loaded,
            restricted: self.restricted,
            mode,
            removing,
            new_code_len: self.new_code.char_count(),
            proof_len: self.proof.char_count(),
            label: display_safe(&self.label, MAX_LABEL),
            focus: self.focus,
            proof_by_code: self.proof_by_code(),
            proof_by_key: self.proof_by_key(),
            can_add_totp: self.can_add(FactorMethod::Totp),
            can_add_key: self.can_add(FactorMethod::SecurityKey),
            key_available: self.key_available,
            seed_text_shown,
            error: self.error,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admin::seed::tests::seed;
    use ferrogate_admin_client::webauthn::{creation_request, CreationOptions};

    const BOTH: Methods = Methods {
        totp: true,
        security_key: true,
    };
    const KEY_ONLY: Methods = Methods {
        totp: false,
        security_key: true,
    };

    fn row(id: &str, method: FactorMethod, label: &str) -> FactorInfo {
        FactorInfo {
            factor_id: id.into(),
            method,
            label: label.into(),
            created_at: 1_790_000_000,
            last_used_at: 0,
        }
    }

    fn request() -> Box<CreationRequest> {
        Box::new(
            creation_request(&CreationOptions {
                challenge: vec![3; 32],
                rp_id: "ferrogate-admin.ferrogate.test".into(),
                rp_name: "FerroGate".into(),
                user_id: vec![4; 32],
                user_name: "alice".into(),
                display_name: "Alice".into(),
                pub_key_cred_params: vec![-7],
                exclude_credential_ids: Vec::new(),
                user_verification: 1,
                attestation: 1,
            })
            .unwrap(),
        )
    }

    fn nonce() -> AddNonce {
        AddNonce::from_bytes(vec![7; 32])
    }

    #[test]
    fn rows_are_escaped_and_the_last_factor_is_never_offered_for_removal() {
        let mut p = FactorsPanel::new(false, BOTH, true);
        p.loaded(vec![row("totp", FactorMethod::Totp, "TOTP\u{1b}[2J")]);
        let v = p.view();
        assert!(v.loaded && !v.rows[0].label.contains('\u{1b}'));
        assert_eq!(p.start_remove("totp"), Err(PanelError::LastFactor));
        assert_eq!(p.view().mode, PanelMode::List);
        assert!(!v.can_add_totp, "a TOTP factor exists");
        assert!(v.can_add_key);
    }

    #[test]
    fn adding_a_key_takes_a_label_and_a_code_proof() {
        let mut p = FactorsPanel::new(false, BOTH, true);
        p.loaded(vec![row("totp", FactorMethod::Totp, "TOTP")]);
        p.offered(nonce(), AddOffer::SecurityKey(request()));
        assert_eq!(p.fields(), vec![FactorField::Label, FactorField::Proof]);
        p.type_text("Desk key");
        p.tab(false);
        p.type_text("12345");
        assert_eq!(p.submit(Submission::Code).err(), Some(PanelError::BadCode));
        p.type_text("6");
        let Ok(Cmd::CompleteAddKey {
            label,
            proof: FactorChoice::Code(code),
            ..
        }) = p.submit(Submission::Code)
        else {
            panic!("a key add with a code proof");
        };
        assert_eq!((label.as_str(), code.expose()), ("Desk key", "123456"));
        let v = p.view();
        assert_eq!(
            (v.mode, v.proof_len, v.label.as_str()),
            (PanelMode::List, 0, "")
        );
    }

    #[test]
    fn adding_totp_shows_the_seed_and_proves_with_a_key() {
        let mut without = FactorsPanel::new(false, KEY_ONLY, false);
        without.loaded(vec![row("wa_1", FactorMethod::SecurityKey, "Key")]);
        assert!(!without.view().can_add_totp, "no key to prove with");

        let mut p = FactorsPanel::new(false, KEY_ONLY, true);
        p.loaded(vec![row("wa_1", FactorMethod::SecurityKey, "Key")]);
        assert!(p.view().can_add_totp);
        p.offered(nonce(), AddOffer::Totp(seed()));
        assert_eq!(p.view().mode, PanelMode::AddTotp);
        assert!(p.seed_display().unwrap().qr.is_some());
        p.toggle_seed_text();
        assert!(p.view().seed_text_shown);
        p.type_text("654321");
        assert_eq!(
            p.submit(Submission::Code).err(),
            Some(PanelError::NotOffered),
            "the account holds no code to prove with"
        );
        assert_eq!(p.default_submission(), Submission::SecurityKey);
        let Ok(Cmd::CompleteAddTotp {
            code,
            proof: FactorChoice::SecurityKey,
            ..
        }) = p.submit(Submission::SecurityKey)
        else {
            panic!("a TOTP add proven by a key");
        };
        assert_eq!(code.expose(), "654321");
        assert!(p.seed_display().is_none(), "the seed is gone once used");
    }

    #[test]
    fn removing_confirms_with_a_proof_and_cancel_wipes() {
        let mut p = FactorsPanel::new(false, BOTH, false);
        p.loaded(vec![
            row("totp", FactorMethod::Totp, "TOTP"),
            row("wa_1", FactorMethod::SecurityKey, "Desk"),
        ]);
        p.start_remove("wa_1").unwrap();
        let v = p.view();
        assert_eq!(
            (v.mode, v.removing.as_deref()),
            (PanelMode::Remove, Some("Desk"))
        );
        p.type_text("123456");
        assert_eq!(
            p.submit(Submission::SecurityKey).err(),
            Some(PanelError::KeyUnavailable)
        );
        p.cancel();
        assert_eq!((p.view().mode, p.view().proof_len), (PanelMode::List, 0));
        p.start_remove("wa_1").unwrap();
        p.type_text("123456");
        let Ok(Cmd::RemoveFactor { factor_id, .. }) = p.submit(Submission::Code) else {
            panic!("a removal");
        };
        assert_eq!(factor_id, "wa_1");
    }

    #[test]
    fn a_restricted_panel_only_registers_a_key() {
        let methods = Methods {
            totp: true,
            security_key: false,
        };
        let mut p = FactorsPanel::new(true, methods, true);
        p.loaded(vec![
            row("totp", FactorMethod::Totp, "TOTP"),
            row("x", FactorMethod::Totp, ""),
        ]);
        let v = p.view();
        assert!(v.restricted && v.can_add_key && !v.can_add_totp);
        assert!(p.start_remove("totp").is_ok());
        assert_eq!(p.view().mode, PanelMode::List, "no removal here");
    }
}
