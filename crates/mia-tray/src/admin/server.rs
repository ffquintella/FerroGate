//! The "admin server" screen (F22 §2): the CMIS admin endpoint and its SPKI
//! pin, typed or pasted into the window and saved to the per-user
//! `admin.toml`, so a first run needs no hand-edited file.

//! Never trust on first use: the pin is only ever what the administrator
//! pasted (from operations, over a trusted channel), never fetched from the
//! server, and a "change server" starts with an empty pin. Both fields are
//! checked by the shared parser ([`ServerChoice::check`]); replacing or
//! shadowing a file in effect asks to confirm the old and the new values.
//! Nothing here is secret: the window draws the fields as typed (inert).

use std::path::PathBuf;

use ferrogate_admin_client::config::{FileValues, PinProblem, ServerChoice, PIN_HEX_LEN};
use ferrogate_admin_client::endpoint::{EndpointProblem, MAX_ENDPOINT_LEN};

use super::config::SaveTarget;

/// Longest pin text kept (longer pastes are cut and then refused by length,
/// never shortened into a pin).
pub const MAX_PIN_INPUT: usize = 2 * PIN_HEX_LEN;

/// A field of the screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerField {
    /// The admin endpoint.
    Endpoint,
    /// The SPKI pin.
    Pin,
}

/// Where the screen is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerStage {
    /// Typing.
    Edit,
    /// Asking to confirm a replacement.
    Confirm,
}

/// Why nothing was saved, or why the saved server is not in use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SaveProblem {
    /// No per-user configuration directory (no `HOME` / `APPDATA`).
    NoUserDir,
    /// The per-user file or a directory fails the trust checks.
    Untrusted,
    /// The file system refused; nothing changed.
    WriteFailed,
    /// Saved, but the configuration read back still cannot be used.
    StillUnusable,
}

/// The confirmation of a replacement: what is in effect and what replaces it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfirmView {
    /// The file in effect now.
    pub path: PathBuf,
    /// Whether that file is replaced (the per-user one) or only shadowed by
    /// a new per-user file (a system one).
    pub replaces: bool,
    /// Its endpoint and pins as written (`None`: it could not be read).
    pub old: Option<(Option<String>, Vec<String>)>,
    /// Whether its `device_token_path` or `refresh_secs` are kept.
    pub keeps_other_keys: bool,
    /// The new endpoint.
    pub endpoint: String,
    /// The new pin, lowercase hex.
    pub pin: String,
}

/// What the window draws (nothing secret).
#[allow(clippy::struct_excessive_bools)] // A flat view model: one flag per control.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerView {
    /// The endpoint as typed.
    pub endpoint: String,
    /// The pin as typed.
    pub pin: String,
    /// The focused field.
    pub focus: ServerField,
    /// The stage.
    pub stage: ServerStage,
    /// The endpoint's problem at the last save.
    pub endpoint_problem: Option<EndpointProblem>,
    /// The pin's problem at the last save.
    pub pin_problem: Option<PinProblem>,
    /// Why the last save did not land.
    pub save_problem: Option<SaveProblem>,
    /// Whether "Save" can be pressed.
    pub can_save: bool,
    /// Whether the screen can be left without saving (a usable server).
    pub can_cancel: bool,
    /// The per-user file a save writes.
    pub target: Option<PathBuf>,
    /// The endpoint environment variable wins over the file.
    pub env_endpoint: bool,
    /// The pin environment variable wins over the file.
    pub env_pin: bool,
    /// The confirmation, at [`ServerStage::Confirm`].
    pub confirm: Option<ConfirmView>,
}

/// A checked save for [`super::config::save`].
#[derive(Debug, Clone)]
pub struct SavePlan {
    /// The per-user file.
    pub path: PathBuf,
    /// The endpoint and pin.
    pub choice: ServerChoice,
    /// The keys kept from the file in effect.
    pub keep: Option<FileValues>,
    /// Whether a file in effect is replaced or shadowed.
    pub replaces: bool,
}

/// The screen's state.
#[derive(Debug)]
pub struct ServerForm {
    endpoint: String,
    pin: String,
    focus: ServerField,
    stage: ServerStage,
    endpoint_problem: Option<EndpointProblem>,
    pin_problem: Option<PinProblem>,
    save_problem: Option<SaveProblem>,
    cancellable: bool,
    target: SaveTarget,
    checked: Option<ServerChoice>,
}

/// Append `text` to `field` without blanks or controls, at most `max` bytes.
fn push_bounded(field: &mut String, text: &str, max: usize) {
    for c in text.chars() {
        if c.is_whitespace() || c.is_control() {
            continue;
        }
        if field.len() + c.len_utf8() > max {
            break;
        }
        field.push(c);
    }
}

impl ServerForm {
    /// The screen over `target`: the endpoint pre-filled from the file in
    /// effect (the pin never is), `cancellable` when a usable server exists.
    #[must_use]
    pub fn new(target: SaveTarget, cancellable: bool) -> Self {
        let mut endpoint = String::new();
        let old = target.current.as_ref().and_then(|c| c.values.as_ref());
        if let Some(e) = old.and_then(|v| v.endpoint.as_deref()) {
            push_bounded(&mut endpoint, e, MAX_ENDPOINT_LEN);
        }
        let focus = if endpoint.is_empty() {
            ServerField::Endpoint
        } else {
            ServerField::Pin
        };
        Self {
            endpoint,
            pin: String::new(),
            focus,
            stage: ServerStage::Edit,
            endpoint_problem: None,
            pin_problem: None,
            save_problem: None,
            cancellable,
            target,
            checked: None,
        }
    }

    fn edited(&mut self) {
        self.endpoint_problem = None;
        self.pin_problem = None;
        self.save_problem = None;
    }

    /// Focus `field` (typing only).
    pub fn focus(&mut self, field: ServerField) {
        if self.stage == ServerStage::Edit {
            self.focus = field;
        }
    }

    /// `Tab` / `Shift-Tab`: the other field.
    pub fn tab(&mut self) {
        self.focus(match self.focus {
            ServerField::Endpoint => ServerField::Pin,
            ServerField::Pin => ServerField::Endpoint,
        });
    }

    /// Typed or pasted text, for the focused field (blanks and controls
    /// dropped, bounded).
    pub fn type_text(&mut self, text: &str) {
        if self.stage != ServerStage::Edit {
            return;
        }
        self.edited();
        match self.focus {
            ServerField::Endpoint => push_bounded(&mut self.endpoint, text, MAX_ENDPOINT_LEN),
            ServerField::Pin => push_bounded(&mut self.pin, text, MAX_PIN_INPUT),
        }
    }

    /// `Backspace`.
    pub fn backspace(&mut self) {
        if self.stage != ServerStage::Edit {
            return;
        }
        self.edited();
        match self.focus {
            ServerField::Endpoint => self.endpoint.pop(),
            ServerField::Pin => self.pin.pop(),
        };
    }

    /// `Esc`: back from the confirmation; on the form, whether the screen
    /// may close.
    pub fn escape(&mut self) -> bool {
        if self.stage == ServerStage::Confirm {
            self.back();
            return false;
        }
        self.cancellable
    }

    /// "Back" from the confirmation.
    pub fn back(&mut self) {
        self.stage = ServerStage::Edit;
        self.checked = None;
    }

    /// `Enter`: "Save" on the form, "Replace" on the confirmation.
    pub fn enter(&mut self) -> Option<SavePlan> {
        match self.stage {
            ServerStage::Edit => self.save(),
            ServerStage::Confirm => self.confirm(),
        }
    }

    /// "Save": check both fields; a file in effect is confirmed first.
    pub fn save(&mut self) -> Option<SavePlan> {
        if self.stage != ServerStage::Edit {
            return None;
        }
        self.edited();
        let choice = match ServerChoice::check(&self.endpoint, &self.pin) {
            Ok(c) => c,
            Err(p) => {
                self.endpoint_problem = p.endpoint;
                self.pin_problem = p.pin;
                self.focus = if p.endpoint.is_some() {
                    ServerField::Endpoint
                } else {
                    ServerField::Pin
                };
                return None;
            }
        };
        if self.target.path.is_none() {
            self.save_problem = Some(SaveProblem::NoUserDir);
            return None;
        }
        if self.target.refused {
            self.save_problem = Some(SaveProblem::Untrusted);
            return None;
        }
        if self.target.current.is_some() {
            self.checked = Some(choice);
            self.stage = ServerStage::Confirm;
            return None;
        }
        self.plan(choice)
    }

    /// "Replace" on the confirmation.
    pub fn confirm(&mut self) -> Option<SavePlan> {
        if self.stage != ServerStage::Confirm {
            return None;
        }
        let choice = self.checked.take()?;
        self.stage = ServerStage::Edit;
        self.plan(choice)
    }

    fn plan(&self, choice: ServerChoice) -> Option<SavePlan> {
        let current = self.target.current.as_ref();
        Some(SavePlan {
            path: self.target.path.clone()?,
            choice,
            keep: current.and_then(|c| c.values.clone()),
            replaces: current.is_some(),
        })
    }

    /// The save did not land, or its server is still not usable (then no
    /// usable server is left to go back to).
    pub fn failed(&mut self, problem: SaveProblem) {
        self.stage = ServerStage::Edit;
        self.checked = None;
        self.save_problem = Some(problem);
        if problem == SaveProblem::StillUnusable {
            self.cancellable = false;
        }
    }

    /// Whether the screen can be left without saving.
    #[must_use]
    pub fn cancellable(&self) -> bool {
        self.cancellable
    }

    /// What to draw.
    #[must_use]
    pub fn view(&self) -> ServerView {
        let confirm = match (&self.checked, &self.target.current) {
            (Some(choice), Some(current)) if self.stage == ServerStage::Confirm => {
                let values = current.values.as_ref();
                Some(ConfirmView {
                    path: current.path.clone(),
                    replaces: current.is_user_file,
                    old: values.map(|v| (v.endpoint.clone(), v.spki_pins.clone())),
                    keeps_other_keys: values
                        .is_some_and(|v| v.device_token_path.is_some() || v.refresh_secs.is_some()),
                    endpoint: choice.endpoint().to_string(),
                    pin: choice.pin_hex(),
                })
            }
            _ => None,
        };
        ServerView {
            endpoint: self.endpoint.clone(),
            pin: self.pin.clone(),
            focus: self.focus,
            stage: self.stage,
            endpoint_problem: self.endpoint_problem,
            pin_problem: self.pin_problem,
            save_problem: self.save_problem,
            can_save: !self.endpoint.is_empty() && !self.pin.is_empty(),
            can_cancel: self.cancellable,
            target: self.target.path.clone(),
            env_endpoint: self.target.env_endpoint,
            env_pin: self.target.env_pin,
            confirm,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admin::config::Current;

    const PIN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn target(current: Option<Current>) -> SaveTarget {
        SaveTarget {
            path: Some(PathBuf::from("/home/a/.config/ferrogate/admin.toml")),
            current,
            refused: false,
            env_endpoint: false,
            env_pin: false,
        }
    }

    fn typed(form: &mut ServerForm, endpoint: &str, pin: &str) {
        form.focus(ServerField::Endpoint);
        form.type_text(endpoint);
        form.focus(ServerField::Pin);
        form.type_text(pin);
    }

    #[test]
    fn a_first_save_writes_straight_away() {
        let mut form = ServerForm::new(target(None), false);
        let v = form.view();
        assert_eq!(
            (v.focus, v.can_save, v.can_cancel),
            (ServerField::Endpoint, false, false)
        );
        assert!(!form.escape(), "no usable server: the screen stays");
        // A pasted pin keeps no line break or blank.
        typed(
            &mut form,
            "https://cmis-admin.test:8444\n",
            &format!(" {PIN}\n"),
        );
        assert!(form.view().can_save);
        let plan = form.enter().expect("no file in effect: no confirmation");
        assert_eq!(plan.choice.endpoint(), "https://cmis-admin.test:8444");
        assert_eq!(plan.choice.pin_hex(), PIN);
        assert!(plan.keep.is_none() && !plan.replaces);
    }

    #[test]
    fn bad_fields_are_marked_and_nothing_is_planned() {
        let cases = [
            (
                "http://cmis:8444",
                PIN.to_string(),
                Some(EndpointProblem::NotHttps),
                None,
            ),
            (
                "https://cmis",
                PIN.to_string(),
                Some(EndpointProblem::NoPort),
                None,
            ),
            (
                "https://u@cmis:1",
                PIN.to_string(),
                Some(EndpointProblem::NoHost),
                None,
            ),
            (
                "https://cmis:1/x",
                PIN.to_string(),
                Some(EndpointProblem::PathOrQuery),
                None,
            ),
            (
                "https://cmis:1",
                PIN[..64].to_string(),
                None,
                Some(PinProblem::Length(64)),
            ),
            (
                "https://cmis:1",
                format!("sha384:{PIN}"),
                None,
                Some(PinProblem::NotHex),
            ),
            (
                "cmis",
                "zz".into(),
                Some(EndpointProblem::NotHttps),
                Some(PinProblem::NotHex),
            ),
        ];
        for (endpoint, pin, want_e, want_p) in cases {
            let mut form = ServerForm::new(target(None), true);
            typed(&mut form, endpoint, &pin);
            assert!(form.save().is_none(), "{endpoint} {pin}");
            let v = form.view();
            assert_eq!(
                (v.endpoint_problem, v.pin_problem),
                (want_e, want_p),
                "{endpoint}"
            );
            assert_eq!(v.stage, ServerStage::Edit);
            form.type_text("x");
            assert_eq!(
                form.view().endpoint_problem,
                None,
                "typing clears the marks"
            );
        }
    }

    #[test]
    fn input_is_bounded_and_an_overlong_pin_is_refused_not_shortened() {
        let mut form = ServerForm::new(target(None), true);
        form.type_text(&format!("https://{}", "a".repeat(2 * MAX_ENDPOINT_LEN)));
        assert_eq!(form.view().endpoint.len(), MAX_ENDPOINT_LEN);
        form.focus(ServerField::Pin);
        form.type_text(&format!("{PIN}{PIN}{PIN}"));
        assert_eq!(form.view().pin.len(), MAX_PIN_INPUT);
        form.save();
        assert_eq!(
            form.view().pin_problem,
            Some(PinProblem::Length(MAX_PIN_INPUT))
        );
        let mut form = ServerForm::new(target(None), true);
        form.type_text("https://\u{1b}[2Jcmis:8444\u{7}\u{202e}");
        assert_eq!(form.view().endpoint, "https://[2Jcmis:8444\u{202e}");
        assert_eq!(
            form.save().map(|_| ()),
            None,
            "a hidden character is refused by the URL parser"
        );
        assert_eq!(form.view().endpoint_problem, Some(EndpointProblem::NotUrl));
    }

    #[test]
    fn replacing_a_file_in_effect_is_confirmed_with_old_and_new_values() {
        let old = FileValues {
            endpoint: Some("https://old:8444".into()),
            spki_pins: vec!["b".repeat(96), "c".repeat(96)],
            device_token_path: Some("/var/dt".into()),
            refresh_secs: None,
        };
        let current = Current {
            path: PathBuf::from("/home/a/.config/ferrogate/admin.toml"),
            is_user_file: true,
            values: Some(old.clone()),
        };
        let mut form = ServerForm::new(target(Some(current)), true);
        let v = form.view();
        assert_eq!(v.endpoint, "https://old:8444", "the endpoint is pre-filled");
        assert_eq!(
            (v.pin.as_str(), v.focus),
            ("", ServerField::Pin),
            "the pin never is"
        );
        form.type_text(&PIN.to_uppercase());
        assert!(form.enter().is_none(), "asks first");
        let v = form.view();
        assert_eq!(v.stage, ServerStage::Confirm);
        let c = v.confirm.unwrap();
        assert!(c.replaces && c.keeps_other_keys);
        assert_eq!(c.old, Some((old.endpoint.clone(), old.spki_pins.clone())));
        assert_eq!(
            (c.endpoint.as_str(), c.pin.as_str()),
            ("https://old:8444", PIN)
        );
        form.type_text("x");
        assert_eq!(
            form.view().pin.len(),
            96,
            "the confirmation takes no typing"
        );
        // Esc goes back to the form; saving again asks again.
        assert!(!form.escape());
        assert_eq!(form.view().stage, ServerStage::Edit);
        assert!(form.save().is_none());
        let plan = form.enter().expect("confirmed");
        assert!(plan.replaces);
        assert_eq!(plan.keep, Some(old));
        assert!(form.confirm().is_none(), "confirmed once");
    }

    #[test]
    fn a_refused_file_or_no_home_saves_nothing_and_says_why() {
        let mut t = target(None);
        t.refused = true;
        let mut form = ServerForm::new(t, true);
        typed(&mut form, "https://cmis:8444", PIN);
        assert!(form.save().is_none());
        assert_eq!(form.view().save_problem, Some(SaveProblem::Untrusted));
        let mut t = target(None);
        t.path = None;
        let mut form = ServerForm::new(t, true);
        typed(&mut form, "https://cmis:8444", PIN);
        assert!(form.save().is_none());
        assert_eq!(form.view().save_problem, Some(SaveProblem::NoUserDir));
        assert!(form.cancellable());
        form.failed(SaveProblem::StillUnusable);
        assert_eq!(form.view().save_problem, Some(SaveProblem::StillUnusable));
        assert!(
            !form.cancellable() && !form.escape(),
            "nothing usable to go back to"
        );
    }

    #[test]
    fn the_environment_overrides_are_shown() {
        let mut t = target(None);
        t.env_pin = true;
        let v = ServerForm::new(t, true).view();
        assert!(v.env_pin && !v.env_endpoint);
    }
}
