//! A small keyboard form engine shared by the login screen, the filter panel
//! and every dialog: text and masked fields, radio choices, multi-selects and
//! toggles, with an inline error per field.
//!
//! Keys: `Tab`/`↓` next field, `Shift-Tab`/`↑` previous, `Space` or `←`/`→`
//! change a choice, `Space` toggles (in a multi-select `←`/`→` move between
//! options), `Enter` submits, `Esc` cancels. Text fields take printable
//! characters only, up to their limit, so a control character can never be
//! typed or pasted into a value that is sent to the server.

use crate::input::Key;
use crate::secret::Secret;

/// What a field holds.
pub enum FieldKind {
    /// Free text, at most `max` characters.
    Text {
        /// The value.
        value: String,
        /// Character limit.
        max: usize,
    },
    /// A masked secret (password or TOTP code).
    Secret {
        /// The value (never displayed).
        value: Secret,
        /// Only ASCII digits (TOTP).
        digits_only: bool,
        /// Character limit.
        max: usize,
    },
    /// One of several options.
    Choice {
        /// Option labels.
        options: Vec<String>,
        /// Selected index.
        selected: usize,
    },
    /// Any subset of several options.
    Multi {
        /// Option labels.
        options: Vec<String>,
        /// Which are checked.
        checked: Vec<bool>,
        /// Option under the cursor.
        cursor: usize,
    },
    /// On or off.
    Toggle {
        /// The state.
        on: bool,
    },
}

/// One field of a form.
pub struct Field {
    /// Stable identifier used by the code.
    pub key: &'static str,
    /// Label shown to the administrator.
    pub label: String,
    /// The value.
    pub kind: FieldKind,
    /// Optional hint shown next to the field.
    pub hint: Option<String>,
    /// Inline validation error (the form is not submitted while one is set).
    pub error: Option<String>,
}

impl Field {
    /// A text field.
    #[must_use]
    pub fn text(key: &'static str, label: &str, value: &str, max: usize) -> Self {
        Self::new(
            key,
            label,
            FieldKind::Text {
                // Pre-filled values may come from the server: drop control
                // characters exactly as typing would.
                value: value
                    .chars()
                    .filter(|c| !c.is_control())
                    .take(max)
                    .collect(),
                max,
            },
        )
    }

    /// A masked field.
    #[must_use]
    pub fn secret(key: &'static str, label: &str, digits_only: bool, max: usize) -> Self {
        Self::new(
            key,
            label,
            FieldKind::Secret {
                value: Secret::new(),
                digits_only,
                max,
            },
        )
    }

    /// A choice field.
    #[must_use]
    pub fn choice(key: &'static str, label: &str, options: &[&str], selected: usize) -> Self {
        Self::new(
            key,
            label,
            FieldKind::Choice {
                options: options.iter().map(|o| (*o).to_string()).collect(),
                selected: selected.min(options.len().saturating_sub(1)),
            },
        )
    }

    /// A multi-select field.
    #[must_use]
    pub fn multi(key: &'static str, label: &str, options: &[&str], checked: &[bool]) -> Self {
        let mut c = vec![false; options.len()];
        for (slot, v) in c.iter_mut().zip(checked) {
            *slot = *v;
        }
        Self::new(
            key,
            label,
            FieldKind::Multi {
                options: options.iter().map(|o| (*o).to_string()).collect(),
                checked: c,
                cursor: 0,
            },
        )
    }

    /// A multi-select field with owned labels.
    #[must_use]
    pub fn multi_owned(key: &'static str, label: &str, options: Vec<String>) -> Self {
        let n = options.len();
        Self::new(
            key,
            label,
            FieldKind::Multi {
                options,
                checked: vec![false; n],
                cursor: 0,
            },
        )
    }

    /// A toggle field.
    #[must_use]
    pub fn toggle(key: &'static str, label: &str, on: bool) -> Self {
        Self::new(key, label, FieldKind::Toggle { on })
    }

    fn new(key: &'static str, label: &str, kind: FieldKind) -> Self {
        Self {
            key,
            label: label.to_string(),
            kind,
            hint: None,
            error: None,
        }
    }

    /// Attach a hint.
    #[must_use]
    pub fn with_hint(mut self, hint: &str) -> Self {
        self.hint = Some(hint.to_string());
        self
    }
}

/// What a key did to the form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormEvent {
    /// Nothing visible beyond a value or focus change.
    Edited,
    /// `Enter`.
    Submit,
    /// `Esc`.
    Cancel,
    /// The key does not apply to the form.
    Ignored,
}

/// An ordered set of fields with one focused.
#[derive(Default)]
pub struct Form {
    /// The fields, in display order.
    pub fields: Vec<Field>,
    /// Index of the focused field.
    pub focus: usize,
}

impl Form {
    /// A form over `fields`, focus on the first.
    #[must_use]
    pub fn new(fields: Vec<Field>) -> Self {
        Self { fields, focus: 0 }
    }

    fn index(&self, key: &str) -> Option<usize> {
        self.fields.iter().position(|f| f.key == key)
    }

    /// The field named `key`.
    #[must_use]
    pub fn field(&self, key: &str) -> Option<&Field> {
        self.index(key).map(|i| &self.fields[i])
    }

    /// The field named `key`, mutably.
    pub fn field_mut(&mut self, key: &str) -> Option<&mut Field> {
        self.index(key).map(|i| &mut self.fields[i])
    }

    /// Focus the field named `key`.
    pub fn focus_on(&mut self, key: &str) {
        if let Some(i) = self.index(key) {
            self.focus = i;
        }
    }

    /// The text of a text field (empty for other kinds or unknown keys).
    #[must_use]
    pub fn text(&self, key: &str) -> &str {
        match self.field(key).map(|f| &f.kind) {
            Some(FieldKind::Text { value, .. }) => value,
            _ => "",
        }
    }

    /// The selected index of a choice field (0 when absent).
    #[must_use]
    pub fn choice(&self, key: &str) -> usize {
        match self.field(key).map(|f| &f.kind) {
            Some(FieldKind::Choice { selected, .. }) => *selected,
            _ => 0,
        }
    }

    /// Select option `i` of a choice field.
    pub fn set_choice(&mut self, key: &str, i: usize) {
        if let Some(FieldKind::Choice { options, selected }) =
            self.field_mut(key).map(|f| &mut f.kind)
        {
            if i < options.len() {
                *selected = i;
            }
        }
    }

    /// The checked flags of a multi-select (empty when absent).
    #[must_use]
    pub fn checked(&self, key: &str) -> Vec<bool> {
        match self.field(key).map(|f| &f.kind) {
            Some(FieldKind::Multi { checked, .. }) => checked.clone(),
            _ => Vec::new(),
        }
    }

    /// The state of a toggle (false when absent).
    #[must_use]
    pub fn toggled(&self, key: &str) -> bool {
        matches!(
            self.field(key).map(|f| &f.kind),
            Some(FieldKind::Toggle { on: true })
        )
    }

    /// Take a secret out of the form, leaving the field empty.
    pub fn take_secret(&mut self, key: &str) -> Secret {
        match self.field_mut(key).map(|f| &mut f.kind) {
            Some(FieldKind::Secret { value, .. }) => value.take(),
            _ => Secret::new(),
        }
    }

    /// The secret in a field, for validation only.
    #[must_use]
    pub fn secret(&self, key: &str) -> Option<&Secret> {
        match self.field(key).map(|f| &f.kind) {
            Some(FieldKind::Secret { value, .. }) => Some(value),
            _ => None,
        }
    }

    /// Wipe every secret field.
    pub fn clear_secrets(&mut self) {
        for f in &mut self.fields {
            if let FieldKind::Secret { value, .. } = &mut f.kind {
                value.clear();
            }
        }
    }

    /// Set the inline error of `key`.
    pub fn set_error(&mut self, key: &str, message: &str) {
        if let Some(f) = self.field_mut(key) {
            f.error = Some(message.to_string());
        }
    }

    /// Remove every inline error.
    pub fn clear_errors(&mut self) {
        for f in &mut self.fields {
            f.error = None;
        }
    }

    /// Whether any field carries an error.
    #[must_use]
    pub fn has_errors(&self) -> bool {
        self.fields.iter().any(|f| f.error.is_some())
    }

    /// Focus the first field with an error.
    pub fn focus_first_error(&mut self) {
        if let Some(i) = self.fields.iter().position(|f| f.error.is_some()) {
            self.focus = i;
        }
    }

    /// Type `text` into the focused field (paste), dropping what the field
    /// does not accept.
    pub fn paste(&mut self, text: &str) {
        for c in text.chars() {
            self.type_char(c);
        }
    }

    fn type_char(&mut self, c: char) {
        let Some(f) = self.fields.get_mut(self.focus) else {
            return;
        };
        match &mut f.kind {
            FieldKind::Text { value, max } if !c.is_control() && value.chars().count() < *max => {
                value.push(c);
                f.error = None;
            }
            FieldKind::Secret {
                value,
                digits_only,
                max,
            } if (!*digits_only || c.is_ascii_digit()) && value.char_count() < *max => {
                value.push(c);
                f.error = None;
            }
            _ => {}
        }
    }

    /// Apply a key.
    pub fn handle(&mut self, key: Key) -> FormEvent {
        let n = self.fields.len();
        match key {
            Key::Enter => return FormEvent::Submit,
            Key::Esc => return FormEvent::Cancel,
            Key::Tab | Key::Down if n > 0 => {
                self.focus = (self.focus + 1) % n;
                return FormEvent::Edited;
            }
            Key::BackTab | Key::Up if n > 0 => {
                self.focus = (self.focus + n - 1) % n;
                return FormEvent::Edited;
            }
            _ => {}
        }
        if let Key::Char(c) = key {
            if matches!(
                self.fields.get(self.focus).map(|f| &f.kind),
                Some(FieldKind::Text { .. } | FieldKind::Secret { .. })
            ) {
                self.type_char(c);
                return FormEvent::Edited;
            }
        }
        let Some(f) = self.fields.get_mut(self.focus) else {
            return FormEvent::Ignored;
        };
        let handled = match (&mut f.kind, key) {
            (FieldKind::Text { value, .. }, Key::Backspace) => {
                value.pop();
                true
            }
            (FieldKind::Secret { value, .. }, Key::Backspace) => {
                value.pop();
                true
            }
            (FieldKind::Choice { options, selected }, Key::Char(' ') | Key::Right) => {
                *selected = (*selected + 1) % options.len().max(1);
                true
            }
            (FieldKind::Choice { options, selected }, Key::Left) => {
                let n = options.len().max(1);
                *selected = (*selected + n - 1) % n;
                true
            }
            (
                FieldKind::Multi {
                    checked, cursor, ..
                },
                Key::Char(' '),
            ) => {
                if let Some(v) = checked.get_mut(*cursor) {
                    *v = !*v;
                }
                true
            }
            (
                FieldKind::Multi {
                    options, cursor, ..
                },
                Key::Right,
            ) => {
                *cursor = (*cursor + 1).min(options.len().saturating_sub(1));
                true
            }
            (FieldKind::Multi { cursor, .. }, Key::Left) => {
                *cursor = cursor.saturating_sub(1);
                true
            }
            (FieldKind::Toggle { on }, Key::Char(' ') | Key::Left | Key::Right) => {
                *on = !*on;
                true
            }
            _ => false,
        };
        if handled {
            f.error = None;
            FormEvent::Edited
        } else {
            FormEvent::Ignored
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn form() -> Form {
        Form::new(vec![
            Field::text("name", "Name", "", 5),
            Field::secret("code", "Code", true, 8),
            Field::choice("c", "Choice", &["a", "b", "c"], 0),
            Field::multi("m", "Multi", &["x", "y"], &[false, true]),
            Field::toggle("t", "Toggle", false),
        ])
    }

    #[test]
    fn keys_edit_navigate_and_respect_limits() {
        let mut f = form();
        for c in "abcdefg".chars() {
            f.handle(Key::Char(c));
        }
        assert_eq!(f.text("name"), "abcde", "limited to 5");
        f.paste("x\u{1b}[2J");
        assert_eq!(f.text("name"), "abcde");
        f.handle(Key::Backspace);
        f.paste("\u{1b}z");
        assert_eq!(f.text("name"), "abcdz", "control characters are dropped");
        f.handle(Key::Tab);
        f.paste("12ab3456");
        assert_eq!(f.secret("code").unwrap().expose(), "123456");
        f.handle(Key::Tab);
        f.handle(Key::Char(' '));
        assert_eq!(f.choice("c"), 1);
        f.handle(Key::Left);
        f.handle(Key::Left);
        assert_eq!(f.choice("c"), 2);
        f.handle(Key::Tab);
        f.handle(Key::Char(' '));
        assert_eq!(f.checked("m"), vec![true, true]);
        f.handle(Key::Right);
        f.handle(Key::Char(' '));
        assert_eq!(f.checked("m"), vec![true, false]);
        f.handle(Key::Tab);
        f.handle(Key::Char(' '));
        assert!(f.toggled("t"));
        f.handle(Key::Tab);
        assert_eq!(f.focus, 0, "wraps");
        f.handle(Key::BackTab);
        assert_eq!(f.focus, 4);
        assert_eq!(f.handle(Key::Enter), FormEvent::Submit);
        assert_eq!(f.handle(Key::Esc), FormEvent::Cancel);
    }

    #[test]
    fn errors_are_set_cleared_by_editing_and_secrets_can_be_taken() {
        let mut f = form();
        f.set_error("name", "bad");
        assert!(f.has_errors());
        f.focus_first_error();
        assert_eq!(f.focus, 0);
        f.handle(Key::Char('a'));
        assert!(!f.has_errors());
        f.focus_on("code");
        f.paste("654321");
        let s = f.take_secret("code");
        assert_eq!(s.expose(), "654321");
        assert!(f.secret("code").unwrap().is_empty());
    }
}
