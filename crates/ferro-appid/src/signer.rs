//! Signer summary of a binary (F19 §4.4), the continuity-anchor input.
//!
//! Verifying a signature is platform code: `ferro_winauth::verify_authenticode`
//! on Windows (leaf SHA-256 thumbprint and subject CN), and the planned
//! `ferro-macsign` on macOS (Team ID). This crate only defines the summary
//! they produce and detects whether a signature is *embedded* at all.

/// Kind of code signature (F19 §2 `signer_kind`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SignerKind {
    /// No signature.
    None,
    /// Windows Authenticode.
    Authenticode,
    /// Apple code signature.
    Apple,
}

impl SignerKind {
    /// Wire and ledger code: 0 none, 1 authenticode, 2 apple.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::None => 0,
            Self::Authenticode => 1,
            Self::Apple => 2,
        }
    }

    /// The kind of a code, if known.
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::None),
            1 => Some(Self::Authenticode),
            2 => Some(Self::Apple),
            _ => None,
        }
    }
}

/// Longest signer id (leaf SHA-256 hex or Team ID), in characters.
pub const MAX_SIGNER_ID_CHARS: usize = 128;
/// Longest signer subject, in characters.
pub const MAX_SIGNER_SUBJECT_CHARS: usize = 256;

/// What a platform verifier reports about a binary's signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignerSummary {
    /// Signature kind.
    pub kind: SignerKind,
    /// Leaf certificate SHA-256 hex (Authenticode) or Team ID (Apple).
    pub id: String,
    /// Subject common name, for display.
    pub subject: Option<String>,
    /// Whether the signature and its chain verified.
    pub valid: bool,
}

impl SignerSummary {
    /// The summary with `id` and `subject` cleaned and bounded like every
    /// other display string (F19 §4.3); `None` when the id is empty after
    /// cleaning.
    #[must_use]
    pub fn cleaned(&self) -> Option<Self> {
        let id = crate::version::clean(&self.id, MAX_SIGNER_ID_CHARS)?;
        Some(Self {
            kind: self.kind,
            id,
            subject: self
                .subject
                .as_deref()
                .and_then(|s| crate::version::clean(s, MAX_SIGNER_SUBJECT_CHARS)),
            valid: self.valid,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summaries_are_cleaned() {
        let s = SignerSummary {
            kind: SignerKind::Authenticode,
            id: format!(" {}\u{202e} ", "ab".repeat(100)),
            subject: Some("ACME\u{0}Corp".into()),
            valid: true,
        }
        .cleaned()
        .unwrap();
        assert_eq!(s.id.chars().count(), MAX_SIGNER_ID_CHARS);
        assert_eq!(s.subject.as_deref(), Some("ACMECorp"));
        assert_eq!(
            SignerKind::from_code(SignerKind::Apple.code()),
            Some(SignerKind::Apple)
        );
        assert!(SignerSummary {
            kind: SignerKind::Apple,
            id: "\u{7}".into(),
            subject: None,
            valid: false
        }
        .cleaned()
        .is_none());
    }
}
