//! The trusted-publisher rule and its wire codes (ADR-0006 §2).

/// Code-signature technology a rule applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SignatureKind {
    /// Windows Authenticode.
    Authenticode,
    /// Apple code signature (macOS).
    Apple,
}

impl SignatureKind {
    /// Wire code (1 authenticode, 2 apple), the same numbering as
    /// `ferro_appid::signer::SignerKind`.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Authenticode => 1,
            Self::Apple => 2,
        }
    }

    /// The kind of a wire code, if known.
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Authenticode),
            2 => Some(Self::Apple),
            _ => None,
        }
    }

    /// Stable name (`authenticode`, `apple`) for logs, CLI and JSON.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Authenticode => "authenticode",
            Self::Apple => "apple",
        }
    }

    /// Parse [`Self::as_str`].
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "authenticode" => Some(Self::Authenticode),
            "apple" => Some(Self::Apple),
            _ => None,
        }
    }
}

/// Which property of the leaf certificate a rule pins. Every pin is a
/// SHA-256 digest of DER bytes, never a display string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PinKind {
    /// SHA-256 of the whole leaf certificate (its thumbprint): one exact
    /// certificate, so a renewal needs a new rule.
    LeafCertSha256,
    /// SHA-256 of the leaf's `SubjectPublicKeyInfo`: survives a renewal that
    /// keeps the key.
    LeafSpkiSha256,
    /// [`crate::subject_pin`] of the leaf's DER subject name: survives
    /// renewals, and is safe only together with the CA pin of the rule.
    SubjectSha256,
}

impl PinKind {
    /// Wire code (1 leaf cert, 2 leaf SPKI, 3 subject).
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::LeafCertSha256 => 1,
            Self::LeafSpkiSha256 => 2,
            Self::SubjectSha256 => 3,
        }
    }

    /// The pin kind of a wire code, if known.
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::LeafCertSha256),
            2 => Some(Self::LeafSpkiSha256),
            3 => Some(Self::SubjectSha256),
            _ => None,
        }
    }

    /// Stable name (`leaf-cert`, `leaf-spki`, `subject`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LeafCertSha256 => "leaf-cert",
            Self::LeafSpkiSha256 => "leaf-spki",
            Self::SubjectSha256 => "subject",
        }
    }

    /// Parse [`Self::as_str`].
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "leaf-cert" => Some(Self::LeafCertSha256),
            "leaf-spki" => Some(Self::LeafSpkiSha256),
            "subject" => Some(Self::SubjectSha256),
            _ => None,
        }
    }
}

/// One trusted publisher as a MIA enforces it: the signature must verify
/// through the OS, the chain must contain the CA `anchor_sha256`, and the
/// leaf's `pin_kind` digest must equal `pin`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublisherRule {
    /// UUID bytes of the CMIS record (audit correlation).
    pub publisher_id: [u8; 16],
    /// Signature technology.
    pub kind: SignatureKind,
    /// SHA-256 of a CA certificate (root or intermediate) that must appear
    /// in the verified chain above the leaf.
    pub anchor_sha256: [u8; 32],
    /// What `pin` digests.
    pub pin_kind: PinKind,
    /// The leaf digest.
    pub pin: [u8; 32],
    /// Refuse a signature that carries no trusted timestamp.
    pub require_timestamp: bool,
    /// Unix seconds after which the rule admits nobody (`None`: no expiry).
    pub expires_at: Option<i64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_and_names_round_trip() {
        for k in [SignatureKind::Authenticode, SignatureKind::Apple] {
            assert_eq!(SignatureKind::from_code(k.code()), Some(k));
            assert_eq!(SignatureKind::parse(k.as_str()), Some(k));
        }
        for p in [
            PinKind::LeafCertSha256,
            PinKind::LeafSpkiSha256,
            PinKind::SubjectSha256,
        ] {
            assert_eq!(PinKind::from_code(p.code()), Some(p));
            assert_eq!(PinKind::parse(p.as_str()), Some(p));
        }
        assert_eq!(SignatureKind::from_code(0), None);
        assert_eq!(PinKind::from_code(4), None);
        assert_eq!(PinKind::parse("Subject"), None);
    }
}
