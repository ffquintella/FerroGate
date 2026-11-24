//! The add and remove requests, built and checked the same way by every
//! front end (CLI and tray). The server re-checks everything; these checks
//! explain a mistake before it costs a second factor.

use ferro_codesign::{PinKind, SignatureKind};
use ferro_proto::admin_v1::{AddTrustedPublisherRequest, RemoveTrustedPublisherRequest};

use super::inspect::{Candidate, Source};
use super::view::hex32;
use crate::approvals::valid_record_id;
use crate::display::inert;

/// Longest label, in characters (the server's limit).
pub const MAX_LABEL: usize = 128;
/// Longest subject or issuer display string, in characters.
pub const MAX_DISPLAY: usize = 512;

/// What is wrong with a draft.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DraftError {
    /// The label is empty or longer than [`MAX_LABEL`].
    #[error("label must be 1 to 128 characters")]
    Label,
    /// The anchor choice is not one of the candidate's CA certificates.
    #[error("choose one of the listed CA certificates as the anchor")]
    Anchor,
    /// A digest is not 64 hexadecimal characters.
    #[error("{0} must be a SHA-256 in hexadecimal (64 characters)")]
    Digest(&'static str),
    /// The expiry is not in the future.
    #[error("the expiry must be in the future")]
    Expiry,
    /// The publisher id is not one CMIS issues.
    #[error("invalid publisher id")]
    Id,
}

/// A trusted publisher about to be added.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublisherDraft {
    /// Signature technology.
    pub kind: SignatureKind,
    /// SHA-256 of the CA certificate to pin.
    pub anchor_sha256: [u8; 32],
    /// What `pin` digests.
    pub pin_kind: PinKind,
    /// The leaf digest.
    pub pin: [u8; 32],
    /// Refuse signatures without a trusted timestamp (default on).
    pub require_timestamp: bool,
    /// Administrator's name for it (display only).
    pub label: String,
    /// Leaf subject, display only (empty when added by pins).
    pub subject: String,
    /// Leaf issuer, display only.
    pub issuer: String,
    /// Leaf thumbprint, display only.
    pub leaf_cert_sha256: Option<[u8; 32]>,
    /// Unix seconds; `None` for no expiry.
    pub expires_at: Option<i64>,
}

/// A SHA-256 typed or pasted as hex; spaces and colons (as Windows shows
/// thumbprints) are ignored, case does not matter.
#[must_use]
pub fn parse_sha256_hex(s: &str) -> Option<[u8; 32]> {
    let compact: String = s.chars().filter(|c| !matches!(c, ' ' | ':')).collect();
    let bytes = hex::decode(compact.to_ascii_lowercase()).ok()?;
    bytes.try_into().ok()
}

impl PublisherDraft {
    /// A draft from a locally read identity: pin `pin_kind` of its leaf and
    /// anchor on its `anchor`-th CA certificate (0 is the nearest issuer).
    pub fn from_candidate(
        c: &Candidate,
        anchor: usize,
        pin_kind: PinKind,
        label: &str,
    ) -> Result<Self, DraftError> {
        let anchor = c.issuers.get(anchor).ok_or(DraftError::Anchor)?;
        Ok(Self {
            kind: c.kind,
            anchor_sha256: anchor.cert_sha256,
            pin_kind,
            pin: c.leaf.pin(pin_kind),
            require_timestamp: true,
            label: label.trim().to_string(),
            subject: inert(&c.leaf.subject, MAX_DISPLAY),
            issuer: inert(&c.leaf.issuer, MAX_DISPLAY),
            leaf_cert_sha256: Some(c.leaf.cert_sha256),
            expires_at: None,
        })
    }

    /// A draft from digests alone (no file at hand).
    pub fn from_pins(
        kind: SignatureKind,
        anchor_hex: &str,
        pin_kind: PinKind,
        pin_hex: &str,
        label: &str,
    ) -> Result<Self, DraftError> {
        Ok(Self {
            kind,
            anchor_sha256: parse_sha256_hex(anchor_hex).ok_or(DraftError::Digest("anchor"))?,
            pin_kind,
            pin: parse_sha256_hex(pin_hex).ok_or(DraftError::Digest("pin"))?,
            require_timestamp: true,
            label: label.trim().to_string(),
            subject: String::new(),
            issuer: String::new(),
            leaf_cert_sha256: None,
            expires_at: None,
        })
    }

    /// Everything wrong with the draft at `now` (empty: ready to send).
    #[must_use]
    pub fn problems(&self, now: i64) -> Vec<DraftError> {
        let mut out = Vec::new();
        let n = self.label.chars().count();
        if n == 0 || n > MAX_LABEL || self.label.chars().any(char::is_control) {
            out.push(DraftError::Label);
        }
        if self.expires_at.is_some_and(|t| t <= now) {
            out.push(DraftError::Expiry);
        }
        out
    }

    /// The lines an administrator confirms before the second factor is
    /// asked for: identity, thumbprints, what is pinned, and warnings.
    #[must_use]
    pub fn confirmation(&self, candidate: Option<&Candidate>) -> Vec<(&'static str, String)> {
        let mut lines = vec![
            ("label", inert(&self.label, MAX_LABEL)),
            ("kind", self.kind.as_str().to_string()),
        ];
        if !self.subject.is_empty() {
            lines.push(("publisher", self.subject.clone()));
            lines.push(("issuer", self.issuer.clone()));
        }
        if let Some(t) = self.leaf_cert_sha256 {
            lines.push(("thumbprint (SHA-256)", hex32(&t)));
        }
        lines.push((
            "pins",
            format!("{} {}", self.pin_kind.as_str(), hex32(&self.pin)),
        ));
        lines.push(("anchor CA (SHA-256)", hex32(&self.anchor_sha256)));
        lines.push((
            "timestamp",
            if self.require_timestamp {
                "required"
            } else {
                "not required"
            }
            .to_string(),
        ));
        lines.push(("scope", "every host, any user".to_string()));
        for w in self.warnings(candidate) {
            lines.push(("warning", w.to_string()));
        }
        lines
    }

    /// Risks of this draft worth a second look.
    #[must_use]
    pub fn warnings(&self, candidate: Option<&Candidate>) -> Vec<&'static str> {
        let mut out = Vec::new();
        if self.pin_kind == PinKind::SubjectSha256 {
            out.push("pins a subject name: any certificate the anchor CA issues with this exact subject matches");
        }
        let anchor_is_root = candidate.is_some_and(|c| {
            c.issuers
                .iter()
                .any(|i| i.cert_sha256 == self.anchor_sha256 && i.subject == i.issuer)
        });
        if anchor_is_root {
            out.push("the anchor is a root CA: prefer the issuing intermediate");
        }
        let untimed_exe =
            candidate.is_some_and(|c| c.source == Source::Executable && !c.timestamped);
        if self.require_timestamp && untimed_exe {
            out.push("this executable's signature has no timestamp, so this rule would refuse it");
        }
        out
    }

    /// The `AddTrustedPublisher` request (its `proof` is set by the sender).
    #[must_use]
    pub fn request(&self, idempotency_key: String) -> AddTrustedPublisherRequest {
        AddTrustedPublisherRequest {
            idempotency_key,
            proof: None,
            kind: u32::from(self.kind.code()),
            anchor_sha256: self.anchor_sha256.to_vec(),
            pin_kind: u32::from(self.pin_kind.code()),
            pin: self.pin.to_vec(),
            require_timestamp: self.require_timestamp,
            label: self.label.clone(),
            subject: self.subject.clone(),
            issuer: self.issuer.clone(),
            leaf_cert_sha256: self
                .leaf_cert_sha256
                .map(|t| t.to_vec())
                .unwrap_or_default(),
            expires_at: self.expires_at.unwrap_or(0),
        }
    }
}

/// The `RemoveTrustedPublisher` request for `publisher_id`.
pub fn remove_request(
    publisher_id: &str,
    idempotency_key: String,
) -> Result<RemoveTrustedPublisherRequest, DraftError> {
    if !valid_record_id(publisher_id) {
        return Err(DraftError::Id);
    }
    Ok(RemoveTrustedPublisherRequest {
        idempotency_key,
        publisher_id: publisher_id.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::publishers::inspect::{inspect_certificates, Candidate};
    use ferro_codesign::testing::TestChain;

    fn candidate() -> Candidate {
        let chain = TestChain::new("ACME Corp");
        inspect_certificates(SignatureKind::Authenticode, &chain.leaf_der, &chain.ca_der).unwrap()
    }

    #[test]
    fn a_candidate_draft_pins_the_chosen_digest_and_anchor() {
        let c = candidate();
        let d = PublisherDraft::from_candidate(&c, 0, PinKind::LeafSpkiSha256, " ACME ").unwrap();
        assert_eq!(d.pin, c.leaf.spki_sha256);
        assert_eq!(d.anchor_sha256, c.issuers[0].cert_sha256);
        assert_eq!(d.label, "ACME");
        assert!(d.require_timestamp, "safe default");
        assert_eq!(d.problems(0), vec![]);
        let r = d.request("k".into());
        assert_eq!((r.kind, r.pin_kind), (1, 2));
        assert_eq!(r.pin, c.leaf.spki_sha256.to_vec());
        assert!(r.proof.is_none());
        assert_eq!(
            PublisherDraft::from_candidate(&c, 1, PinKind::LeafCertSha256, "x"),
            Err(DraftError::Anchor)
        );
    }

    #[test]
    fn the_confirmation_shows_identity_thumbprint_and_warnings() {
        let c = candidate();
        let d = PublisherDraft::from_candidate(&c, 0, PinKind::SubjectSha256, "ACME").unwrap();
        let lines = d.confirmation(Some(&c));
        let get = |k: &str| lines.iter().find(|(n, _)| *n == k).map(|(_, v)| v.clone());
        assert!(get("publisher").unwrap().contains("ACME Corp"));
        assert_eq!(
            get("thumbprint (SHA-256)").unwrap(),
            hex32(&c.leaf.cert_sha256)
        );
        let warnings: Vec<_> = lines.iter().filter(|(n, _)| *n == "warning").collect();
        assert_eq!(
            warnings.len(),
            2,
            "subject pin and root anchor: {warnings:?}"
        );
        let mut exe = c.clone();
        exe.source = Source::Executable;
        exe.timestamped = false;
        let lines = d.confirmation(Some(&exe));
        assert_eq!(lines.iter().filter(|(n, _)| *n == "warning").count(), 3);
    }

    #[test]
    fn pins_parse_like_windows_shows_them_and_bad_input_is_named() {
        let hex = "AB ".repeat(32);
        assert_eq!(parse_sha256_hex(&hex), Some([0xab; 32]));
        assert_eq!(parse_sha256_hex(&"ab:".repeat(32)), Some([0xab; 32]));
        assert_eq!(parse_sha256_hex("abcd"), None);
        let d = PublisherDraft::from_pins(
            SignatureKind::Apple,
            &"01".repeat(32),
            PinKind::LeafCertSha256,
            "zz",
            "x",
        );
        assert_eq!(d, Err(DraftError::Digest("pin")));
        let mut ok = PublisherDraft::from_pins(
            SignatureKind::Apple,
            &"01".repeat(32),
            PinKind::LeafCertSha256,
            &"02".repeat(32),
            "",
        )
        .unwrap();
        ok.expires_at = Some(10);
        assert_eq!(ok.problems(10), vec![DraftError::Label, DraftError::Expiry]);
    }

    #[test]
    fn removal_needs_a_valid_id() {
        assert_eq!(remove_request("bad id", "k".into()), Err(DraftError::Id));
        assert_eq!(
            remove_request("p-1", "k".into()).unwrap().publisher_id,
            "p-1"
        );
    }
}
