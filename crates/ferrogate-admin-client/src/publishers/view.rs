//! How a trusted publisher is shown: one cleaned, display-ready row per
//! record (text and JSON), lookups by id or short id, and the typed
//! confirmation a removal asks for.

use serde::Serialize;

use ferro_codesign::{PinKind, SignatureKind};
use ferro_proto::admin_v1::TrustedPublisherInfo;

use super::draft::{MAX_DISPLAY, MAX_LABEL};
use crate::approvals::rules::short_id;
use crate::display::inert;

/// Lowercase hex of a 32-byte digest.
#[must_use]
pub fn hex32(d: &[u8; 32]) -> String {
    hex::encode(d)
}

/// Lowercase hex of a digest the server sent (any length, shown as is).
fn hex_any(d: &[u8]) -> String {
    hex::encode(d)
}

/// A trusted publisher, every server string cleaned for display.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PublisherRow {
    /// Full id.
    pub id: String,
    /// Short id (`P-XXXXXXXX`), what a removal is confirmed with.
    pub short_id: String,
    /// `authenticode`, `apple` or `unknown`.
    pub kind: &'static str,
    /// `leaf-cert`, `leaf-spki`, `subject` or `unknown`.
    pub pin_kind: &'static str,
    /// Pinned digest, hex.
    pub pin: String,
    /// Anchor CA SHA-256, hex.
    pub anchor_sha256: String,
    /// Leaf thumbprint at add time, hex (empty when added by pins).
    pub leaf_cert_sha256: String,
    /// Signatures must be timestamped.
    pub require_timestamp: bool,
    /// Label.
    pub label: String,
    /// Leaf subject at add time.
    pub subject: String,
    /// Leaf issuer at add time.
    pub issuer: String,
    /// Unix seconds.
    pub created_at: i64,
    /// Adding administrator.
    pub created_by: String,
    /// Unix seconds; `None` for no expiry.
    pub expires_at: Option<i64>,
    /// `active` or `removed`.
    pub state: &'static str,
    /// Unix seconds; `None` while active.
    pub removed_at: Option<i64>,
    /// Removing administrator (empty while active).
    pub removed_by: String,
}

impl PublisherRow {
    /// The row of `p`.
    #[must_use]
    pub fn of(p: &TrustedPublisherInfo) -> Self {
        let kind = u8::try_from(p.kind)
            .ok()
            .and_then(SignatureKind::from_code)
            .map_or("unknown", SignatureKind::as_str);
        let pin_kind = u8::try_from(p.pin_kind)
            .ok()
            .and_then(PinKind::from_code)
            .map_or("unknown", PinKind::as_str);
        Self {
            id: inert(&p.publisher_id, 64),
            short_id: short_id("P", &p.publisher_id),
            kind,
            pin_kind,
            pin: hex_any(&p.pin),
            anchor_sha256: hex_any(&p.anchor_sha256),
            leaf_cert_sha256: hex_any(&p.leaf_cert_sha256),
            require_timestamp: p.require_timestamp,
            label: inert(&p.label, MAX_LABEL),
            subject: inert(&p.subject, MAX_DISPLAY),
            issuer: inert(&p.issuer, MAX_DISPLAY),
            created_at: p.created_at,
            created_by: inert(&p.created_by_admin_id, 64),
            expires_at: (p.expires_at != 0).then_some(p.expires_at),
            state: if p.state == 2 { "removed" } else { "active" },
            removed_at: (p.removed_at != 0).then_some(p.removed_at),
            removed_by: inert(&p.removed_by_admin_id, 64),
        }
    }

    /// The text a removal must be confirmed with (the short id).
    #[must_use]
    pub fn confirm_phrase(&self) -> &str {
        &self.short_id
    }

    /// `label — subject` for one-line lists.
    #[must_use]
    pub fn title(&self) -> String {
        if self.subject.is_empty() {
            self.label.clone()
        } else {
            format!("{} — {}", self.label, self.subject)
        }
    }
}

/// The publisher whose full id, or short id (case-insensitive), is `key`.
#[must_use]
pub fn find<'a>(all: &'a [TrustedPublisherInfo], key: &str) -> Option<&'a TrustedPublisherInfo> {
    let key = key.trim();
    all.iter()
        .find(|p| p.publisher_id == key || short_id("P", &p.publisher_id).eq_ignore_ascii_case(key))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info() -> TrustedPublisherInfo {
        TrustedPublisherInfo {
            publisher_id: "0190f0aa-0000-7000-8000-00000000beef".into(),
            kind: 1,
            anchor_sha256: vec![0xaa; 32],
            pin_kind: 3,
            pin: vec![0xbb; 32],
            require_timestamp: true,
            label: "ACME\u{1b}[31m".into(),
            subject: "CN=ACME Corp".into(),
            issuer: "CN=CA".into(),
            created_at: 5,
            created_by_admin_id: "admin-1".into(),
            state: 1,
            ..TrustedPublisherInfo::default()
        }
    }

    #[test]
    fn rows_are_cleaned_and_named() {
        let r = PublisherRow::of(&info());
        assert_eq!(r.short_id, "P-0000BEEF");
        assert_eq!(
            (r.kind, r.pin_kind, r.state),
            ("authenticode", "subject", "active")
        );
        assert!(!r.label.contains('\u{1b}'), "{}", r.label);
        assert_eq!(r.expires_at, None);
        assert_eq!(r.pin, "bb".repeat(32));
        let json = serde_json::to_value(&r).unwrap();
        assert_eq!(json["pin_kind"], "subject");
        let unknown = PublisherRow::of(&TrustedPublisherInfo {
            kind: 9,
            pin_kind: 0,
            state: 2,
            ..info()
        });
        assert_eq!(
            (unknown.kind, unknown.pin_kind, unknown.state),
            ("unknown", "unknown", "removed")
        );
    }

    #[test]
    fn find_by_full_or_short_id() {
        let all = [info()];
        assert!(find(&all, "0190f0aa-0000-7000-8000-00000000beef").is_some());
        assert!(find(&all, "p-0000beef").is_some());
        assert!(find(&all, "P-00000000").is_none());
    }
}
