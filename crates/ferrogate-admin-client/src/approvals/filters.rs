//! Search and filters of the request and approval lists (F21 §5, F22 §4),
//! mapped one-to-one to the structured fields of `ListAppRequests` and
//! `ListApprovals` (F19 §7.5). Shared by the TUI and the tray admin client,
//! which each draw their own panel over these values.

//! Values are checked before a listing is built ([`check`],
//! [`RequestFilters::invalid_fields`]); every text is bounded by the
//! server's limit. Filters travel as separate protobuf fields, never as a
//! query string: the server binds them as SQL parameters.

use std::fmt::Write as _;

use ferro_proto::admin_v1::{ListAppRequestsRequest, ListApprovalsRequest, PageRequest};

/// The F19 §4.5 risk-flag bits (so front ends need no `ferro-appid`).
pub use ferro_appid::flags::RiskFlags;

use crate::timefmt;

/// Longest free-text filter (the server's `MAX_TEXT_CHARS`).
pub const MAX_TEXT: usize = 128;
/// Rows per page requested from the server.
pub const PAGE_SIZE: u32 = 50;

/// Request states, in wire-code order (1…5).
pub const REQUEST_STATES: [&str; 5] = ["pending", "approved", "auto-approved", "denied", "expired"];
/// Request origins, in wire-code order (1…4).
pub const REQUEST_ORIGINS: [&str; 4] = ["self", "assisted", "admin_direct", "observed"];
/// Request kinds (0 = any, then wire codes 1…2).
pub const REQUEST_KINDS: [&str; 3] = ["any", "register", "update"];
/// Approval states, in wire-code order (1…3).
pub const APPROVAL_STATES: [&str; 3] = ["active", "expired", "revoked"];
/// Update policies, in wire-code order (1…2).
pub const POLICIES: [&str; 2] = ["manual", "auto-update"];
/// Approval origins, in wire-code order (1…4).
pub const APPROVAL_ORIGINS: [&str; 4] = ["manual", "auto_update", "admin_direct", "legacy_import"];
/// Approval presets.
pub const PRESETS: [&str; 5] = [
    "none",
    "expiring ≤ 14 d",
    "legacy, no expiry",
    "superseded",
    "auto-update",
];

/// The F19 §4.5 risk flags with their short names, in bit order.
pub const FLAG_NAMES: [(u32, &str); 15] = [
    (RiskFlags::PATH_PROTECTED, "path protected"),
    (RiskFlags::USER_WRITABLE_PATH, "user-writable path"),
    (RiskFlags::WORLD_WRITABLE, "world-writable"),
    (RiskFlags::TEMP_DIR, "temp dir"),
    (RiskFlags::NETWORK_PATH, "network path"),
    (RiskFlags::INTERPRETER, "interpreter"),
    (RiskFlags::UNSIGNED, "unsigned"),
    (RiskFlags::SIGNER_CHANGED, "signer changed"),
    (RiskFlags::VERSION_COLLISION, "version collision"),
    (RiskFlags::VERSION_DOWNGRADE, "version downgrade"),
    (RiskFlags::HASH_PREVIOUSLY_REVOKED, "hash revoked before"),
    (RiskFlags::HASH_PREVIOUSLY_DENIED, "hash denied before"),
    (RiskFlags::DELETED_ON_DISK, "deleted on disk"),
    (RiskFlags::IMA_UNVERIFIED, "IMA unverified"),
    (RiskFlags::HOST_TIER_B, "host-key tier"),
];

/// The names of the bits set in `flags` that warrant a warning (every flag
/// except `path protected`, which is good news).
#[must_use]
pub fn warning_flags(flags: u32) -> Vec<&'static str> {
    FLAG_NAMES
        .iter()
        .filter(|(bit, _)| *bit != RiskFlags::PATH_PROTECTED && flags & bit != 0)
        .map(|(_, name)| *name)
        .collect()
}

/// The longest value a filter field takes, in characters (by the TUI's form
/// key); 0 for a key that is not a text field.
#[must_use]
pub fn max_chars(key: &str) -> usize {
    match key {
        "host" => 36,
        "sha" => 96,
        "from" | "to" | "after" | "before" => 10,
        "lineage" => 64,
        "path" | "product" | "user" | "version" | "text" => MAX_TEXT,
        _ => 0,
    }
}

fn codes(checked: &[bool]) -> Vec<u32> {
    checked
        .iter()
        .zip(1u32..)
        .filter(|(on, _)| **on)
        .map(|(_, code)| code)
        .collect()
}

fn names(checked: &[bool], labels: &[&str]) -> String {
    let picked: Vec<&str> = checked
        .iter()
        .zip(labels)
        .filter(|(on, _)| **on)
        .map(|(_, l)| *l)
        .collect();
    if picked.is_empty() || picked.len() == labels.len() {
        "any".to_string()
    } else {
        picked.join(",")
    }
}

/// Inline checks shared by both panels.
pub mod check {
    use super::MAX_TEXT;
    use crate::timefmt;

    /// Text within the server limit.
    ///
    /// # Errors
    /// Why the value is refused.
    pub fn text(v: &str) -> Result<(), String> {
        if v.chars().count() > MAX_TEXT {
            return Err(format!("at most {MAX_TEXT} characters"));
        }
        Ok(())
    }

    /// Empty, or a `YYYY-MM-DD` date.
    ///
    /// # Errors
    /// Why the value is refused.
    pub fn date(v: &str) -> Result<Option<i64>, String> {
        if v.is_empty() {
            return Ok(None);
        }
        timefmt::parse_date(v)
            .map(Some)
            .ok_or_else(|| "use YYYY-MM-DD (a real date)".to_string())
    }

    /// Empty, or 8 to 96 hex characters.
    ///
    /// # Errors
    /// Why the value is refused.
    pub fn hash_prefix(v: &str) -> Result<(), String> {
        if v.is_empty() || ((8..=96).contains(&v.len()) && v.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            Ok(())
        } else {
            Err("8 to 96 hex characters".to_string())
        }
    }

    /// Empty, or a UUID.
    ///
    /// # Errors
    /// Why the value is refused.
    pub fn uuid(v: &str) -> Result<(), String> {
        if v.is_empty() || uuid::Uuid::parse_str(v).is_ok() {
            Ok(())
        } else {
            Err("a host UUID (8-4-4-4-12 hex)".to_string())
        }
    }

    /// Empty, or at most 64 printable ASCII characters (an id).
    ///
    /// # Errors
    /// Why the value is refused.
    pub fn id(v: &str) -> Result<(), String> {
        if v.len() <= 64 && v.bytes().all(|b| b.is_ascii_graphic()) {
            Ok(())
        } else {
            Err("an id (at most 64 printable characters)".to_string())
        }
    }
}

/// A field key, its value and whether that value passes its check.
type Checked<'a> = (&'static str, &'a str, fn(&str) -> bool);

/// The keys of `fields` whose value fails its check.
fn failing(fields: &[Checked<'_>]) -> Vec<&'static str> {
    fields
        .iter()
        .filter(|(_, v, ok)| !ok(v))
        .map(|(k, _, _)| *k)
        .collect()
}

fn ok_text(v: &str) -> bool {
    check::text(v).is_ok()
}

fn ok_date(v: &str) -> bool {
    check::date(v).is_ok()
}

fn ok_hash(v: &str) -> bool {
    check::hash_prefix(v).is_ok()
}

fn ok_uuid(v: &str) -> bool {
    check::uuid(v).is_ok()
}

fn ok_id(v: &str) -> bool {
    check::id(v).is_ok()
}

/// `true` when both dates parse and `from` is after `to`.
fn reversed(from: &str, to: &str) -> bool {
    matches!(
        (timefmt::parse_date(from), timefmt::parse_date(to)),
        (Some(f), Some(t)) if f > t
    )
}

/// Filters of the Requests screen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestFilters {
    /// States, wire-code order.
    pub states: Vec<bool>,
    /// Origins, wire-code order.
    pub origins: Vec<bool>,
    /// Kind (0 any).
    pub kind: usize,
    /// Host UUID (exact).
    pub host: String,
    /// Path contains.
    pub path: String,
    /// Product contains.
    pub product: String,
    /// User name (exact).
    pub user: String,
    /// Declared version (exact).
    pub version: String,
    /// Hash prefix.
    pub sha_prefix: String,
    /// Flags (any of), bit order of [`FLAG_NAMES`].
    pub flags: Vec<bool>,
    /// Submitted on or after (`YYYY-MM-DD`).
    pub from: String,
    /// Submitted before the end of (`YYYY-MM-DD`).
    pub to: String,
    /// Free text.
    pub text: String,
}

impl Default for RequestFilters {
    /// Pending requests only.
    fn default() -> Self {
        Self {
            states: vec![true, false, false, false, false],
            origins: vec![false; REQUEST_ORIGINS.len()],
            kind: 0,
            host: String::new(),
            path: String::new(),
            product: String::new(),
            user: String::new(),
            version: String::new(),
            sha_prefix: String::new(),
            flags: vec![false; FLAG_NAMES.len()],
            from: String::new(),
            to: String::new(),
            text: String::new(),
        }
    }
}

impl RequestFilters {
    /// Trim every text and lowercase the hash prefix (as the TUI's panel
    /// reads them back).
    pub fn normalize(&mut self) {
        for v in [
            &mut self.host,
            &mut self.path,
            &mut self.product,
            &mut self.user,
            &mut self.version,
            &mut self.from,
            &mut self.to,
            &mut self.text,
        ] {
            *v = v.trim().to_string();
        }
        self.sha_prefix = self.sha_prefix.trim().to_ascii_lowercase();
    }

    /// The fields (by the TUI's form keys) whose value would be refused;
    /// empty when the filters may be sent.
    #[must_use]
    pub fn invalid_fields(&self) -> Vec<&'static str> {
        let mut bad = failing(&[
            ("host", &self.host, ok_uuid),
            ("path", &self.path, ok_text),
            ("product", &self.product, ok_text),
            ("user", &self.user, ok_text),
            ("version", &self.version, ok_text),
            ("sha", &self.sha_prefix, ok_hash),
            ("from", &self.from, ok_date),
            ("to", &self.to, ok_date),
            ("text", &self.text, ok_text),
        ]);
        if reversed(&self.from, &self.to) && !bad.contains(&"to") {
            bad.push("to");
        }
        bad
    }

    /// The listing request for one page.
    #[must_use]
    pub fn to_request(&self, ascending: bool, page_token: &str) -> ListAppRequestsRequest {
        let flags_any = self
            .flags
            .iter()
            .zip(FLAG_NAMES)
            .filter(|(on, _)| **on)
            .fold(0u32, |acc, (_, (bit, _))| acc | bit);
        ListAppRequestsRequest {
            states: codes(&self.states),
            host_uuid: self.host.clone(),
            path_contains: self.path.clone(),
            product_contains: self.product.clone(),
            user_name: self.user.clone(),
            declared_version: self.version.clone(),
            bin_sha_prefix: self.sha_prefix.clone(),
            origins: codes(&self.origins),
            kinds: if self.kind == 0 {
                Vec::new()
            } else {
                vec![u32::try_from(self.kind).unwrap_or(0)]
            },
            flags_any,
            submitted_after: timefmt::parse_date(&self.from).unwrap_or(0),
            // Inclusive "to": before the end of that day.
            submitted_before: timefmt::parse_date(&self.to).map_or(0, |t| t + timefmt::DAY),
            text: self.text.clone(),
            ascending,
            page: Some(PageRequest {
                page_size: PAGE_SIZE,
                page_token: page_token.to_string(),
            }),
        }
    }

    /// A one-line summary for the list header.
    #[must_use]
    pub fn summary(&self) -> String {
        let mut s = format!(
            "state:{} origin:{} kind:{} host:{}",
            names(&self.states, &REQUEST_STATES),
            names(&self.origins, &REQUEST_ORIGINS),
            REQUEST_KINDS.get(self.kind).unwrap_or(&"any"),
            if self.host.is_empty() {
                "*".to_string()
            } else {
                self.host.chars().take(8).collect::<String>()
            }
        );
        for (label, v) in [
            ("path", &self.path),
            ("product", &self.product),
            ("user", &self.user),
            ("version", &self.version),
            ("sha", &self.sha_prefix),
            ("from", &self.from),
            ("to", &self.to),
        ] {
            if !v.is_empty() {
                let _ = write!(s, " {label}:{v}");
            }
        }
        if self.flags.iter().any(|f| *f) {
            s.push_str(" flags:…");
        }
        s
    }
}

/// Filters of the Approvals screen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalFilters {
    /// Preset (index into [`PRESETS`]).
    pub preset: usize,
    /// States, wire-code order.
    pub states: Vec<bool>,
    /// Policies, wire-code order.
    pub policies: Vec<bool>,
    /// Approval origins, wire-code order.
    pub origins: Vec<bool>,
    /// Expires on or after (`YYYY-MM-DD`).
    pub expires_after: String,
    /// Expires before the end of (`YYYY-MM-DD`).
    pub expires_before: String,
    /// Include superseded approvals.
    pub include_superseded: bool,
    /// Lineage id (exact).
    pub lineage: String,
    /// Host UUID (exact).
    pub host: String,
    /// Path contains.
    pub path: String,
    /// Product contains.
    pub product: String,
    /// User name (exact).
    pub user: String,
    /// Hash prefix.
    pub sha_prefix: String,
    /// Free text.
    pub text: String,
}

impl Default for ApprovalFilters {
    /// Active approvals.
    fn default() -> Self {
        Self {
            preset: 0,
            states: vec![true, false, false],
            policies: vec![false; POLICIES.len()],
            origins: vec![false; APPROVAL_ORIGINS.len()],
            expires_after: String::new(),
            expires_before: String::new(),
            include_superseded: false,
            lineage: String::new(),
            host: String::new(),
            path: String::new(),
            product: String::new(),
            user: String::new(),
            sha_prefix: String::new(),
            text: String::new(),
        }
    }
}

impl ApprovalFilters {
    /// Every approval of one lineage (the "lineage" jump from a request).
    #[must_use]
    pub fn lineage(lineage_id: &str) -> Self {
        Self {
            states: vec![false; APPROVAL_STATES.len()],
            include_superseded: true,
            lineage: lineage_id.to_string(),
            ..Self::default()
        }
    }

    /// Trim every text and lowercase the hash prefix.
    pub fn normalize(&mut self) {
        for v in [
            &mut self.expires_after,
            &mut self.expires_before,
            &mut self.lineage,
            &mut self.host,
            &mut self.path,
            &mut self.product,
            &mut self.user,
            &mut self.text,
        ] {
            *v = v.trim().to_string();
        }
        self.sha_prefix = self.sha_prefix.trim().to_ascii_lowercase();
    }

    /// The fields (by the TUI's form keys) whose value would be refused;
    /// empty when the filters may be sent.
    #[must_use]
    pub fn invalid_fields(&self) -> Vec<&'static str> {
        let mut bad = failing(&[
            ("after", &self.expires_after, ok_date),
            ("before", &self.expires_before, ok_date),
            ("lineage", &self.lineage, ok_id),
            ("host", &self.host, ok_uuid),
            ("path", &self.path, ok_text),
            ("product", &self.product, ok_text),
            ("user", &self.user, ok_text),
            ("sha", &self.sha_prefix, ok_hash),
            ("text", &self.text, ok_text),
        ]);
        if reversed(&self.expires_after, &self.expires_before) && !bad.contains(&"before") {
            bad.push("before");
        }
        bad
    }

    /// The listing request for one page at Unix time `now` (for presets).
    #[must_use]
    pub fn to_request(&self, now: i64, ascending: bool, page_token: &str) -> ListApprovalsRequest {
        let mut req = ListApprovalsRequest {
            states: codes(&self.states),
            host_uuid: self.host.clone(),
            lineage_id: self.lineage.clone(),
            path_contains: self.path.clone(),
            product_contains: self.product.clone(),
            user_name: self.user.clone(),
            bin_sha_prefix: self.sha_prefix.clone(),
            policies: codes(&self.policies),
            approval_origins: codes(&self.origins),
            expires_after: timefmt::parse_date(&self.expires_after).unwrap_or(0),
            expires_before: timefmt::parse_date(&self.expires_before)
                .map_or(0, |t| t + timefmt::DAY),
            include_superseded: self.include_superseded,
            text: self.text.clone(),
            ascending,
            page: Some(PageRequest {
                page_size: PAGE_SIZE,
                page_token: page_token.to_string(),
            }),
            ..ListApprovalsRequest::default()
        };
        match self.preset {
            1 => {
                req.states = vec![1];
                req.expires_after = now;
                req.expires_before = now + 14 * timefmt::DAY;
            }
            2 => {
                req.legacy_only = true;
                req.no_expiry_only = true;
            }
            3 => req.include_superseded = true,
            4 => req.policies = vec![2],
            _ => {}
        }
        req
    }

    /// A one-line summary for the list header.
    #[must_use]
    pub fn summary(&self) -> String {
        let mut s = format!(
            "state:{} policy:{} origin:{}",
            names(&self.states, &APPROVAL_STATES),
            names(&self.policies, &POLICIES),
            names(&self.origins, &APPROVAL_ORIGINS),
        );
        if self.preset != 0 {
            let _ = write!(s, " preset:{}", PRESETS[self.preset.min(PRESETS.len() - 1)]);
        }
        if self.include_superseded {
            s.push_str(" +superseded");
        }
        for (label, v) in [
            ("lineage", &self.lineage),
            ("host", &self.host),
            ("path", &self.path),
            ("product", &self.product),
            ("user", &self.user),
            ("sha", &self.sha_prefix),
            ("after", &self.expires_after),
            ("before", &self.expires_before),
        ] {
            if !v.is_empty() {
                let _ = write!(s, " {label}:{v}");
            }
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_values_are_named_and_reversed_dates_flag_the_end() {
        let mut f = RequestFilters {
            sha_prefix: " ABCDEF0123 ".into(),
            host: "not-a-uuid".into(),
            from: "2026-10-14".into(),
            to: "2026-10-01".into(),
            text: "x".repeat(MAX_TEXT + 1),
            ..RequestFilters::default()
        };
        f.normalize();
        assert_eq!(f.sha_prefix, "abcdef0123");
        assert_eq!(f.invalid_fields(), vec!["host", "text", "to"]);
        f.host.clear();
        f.text.clear();
        f.to = "2026-10-15".into();
        assert_eq!(f.invalid_fields(), Vec::<&str>::new());
        let r = f.to_request(false, "tok");
        assert_eq!(r.states, vec![1]);
        assert_eq!(r.bin_sha_prefix, "abcdef0123");
        assert_eq!(
            r.submitted_before,
            timefmt::parse_date("2026-10-16").unwrap()
        );

        let mut a = ApprovalFilters {
            lineage: "bad id".into(),
            expires_after: "2026-02-30".into(),
            ..ApprovalFilters::default()
        };
        a.normalize();
        assert_eq!(a.invalid_fields(), vec!["after", "lineage"]);
        a.expires_after = "2026-10-14".into();
        a.expires_before = "2026-10-01".into();
        a.lineage = "lin-1".into();
        assert_eq!(a.invalid_fields(), vec!["before"]);
    }

    #[test]
    fn approval_presets_and_lineage_map_to_server_fields() {
        let now = 1_791_936_000;
        let f = ApprovalFilters {
            preset: 1,
            ..ApprovalFilters::default()
        };
        let r = f.to_request(now, false, "");
        assert_eq!(
            (r.states.clone(), r.expires_after, r.expires_before),
            (vec![1], now, now + 14 * 86_400)
        );
        let r = ApprovalFilters::lineage("lin-1").to_request(now, true, "");
        assert!(r.states.is_empty() && r.include_superseded && r.ascending);
        assert_eq!(r.lineage_id, "lin-1");
    }

    #[test]
    fn warning_flags_skip_the_protected_bit_and_limits_are_known() {
        let w = warning_flags(RiskFlags::PATH_PROTECTED | RiskFlags::UNSIGNED);
        assert_eq!(w, vec!["unsigned"]);
        assert_eq!(max_chars("sha"), 96);
        assert_eq!(max_chars("text"), MAX_TEXT);
        assert_eq!(max_chars("states"), 0);
    }
}
