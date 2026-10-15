//! The search and filter panel (F21 §5), mapped one-to-one to the structured
//! fields of `ListAppRequests` and `ListApprovals` (F19 §7.5).
//!
//! Values are validated here, inline, and an invalid panel is never sent: a
//! date must be `YYYY-MM-DD`, a hash prefix 8 to 96 hex characters, a host a
//! UUID, and every text at most 128 characters (the server's limit). Filters
//! travel as separate protobuf fields and are never concatenated into a query
//! string; the server binds them as SQL parameters.

use std::fmt::Write as _;

use ferro_appid::flags::RiskFlags;
use ferro_proto::admin_v1::{ListAppRequestsRequest, ListApprovalsRequest, PageRequest};

use super::form::{Field, Form};
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
    pub fn text(v: &str) -> Result<(), String> {
        if v.chars().count() > MAX_TEXT {
            return Err(format!("at most {MAX_TEXT} characters"));
        }
        Ok(())
    }

    /// Empty, or a `YYYY-MM-DD` date.
    pub fn date(v: &str) -> Result<Option<i64>, String> {
        if v.is_empty() {
            return Ok(None);
        }
        timefmt::parse_date(v)
            .map(Some)
            .ok_or_else(|| "use YYYY-MM-DD (a real date)".to_string())
    }

    /// Empty, or 8 to 96 hex characters.
    pub fn hash_prefix(v: &str) -> Result<(), String> {
        if v.is_empty() || ((8..=96).contains(&v.len()) && v.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            Ok(())
        } else {
            Err("8 to 96 hex characters".to_string())
        }
    }

    /// Empty, or a UUID.
    pub fn uuid(v: &str) -> Result<(), String> {
        if v.is_empty() || uuid::Uuid::parse_str(v).is_ok() {
            Ok(())
        } else {
            Err("a host UUID (8-4-4-4-12 hex)".to_string())
        }
    }

    /// Empty, or at most 64 printable ASCII characters (an id).
    pub fn id(v: &str) -> Result<(), String> {
        if v.len() <= 64 && v.bytes().all(|b| b.is_ascii_graphic()) {
            Ok(())
        } else {
            Err("an id (at most 64 printable characters)".to_string())
        }
    }
}

/// Run `f` on the text of `key` and record its error inline.
fn validated<T>(form: &mut Form, key: &str, f: impl Fn(&str) -> Result<T, String>) -> Option<T> {
    let value = form.text(key).trim().to_string();
    match f(&value) {
        Ok(v) => Some(v),
        Err(e) => {
            form.set_error(key, &e);
            None
        }
    }
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
    /// The filter panel pre-filled with these values.
    #[must_use]
    pub fn form(&self) -> Form {
        let flag_labels: Vec<&str> = FLAG_NAMES.iter().map(|(_, n)| *n).collect();
        Form::new(vec![
            Field::multi("states", "State", &REQUEST_STATES, &self.states),
            Field::multi("origins", "Origin", &REQUEST_ORIGINS, &self.origins),
            Field::choice("kind", "Kind", &REQUEST_KINDS, self.kind),
            Field::text("host", "Host UUID", &self.host, 36),
            Field::text("path", "Path contains", &self.path, MAX_TEXT),
            Field::text("product", "Product contains", &self.product, MAX_TEXT),
            Field::text("user", "User name", &self.user, MAX_TEXT),
            Field::text("version", "Declared version", &self.version, MAX_TEXT),
            Field::text("sha", "Hash prefix", &self.sha_prefix, 96).with_hint("≥ 8 hex"),
            Field::multi("flags", "Flags (any of)", &flag_labels, &self.flags),
            Field::text("from", "Submitted from", &self.from, 10).with_hint("YYYY-MM-DD"),
            Field::text("to", "Submitted to", &self.to, 10).with_hint("YYYY-MM-DD"),
            Field::text("text", "Free text", &self.text, MAX_TEXT),
        ])
    }

    /// Read the panel back; `None` (with inline errors set) when invalid.
    pub fn from_form(form: &mut Form) -> Option<Self> {
        form.clear_errors();
        let host = validated(form, "host", |v| check::uuid(v).map(|()| v.to_string()));
        let path = validated(form, "path", |v| check::text(v).map(|()| v.to_string()));
        let product = validated(form, "product", |v| check::text(v).map(|()| v.to_string()));
        let user = validated(form, "user", |v| check::text(v).map(|()| v.to_string()));
        let version = validated(form, "version", |v| check::text(v).map(|()| v.to_string()));
        let sha = validated(form, "sha", |v| {
            check::hash_prefix(v).map(|()| v.to_ascii_lowercase())
        });
        let from = validated(form, "from", check::date);
        let to = validated(form, "to", check::date);
        let text = validated(form, "text", |v| check::text(v).map(|()| v.to_string()));
        if let (Some(Some(f)), Some(Some(t))) = (from, to) {
            if f > t {
                form.set_error("to", "must not be before \"Submitted from\"");
            }
        }
        if form.has_errors() {
            form.focus_first_error();
            return None;
        }
        Some(Self {
            states: form.checked("states"),
            origins: form.checked("origins"),
            kind: form.choice("kind"),
            host: host?,
            path: path?,
            product: product?,
            user: user?,
            version: version?,
            sha_prefix: sha?,
            flags: form.checked("flags"),
            from: form.text("from").trim().to_string(),
            to: form.text("to").trim().to_string(),
            text: text?,
        })
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
    /// Every approval of one lineage (the `l` jump from a request).
    #[must_use]
    pub fn lineage(lineage_id: &str) -> Self {
        Self {
            states: vec![false; APPROVAL_STATES.len()],
            include_superseded: true,
            lineage: lineage_id.to_string(),
            ..Self::default()
        }
    }

    /// The filter panel pre-filled with these values.
    #[must_use]
    pub fn form(&self) -> Form {
        Form::new(vec![
            Field::choice("preset", "Preset", &PRESETS, self.preset),
            Field::multi("states", "State", &APPROVAL_STATES, &self.states),
            Field::multi("policies", "Policy", &POLICIES, &self.policies),
            Field::multi("origins", "Origin", &APPROVAL_ORIGINS, &self.origins),
            Field::text("after", "Expires after", &self.expires_after, 10).with_hint("YYYY-MM-DD"),
            Field::text("before", "Expires before", &self.expires_before, 10)
                .with_hint("YYYY-MM-DD"),
            Field::toggle("superseded", "Include superseded", self.include_superseded),
            Field::text("lineage", "Lineage id", &self.lineage, 64),
            Field::text("host", "Host UUID", &self.host, 36),
            Field::text("path", "Path contains", &self.path, MAX_TEXT),
            Field::text("product", "Product contains", &self.product, MAX_TEXT),
            Field::text("user", "User name", &self.user, MAX_TEXT),
            Field::text("sha", "Hash prefix", &self.sha_prefix, 96).with_hint("≥ 8 hex"),
            Field::text("text", "Free text", &self.text, MAX_TEXT),
        ])
    }

    /// Read the panel back; `None` (with inline errors set) when invalid.
    pub fn from_form(form: &mut Form) -> Option<Self> {
        form.clear_errors();
        let after = validated(form, "after", check::date);
        let before = validated(form, "before", check::date);
        let lineage = validated(form, "lineage", |v| check::id(v).map(|()| v.to_string()));
        let host = validated(form, "host", |v| check::uuid(v).map(|()| v.to_string()));
        let path = validated(form, "path", |v| check::text(v).map(|()| v.to_string()));
        let product = validated(form, "product", |v| check::text(v).map(|()| v.to_string()));
        let user = validated(form, "user", |v| check::text(v).map(|()| v.to_string()));
        let sha = validated(form, "sha", |v| {
            check::hash_prefix(v).map(|()| v.to_ascii_lowercase())
        });
        let text = validated(form, "text", |v| check::text(v).map(|()| v.to_string()));
        if let (Some(Some(a)), Some(Some(b))) = (after, before) {
            if a > b {
                form.set_error("before", "must not be before \"Expires after\"");
            }
        }
        if form.has_errors() {
            form.focus_first_error();
            return None;
        }
        Some(Self {
            preset: form.choice("preset"),
            states: form.checked("states"),
            policies: form.checked("policies"),
            origins: form.checked("origins"),
            expires_after: form.text("after").trim().to_string(),
            expires_before: form.text("before").trim().to_string(),
            include_superseded: form.toggled("superseded"),
            lineage: lineage?,
            host: host?,
            path: path?,
            product: product?,
            user: user?,
            sha_prefix: sha?,
            text: text?,
        })
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
    use crate::input::Key;

    fn set(form: &mut Form, key: &str, value: &str) {
        form.focus_on(key);
        form.paste(value);
    }

    #[test]
    fn invalid_filters_are_flagged_inline_and_never_built() {
        let mut form = RequestFilters::default().form();
        set(&mut form, "sha", "abc");
        set(&mut form, "from", "2026-02-30");
        set(&mut form, "host", "not-a-uuid");
        assert!(RequestFilters::from_form(&mut form).is_none());
        for key in ["sha", "from", "host"] {
            assert!(form.field(key).unwrap().error.is_some(), "{key}");
        }
        assert_eq!(
            form.fields[form.focus].key, "host",
            "focus on the first error"
        );

        let mut form = RequestFilters::default().form();
        set(&mut form, "from", "2026-10-14");
        set(&mut form, "to", "2026-10-01");
        assert!(RequestFilters::from_form(&mut form).is_none());
        assert!(form.field("to").unwrap().error.is_some());

        // 128 characters is the limit; the field refuses more.
        let mut form = RequestFilters::default().form();
        set(&mut form, "text", &"x".repeat(200));
        assert_eq!(form.text("text").chars().count(), MAX_TEXT);
    }

    #[test]
    fn request_filters_map_to_structured_fields() {
        let mut form = RequestFilters::default().form();
        set(&mut form, "path", "zoom");
        set(&mut form, "sha", "ABCDEF0123");
        set(&mut form, "from", "2026-10-01");
        set(&mut form, "to", "2026-10-14");
        form.focus_on("kind");
        form.handle(Key::Char(' '));
        form.focus_on("flags");
        form.handle(Key::Right); // user-writable path
        form.handle(Key::Char(' '));
        let f = RequestFilters::from_form(&mut form).unwrap();
        let r = f.to_request(false, "tok");
        assert_eq!(r.states, vec![1]);
        assert_eq!(r.kinds, vec![1]);
        assert_eq!(r.path_contains, "zoom");
        assert_eq!(r.bin_sha_prefix, "abcdef0123", "lowercased");
        assert_eq!(r.flags_any, RiskFlags::USER_WRITABLE_PATH);
        assert_eq!(
            r.submitted_after,
            timefmt::parse_date("2026-10-01").unwrap()
        );
        assert_eq!(
            r.submitted_before,
            timefmt::parse_date("2026-10-15").unwrap(),
            "inclusive end day"
        );
        assert_eq!(r.page.unwrap().page_token, "tok");
        assert!(f.summary().contains("path:zoom"));
    }

    #[test]
    fn approval_presets_map_to_server_fields() {
        let now = 1_791_936_000;
        let mut f = ApprovalFilters {
            preset: 1,
            ..ApprovalFilters::default()
        };
        let r = f.to_request(now, false, "");
        assert_eq!(
            (r.expires_after, r.expires_before),
            (now, now + 14 * 86_400)
        );
        f.preset = 2;
        let r = f.to_request(now, false, "");
        assert!(r.legacy_only && r.no_expiry_only);
        f.preset = 4;
        assert_eq!(f.to_request(now, false, "").policies, vec![2]);
        let l = ApprovalFilters::lineage("lin-1");
        let r = l.to_request(now, false, "");
        assert!(r.states.is_empty() && r.include_superseded);
        assert_eq!(r.lineage_id, "lin-1");

        let mut form = ApprovalFilters::default().form();
        set(&mut form, "lineage", "bad id");
        assert!(ApprovalFilters::from_form(&mut form).is_none());
    }

    #[test]
    fn warning_flags_skip_the_protected_bit() {
        let w = warning_flags(RiskFlags::PATH_PROTECTED | RiskFlags::UNSIGNED);
        assert_eq!(w, vec!["unsigned"]);
    }
}
