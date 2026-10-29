//! The search and filter panel (F21 §5), mapped one-to-one to the structured
//! fields of `ListAppRequests` and `ListApprovals` (F19 §7.5).
//!
//! The filter values, their checks and the listing requests are shared with
//! the tray admin client (`ferrogate_admin_client::approvals::filters`,
//! T283); this module draws them as the TUI's panel ([`FilterForm`]).

//! Values are validated inline and an invalid panel is never sent. Filters
//! travel as separate protobuf fields; the server binds them as SQL
//! parameters.

#[cfg(test)]
use ferro_appid::flags::RiskFlags;

pub use ferrogate_admin_client::approvals::filters::{
    check, warning_flags, ApprovalFilters, RequestFilters, APPROVAL_ORIGINS, APPROVAL_STATES,
    FLAG_NAMES, MAX_TEXT, PAGE_SIZE, POLICIES, PRESETS, REQUEST_KINDS, REQUEST_ORIGINS,
    REQUEST_STATES,
};

use super::form::{Field, Form};
#[cfg(test)]
use crate::timefmt;

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

/// The TUI's filter panel over a set of filters.
pub trait FilterForm: Sized {
    /// The filter panel pre-filled with these values.
    #[must_use]
    fn form(&self) -> Form;

    /// Read the panel back; `None` (with inline errors set) when invalid.
    fn from_form(form: &mut Form) -> Option<Self>;
}

impl FilterForm for RequestFilters {
    fn form(&self) -> Form {
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

    fn from_form(form: &mut Form) -> Option<Self> {
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
}

impl FilterForm for ApprovalFilters {
    fn form(&self) -> Form {
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

    fn from_form(form: &mut Form) -> Option<Self> {
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
