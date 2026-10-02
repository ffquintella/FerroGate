//! Reading `mia test --json` for display and for the diagnostics bundle.
//!
//! The document is `mia`'s (see `crates/mia/src/selftest.rs`): `{version,
//! config, environment, passed, failures, checks: [{id, step, status,
//! detail, hints, notes}]}`. It reports a test token's size and expiry,
//! never the token. Every string is escaped and bounded here before display.

use crate::text::display_safe;

/// Most checks shown.
pub const MAX_CHECKS: usize = 32;

/// One check, ready to display.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckLine {
    /// `[2/5] CMIS connection`.
    pub step: String,
    /// `ok`, `FAIL`, `skip`, `info`, `warn`.
    pub status: String,
    /// One-line detail.
    pub detail: String,
    /// Remediation hints and notes.
    pub hints: Vec<String>,
}

impl CheckLine {
    /// Whether this check failed.
    #[must_use]
    pub fn failed(&self) -> bool {
        self.status.eq_ignore_ascii_case("fail")
    }
}

/// A parsed self-test.
#[derive(Debug, Clone, PartialEq)]
pub struct SelfTest {
    /// All checks passed.
    pub passed: bool,
    /// The checks.
    pub checks: Vec<CheckLine>,
    /// The raw (validated JSON) document, for the bundle.
    pub document: serde_json::Value,
}

/// Parse `mia test --json` stdout (`mia` exits non-zero when a check fails but
/// still prints the document).
#[must_use]
pub fn parse(stdout: &[u8]) -> Option<SelfTest> {
    let document: serde_json::Value = serde_json::from_slice(stdout.trim_ascii()).ok()?;
    let passed = document.get("passed")?.as_bool()?;
    let text = |v: &serde_json::Value, k: &str, max: usize| {
        display_safe(
            v.get(k)
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default(),
            max,
        )
    };
    let list = |v: &serde_json::Value, k: &str| -> Vec<String> {
        v.get(k)
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
            .take(16)
            .filter_map(|h| h.as_str().map(|s| display_safe(s, 600)))
            .collect()
    };
    let checks = document
        .get("checks")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .take(MAX_CHECKS)
        .map(|c| {
            let mut hints = list(c, "notes");
            hints.extend(list(c, "hints"));
            CheckLine {
                step: text(c, "step", 80),
                status: text(c, "status", 8),
                detail: text(c, "detail", 600),
                hints,
            }
        })
        .collect();
    Some(SelfTest {
        passed,
        checks,
        document,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_self_test_document_is_parsed_and_escaped() {
        let doc = br#"{"version": "0.21.6", "config": null, "environment": null, "passed": false,
            "failures": ["CMIS connection"],
            "checks": [
              {"id": "configuration", "step": "[1/5] configuration", "status": "ok",
               "detail": "endpoint https://cmis:8443", "hints": [], "notes": []},
              {"id": "cmis_connection", "step": "[2/5] CMIS connection", "status": "FAIL",
               "detail": "dial failed\u001b[2J", "hints": ["check DNS"], "notes": ["SRV a:1 down"]}
            ]}"#;
        let st = parse(doc).unwrap();
        assert!(!st.passed);
        assert_eq!(st.checks.len(), 2);
        assert!(st.checks[1].failed() && !st.checks[0].failed());
        assert_eq!(st.checks[1].detail, "dial failed\\u{1b}[2J");
        assert_eq!(st.checks[1].hints, ["SRV a:1 down", "check DNS"]);
        assert_eq!(st.document["failures"][0], "CMIS connection");
        assert!(parse(b"FerroGate MIA self-test").is_none());
        assert!(parse(br#"{"checks": []}"#).is_none(), "passed is required");
    }
}
