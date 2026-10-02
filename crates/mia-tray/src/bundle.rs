//! The diagnostics bundle for support tickets.
//!
//! Plain text, written only where the person chooses, containing only what
//! the tray already shows: the status snapshots (non-sensitive by
//! construction — no tokens, SVIDs, keys, pins or `jti`s), the `mia test
//! --json` result (which reports a minted token's size and expiry, never the
//! token), and the last records of the daemon's log buffer (redacted by the
//! daemon before they were buffered). Every daemon- or `mia`-provided string
//! is escaped again here, so the file cannot carry terminal escapes.

use std::io::Write as _;
use std::path::Path;

use mia_status_proto::{LogRecord, StatusSnapshot};

use crate::logview::render_record;
use crate::text::{display_safe_block, rfc3339_utc_ms, MAX_BLOCK_CHARS};

/// Log records included.
pub const BUNDLE_RECORDS: usize = 500;

/// Largest bundle written, in bytes.
pub const MAX_BUNDLE_BYTES: usize = 4 * 1024 * 1024;

/// What goes into a bundle.
#[derive(Debug, Clone, Default)]
pub struct BundleInput<'a> {
    /// Generation time, Unix ms.
    pub generated_at_ms: i64,
    /// `"macos aarch64"` etc.
    pub platform: String,
    /// Status snapshots.
    pub snapshots: &'a [StatusSnapshot],
    /// Where they came from (free text from the tray, e.g. "status endpoint").
    pub source: String,
    /// The `mia test --json` document, if one ran.
    pub self_test: Option<&'a serde_json::Value>,
    /// Why there is no self-test (when `self_test` is `None`).
    pub self_test_note: Option<String>,
    /// Recent log records (oldest first; the last [`BUNDLE_RECORDS`] are used).
    pub records: &'a [LogRecord],
}

/// Render the bundle.
#[must_use]
pub fn render(input: &BundleInput<'_>) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    out.push_str("FerroGate MIA diagnostics bundle\n");
    out.push_str("================================\n");
    let _ = write!(
        out,
        "generated: {}\ntray:      mia-tray {}\nplatform:  {}\nsource:    {}\n\n",
        rfc3339_utc_ms(input.generated_at_ms),
        crate::VERSION,
        display_safe_block(&input.platform, 128),
        display_safe_block(&input.source, 128),
    );
    out.push_str("## Status snapshots\n\n");
    let status = serde_json::to_string_pretty(input.snapshots).unwrap_or_default();
    out.push_str(&display_safe_block(&status, MAX_BLOCK_CHARS * 4));
    out.push_str("\n\n## Self-test (mia test --json)\n\n");
    match input.self_test {
        Some(doc) => {
            let text = serde_json::to_string_pretty(doc).unwrap_or_default();
            out.push_str(&display_safe_block(&text, MAX_BLOCK_CHARS * 4));
        }
        None => out.push_str(&display_safe_block(
            input.self_test_note.as_deref().unwrap_or("not run"),
            512,
        )),
    }
    let start = input.records.len().saturating_sub(BUNDLE_RECORDS);
    let _ = write!(
        out,
        "\n\n## Last {} log records (redacted by the agent)\n\n",
        input.records.len() - start
    );
    for r in &input.records[start..] {
        out.push_str(&render_record(r));
        out.push('\n');
    }
    if out.len() > MAX_BUNDLE_BYTES {
        let mut cut = MAX_BUNDLE_BYTES;
        while !out.is_char_boundary(cut) {
            cut -= 1;
        }
        out.truncate(cut);
        out.push_str("\n[truncated]\n");
    }
    out
}

/// Write `contents` to the path the person chose (created or replaced;
/// `0600` on Unix — it names hosts and identities).
pub fn write(path: &Path, contents: &str) -> std::io::Result<()> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    #[cfg(unix)]
    {
        // Also when replacing an existing file (the mode above applies only
        // on creation); through the handle, so no path is re-resolved.
        use std::os::unix::fs::PermissionsExt as _;
        f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    f.write_all(contents.as_bytes())?;
    f.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::synthesised;
    use mia_status_proto::{AgentState, Level};

    #[test]
    fn the_bundle_has_every_section_and_is_escaped() {
        let snaps = vec![synthesised(
            AgentState::CrlStale,
            "crl_stale",
            "stale\u{1b}[31m",
            0,
        )];
        let st =
            serde_json::json!({"passed": false, "checks": [{"id": "cmis_crl", "status": "FAIL"}]});
        let rec = LogRecord {
            seq: 1,
            ts_ms: 0,
            level: Level::Warn,
            target: "mia".into(),
            environment: None,
            message: "two\nlines".into(),
            fields: vec![],
        };
        let records = vec![rec; BUNDLE_RECORDS + 5];
        let text = render(&BundleInput {
            generated_at_ms: 0,
            platform: "macos aarch64".into(),
            snapshots: &snaps,
            source: "status endpoint".into(),
            self_test: Some(&st),
            self_test_note: None,
            records: &records,
        });
        assert!(text.contains("## Status snapshots"));
        assert!(text.contains("\"crl_stale\""));
        assert!(text.contains("\"cmis_crl\""));
        assert!(text.contains(&format!("## Last {BUNDLE_RECORDS} log records")));
        assert_eq!(text.matches("two\\nlines").count(), BUNDLE_RECORDS);
        assert!(!text.contains('\u{1b}'));
    }

    #[test]
    fn written_bundles_are_private() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("diag.txt");
        // A pre-existing, world-readable file is tightened when replaced.
        std::fs::write(&p, "old").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        write(&p, "x").unwrap();
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "x");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
}
