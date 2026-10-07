//! Autofix for an unset `allowlist.key`: name the platform-default key file
//! in the configuration file, so `mia allowlist-key fetch` (and `mia test
//! --fix`) can take a host from "every caller is denied" to working in one
//! command instead of a hand edit of `mia.toml` first.
//!
//! This is **not** a configuration default. [`crate::config`] keeps
//! `allowlist.key` defaultless — the trust anchor is never inferred from a
//! file at a well-known path. The path is written only:
//!
//! - by an explicit, privileged `mia` command (root, into a root-owned
//!   directory that is not group/other-writable; see
//!   [`super::require_privileged_at`]);
//! - after the key it names was fetched over the pinned channel and accepted
//!   (fingerprint verified, or `--yes`), see `super::apply`; a refused key
//!   leaves the configuration untouched;
//! - and the key's *content* is still verified on every load.
//!
//! The edit is surgical, so the operator's comments, ordering and every other
//! key survive byte for byte ([`set_allowlist_key`]): one `key = "…"` line is
//! inserted right below the existing `[allowlist]` header, or — when the file
//! has no `[allowlist]` table — one is appended. An `[allowlist]` table is
//! never duplicated. Forms a line edit cannot handle safely (dotted keys, an
//! inline table, a blank `key`, an ambiguous header) are refused with the
//! line to add by hand. Every edit is then *proven*: the result must parse
//! under the strict schema and differ from the original by exactly
//! `allowlist.key` and nothing else, or nothing is written.
//!
//! The write ([`ConfigFix::commit`]) goes through the wizard's own
//! [`crate::setup_apply::write_config`]: temp file + `fsync` + rename, mode
//! `0640` with the previous owner kept, a symlinked target refused, and a
//! `ConfigChanged { keys: ["allowlist.key"] }` record — names only — appended
//! to the local audit journal before the rename. The file is re-read first and
//! the edit abandoned if it changed since it was planned.

use std::path::{Component, Path, PathBuf};

use anyhow::Context as _;

use crate::config::Config;

/// Largest configuration file the autofix edits (the shipped template is
/// ~10 KiB).
pub const MAX_CONFIG_BYTES: u64 = 256 * 1024;

/// The comment placed above the inserted `key` line.
const PROVENANCE: &str =
    "# Set by `mia allowlist-key fetch`: the CMIS enrollment public key (trust anchor).";

/// The key file the autofix names: `allowlist.pub` — `allowlist-<env>.pub`
/// for a named environment — in the system configuration directory
/// ([`crate::config::system_config_dir`]). It is the path `mia setup`
/// suggests and the one the "not set" error message names.
#[must_use]
pub fn suggested_key_path(environment: Option<&str>) -> PathBuf {
    let name = environment.map_or_else(
        || "allowlist.pub".to_owned(),
        |env| format!("allowlist-{env}.pub"),
    );
    crate::config::system_config_dir().join(name)
}

/// A validated, not yet written edit of one configuration file that sets
/// `allowlist.key`.
#[derive(Debug, Clone)]
pub struct ConfigFix {
    config_path: PathBuf,
    key_path: PathBuf,
    /// The file as read when the fix was planned.
    original: String,
    /// The proven edit of `original`.
    edited: String,
}

impl ConfigFix {
    /// The configuration file the fix edits.
    #[must_use]
    pub fn config_path(&self) -> &Path {
        &self.config_path
    }

    /// The `allowlist.key` value the fix writes.
    #[must_use]
    pub fn key_path(&self) -> &Path {
        &self.key_path
    }

    /// The edited file content.
    #[must_use]
    pub fn edited(&self) -> &str {
        &self.edited
    }

    /// Write the edit: re-read the file and refuse if it changed since
    /// [`plan`], then the atomic, audited replace of
    /// [`crate::setup_apply::write_config`]. Returns the changed key names
    /// (`["allowlist.key"]`).
    ///
    /// # Errors
    ///
    /// The file changed or cannot be read; the staging, audit or rename
    /// failure. The file is then unchanged.
    pub fn commit(&self) -> anyhow::Result<Vec<String>> {
        let current = read_config(&self.config_path)?;
        anyhow::ensure!(
            current == self.original,
            "{} changed while the key was being fetched; it was not edited — re-run the command",
            self.config_path.display()
        );
        let existing = Config::from_toml(&self.original)
            .with_context(|| format!("parsing {}", self.config_path.display()))?;
        crate::setup_apply::write_config(&self.config_path, &self.edited, &existing)
            .with_context(|| format!("setting allowlist.key in {}", self.config_path.display()))
    }
}

/// Plan setting `allowlist.key = key_path` in the configuration file at
/// `config_path`, without writing anything. `Ok(None)` when the file already
/// sets a (non-blank) `allowlist.key`: the fix is idempotent.
///
/// `config_path` is made absolute; it must not contain `..` and must be a
/// regular file (a symlink is refused rather than edited through), at most
/// [`MAX_CONFIG_BYTES`].
///
/// # Errors
///
/// An unusable path or file, or an edit [`set_allowlist_key`] refuses.
pub fn plan(config_path: &Path, key_path: &Path) -> anyhow::Result<Option<ConfigFix>> {
    let config_path = std::path::absolute(config_path)
        .with_context(|| format!("resolving {}", config_path.display()))?;
    anyhow::ensure!(
        !config_path.components().any(|c| c == Component::ParentDir),
        "the configuration path {} must not contain `..`",
        config_path.display()
    );
    let original = read_config(&config_path)?;
    let edited = set_allowlist_key(&original, key_path)
        .with_context(|| format!("setting allowlist.key in {}", config_path.display()))?;
    Ok(edited.map(|edited| ConfigFix {
        config_path,
        key_path: key_path.to_path_buf(),
        original,
        edited,
    }))
}

/// Return `text` with `[allowlist] key = "<key_path>"` set, or `None` when it
/// already sets a non-blank `allowlist.key`.
///
/// The key line goes right below the single `[allowlist]` header, or a new
/// `[allowlist]` table is appended when the file has none; every other byte
/// is kept, including the file's line endings. The result is verified to
/// parse under the strict [`Config`] schema and to differ from `text` by
/// exactly `allowlist.key`.
///
/// # Errors
///
/// `text` does not parse; `allowlist` is written as dotted keys or an inline
/// table, has a blank `key`, or its header cannot be told apart; `key_path`
/// is not UTF-8; or the edit fails verification. Errors never quote the file.
pub fn set_allowlist_key(text: &str, key_path: &Path) -> anyhow::Result<Option<String>> {
    let key = key_path
        .to_str()
        .context("the allowlist.key path is not valid UTF-8")?;
    let before: toml::Table = toml::from_str(text)
        .map_err(|_| anyhow::anyhow!("the configuration does not parse as TOML"))?;
    Config::from_toml(text)
        .map_err(|_| anyhow::anyhow!("the configuration does not match the mia.toml schema"))?;
    let by_hand = format!("add `key = {}` under [allowlist] by hand", basic_str(key));

    let edited = match before.get("allowlist") {
        None => append_table(text, key),
        Some(toml::Value::Table(table)) => {
            match table.get("key") {
                Some(toml::Value::String(s)) if !s.trim().is_empty() => return Ok(None),
                Some(_) => anyhow::bail!(
                    "[allowlist] has a blank or non-string `key`; remove that line or {by_hand}"
                ),
                None => {}
            }
            let headers: Vec<usize> = lines(text)
                .enumerate()
                .filter(|(_, l)| is_allowlist_header(l))
                .map(|(i, _)| i)
                .collect();
            match headers.as_slice() {
                [one] => insert_after(text, *one, key),
                [] => anyhow::bail!(
                    "the allowlist table is written as dotted keys or an inline table, which this \
                     fix does not rewrite; {by_hand}"
                ),
                _ => anyhow::bail!(
                    "more than one line looks like an [allowlist] header (one may be inside a \
                     multi-line string); {by_hand}"
                ),
            }
        }
        Some(_) => anyhow::bail!("`allowlist` is not a table; {by_hand}"),
    };

    verify(&before, &edited, key, key_path).with_context(|| {
        format!(
            "internal: the edited configuration failed verification; nothing written — {by_hand}"
        )
    })?;
    Ok(Some(edited))
}

/// Prove `edited` is `before` plus `allowlist.key = key` and nothing else,
/// and that the daemon would resolve exactly `key_path` from it.
fn verify(before: &toml::Table, edited: &str, key: &str, key_path: &Path) -> anyhow::Result<()> {
    let after: toml::Table = toml::from_str(edited).context("the edit does not parse")?;
    let mut expected = before.clone();
    let table = expected
        .entry("allowlist")
        .or_insert(toml::Value::Table(toml::Table::new()));
    let toml::Value::Table(table) = table else {
        anyhow::bail!("`allowlist` is not a table");
    };
    table.insert("key".to_owned(), toml::Value::String(key.to_owned()));
    anyhow::ensure!(
        after == expected,
        "the edit changed more than allowlist.key"
    );
    let config = Config::from_toml(edited).context("the edit does not match the schema")?;
    anyhow::ensure!(
        config.allowlist_key() == Some(key_path),
        "the edit does not resolve to the intended allowlist.key"
    );
    Ok(())
}

/// The lines of `text`, each with its line ending.
fn lines(text: &str) -> impl Iterator<Item = &str> {
    text.split_inclusive('\n')
}

/// The line ending to use next to `line` (or, for `None`, in `text`).
fn line_ending(sample: &str) -> &'static str {
    if sample.contains("\r\n") {
        "\r\n"
    } else {
        "\n"
    }
}

/// The two lines the fix adds, each terminated by `eol`.
fn key_lines(key: &str, eol: &str) -> String {
    format!("{PROVENANCE}{eol}key = {}{eol}", basic_str(key))
}

/// Insert the key lines right after line `index` (the `[allowlist]` header).
fn insert_after(text: &str, index: usize, key: &str) -> String {
    let mut out = String::with_capacity(text.len() + 160);
    for (i, line) in lines(text).enumerate() {
        out.push_str(line);
        if i == index {
            let eol = if line.ends_with('\n') {
                line_ending(line)
            } else {
                // The header is the last line, without a line ending.
                let eol = line_ending(text);
                out.push_str(eol);
                eol
            };
            out.push_str(&key_lines(key, eol));
        }
    }
    out
}

/// Append a new `[allowlist]` table holding only the key.
fn append_table(text: &str, key: &str) -> String {
    let eol = line_ending(text);
    let mut out = String::with_capacity(text.len() + 160);
    out.push_str(text);
    if !out.is_empty() && !out.ends_with('\n') {
        out.push_str(eol);
    }
    if !out.is_empty() {
        out.push_str(eol);
    }
    out.push_str("[allowlist]");
    out.push_str(eol);
    out.push_str(&key_lines(key, eol));
    out
}

/// Whether `line` is a `[allowlist]` table header (`[allowlist]`,
/// `[ "allowlist" ]`, `['allowlist']`, optionally followed by a comment).
/// Array-of-tables headers and other tables do not count.
fn is_allowlist_header(line: &str) -> bool {
    let t = line.trim();
    let Some(rest) = t.strip_prefix('[') else {
        return false;
    };
    if rest.starts_with('[') {
        return false;
    }
    let Some(end) = rest.find(']') else {
        return false;
    };
    let name = rest[..end].trim();
    let after = rest[end + 1..].trim_start();
    matches!(name, "allowlist" | "\"allowlist\"" | "'allowlist'")
        && (after.is_empty() || after.starts_with('#'))
}

/// A TOML basic string (`"…"`) for `v`, escaped.
fn basic_str(v: &str) -> String {
    crate::setup::basic_str(v)
}

/// Read the configuration file defensively: a regular file (no symlink), at
/// most [`MAX_CONFIG_BYTES`], judged as the daemon judges it
/// ([`crate::system_dir::read_trusted`]), UTF-8.
fn read_config(path: &Path) -> anyhow::Result<String> {
    let meta = std::fs::symlink_metadata(path)
        .with_context(|| format!("inspecting {}", path.display()))?;
    anyhow::ensure!(
        !meta.file_type().is_symlink(),
        "{} is a symbolic link; refusing to edit the configuration through it (edit the link's \
         target, or pass it with --config)",
        path.display()
    );
    anyhow::ensure!(meta.is_file(), "{} is not a regular file", path.display());
    anyhow::ensure!(
        meta.len() <= MAX_CONFIG_BYTES,
        "{} is larger than {MAX_CONFIG_BYTES} bytes; set allowlist.key by hand",
        path.display()
    );
    let bytes = crate::system_dir::read_trusted(path)
        .with_context(|| format!("reading {}", path.display()))?;
    anyhow::ensure!(
        u64::try_from(bytes.len()).is_ok_and(|n| n <= MAX_CONFIG_BYTES),
        "{} grew past {MAX_CONFIG_BYTES} bytes while being read",
        path.display()
    );
    String::from_utf8(bytes).with_context(|| format!("{} is not UTF-8", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "/Library/Application Support/FerroGate/allowlist.pub";

    fn set(text: &str) -> anyhow::Result<Option<String>> {
        set_allowlist_key(text, Path::new(KEY))
    }

    fn headers(text: &str) -> usize {
        lines(text).filter(|l| is_allowlist_header(l)).count()
    }

    fn key_of(text: &str) -> Option<PathBuf> {
        Config::from_toml(text)
            .unwrap()
            .allowlist_key()
            .map(Path::to_path_buf)
    }

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("mia-config-fix-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir.canonicalize().unwrap()
    }

    fn journal(dir: &Path) -> Vec<String> {
        std::fs::read_to_string(dir.join(crate::audit_client::LOCAL_JOURNAL_NAME))
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    #[test]
    fn the_suggested_path_is_the_one_setup_suggests() {
        let dir = crate::config::system_config_dir();
        assert_eq!(suggested_key_path(None), dir.join("allowlist.pub"));
        assert_eq!(
            suggested_key_path(Some("prod")),
            dir.join("allowlist-prod.pub")
        );
    }

    #[test]
    fn an_existing_table_without_key_gets_the_key_and_keeps_everything_else() {
        let text = "# operator note\nlog = 'info'\n\n[allowlist]\n# keep me\n#key = '/x.pub'\n\
                    path = '/srv/al.cbor'\nmax_age_secs = 3600\n\n[attestation]\nbackend = 'host-key'\n";
        let edited = set(text).unwrap().unwrap();
        assert_eq!(headers(&edited), 1, "{edited}");
        assert_eq!(key_of(&edited).as_deref(), Some(Path::new(KEY)));
        // Purely additive: removing the two inserted lines gives the original.
        let added = key_lines(KEY, "\n");
        assert_eq!(edited.replacen(&added, "", 1), text);
        assert!(edited.contains("[allowlist]\n# Set by `mia allowlist-key fetch`"));
        let cfg = Config::from_toml(&edited).unwrap();
        assert_eq!(
            cfg.allowlist.path.as_deref(),
            Some(Path::new("/srv/al.cbor"))
        );
        assert_eq!(cfg.allowlist.max_age_secs, Some(3600));
        // Idempotent.
        assert_eq!(set(&edited).unwrap(), None);
    }

    #[test]
    fn a_file_without_the_table_gets_it_once_and_the_fix_is_idempotent() {
        for text in ["[cmis]\nendpoint = 'https://c:8443'\n", "log = 'info'", ""] {
            let edited = set(text).unwrap().unwrap();
            assert_eq!(headers(&edited), 1, "{edited:?}");
            assert!(edited.starts_with(text));
            assert_eq!(key_of(&edited).as_deref(), Some(Path::new(KEY)));
            assert_eq!(set(&edited).unwrap(), None, "second run changes nothing");
        }
    }

    #[test]
    fn the_shipped_template_is_fixed_in_place() {
        let text = include_str!("../../dist/mia.toml");
        let edited = set(text).unwrap().unwrap();
        assert_eq!(headers(&edited), 1);
        assert_eq!(key_of(&edited).as_deref(), Some(Path::new(KEY)));
        assert_eq!(edited.len(), text.len() + key_lines(KEY, "\n").len());
    }

    #[test]
    fn header_variants_and_line_endings_are_kept() {
        let text = "[ \"allowlist\" ]   # the allowlist\r\npath = '/x'\r\n";
        let edited = set(text).unwrap().unwrap();
        assert!(
            edited.starts_with("[ \"allowlist\" ]   # the allowlist\r\n# Set by"),
            "{edited:?}"
        );
        assert!(!edited.replace("\r\n", "").contains('\n'), "CRLF kept");
        assert_eq!(key_of(&edited).as_deref(), Some(Path::new(KEY)));
        // A header on the last line, without a newline.
        let edited = set("log = 'info'\n['allowlist']").unwrap().unwrap();
        assert_eq!(key_of(&edited).as_deref(), Some(Path::new(KEY)));
    }

    #[test]
    fn a_path_needing_escapes_round_trips() {
        let key = Path::new(r#"C:\ProgramData\FerroGate\allow"list.pub"#);
        let edited = set_allowlist_key("[allowlist]\n", key).unwrap().unwrap();
        assert_eq!(key_of(&edited).as_deref(), Some(key));
    }

    #[test]
    fn forms_a_line_edit_cannot_handle_are_refused() {
        for text in [
            "allowlist.path = '/x'\n",       // dotted keys
            "allowlist = { path = '/x' }\n", // inline table
            "[allowlist]\nkey = ''\n",       // blank key
            "[allowlist]\nkey = '   '\n",    // blank key
            "log = \"\"\"\n[allowlist]\n\"\"\"\n[allowlist]\npath = '/x'\n", // decoy header
            "not toml = = =",
            "[allowlist]\nbogus = 1\n", // not the schema
        ] {
            let err = set(text).unwrap_err();
            let msg = format!("{err:#}");
            assert!(!msg.contains("/x"), "never quotes the file: {msg}");
        }
        // An already-set key is left alone, even with dotted keys.
        assert_eq!(set("allowlist.key = '/k.pub'\n").unwrap(), None);
    }

    #[test]
    fn header_matching_is_exact() {
        assert!(is_allowlist_header("[allowlist]\n"));
        assert!(is_allowlist_header("  [ allowlist ] # c\r\n"));
        assert!(is_allowlist_header("['allowlist']"));
        assert!(!is_allowlist_header("[[allowlist]]"));
        assert!(!is_allowlist_header("[allowlist.sub]"));
        assert!(!is_allowlist_header("# [allowlist]"));
        assert!(!is_allowlist_header("[allowlist] x = 1"));
        assert!(!is_allowlist_header("[allowlists]"));
    }

    #[test]
    fn commit_writes_once_audits_names_only_and_is_idempotent() {
        let dir = scratch("commit");
        let config = dir.join("mia.toml");
        let key = dir.join("allowlist.pub");
        std::fs::write(
            &config,
            "[cmis]\nendpoint = 'https://c:8443'\n\n[allowlist]\n",
        )
        .unwrap();

        let fix = plan(&config, &key).unwrap().unwrap();
        assert_eq!(fix.config_path(), config);
        assert_eq!(fix.key_path(), key);
        assert_eq!(fix.commit().unwrap(), vec!["allowlist.key".to_owned()]);
        let text = std::fs::read_to_string(&config).unwrap();
        assert_eq!(text, fix.edited());
        assert_eq!(headers(&text), 1);
        assert_eq!(key_of(&text).as_deref(), Some(key.as_path()));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&config).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o640);
        }
        let lines = journal(&dir);
        assert_eq!(lines.len(), 1, "{lines:?}");
        let v: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();
        assert_eq!(v["event"]["type"], "ConfigChanged");
        assert_eq!(v["event"]["keys"], serde_json::json!(["allowlist.key"]));
        assert!(
            !lines[0].contains("allowlist.pub"),
            "names only: {}",
            lines[0]
        );

        // A second run plans nothing, writes nothing, audits nothing.
        assert!(plan(&config, &key).unwrap().is_none());
        assert_eq!(journal(&dir).len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_file_changed_after_planning_is_not_overwritten() {
        let dir = scratch("race");
        let config = dir.join("mia.toml");
        std::fs::write(&config, "[allowlist]\n").unwrap();
        let fix = plan(&config, &dir.join("allowlist.pub")).unwrap().unwrap();
        std::fs::write(&config, "[allowlist]\nmax_age_secs = 60\n").unwrap();
        let err = fix.commit().unwrap_err();
        assert!(format!("{err:#}").contains("changed"), "{err:#}");
        assert_eq!(
            std::fs::read_to_string(&config).unwrap(),
            "[allowlist]\nmax_age_secs = 60\n"
        );
        assert_eq!(journal(&dir), Vec::<String>::new());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_config_is_refused() {
        let dir = scratch("symlink");
        let real = dir.join("real.toml");
        std::fs::write(&real, "[allowlist]\n").unwrap();
        let link = dir.join("mia.toml");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let err = plan(&link, &dir.join("allowlist.pub")).unwrap_err();
        assert!(format!("{err:#}").contains("symbolic link"), "{err:#}");
        assert_eq!(std::fs::read_to_string(&real).unwrap(), "[allowlist]\n");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
