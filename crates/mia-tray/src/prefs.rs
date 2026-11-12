//! The tray's per-user preferences (F23 §5): the UI language override and
//! nothing else — no secret, no personal data, a tag from a closed set.
//!
//! The file sits beside the admin client's `admin.toml` (same directory
//! rule). Reading is bounded and forgiving; writing is atomic and
//! owner-only. [`LANG_ENV`] overrides the file.

use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};

use crate::i18n::Lang;

/// The file's name.
pub const FILE_NAME: &str = "mia-tray.toml";
/// Largest preference file read, in bytes.
pub const MAX_BYTES: u64 = 4096;
/// The variable that overrides the language (`en`, `pt-BR`, `es`, …).
pub const LANG_ENV: &str = "MIA_TRAY_LANG";

/// The preferences.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Prefs {
    /// The language chosen in the window; `None` follows the system.
    pub language: Option<Lang>,
}

/// The file as written (unknown keys are ignored for forward compatibility).
#[derive(serde::Deserialize)]
struct Raw {
    language: Option<String>,
}

/// The per-user directory for `os` (`std::env::consts::OS` values), from
/// the injected environment; `None` without a usable (absolute) home.
#[must_use]
pub fn user_dir(os: &str, env: &dyn Fn(&str) -> Option<String>) -> Option<PathBuf> {
    // A relative "home" would resolve against the start directory.
    let var = |k: &str| {
        env(k)
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
    };
    match os {
        "macos" => var("HOME").map(|h| h.join("Library/Application Support/FerroGate")),
        "windows" => var("APPDATA").map(|a| a.join("FerroGate")),
        _ => var("XDG_CONFIG_HOME")
            .map(|d| d.join("ferrogate"))
            .or_else(|| var("HOME").map(|h| h.join(".config/ferrogate"))),
    }
}

/// The preference file for `os` and `env`.
#[must_use]
pub fn path(os: &str, env: &dyn Fn(&str) -> Option<String>) -> Option<PathBuf> {
    user_dir(os, env).map(|d| d.join(FILE_NAME))
}

/// This user's preference file.
#[must_use]
pub fn user_path() -> Option<PathBuf> {
    path(std::env::consts::OS, &|k| std::env::var(k).ok())
}

/// Parse the file's text (forgiving: anything unusable is no preference).
#[must_use]
pub fn parse(text: &str) -> Prefs {
    match toml::from_str::<Raw>(text) {
        Ok(raw) => Prefs {
            language: raw.language.as_deref().and_then(Lang::from_tag),
        },
        Err(e) => {
            tracing::debug!(error = %e, "ignoring an unreadable preference file");
            Prefs::default()
        }
    }
}

/// Read `path` (missing, oversized or unreadable: the defaults).
#[must_use]
pub fn load(path: &Path) -> Prefs {
    let Ok(file) = std::fs::File::open(path) else {
        return Prefs::default();
    };
    let mut text = String::new();
    // One byte more than allowed tells an oversized file apart.
    match file.take(MAX_BYTES + 1).read_to_string(&mut text) {
        Ok(n) if u64::try_from(n).unwrap_or(u64::MAX) <= MAX_BYTES => parse(&text),
        Ok(_) => {
            tracing::debug!("ignoring an oversized preference file");
            Prefs::default()
        }
        Err(e) => {
            tracing::debug!(error = %e, "ignoring an unreadable preference file");
            Prefs::default()
        }
    }
}

/// The file's text for `prefs` (the tag comes from a closed set, so nothing
/// typed reaches the file).
#[must_use]
pub fn render(prefs: &Prefs) -> String {
    let mut out = String::from("# FerroGate MIA tray preferences (written by the tray).\n");
    if let Some(lang) = prefs.language {
        out.push_str("language = \"");
        out.push_str(lang.code());
        out.push_str("\"\n");
    }
    out
}

/// Write `prefs` to `path`: the directory is created (`0700` on Unix), then
/// the file is replaced atomically, readable by its owner only.
///
/// # Errors
/// Any I/O error creating the directory or writing the file.
pub fn save(path: &Path, prefs: &Prefs) -> std::io::Result<()> {
    let dir = path.parent().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "no parent directory")
    })?;
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    builder.create(dir)?;
    // `tempfile` creates the file `0600` on Unix and owner-only on Windows.
    let mut tmp = tempfile::NamedTempFile::new_in(dir)?;
    tmp.write_all(render(prefs).as_bytes())?;
    tmp.as_file().sync_all()?;
    tmp.persist(path).map_err(|e| e.error)?;
    Ok(())
}

/// The language from the override variable, the preferences, the locale
/// variables and the OS locale, in that order ([`Lang::resolve`]).
#[must_use]
pub fn resolve_lang(
    prefs: &Prefs,
    env: impl Fn(&str) -> Option<String>,
    os_locale: Option<String>,
) -> Lang {
    let forced = env(LANG_ENV).as_deref().and_then(Lang::from_tag);
    Lang::resolve(forced.or(prefs.language), env, os_locale)
}

/// This user's language now.
#[must_use]
pub fn effective_lang() -> Lang {
    let prefs = user_path().map(|p| load(&p)).unwrap_or_default();
    resolve_lang(&prefs, |k| std::env::var(k).ok(), sys_locale::get_locale())
}

/// The modification time of `path`, to notice another process's change.
#[must_use]
pub fn stamp(path: &Path) -> Option<std::time::SystemTime> {
    std::fs::metadata(path).and_then(|m| m.modified()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &'static [(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> {
        move |k: &str| {
            pairs
                .iter()
                .find(|(n, _)| *n == k)
                .map(|(_, v)| (*v).to_string())
        }
    }

    #[test]
    fn the_file_lives_in_the_per_user_directory() {
        let e = env(&[("HOME", "/home/a")]);
        assert_eq!(
            path("linux", &e),
            Some(PathBuf::from("/home/a/.config/ferrogate/mia-tray.toml"))
        );
        assert_eq!(
            path("macos", &e),
            Some(PathBuf::from(
                "/home/a/Library/Application Support/FerroGate/mia-tray.toml"
            ))
        );
        let xdg = env(&[("XDG_CONFIG_HOME", "/x"), ("HOME", "/home/a")]);
        assert_eq!(
            path("linux", &xdg),
            Some(PathBuf::from("/x/ferrogate/mia-tray.toml"))
        );
        // No home, or a relative one: no file.
        assert_eq!(path("linux", &env(&[])), None);
        assert_eq!(path("linux", &env(&[("HOME", "rel/home")])), None);
    }

    #[test]
    fn a_saved_language_reads_back_and_the_file_is_private() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("nested/ferrogate").join(FILE_NAME);
        let prefs = Prefs {
            language: Some(Lang::Es),
        };
        save(&p, &prefs).unwrap();
        assert_eq!(load(&p), prefs);
        save(&p, &Prefs::default()).unwrap();
        assert_eq!(load(&p), Prefs::default());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[test]
    fn unusable_files_are_ignored() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(load(&dir.path().join("absent.toml")), Prefs::default());
        let p = dir.path().join(FILE_NAME);
        std::fs::write(&p, "language = [").unwrap();
        assert_eq!(load(&p), Prefs::default());
        std::fs::write(&p, "language = \"klingon\"\n").unwrap();
        assert_eq!(load(&p), Prefs::default());
        // Oversized, even if valid.
        let filler = "x".repeat(usize::try_from(MAX_BYTES).unwrap());
        std::fs::write(&p, format!("language = \"pt-BR\"\n#{filler}\n")).unwrap();
        assert_eq!(load(&p), Prefs::default());
        // Unknown keys are tolerated.
        std::fs::write(&p, "language = \"pt-BR\"\ntheme = \"dark\"\n").unwrap();
        assert_eq!(load(&p).language, Some(Lang::Pt));
    }

    #[test]
    fn the_override_variable_then_the_file_then_the_locale() {
        let file = Prefs {
            language: Some(Lang::Pt),
        };
        let locale_es = env(&[("LANG", "es_ES.UTF-8")]);
        assert_eq!(resolve_lang(&file, &locale_es, None), Lang::Pt);
        assert_eq!(resolve_lang(&Prefs::default(), &locale_es, None), Lang::Es);
        let forced = env(&[(LANG_ENV, "en"), ("LANG", "es_ES.UTF-8")]);
        assert_eq!(resolve_lang(&file, &forced, None), Lang::En);
        // A bogus override is ignored.
        let bogus = env(&[(LANG_ENV, "xx"), ("LANG", "es_ES.UTF-8")]);
        assert_eq!(resolve_lang(&Prefs::default(), &bogus, None), Lang::Es);
    }
}
