//! The host-wide **default environment**: which environment serves the helper
//! API's well-known address (feature F08).
//!
//! One host can carry several environments — `mia.toml` plus any number of
//! `mia-<env>.toml` — and each serves the helper API on its own
//! environment-scoped address ([`crate::config::default_helper_socket`]). One
//! address is special: the *well-known* one local callers dial without any
//! configuration (Linux `/run/ferrogate/mia.sock`, macOS
//! `/Library/Application Support/FerroGate/run/mia.sock`, Windows
//! `\\.\pipe\ferrogate-mia`). By default `mia.toml` owns it. An operator can
//! hand it to a named environment instead:
//!
//! 1. `default_environment = "<env>"` in [`environments_file_path`]
//!    (`environments.toml` in the **system** config directory), or
//! 2. `FERROGATE_DEFAULT_ENVIRONMENT=<env>`, which wins over the file. A
//!    blank value explicitly clears the selection (`mia.toml` keeps the
//!    address) whatever the file says.
//!
//! Unset everywhere ⇒ exactly the historical behaviour. When set:
//!
//! - the selected environment serves the well-known address when its own
//!   `helper.socket` is unset (one listener: it no longer binds
//!   `mia-<env>.sock`);
//! - `mia.toml` **yields**: with `helper.socket` unset it falls back to
//!   [`crate::config::yielded_helper_socket`] (`mia.default.sock`), an address
//!   no environment name can produce;
//! - an explicit `helper.socket` naming the well-known address in any other
//!   environment is a load error ([`crate::config::Config::apply_default_selection`]):
//!   two identities never share one address.
//!
//! The selection is host policy, so only the root-owned *system* directory is
//! consulted — never the per-user one, which an unprivileged user could write.
//! It is resolved by every `mia` process the same way (daemon, `mia test`,
//! `mia setup`), and is a startup setting: a SIGHUP reload does not move a
//! bound listener. Everything here fails closed: an unreadable or malformed
//! file, an invalid or reserved name, or (in the daemon's serve-all mode) a
//! selection with no matching `mia-<env>.toml` is an error, never a silent
//! fallback to `mia.toml`.

use std::fmt;
use std::io::Read as _;
use std::path::{Path, PathBuf};

use anyhow::Context as _;
use serde::{Deserialize, Serialize};

use crate::config::DiscoveredConfig;

/// Environment variable that selects the default environment; wins over
/// [`environments_file_path`]. Blank ⇒ explicitly no selection.
pub const ENV_DEFAULT_ENVIRONMENT: &str = "FERROGATE_DEFAULT_ENVIRONMENT";

/// File name of the host-wide environments file in the system config
/// directory. Deliberately not `mia-*.toml`, so the serve-all discovery can
/// never mistake it for an environment configuration.
pub const ENVIRONMENTS_FILE_NAME: &str = "environments.toml";

/// Largest environments file accepted, in bytes. It holds one short key; the
/// bound keeps a corrupted or hostile file from being read without limit.
pub const MAX_ENVIRONMENTS_FILE_BYTES: u64 = 16 * 1024;

/// The reserved name that can never be selected: it is the label of the
/// `mia.toml` environment (`mia status -e default`,
/// [`crate::status::DEFAULT_ENVIRONMENT_LABEL`]), so selecting it would be
/// ambiguous. Leave the selection unset to keep `mia.toml` the default.
pub const RESERVED_ENVIRONMENT: &str = crate::status::DEFAULT_ENVIRONMENT_LABEL;

/// The host-wide environments file ([`ENVIRONMENTS_FILE_NAME`] in the OS
/// system config directory): Linux `/etc/ferrogate/environments.toml`, macOS
/// `/Library/Application Support/FerroGate/environments.toml`, Windows
/// `%ProgramData%\FerroGate\environments.toml`.
#[must_use]
pub fn environments_file_path() -> PathBuf {
    crate::config::system_config_dir().join(ENVIRONMENTS_FILE_NAME)
}

/// The parsed environments file. Unknown keys are rejected, so a typo is an
/// error rather than a silently ignored setting.
#[derive(Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct EnvironmentsFile {
    /// The environment that serves the well-known helper address. `None` or
    /// blank ⇒ `mia.toml` (the built-in default).
    pub default_environment: Option<String>,
}

/// Where a [`DefaultSelection`] came from, for logs and operator output.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum SelectionSource {
    /// Nothing selected anywhere: `mia.toml` is the default.
    #[default]
    BuiltIn,
    /// `default_environment` in this environments file.
    File(PathBuf),
    /// The [`ENV_DEFAULT_ENVIRONMENT`] variable.
    EnvVar,
}

impl fmt::Display for SelectionSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BuiltIn => f.write_str("built-in default"),
            Self::File(path) => write!(f, "default_environment in {}", path.display()),
            Self::EnvVar => write!(f, "${ENV_DEFAULT_ENVIRONMENT}"),
        }
    }
}

/// The resolved host-wide default-environment selection.
///
/// `environment() == None` ⇒ `mia.toml` owns the well-known helper address
/// (the historical behaviour); `Some(env)` ⇒ `mia-<env>.toml` does.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DefaultSelection {
    environment: Option<String>,
    source: SelectionSource,
}

impl DefaultSelection {
    /// No selection: `mia.toml` is the default environment.
    #[must_use]
    pub fn unset() -> Self {
        Self::default()
    }

    /// Resolve the selection for this host: [`ENV_DEFAULT_ENVIRONMENT`] if
    /// set, else [`environments_file_path`] if present, else unset.
    ///
    /// Fails closed: a non-Unicode variable, an unreadable, oversized or
    /// malformed file, or an invalid or reserved name is an error.
    pub fn load() -> anyhow::Result<Self> {
        let env_value = match std::env::var(ENV_DEFAULT_ENVIRONMENT) {
            Ok(v) => Some(v),
            Err(std::env::VarError::NotPresent) => None,
            Err(std::env::VarError::NotUnicode(_)) => {
                anyhow::bail!("{ENV_DEFAULT_ENVIRONMENT} is not valid Unicode")
            }
        };
        Self::resolve(&environments_file_path(), env_value)
    }

    /// The precedence core of [`Self::load`]: `env_value` (the variable, if
    /// set) wins over the file at `file`. Split out so tests need neither the
    /// process environment nor the OS config directory.
    pub(crate) fn resolve(file: &Path, env_value: Option<String>) -> anyhow::Result<Self> {
        let (raw, source) = if let Some(v) = env_value {
            (v, SelectionSource::EnvVar)
        } else {
            match read_environments_file(file)?.and_then(|f| f.default_environment) {
                Some(v) => (v, SelectionSource::File(file.to_path_buf())),
                None => return Ok(Self::unset()),
            }
        };
        let name = raw.trim();
        if name.is_empty() {
            // An explicit blank: mia.toml stays the default, and the source
            // is recorded so operators see *why*.
            return Ok(Self {
                environment: None,
                source,
            });
        }
        validate_selection(name)
            .with_context(|| format!("invalid default environment ({source})"))?;
        Ok(Self {
            environment: Some(name.to_owned()),
            source,
        })
    }

    /// A selection of `name` read from the environments file `file`, validated
    /// with [`validate_selection`] — what `file` will say once
    /// `mia default-environment set` has written it.
    pub(crate) fn selected_in_file(file: &Path, name: &str) -> anyhow::Result<Self> {
        validate_selection(name)?;
        Ok(Self {
            environment: Some(name.to_owned()),
            source: SelectionSource::File(file.to_path_buf()),
        })
    }

    /// The selected environment (`None` ⇒ `mia.toml`).
    #[must_use]
    pub fn environment(&self) -> Option<&str> {
        self.environment.as_deref()
    }

    /// Where the selection came from.
    #[must_use]
    pub fn source(&self) -> &SelectionSource {
        &self.source
    }

    /// Whether the environment `environment` (`None` ⇒ `mia.toml`) is the
    /// host's default environment — the one entitled to the well-known helper
    /// address.
    #[must_use]
    pub fn is_default(&self, environment: Option<&str>) -> bool {
        self.environment() == environment
    }

    /// The display label of the default environment: the environment name, or
    /// `default` for `mia.toml`.
    #[must_use]
    pub fn label(&self) -> &str {
        self.environment().unwrap_or(RESERVED_ENVIRONMENT)
    }

    /// In the daemon's serve-all mode, require the selected environment to be
    /// among the `discovered` configuration files. A selection naming a file
    /// that does not exist (usually a typo) must stop startup rather than
    /// leave the well-known address to nobody — or to the wrong environment.
    pub fn ensure_discovered(&self, discovered: &[DiscoveredConfig]) -> anyhow::Result<()> {
        let Some(env) = self.environment() else {
            return Ok(());
        };
        anyhow::ensure!(
            discovered
                .iter()
                .any(|d| d.environment.as_deref() == Some(env)),
            "the default environment `{env}` ({}) has no {} in the system or user config \
             directory; refusing to start rather than serve the well-known helper address from \
             another environment. Create that file, or clear the selection",
            self.source,
            crate::config::config_filename(Some(env)),
        );
        Ok(())
    }
}

/// Validate a selected name: a valid environment name
/// ([`mia_status_proto::validate_environment`]), at most
/// [`mia_status_proto::MAX_ENVIRONMENT_LEN`] long, and not
/// [`RESERVED_ENVIRONMENT`]. The name is echoed Debug-escaped, so a hostile
/// value cannot inject control characters into a log line or terminal.
///
/// The one rule for every way a selection enters: the variable, the file, and
/// `mia default-environment set`.
pub fn validate_selection(name: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        name.len() <= mia_status_proto::MAX_ENVIRONMENT_LEN,
        "the environment name is longer than {} bytes",
        mia_status_proto::MAX_ENVIRONMENT_LEN
    );
    mia_status_proto::validate_environment(name)
        .map_err(|e| anyhow::anyhow!("environment name {name:?} is invalid: {e}"))?;
    anyhow::ensure!(
        name != RESERVED_ENVIRONMENT,
        "`{RESERVED_ENVIRONMENT}` is reserved (it is the label of the mia.toml environment); \
         leave the selection unset to keep mia.toml the default environment"
    );
    Ok(())
}

/// The shipped `environments.toml` template: documentation only, it selects
/// nothing.
const ENVIRONMENTS_TEMPLATE: &str = include_str!("../dist/environments.toml");

/// Render the environments file that selects `environment` (`None` ⇒ no
/// selection: `mia.toml` is the default): the shipped template, plus the
/// `default_environment` key when one is selected. The value is serialised by
/// the TOML library, never spliced into the text by hand.
///
/// Fails if `environment` is not a valid selection ([`validate_selection`]),
/// or — an internal error — if the rendered text does not parse back to
/// exactly that selection.
pub fn render_environments_file(environment: Option<&str>) -> anyhow::Result<String> {
    let mut out = ENVIRONMENTS_TEMPLATE.to_owned();
    if let Some(env) = environment {
        validate_selection(env)?;
        if !out.ends_with('\n') {
            out.push('\n');
        }
        out.push_str("default_environment = ");
        out.push_str(&toml::Value::String(env.to_owned()).to_string());
        out.push('\n');
    }
    let parsed: EnvironmentsFile =
        toml::from_str(&out).context("internal: the rendered environments file does not parse")?;
    anyhow::ensure!(
        parsed.default_environment.as_deref() == environment,
        "internal: the rendered environments file does not select {environment:?}"
    );
    Ok(out)
}

/// Read and parse the environments file: `Ok(None)` when it does not exist;
/// an error when it exists but is not a regular file, exceeds
/// [`MAX_ENVIRONMENTS_FILE_BYTES`], cannot be read, or does not parse.
fn read_environments_file(path: &Path) -> anyhow::Result<Option<EnvironmentsFile>> {
    let meta = match std::fs::metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };
    anyhow::ensure!(meta.is_file(), "{} is not a regular file", path.display());
    let mut text = String::new();
    std::fs::File::open(path)
        .and_then(|f| {
            f.take(MAX_ENVIRONMENTS_FILE_BYTES + 1)
                .read_to_string(&mut text)
        })
        .with_context(|| format!("reading {}", path.display()))?;
    anyhow::ensure!(
        u64::try_from(text.len()).unwrap_or(u64::MAX) <= MAX_ENVIRONMENTS_FILE_BYTES,
        "{} is larger than {MAX_ENVIRONMENTS_FILE_BYTES} bytes",
        path.display()
    );
    toml::from_str(&text)
        .map(Some)
        .with_context(|| format!("parsing {}", path.display()))
}

/// Whether two helper listener addresses name the same listener. Windows pipe
/// names compare case-insensitively (and `\\?\` / `/` spellings are folded).
#[cfg(windows)]
#[must_use]
pub fn same_helper_address(a: &Path, b: &Path) -> bool {
    fn norm(p: &Path) -> String {
        let s = p.to_string_lossy().replace('/', "\\").to_ascii_lowercase();
        if let Some(rest) = s.strip_prefix(r"\\?\") {
            return format!(r"\\.\{rest}");
        }
        s
    }
    norm(a) == norm(b)
}

/// Whether two helper listener addresses name the same socket file:
/// component-wise equal, or equal file names in directories that canonicalize
/// to the same place (so `/var/run/ferrogate/mia.sock` matches
/// `/run/ferrogate/mia.sock` through the symlink). On macOS, whose default
/// file system is case-insensitive, names compare case-insensitively — an
/// over-approximation that can only reject more, never less.
#[cfg(not(windows))]
#[must_use]
pub fn same_helper_address(a: &Path, b: &Path) -> bool {
    fn fold(s: &std::ffi::OsStr) -> String {
        let s = s.to_string_lossy();
        if cfg!(target_os = "macos") {
            s.to_ascii_lowercase()
        } else {
            s.into_owned()
        }
    }
    if a == b || fold(a.as_os_str()) == fold(b.as_os_str()) {
        return true;
    }
    match (a.file_name(), b.file_name()) {
        (Some(x), Some(y)) if fold(x) == fold(y) => {}
        _ => return false,
    }
    let canonical_parent = |p: &Path| p.parent().and_then(|d| std::fs::canonicalize(d).ok());
    match (canonical_parent(a), canonical_parent(b)) {
        (Some(x), Some(y)) => fold(x.as_os_str()) == fold(y.as_os_str()),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("mia-defenv-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn unset_everywhere_is_the_builtin_default() {
        let dir = scratch("unset");
        let sel = DefaultSelection::resolve(&dir.join(ENVIRONMENTS_FILE_NAME), None).unwrap();
        assert_eq!(sel, DefaultSelection::unset());
        assert_eq!(sel.environment(), None);
        assert_eq!(sel.source(), &SelectionSource::BuiltIn);
        // mia.toml is the default environment; named ones are not.
        assert!(sel.is_default(None));
        assert!(!sel.is_default(Some("prod")));
        assert_eq!(sel.label(), "default");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn file_selects_and_env_var_overrides() {
        let dir = scratch("precedence");
        let file = dir.join(ENVIRONMENTS_FILE_NAME);
        std::fs::write(&file, "default_environment = \"prod\"\n").unwrap();

        // The file selects.
        let sel = DefaultSelection::resolve(&file, None).unwrap();
        assert_eq!(sel.environment(), Some("prod"));
        assert_eq!(sel.source(), &SelectionSource::File(file.clone()));
        assert!(sel.is_default(Some("prod")));
        assert!(!sel.is_default(None));

        // The variable wins over the file…
        let sel = DefaultSelection::resolve(&file, Some("staging".into())).unwrap();
        assert_eq!(sel.environment(), Some("staging"));
        assert_eq!(sel.source(), &SelectionSource::EnvVar);

        // …and a blank variable explicitly clears it (mia.toml again).
        let sel = DefaultSelection::resolve(&file, Some("  ".into())).unwrap();
        assert_eq!(sel.environment(), None);
        assert_eq!(sel.source(), &SelectionSource::EnvVar);
        assert!(sel.is_default(None));

        // The variable alone works without any file.
        let sel = DefaultSelection::resolve(&dir.join("absent.toml"), Some("qa".into())).unwrap();
        assert_eq!(sel.environment(), Some("qa"));

        // A blank or absent key in the file is no selection.
        std::fs::write(&file, "default_environment = \"\"\n").unwrap();
        assert_eq!(
            DefaultSelection::resolve(&file, None)
                .unwrap()
                .environment(),
            None
        );
        std::fs::write(&file, "# nothing selected\n").unwrap();
        assert_eq!(
            DefaultSelection::resolve(&file, None).unwrap(),
            DefaultSelection::unset()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn invalid_or_reserved_selections_fail_closed() {
        let dir = scratch("invalid");
        let absent = dir.join("absent.toml");
        for bad in ["../etc", "a/b", "a b", ".", "..", "default", "x\u{1b}[31m"] {
            assert!(
                DefaultSelection::resolve(&absent, Some(bad.into())).is_err(),
                "{bad:?} must be rejected"
            );
        }
        let long = "a".repeat(mia_status_proto::MAX_ENVIRONMENT_LEN + 1);
        assert!(DefaultSelection::resolve(&absent, Some(long)).is_err());

        // A bad value in the file is an error too, never a fallback.
        let file = dir.join(ENVIRONMENTS_FILE_NAME);
        std::fs::write(&file, "default_environment = \"../prod\"\n").unwrap();
        let err = DefaultSelection::resolve(&file, None).unwrap_err();
        assert!(format!("{err:#}").contains("environments.toml"), "{err:#}");

        // Unknown keys (a typo) and malformed TOML are rejected.
        std::fs::write(&file, "default_enviroment = \"prod\"\n").unwrap();
        assert!(DefaultSelection::resolve(&file, None).is_err());
        std::fs::write(&file, "default_environment = \n").unwrap();
        assert!(DefaultSelection::resolve(&file, None).is_err());

        // Oversized and non-regular files are rejected.
        let big = format!(
            "# {}\ndefault_environment = \"prod\"\n",
            "x".repeat(usize::try_from(MAX_ENVIRONMENTS_FILE_BYTES).unwrap())
        );
        std::fs::write(&file, big).unwrap();
        assert!(DefaultSelection::resolve(&file, None).is_err());
        let as_dir = dir.join("dir.toml");
        std::fs::create_dir_all(&as_dir).unwrap();
        assert!(DefaultSelection::resolve(&as_dir, None).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn serve_all_requires_the_selected_environment_file() {
        let discovered = vec![
            DiscoveredConfig {
                environment: None,
                path: PathBuf::from("/etc/ferrogate/mia.toml"),
            },
            DiscoveredConfig {
                environment: Some("prod".into()),
                path: PathBuf::from("/etc/ferrogate/mia-prod.toml"),
            },
        ];
        let absent = Path::new("/nonexistent/environments.toml");
        // Unset never requires anything (even with no files at all).
        DefaultSelection::unset()
            .ensure_discovered(&discovered)
            .unwrap();
        DefaultSelection::unset().ensure_discovered(&[]).unwrap();
        // A present selection passes; a missing one is a startup error.
        let prod = DefaultSelection::resolve(absent, Some("prod".into())).unwrap();
        prod.ensure_discovered(&discovered).unwrap();
        assert!(prod.ensure_discovered(&discovered[..1]).is_err());
        let typo = DefaultSelection::resolve(absent, Some("prdo".into())).unwrap();
        let err = typo.ensure_discovered(&discovered).unwrap_err();
        assert!(err.to_string().contains("mia-prdo.toml"), "{err}");
    }

    #[test]
    fn same_helper_address_folds_equivalent_spellings() {
        #[cfg(not(windows))]
        {
            assert!(same_helper_address(
                Path::new("/run/ferrogate/mia.sock"),
                Path::new("/run//ferrogate/mia.sock/")
            ));
            assert!(!same_helper_address(
                Path::new("/run/ferrogate/mia.sock"),
                Path::new("/run/ferrogate/mia-prod.sock")
            ));
            // Through a symlinked directory.
            let dir = scratch("same-addr");
            let real = dir.join("real");
            std::fs::create_dir_all(&real).unwrap();
            let link = dir.join("link");
            std::os::unix::fs::symlink(&real, &link).unwrap();
            assert!(same_helper_address(
                &real.join("mia.sock"),
                &link.join("mia.sock")
            ));
            assert!(!same_helper_address(
                &real.join("mia.sock"),
                &link.join("other.sock")
            ));
            let _ = std::fs::remove_dir_all(&dir);
        }
        #[cfg(windows)]
        {
            assert!(same_helper_address(
                Path::new(r"\\.\pipe\ferrogate-mia"),
                Path::new(r"\\?\PIPE\FerroGate-MIA")
            ));
            assert!(!same_helper_address(
                Path::new(r"\\.\pipe\ferrogate-mia"),
                Path::new(r"\\.\pipe\ferrogate-mia-prod")
            ));
        }
    }

    #[test]
    fn shipped_environments_template_selects_nothing() {
        let template = include_str!("../dist/environments.toml");
        let parsed: EnvironmentsFile = toml::from_str(template).unwrap();
        assert_eq!(parsed, EnvironmentsFile::default());
    }

    #[test]
    fn rendered_environments_files_round_trip_through_the_loader() {
        let dir = scratch("render");
        let file = dir.join(ENVIRONMENTS_FILE_NAME);
        // No selection: the template itself.
        let none = render_environments_file(None).unwrap();
        assert_eq!(none, ENVIRONMENTS_TEMPLATE);
        std::fs::write(&file, &none).unwrap();
        assert_eq!(
            DefaultSelection::resolve(&file, None).unwrap(),
            DefaultSelection::unset()
        );
        // A selection: the template plus exactly one key, read back as such.
        let prod = render_environments_file(Some("prod")).unwrap();
        assert!(prod.starts_with(ENVIRONMENTS_TEMPLATE));
        assert!(
            prod.ends_with("\ndefault_environment = \"prod\"\n"),
            "{prod}"
        );
        std::fs::write(&file, &prod).unwrap();
        let sel = DefaultSelection::resolve(&file, None).unwrap();
        assert_eq!(sel.environment(), Some("prod"));
        assert_eq!(
            sel,
            DefaultSelection::selected_in_file(&file, "prod").unwrap()
        );
        // The shared validator guards the renderer too.
        for bad in ["default", "../x", "a\"b", "a\nb", ""] {
            assert!(render_environments_file(Some(bad)).is_err(), "{bad:?}");
            assert!(
                DefaultSelection::selected_in_file(&file, bad).is_err(),
                "{bad:?}"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
