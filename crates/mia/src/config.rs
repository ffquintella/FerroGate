//! `mia` configuration file (TOML) and its merge with the environment.
//!
//! Historically MIA was configured entirely by environment variable (the
//! systemd `EnvironmentFile` at `/etc/ferrogate/mia.env`). This module adds an
//! optional structured TOML configuration file while keeping that path working
//! unchanged.
//!
//! ## Precedence
//!
//! Lowest to highest:
//!
//! 1. built-in defaults (e.g. socket mode `660`, allowlist max-age `86400`);
//! 2. the TOML configuration file, if one is found;
//! 3. environment variables (`FERROGATE_*`, `RUST_LOG`).
//!
//! So an explicitly-set environment variable always wins over the file — the
//! more specific source overrides the more general one — and a deployment that
//! sets everything via env behaves exactly as before (no file required).
//!
//! ## Discovery
//!
//! [`Config::load`] resolves the file in this order:
//!
//! 1. an explicit path (`--config <path>` / [`Config::load`]'s argument):
//!    must exist, else a hard error;
//! 2. `$FERROGATE_CONFIG`: if set, must exist, else a hard error;
//! 3. the OS [`system_config_path`], then the [`user_config_path`]: each loaded
//!    if present, silently skipped if absent (so env-only deployments are
//!    unaffected).
//!
//! ## Per-OS locations
//!
//! | OS | system path | user path |
//! |----|-------------|-----------|
//! | Linux | `/etc/ferrogate/mia.toml` | `$XDG_CONFIG_HOME/ferrogate/mia.toml` (or `~/.config/...`) |
//! | macOS | `/Library/Application Support/FerroGate/mia.toml` | `~/Library/Application Support/FerroGate/mia.toml` |
//! | Windows | `%ProgramData%\FerroGate\mia.toml` | `%APPDATA%\FerroGate\mia.toml` |
//!
//! See `crates/mia/dist/mia.toml` for a documented example.

use std::path::{Path, PathBuf};

use anyhow::Context as _;
use serde::Deserialize;

/// Environment variable naming an explicit configuration file.
pub const ENV_CONFIG: &str = "FERROGATE_CONFIG";

/// The OS-idiomatic *system* configuration path (writable by root/admin),
/// where a system service / daemon / launchd job looks: macOS
/// `/Library/Application Support/FerroGate/mia.toml`.
#[cfg(target_os = "macos")]
#[must_use]
pub fn system_config_path() -> PathBuf {
    PathBuf::from("/Library/Application Support/FerroGate/mia.toml")
}

/// The OS-idiomatic *system* configuration path: Windows
/// `%ProgramData%\FerroGate\mia.toml`.
#[cfg(windows)]
#[must_use]
pub fn system_config_path() -> PathBuf {
    std::env::var_os("ProgramData")
        .map_or_else(|| PathBuf::from(r"C:\ProgramData"), PathBuf::from)
        .join("FerroGate")
        .join("mia.toml")
}

/// The OS-idiomatic *system* configuration path: Linux/other Unix
/// `/etc/ferrogate/mia.toml`.
#[cfg(not(any(target_os = "macos", windows)))]
#[must_use]
pub fn system_config_path() -> PathBuf {
    PathBuf::from("/etc/ferrogate/mia.toml")
}

/// The OS-idiomatic *per-user* configuration path (no elevation needed), or
/// `None` if the relevant home/config environment variable is unset: macOS
/// `~/Library/Application Support/FerroGate/mia.toml`.
#[cfg(target_os = "macos")]
#[must_use]
pub fn user_config_path() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .map(|h| PathBuf::from(h).join("Library/Application Support/FerroGate/mia.toml"))
}

/// The OS-idiomatic *per-user* configuration path: Windows
/// `%APPDATA%\FerroGate\mia.toml`.
#[cfg(windows)]
#[must_use]
pub fn user_config_path() -> Option<PathBuf> {
    std::env::var_os("APPDATA").map(|a| PathBuf::from(a).join("FerroGate").join("mia.toml"))
}

/// The OS-idiomatic *per-user* configuration path: Linux/other Unix
/// `$XDG_CONFIG_HOME/ferrogate/mia.toml` (or `~/.config/ferrogate/mia.toml`).
#[cfg(not(any(target_os = "macos", windows)))]
#[must_use]
pub fn user_config_path() -> Option<PathBuf> {
    if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
        return Some(PathBuf::from(xdg).join("ferrogate").join("mia.toml"));
    }
    std::env::var_os("HOME").map(|h| {
        PathBuf::from(h)
            .join(".config")
            .join("ferrogate")
            .join("mia.toml")
    })
}

/// Default helper-socket mode when unset (`0o660`).
pub const DEFAULT_SOCKET_MODE: u32 = 0o660;

/// Default maximum accepted allowlist age, in seconds.
pub const DEFAULT_ALLOWLIST_MAX_AGE_SECS: i64 = 86_400;

/// The fully parsed configuration. Every value is optional: an absent value
/// falls back to its built-in default at the point of use.
#[derive(Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Tracing verbosity (tracing `EnvFilter` syntax); maps to `RUST_LOG`.
    pub log: Option<String>,
    /// CMIS server connection.
    pub cmis: CmisConfig,
    /// Local helper API.
    pub helper: HelperConfig,
    /// Signed caller allowlist.
    pub allowlist: AllowlistConfig,
    /// Attestation inputs.
    pub attestation: AttestationConfig,
}

/// `[cmis]` — the Central Machine Identity Service to attest to.
#[derive(Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CmisConfig {
    /// `https://host:port` endpoint (`https` ⇒ hybrid-PQC TLS, SPKI-pinned).
    pub endpoint: Option<String>,
    /// Accepted CMIS SPKI pin (lowercase-hex SHA-384).
    pub spki_pin: Option<String>,
}

/// `[helper]` — the local helper-API listening surface (feature F08).
#[derive(Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HelperConfig {
    /// Helper listener address — the Unix-socket path (Linux/macOS) or the
    /// named-pipe name (Windows, e.g. `\\.\pipe\ferrogate-mia`). Its presence
    /// ENABLES the helper API.
    pub socket: Option<PathBuf>,
    /// **Unix only.** Octal socket mode as a string (e.g. `"660"`); default
    /// [`DEFAULT_SOCKET_MODE`].
    pub socket_mode: Option<String>,
    /// **Windows only.** Local group whose members may open the pipe (e.g.
    /// `FerroGateClients`). `None` ⇒ the pipe's default DACL applies.
    pub windows_group: Option<String>,
}

/// `[allowlist]` — the signed CBOR allowlist of vetted local callers.
#[derive(Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AllowlistConfig {
    /// Path to the signed CBOR allowlist. Absent ⇒ deny every caller.
    pub path: Option<PathBuf>,
    /// Trusted CMIS enrollment public key used to verify the allowlist.
    pub key: Option<PathBuf>,
    /// Maximum accepted allowlist age in seconds; default
    /// [`DEFAULT_ALLOWLIST_MAX_AGE_SECS`].
    pub max_age_secs: Option<i64>,
}

/// `[attestation]` — attestation inputs.
#[derive(Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AttestationConfig {
    /// Override the IMA runtime-measurement log path.
    pub ima_log: Option<PathBuf>,
}

impl Config {
    /// Discover, parse, and env-overlay the configuration.
    ///
    /// `explicit` is the `--config <path>` value, if any. Returns the merged
    /// configuration and the path actually loaded (`None` ⇒ no file, env/defaults
    /// only).
    pub fn load(explicit: Option<&Path>) -> anyhow::Result<(Self, Option<PathBuf>)> {
        let (mut config, source) = Self::load_file(explicit)?;
        config.apply_env()?;
        Ok((config, source))
    }

    /// Resolve and parse the file portion only (no env overlay). Exposed for
    /// testing; [`Config::load`] is the real entry point.
    fn load_file(explicit: Option<&Path>) -> anyhow::Result<(Self, Option<PathBuf>)> {
        // 1) explicit --config: must exist.
        if let Some(path) = explicit {
            let cfg = Self::from_path(path)
                .with_context(|| format!("loading config file {}", path.display()))?;
            return Ok((cfg, Some(path.to_path_buf())));
        }
        // 2) $FERROGATE_CONFIG: if set, must exist.
        if let Some(env_path) = std::env::var_os(ENV_CONFIG) {
            let path = PathBuf::from(env_path);
            let cfg = Self::from_path(&path)
                .with_context(|| format!("loading {ENV_CONFIG}={}", path.display()))?;
            return Ok((cfg, Some(path)));
        }
        // 3) OS system path, then per-user path: load the first that exists,
        //    else fall back to env/defaults.
        let candidates = [Some(system_config_path()), user_config_path()];
        for path in candidates.into_iter().flatten() {
            if path.exists() {
                let cfg = Self::from_path(&path)
                    .with_context(|| format!("loading config file {}", path.display()))?;
                return Ok((cfg, Some(path)));
            }
        }
        Ok((Self::default(), None))
    }

    /// Parse a TOML configuration file from `path`.
    fn from_path(path: &Path) -> anyhow::Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        Self::from_toml(&text)
    }

    /// Parse a configuration from a TOML string.
    pub fn from_toml(text: &str) -> anyhow::Result<Self> {
        toml::from_str(text).context("parsing TOML configuration")
    }

    /// Overlay environment variables onto `self` (env wins). Reads the process
    /// environment.
    pub fn apply_env(&mut self) -> anyhow::Result<()> {
        self.apply_overrides(|k| std::env::var(k).ok())
    }

    /// Overlay overrides resolved by `get` onto `self`. Factored out so tests
    /// can supply a map instead of mutating the global environment.
    fn apply_overrides(&mut self, get: impl Fn(&str) -> Option<String>) -> anyhow::Result<()> {
        if let Some(v) = get("RUST_LOG") {
            self.log = Some(v);
        }
        if let Some(v) = get("FERROGATE_CMIS_ENDPOINT") {
            self.cmis.endpoint = Some(v);
        }
        if let Some(v) = get("FERROGATE_CMIS_SPKI_PIN") {
            self.cmis.spki_pin = Some(v);
        }
        if let Some(v) = get("FERROGATE_HELPER_SOCKET") {
            self.helper.socket = Some(PathBuf::from(v));
        }
        if let Some(v) = get("FERROGATE_HELPER_SOCKET_MODE") {
            self.helper.socket_mode = Some(v);
        }
        if let Some(v) = get("FERROGATE_HELPER_WINDOWS_GROUP") {
            self.helper.windows_group = Some(v);
        }
        if let Some(v) = get("FERROGATE_ALLOWLIST") {
            self.allowlist.path = Some(PathBuf::from(v));
        }
        if let Some(v) = get("FERROGATE_ALLOWLIST_KEY") {
            self.allowlist.key = Some(PathBuf::from(v));
        }
        if let Some(v) = get("FERROGATE_ALLOWLIST_MAX_AGE_SECS") {
            let n: i64 = v
                .parse()
                .context("FERROGATE_ALLOWLIST_MAX_AGE_SECS is not an integer")?;
            self.allowlist.max_age_secs = Some(n);
        }
        if let Some(v) = get("FERROGATE_IMA_LOG") {
            self.attestation.ima_log = Some(PathBuf::from(v));
        }
        Ok(())
    }

    // ── Resolved accessors (apply built-in defaults) ────────────────────────

    /// The tracing filter directive (`log`, else `info`).
    #[must_use]
    pub fn log_directive(&self) -> &str {
        self.log.as_deref().unwrap_or("info")
    }

    /// The helper socket path, if the helper API is enabled.
    #[must_use]
    pub fn helper_socket(&self) -> Option<&Path> {
        self.helper.socket.as_deref()
    }

    /// The helper socket mode, parsed as octal; default [`DEFAULT_SOCKET_MODE`].
    pub fn socket_mode(&self) -> anyhow::Result<u32> {
        match &self.helper.socket_mode {
            Some(s) => u32::from_str_radix(s.trim().trim_start_matches("0o"), 8)
                .with_context(|| format!("helper.socket_mode {s:?} is not an octal mode")),
            None => Ok(DEFAULT_SOCKET_MODE),
        }
    }

    /// The maximum accepted allowlist age; default
    /// [`DEFAULT_ALLOWLIST_MAX_AGE_SECS`].
    #[must_use]
    pub fn allowlist_max_age(&self) -> i64 {
        self.allowlist
            .max_age_secs
            .unwrap_or(DEFAULT_ALLOWLIST_MAX_AGE_SECS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn config_paths_are_os_appropriate() {
        let sys = system_config_path();
        let sys = sys.to_string_lossy();
        #[cfg(target_os = "macos")]
        assert!(sys.contains("/Library/Application Support/FerroGate/"));
        #[cfg(windows)]
        assert!(sys.contains("FerroGate"));
        #[cfg(all(unix, not(target_os = "macos")))]
        assert_eq!(sys, "/etc/ferrogate/mia.toml");
        // The user path ends in the same file name when resolvable.
        if let Some(user) = user_config_path() {
            assert!(user.ends_with("mia.toml"));
        }
    }

    #[test]
    fn shipped_template_parses_to_defaults() {
        // The packaged template ships with every value commented out, so it
        // must parse and yield the all-defaults config. Guards against drift
        // between the schema and `dist/mia.toml`.
        let template = include_str!("../dist/mia.toml");
        let parsed = Config::from_toml(template).expect("dist/mia.toml must parse");
        assert_eq!(parsed, Config::default());
    }

    #[test]
    fn windows_group_round_trips() {
        let c = Config::from_toml("[helper]\nwindows_group = \"FerroGateClients\"").unwrap();
        assert_eq!(c.helper.windows_group.as_deref(), Some("FerroGateClients"));
    }

    #[test]
    fn empty_toml_is_all_defaults() {
        let c = Config::from_toml("").unwrap();
        assert_eq!(c, Config::default());
        assert_eq!(c.log_directive(), "info");
        assert_eq!(c.socket_mode().unwrap(), 0o660);
        assert_eq!(c.allowlist_max_age(), 86_400);
        assert!(c.helper_socket().is_none());
    }

    #[test]
    fn full_toml_parses_every_section() {
        let toml = r#"
            log = "mia=debug,info"

            [cmis]
            endpoint = "https://cmis.example.com:8443"
            spki_pin = "abc123"

            [helper]
            socket = "/run/ferrogate/mia.sock"
            socket_mode = "640"

            [allowlist]
            path = "/etc/ferrogate/allowlist.cbor"
            key = "/etc/ferrogate/allowlist.pub"
            max_age_secs = 3600

            [attestation]
            ima_log = "/sys/kernel/security/integrity/ima/ascii_runtime_measurements"
        "#;
        let c = Config::from_toml(toml).unwrap();
        assert_eq!(c.log_directive(), "mia=debug,info");
        assert_eq!(
            c.cmis.endpoint.as_deref(),
            Some("https://cmis.example.com:8443")
        );
        assert_eq!(
            c.helper_socket(),
            Some(Path::new("/run/ferrogate/mia.sock"))
        );
        assert_eq!(c.socket_mode().unwrap(), 0o640);
        assert_eq!(c.allowlist_max_age(), 3600);
        assert_eq!(
            c.allowlist.key.as_deref(),
            Some(Path::new("/etc/ferrogate/allowlist.pub"))
        );
        assert!(c.attestation.ima_log.is_some());
    }

    #[test]
    fn unknown_keys_are_rejected() {
        let err = Config::from_toml("nonsense = true").unwrap_err();
        assert!(err.to_string().contains("parsing TOML"));
    }

    #[test]
    fn env_overrides_file_values() {
        let mut c = Config::from_toml(
            r#"
            log = "info"
            [helper]
            socket = "/from/file.sock"
            socket_mode = "660"
            [allowlist]
            max_age_secs = 86400
            "#,
        )
        .unwrap();

        let env: HashMap<&str, &str> = HashMap::from([
            ("RUST_LOG", "debug"),
            ("FERROGATE_HELPER_SOCKET", "/from/env.sock"),
            ("FERROGATE_ALLOWLIST_MAX_AGE_SECS", "120"),
        ]);
        c.apply_overrides(|k| env.get(k).map(|s| (*s).to_string()))
            .unwrap();

        // Overridden by env.
        assert_eq!(c.log_directive(), "debug");
        assert_eq!(c.helper_socket(), Some(Path::new("/from/env.sock")));
        assert_eq!(c.allowlist_max_age(), 120);
        // Untouched by env ⇒ keeps the file value.
        assert_eq!(c.socket_mode().unwrap(), 0o660);
    }

    #[test]
    fn env_fills_unset_file_values() {
        let mut c = Config::default();
        let env: HashMap<&str, &str> = HashMap::from([("FERROGATE_HELPER_SOCKET", "/run/x.sock")]);
        c.apply_overrides(|k| env.get(k).map(|s| (*s).to_string()))
            .unwrap();
        assert_eq!(c.helper_socket(), Some(Path::new("/run/x.sock")));
    }

    #[test]
    fn bad_octal_socket_mode_errors() {
        let c = Config::from_toml("[helper]\nsocket_mode = \"999\"").unwrap();
        assert!(c.socket_mode().is_err());
    }

    #[test]
    fn bad_env_max_age_errors() {
        let mut c = Config::default();
        let env: HashMap<&str, &str> =
            HashMap::from([("FERROGATE_ALLOWLIST_MAX_AGE_SECS", "soon")]);
        let err = c
            .apply_overrides(|k| env.get(k).map(|s| (*s).to_string()))
            .unwrap_err();
        assert!(err.to_string().contains("MAX_AGE"));
    }
}
