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

/// The base name of the configuration file for an `--environment` selector.
/// `None` ⇒ the default `mia.toml`; `Some("staging")` ⇒ `mia-staging.toml`. The
/// selector lets one host carry side-by-side configs for different deployments
/// (`mia --environment staging test`, `mia --environment prod`, …) without
/// juggling explicit `--config` paths. The name must already have passed
/// [`validate_environment`].
#[must_use]
pub fn config_filename(environment: Option<&str>) -> String {
    match environment {
        Some(env) => format!("mia-{env}.toml"),
        None => "mia.toml".to_string(),
    }
}

/// The OS-idiomatic *system* configuration directory (writable by root/admin),
/// where a system service / daemon / launchd job looks: macOS
/// `/Library/Application Support/FerroGate`.
#[cfg(target_os = "macos")]
fn system_config_dir() -> PathBuf {
    PathBuf::from("/Library/Application Support/FerroGate")
}

/// The OS-idiomatic *system* configuration directory: Windows
/// `%ProgramData%\FerroGate`.
#[cfg(windows)]
fn system_config_dir() -> PathBuf {
    std::env::var_os("ProgramData")
        .map_or_else(|| PathBuf::from(r"C:\ProgramData"), PathBuf::from)
        .join("FerroGate")
}

/// The OS-idiomatic *system* configuration directory: Linux/other Unix
/// `/etc/ferrogate`.
#[cfg(not(any(target_os = "macos", windows)))]
fn system_config_dir() -> PathBuf {
    PathBuf::from("/etc/ferrogate")
}

/// The OS-idiomatic *per-user* configuration directory (no elevation needed), or
/// `None` if the relevant home/config environment variable is unset: macOS
/// `~/Library/Application Support/FerroGate`.
#[cfg(target_os = "macos")]
fn user_config_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(|h| PathBuf::from(h).join("Library/Application Support/FerroGate"))
}

/// The OS-idiomatic *per-user* configuration directory: Windows
/// `%APPDATA%\FerroGate`.
#[cfg(windows)]
fn user_config_dir() -> Option<PathBuf> {
    std::env::var_os("APPDATA").map(|a| PathBuf::from(a).join("FerroGate"))
}

/// The OS-idiomatic *per-user* configuration directory: Linux/other Unix
/// `$XDG_CONFIG_HOME/ferrogate` (or `~/.config/ferrogate`).
#[cfg(not(any(target_os = "macos", windows)))]
fn user_config_dir() -> Option<PathBuf> {
    if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
        return Some(PathBuf::from(xdg).join("ferrogate"));
    }
    std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config").join("ferrogate"))
}

/// The OS-idiomatic *system* configuration path for the default environment
/// (`mia.toml`). Equivalent to `system_config_path_for(None)`.
#[must_use]
pub fn system_config_path() -> PathBuf {
    system_config_path_for(None)
}

/// The OS-idiomatic *system* configuration path for an `--environment` selector:
/// the system config directory joined with [`config_filename`].
#[must_use]
pub fn system_config_path_for(environment: Option<&str>) -> PathBuf {
    system_config_dir().join(config_filename(environment))
}

/// The OS-idiomatic *per-user* configuration path for the default environment
/// (`mia.toml`), or `None` if no home/config directory is resolvable.
#[must_use]
pub fn user_config_path() -> Option<PathBuf> {
    user_config_path_for(None)
}

/// The OS-idiomatic *per-user* configuration path for an `--environment`
/// selector, or `None` if no home/config directory is resolvable.
#[must_use]
pub fn user_config_path_for(environment: Option<&str>) -> Option<PathBuf> {
    user_config_dir().map(|d| d.join(config_filename(environment)))
}

/// Validate an `--environment` selector. The name becomes part of a config
/// filename (`mia-<env>.toml`), so it must be a safe single path component:
/// non-empty, neither `.` nor `..`, and limited to ASCII letters, digits, `.`,
/// `-`, and `_` — so it can neither inject a path separator nor traverse out of
/// the config directory.
pub fn validate_environment(name: &str) -> anyhow::Result<()> {
    if name.is_empty() {
        anyhow::bail!("--environment name must not be empty");
    }
    if name == "." || name == ".." {
        anyhow::bail!("--environment name `{name}` is not a valid environment");
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
    {
        anyhow::bail!(
            "--environment name `{name}` is invalid: use only letters, digits, '.', '-', '_'"
        );
    }
    Ok(())
}

/// A configuration file discovered for the daemon's "serve every environment"
/// mode: the environment it represents (`None` ⇒ the default `mia.toml`) and the
/// file to load.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredConfig {
    /// The environment name, or `None` for the default `mia.toml`.
    pub environment: Option<String>,
    /// The resolved path to load.
    pub path: PathBuf,
}

/// Discover every environment configuration file in the standard locations.
///
/// Scans the system config directory, then the per-user one, for `mia.toml`
/// (the default environment) and `mia-<env>.toml` (named environments). When the
/// same environment exists in both, the **system** copy wins (mirroring the
/// single-file discovery precedence). The result is sorted with the default
/// environment first, then environments by name, for a stable serve order.
///
/// Used by the daemon's default "serve all environments" mode; an explicit
/// `--config` / `--environment` / `$FERROGATE_CONFIG` bypasses it.
#[must_use]
pub fn discover_environment_configs() -> Vec<DiscoveredConfig> {
    let dirs: Vec<PathBuf> = [Some(system_config_dir()), user_config_dir()]
        .into_iter()
        .flatten()
        .collect();
    scan_config_dirs(&dirs)
}

/// The directory-scan core of [`discover_environment_configs`], split out so it
/// can be tested against temporary directories instead of the OS paths.
fn scan_config_dirs(dirs: &[PathBuf]) -> Vec<DiscoveredConfig> {
    use std::collections::BTreeMap;

    // `Option<String>` orders `None` (the default env) first, then names
    // alphabetically — a stable, predictable serve order. `or_insert` keeps the
    // first directory's copy, so the system dir (scanned first) wins on conflict.
    let mut found: BTreeMap<Option<String>, PathBuf> = BTreeMap::new();
    for dir in dirs {
        let Ok(entries) = std::fs::read_dir(dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            let env = match classify_config_filename(name) {
                Some(ConfigFile::Default) => None,
                // Defensively skip a file whose embedded name isn't a valid
                // environment; the default `mia.toml` is always fine.
                Some(ConfigFile::Named(env)) if validate_environment(&env).is_ok() => Some(env),
                _ => continue,
            };
            found.entry(env).or_insert_with(|| dir.join(name));
        }
    }
    found
        .into_iter()
        .map(|(environment, path)| DiscoveredConfig { environment, path })
        .collect()
}

/// The classification of a config filename for environment discovery.
#[derive(Debug, PartialEq, Eq)]
enum ConfigFile {
    /// `mia.toml` — the default environment.
    Default,
    /// `mia-<env>.toml` — a named environment.
    Named(String),
}

/// Classify a filename: `mia.toml` ⇒ [`ConfigFile::Default`], `mia-<env>.toml`
/// ⇒ [`ConfigFile::Named`], anything else ⇒ `None` (not a config file).
fn classify_config_filename(name: &str) -> Option<ConfigFile> {
    let stem = name.strip_suffix(".toml")?;
    if stem == "mia" {
        Some(ConfigFile::Default)
    } else {
        stem.strip_prefix("mia-")
            .filter(|env| !env.is_empty())
            .map(|env| ConfigFile::Named(env.to_string()))
    }
}

/// Default helper-socket mode when unset (`0o660`).
pub const DEFAULT_SOCKET_MODE: u32 = 0o660;

/// Default maximum accepted allowlist age, in seconds (96 h). Matches the CMIS
/// issuer's default `allowlist_ttl_secs` so a freshly signed list is accepted.
pub const DEFAULT_ALLOWLIST_MAX_AGE_SECS: i64 = 96 * 3600;

/// Default interval between allowlist proposals when `allowlist.propose` is on.
pub const DEFAULT_ALLOWLIST_PROPOSE_INTERVAL_SECS: u64 = 300;

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
    /// A single `https://host:port` endpoint (`https` ⇒ hybrid-PQC TLS,
    /// SPKI-pinned). Mutually exclusive with [`srv`](Self::srv).
    pub endpoint: Option<String>,
    /// A DNS **SRV** record owner name (e.g. `_cmis._tcp.example.com`) advertising
    /// one or more CMIS nodes for high availability. When set, the agent resolves
    /// it, prefers the records by RFC 2782 priority/weight, dials them best-first,
    /// and fails over to the next live node automatically. Mutually exclusive with
    /// [`endpoint`](Self::endpoint); the SPKI pin still authenticates every node
    /// (a CMIS cluster shares one pinned identity). Resolved candidates are always
    /// dialed over `https` hybrid-PQC TLS.
    pub srv: Option<String>,
    /// Accepted CMIS SPKI pin (lowercase-hex SHA-384). Required whenever
    /// `endpoint` or `srv` is set.
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
    /// **Unix only.** Numeric gid to `chown` the socket to, as a string (e.g.
    /// `"555"`). Members of that group may then open the socket (with the
    /// default `0o660` mode). `None`/blank ⇒ the socket keeps the daemon's
    /// primary group. A *group name* is intentionally not accepted here:
    /// resolving one needs `getgrnam`, and `mia` is `#![forbid(unsafe_code)]`,
    /// so the installer resolves the FerroGate group name to its gid and passes
    /// the number (see `make mia-install`).
    pub socket_gid: Option<String>,
    /// **Windows only.** Local group whose members may open the pipe (e.g.
    /// `FerroGateClients`). `None` ⇒ the pipe's default DACL applies.
    pub windows_group: Option<String>,
    /// **Windows only.** Require a valid Authenticode signature on every caller's
    /// image (the Code-Integrity analogue of the Linux IMA cross-check). `None`
    /// ⇒ the default, which **requires** it. Set `false` for environments whose
    /// clients (and `mia` itself) are not code-signed; identity then rests on
    /// PID + image SHA-384 + RID only. Ignored off Windows.
    pub require_authenticode: Option<bool>,
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
    /// When `true`, the daemon fetches this host's signed allowlist from CMIS
    /// (the `GetAllowlist` RPC, keyed by the host's EK-derived UUID) at startup
    /// and writes it to `path` before loading — so the on-disk artefact stays in
    /// sync with what the operator provisioned. Requires `cmis.endpoint` +
    /// `cmis.spki_pin` and a successful attestation; a fetch failure is
    /// non-fatal and falls back to whatever is already at `path`.
    pub fetch: bool,
    /// When `true`, the daemon periodically proposes the local callers it has
    /// observed (granted *and* denied) to CMIS (the `ProposeAllowlist` RPC). On
    /// a host with no allowlist yet CMIS may auto-adopt the first proposal
    /// (first-use bootstrap); otherwise it queues it for operator review.
    /// Requires `cmis.endpoint` + `cmis.spki_pin` and a host SVID. Opt-in
    /// (default `false`) — enable it to let a fresh host bootstrap its own
    /// allowlist instead of an operator hand-enumerating callers.
    pub propose: bool,
    /// How often (seconds) to propose the observed caller set when `propose` is
    /// enabled. `None` ⇒ [`DEFAULT_ALLOWLIST_PROPOSE_INTERVAL_SECS`].
    pub propose_interval_secs: Option<u64>,
}

/// `[attestation]` — attestation inputs.
#[derive(Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AttestationConfig {
    /// Override the IMA runtime-measurement log path.
    pub ima_log: Option<PathBuf>,
}

/// Which environment-variable overrides [`Config::apply_env`] overlays.
///
/// `Full` is the normal case: an explicitly selected configuration
/// (`--config`, `--environment`, `$FERROGATE_CONFIG`) or the default
/// environment. `SharedOnly` is for *named* environments discovered by the
/// daemon's serve-all scan: it skips `FERROGATE_HELPER_SOCKET`, because that
/// process-wide path can only describe one environment's socket — applying it
/// to all of them would collide every environment onto one path and leave all
/// but the first unserved. All other overrides (including the socket
/// `_MODE`/`_GID`) apply in both scopes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvOverrideScope {
    /// Apply every override, including the helper-socket path.
    Full,
    /// Apply every override *except* the helper-socket path.
    SharedOnly,
}

impl Config {
    /// Discover, parse, and env-overlay the configuration.
    ///
    /// `explicit` is the `--config <path>` value, if any. `environment` is the
    /// `--environment <env>` selector, if any: it picks `mia-<env>.toml` in the
    /// standard system/user locations instead of the default `mia.toml`, and is
    /// mutually exclusive with `explicit`. Returns the merged configuration and
    /// the path actually loaded (`None` ⇒ no file, env/defaults only).
    pub fn load(
        explicit: Option<&Path>,
        environment: Option<&str>,
    ) -> anyhow::Result<(Self, Option<PathBuf>)> {
        let (mut config, source) = Self::load_file(explicit, environment)?;
        config.apply_env(EnvOverrideScope::Full)?;
        Ok((config, source))
    }

    /// Resolve and parse the file portion only (no env overlay). Exposed for
    /// testing; [`Config::load`] is the real entry point.
    fn load_file(
        explicit: Option<&Path>,
        environment: Option<&str>,
    ) -> anyhow::Result<(Self, Option<PathBuf>)> {
        if let Some(env) = environment {
            validate_environment(env)?;
            anyhow::ensure!(
                explicit.is_none(),
                "--config and --environment are mutually exclusive: --config names one exact \
                 file, --environment selects mia-{env}.toml from the standard config locations"
            );
        }
        // The exact-path sources name a single fixed file, so they apply only
        // without an `--environment` selector; with one, go straight to the
        // standard `mia-<env>.toml` discovery so the selector is not shadowed.
        if environment.is_none() {
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
        }
        // 3) OS system path, then per-user path (the `mia-<env>.toml` filename
        //    when an environment is selected): load the first that exists, else
        //    fall back to env/defaults.
        let candidates = [
            Some(system_config_path_for(environment)),
            user_config_path_for(environment),
        ];
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
    pub fn apply_env(&mut self, scope: EnvOverrideScope) -> anyhow::Result<()> {
        self.apply_overrides(scope, |k| std::env::var(k).ok())
    }

    /// Overlay overrides resolved by `get` onto `self`. Factored out so tests
    /// can supply a map instead of mutating the global environment.
    fn apply_overrides(
        &mut self,
        scope: EnvOverrideScope,
        get: impl Fn(&str) -> Option<String>,
    ) -> anyhow::Result<()> {
        if let Some(v) = get("RUST_LOG") {
            self.log = Some(v);
        }
        if let Some(v) = get("FERROGATE_CMIS_ENDPOINT") {
            self.cmis.endpoint = Some(v);
        }
        if let Some(v) = get("FERROGATE_CMIS_SRV") {
            self.cmis.srv = Some(v);
        }
        if let Some(v) = get("FERROGATE_CMIS_SPKI_PIN") {
            self.cmis.spki_pin = Some(v);
        }
        // The socket *path* is per-environment: in serve-all mode a single
        // process-wide FERROGATE_HELPER_SOCKET would force every environment
        // onto one path, and the daemon's duplicate-socket guard would then
        // serve only the first. Mode/gid below stay global — sharing those
        // across environments is harmless and usually intended.
        if scope == EnvOverrideScope::Full {
            if let Some(v) = get("FERROGATE_HELPER_SOCKET") {
                self.helper.socket = Some(PathBuf::from(v));
            }
        }
        if let Some(v) = get("FERROGATE_HELPER_SOCKET_MODE") {
            self.helper.socket_mode = Some(v);
        }
        if let Some(v) = get("FERROGATE_HELPER_SOCKET_GID") {
            self.helper.socket_gid = Some(v);
        }
        if let Some(v) = get("FERROGATE_HELPER_WINDOWS_GROUP") {
            self.helper.windows_group = Some(v);
        }
        if let Some(v) = get("FERROGATE_HELPER_REQUIRE_AUTHENTICODE") {
            self.helper.require_authenticode =
                Some(parse_bool_env("FERROGATE_HELPER_REQUIRE_AUTHENTICODE", &v)?);
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
        if let Some(v) = get("FERROGATE_ALLOWLIST_FETCH") {
            self.allowlist.fetch = parse_bool_env("FERROGATE_ALLOWLIST_FETCH", &v)?;
        }
        if let Some(v) = get("FERROGATE_ALLOWLIST_PROPOSE") {
            self.allowlist.propose = parse_bool_env("FERROGATE_ALLOWLIST_PROPOSE", &v)?;
        }
        if let Some(v) = get("FERROGATE_ALLOWLIST_PROPOSE_INTERVAL_SECS") {
            let n: u64 = v
                .parse()
                .context("FERROGATE_ALLOWLIST_PROPOSE_INTERVAL_SECS is not an integer")?;
            self.allowlist.propose_interval_secs = Some(n);
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

    /// The gid to `chown` the helper socket to, parsed from `helper.socket_gid`.
    /// A blank value is treated as unset. `None` ⇒ leave the socket's group as
    /// the daemon's primary group.
    pub fn socket_gid(&self) -> anyhow::Result<Option<u32>> {
        match self.helper.socket_gid.as_deref().map(str::trim) {
            None | Some("") => Ok(None),
            Some(s) => s
                .parse::<u32>()
                .map(Some)
                .with_context(|| format!("helper.socket_gid {s:?} is not a numeric gid")),
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

    /// The allowlist-propose interval; default
    /// [`DEFAULT_ALLOWLIST_PROPOSE_INTERVAL_SECS`], clamped to ≥ 1s.
    #[must_use]
    pub fn allowlist_propose_interval(&self) -> u64 {
        self.allowlist
            .propose_interval_secs
            .filter(|n| *n > 0)
            .unwrap_or(DEFAULT_ALLOWLIST_PROPOSE_INTERVAL_SECS)
    }
}

/// Where the daemon found — and will re-read, on SIGHUP — its configuration:
/// the explicit `--config` path (if any) and the `--environment` selector (if
/// any). Carrying both through the serve path lets the live reload re-resolve
/// the *same* source it started from. The two are mutually exclusive (enforced
/// by [`Config::load`]); a default `ConfigSource` means "standard discovery,
/// default environment".
#[derive(Debug, Clone, Default)]
pub struct ConfigSource {
    /// The explicit `--config <path>`, if one was given.
    pub path: Option<PathBuf>,
    /// The `--environment <env>` selector, if one was given.
    pub environment: Option<String>,
    /// True when this source is a *named* environment found by the daemon's
    /// serve-all discovery scan (its `path` points at the discovered
    /// `mia-<env>.toml`), rather than one the operator selected explicitly.
    /// Such sources load with [`EnvOverrideScope::SharedOnly`], so a
    /// process-wide `FERROGATE_HELPER_SOCKET` cannot collapse every
    /// environment onto one socket path.
    pub discovered_named_env: bool,
}

impl ConfigSource {
    /// Resolve and load the configuration this source describes.
    pub fn load(&self) -> anyhow::Result<(Config, Option<PathBuf>)> {
        let (mut config, path) =
            Config::load_file(self.path.as_deref(), self.environment.as_deref())?;
        let scope = if self.discovered_named_env {
            EnvOverrideScope::SharedOnly
        } else {
            EnvOverrideScope::Full
        };
        config.apply_env(scope)?;
        Ok((config, path))
    }
}

/// Parse a boolean environment value, accepting the usual truthy/falsy spellings
/// so an operator can write `1`, `true`, `yes`, or `on` (and their opposites).
fn parse_bool_env(name: &str, raw: &str) -> anyhow::Result<bool> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" | "" => Ok(false),
        other => anyhow::bail!("{name} must be a boolean (true/false), got `{other}`"),
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
    fn environment_selects_named_config_filename() {
        // Default ⇒ mia.toml; a selector ⇒ mia-<env>.toml, in the same dir.
        assert!(config_filename(None) == "mia.toml");
        assert_eq!(config_filename(Some("staging")), "mia-staging.toml");
        let default = system_config_path_for(None);
        let staging = system_config_path_for(Some("staging"));
        assert_eq!(default.parent(), staging.parent());
        assert!(default.ends_with("mia.toml"));
        assert!(staging.ends_with("mia-staging.toml"));
        // The plain accessor is the default-environment path.
        assert_eq!(system_config_path(), default);
    }

    #[test]
    fn environment_names_are_validated() {
        for ok in ["staging", "prod", "qa-1", "us.east", "blue_green"] {
            assert!(validate_environment(ok).is_ok(), "{ok} should be valid");
        }
        for bad in ["", ".", "..", "a/b", "../etc", "a b", "a\\b"] {
            assert!(validate_environment(bad).is_err(), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn classify_config_filename_classifies() {
        assert_eq!(classify_config_filename("mia.toml"), Some(ConfigFile::Default));
        assert_eq!(
            classify_config_filename("mia-staging.toml"),
            Some(ConfigFile::Named("staging".to_string()))
        );
        // Not config files.
        assert_eq!(classify_config_filename("mia-.toml"), None);
        assert_eq!(classify_config_filename("mia.txt"), None);
        assert_eq!(classify_config_filename("allowlist.cbor"), None);
        assert_eq!(classify_config_filename("notmia.toml"), None);
    }

    #[test]
    fn scan_config_dirs_finds_and_orders_environments() {
        let base = std::env::temp_dir().join(format!("mia-scan-{}", std::process::id()));
        let sys = base.join("sys");
        let user = base.join("user");
        std::fs::create_dir_all(&sys).unwrap();
        std::fs::create_dir_all(&user).unwrap();
        // System: default + prod. User: staging + a *duplicate* prod that must lose.
        std::fs::write(sys.join("mia.toml"), "").unwrap();
        std::fs::write(sys.join("mia-prod.toml"), "").unwrap();
        std::fs::write(user.join("mia-staging.toml"), "").unwrap();
        std::fs::write(user.join("mia-prod.toml"), "").unwrap();
        std::fs::write(user.join("ignore-me.toml"), "").unwrap();

        let found = scan_config_dirs(&[sys.clone(), user.clone()]);
        // Order: default (None) first, then prod, then staging.
        assert_eq!(
            found.iter().map(|d| d.environment.clone()).collect::<Vec<_>>(),
            vec![None, Some("prod".to_string()), Some("staging".to_string())]
        );
        // The system copy of `prod` wins over the user one.
        let prod = found
            .iter()
            .find(|d| d.environment.as_deref() == Some("prod"))
            .unwrap();
        assert_eq!(prod.path, sys.join("mia-prod.toml"));

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn config_and_environment_are_mutually_exclusive() {
        let err = Config::load(Some(Path::new("/tmp/x.toml")), Some("staging")).unwrap_err();
        assert!(err.to_string().contains("mutually exclusive"));
    }

    #[test]
    fn invalid_environment_is_rejected_by_load() {
        let err = Config::load(None, Some("../etc/passwd")).unwrap_err();
        assert!(err.to_string().contains("--environment"));
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
        assert_eq!(c.allowlist_max_age(), 96 * 3600);
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
        c.apply_overrides(EnvOverrideScope::Full, |k| {
            env.get(k).map(|s| (*s).to_string())
        })
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
        c.apply_overrides(EnvOverrideScope::Full, |k| {
            env.get(k).map(|s| (*s).to_string())
        })
        .unwrap();
        assert_eq!(c.helper_socket(), Some(Path::new("/run/x.sock")));
    }

    #[test]
    fn shared_only_scope_skips_socket_path_keeps_mode_and_gid() {
        // A discovered named environment: the global socket *path* override
        // must not displace its file value, but mode/gid still apply.
        let mut c = Config::from_toml("[helper]\nsocket = \"/from/file.sock\"").unwrap();
        let env: HashMap<&str, &str> = HashMap::from([
            ("FERROGATE_HELPER_SOCKET", "/from/env.sock"),
            ("FERROGATE_HELPER_SOCKET_MODE", "600"),
            ("FERROGATE_HELPER_SOCKET_GID", "777"),
        ]);
        c.apply_overrides(EnvOverrideScope::SharedOnly, |k| {
            env.get(k).map(|s| (*s).to_string())
        })
        .unwrap();
        assert_eq!(c.helper_socket(), Some(Path::new("/from/file.sock")));
        assert_eq!(c.socket_mode().unwrap(), 0o600);
        assert_eq!(c.socket_gid().unwrap(), Some(777));
    }

    #[test]
    fn shared_only_scope_leaves_unset_socket_unset() {
        // Without a file value, SharedOnly must not fill the socket from the
        // env either — the environment simply has no helper socket.
        let mut c = Config::default();
        let env: HashMap<&str, &str> = HashMap::from([("FERROGATE_HELPER_SOCKET", "/run/x.sock")]);
        c.apply_overrides(EnvOverrideScope::SharedOnly, |k| {
            env.get(k).map(|s| (*s).to_string())
        })
        .unwrap();
        assert_eq!(c.helper_socket(), None);
    }

    #[test]
    fn bad_octal_socket_mode_errors() {
        let c = Config::from_toml("[helper]\nsocket_mode = \"999\"").unwrap();
        assert!(c.socket_mode().is_err());
    }

    #[test]
    fn socket_gid_parses_and_defaults() {
        // Unset ⇒ None.
        assert_eq!(Config::default().socket_gid().unwrap(), None);
        // Numeric ⇒ Some(gid).
        let c = Config::from_toml("[helper]\nsocket_gid = \"555\"").unwrap();
        assert_eq!(c.socket_gid().unwrap(), Some(555));
        // Blank ⇒ treated as unset.
        let c = Config::from_toml("[helper]\nsocket_gid = \"  \"").unwrap();
        assert_eq!(c.socket_gid().unwrap(), None);
        // Non-numeric (e.g. a group name) is rejected — the installer resolves
        // names to gids, the daemon only accepts the number.
        let c = Config::from_toml("[helper]\nsocket_gid = \"_ferrogate\"").unwrap();
        assert!(c.socket_gid().is_err());
    }

    #[test]
    fn socket_gid_env_override() {
        let mut c = Config::default();
        let env: HashMap<&str, &str> = HashMap::from([("FERROGATE_HELPER_SOCKET_GID", "777")]);
        c.apply_overrides(EnvOverrideScope::Full, |k| {
            env.get(k).map(|s| (*s).to_string())
        })
        .unwrap();
        assert_eq!(c.socket_gid().unwrap(), Some(777));
    }

    #[test]
    fn bad_env_max_age_errors() {
        let mut c = Config::default();
        let env: HashMap<&str, &str> =
            HashMap::from([("FERROGATE_ALLOWLIST_MAX_AGE_SECS", "soon")]);
        let err = c
            .apply_overrides(EnvOverrideScope::Full, |k| {
                env.get(k).map(|s| (*s).to_string())
            })
            .unwrap_err();
        assert!(err.to_string().contains("MAX_AGE"));
    }
}
