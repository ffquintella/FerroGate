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
//! 1. built-in defaults (e.g. socket mode `660`, allowlist max-age `259200`,
//!    and the per-platform, per-environment helper socket
//!    ([`default_helper_socket`](crate::config::default_helper_socket)) and
//!    signed allowlist body
//!    ([`default_allowlist_path`](crate::config::default_allowlist_path)); the
//!    allowlist's verification key `allowlist.key` deliberately has no
//!    default);
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
use serde::{Deserialize, Serialize};

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
pub(crate) fn system_config_dir() -> PathBuf {
    PathBuf::from("/Library/Application Support/FerroGate")
}

/// The OS-idiomatic *system* configuration directory: Windows
/// `%ProgramData%\FerroGate`.
#[cfg(windows)]
pub(crate) fn system_config_dir() -> PathBuf {
    std::env::var_os("ProgramData")
        .map_or_else(|| PathBuf::from(r"C:\ProgramData"), PathBuf::from)
        .join("FerroGate")
}

/// The OS-idiomatic *system* configuration directory: Linux/other Unix
/// `/etc/ferrogate`.
#[cfg(not(any(target_os = "macos", windows)))]
pub(crate) fn system_config_dir() -> PathBuf {
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
///
/// The rule itself lives in [`mia_status_proto::validate_environment`] so the
/// `mia-tray` companion applies exactly the same check before it passes
/// `-e <env>` to a `mia` command; this wrapper only adds the CLI wording.
pub fn validate_environment(name: &str) -> anyhow::Result<()> {
    use mia_status_proto::EnvironmentNameError;
    match mia_status_proto::validate_environment(name) {
        Ok(()) => Ok(()),
        Err(EnvironmentNameError::Empty) => {
            anyhow::bail!("--environment name must not be empty")
        }
        Err(EnvironmentNameError::DotName) => {
            anyhow::bail!("--environment name `{name}` is not a valid environment")
        }
        Err(EnvironmentNameError::InvalidCharacter) => anyhow::bail!(
            "--environment name `{name}` is invalid: use only letters, digits, '.', '-', '_'"
        ),
    }
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

/// The environment a configuration file belongs to, judged by its file name:
/// `mia-<env>.toml` (with a valid `<env>`, see [`validate_environment`]) ⇒
/// `Some(env)`; `mia.toml` or any other name ⇒ `None` (the default
/// environment). The serve-all discovery uses the same rule, so a file loaded
/// by path (`--config`, `$FERROGATE_CONFIG`, a discovered `mia-<env>.toml`)
/// resolves to the same per-environment defaults — notably the helper socket —
/// however it was selected.
#[must_use]
pub fn environment_for_path(path: &Path) -> Option<String> {
    match classify_config_filename(path.file_name()?.to_str()?)? {
        ConfigFile::Named(env) if validate_environment(&env).is_ok() => Some(env),
        _ => None,
    }
}

/// The helper socket's file name for an environment: `mia.sock` or
/// `mia-<env>.sock`.
#[cfg(not(windows))]
fn helper_socket_name(environment: Option<&str>) -> String {
    match environment {
        Some(env) => format!("mia-{env}.sock"),
        None => "mia.sock".to_string(),
    }
}

/// The platform's default helper listener address (Windows named pipe):
/// `\\.\pipe\ferrogate-mia`, or `\\.\pipe\ferrogate-mia-<env>` for a named
/// environment, so side-by-side environments never contend for one pipe.
///
/// This is what [`Config::helper_socket`] resolves to when neither
/// `helper.socket` nor `FERROGATE_HELPER_SOCKET` is set. `environment` must
/// already have passed [`validate_environment`].
#[cfg(windows)]
#[must_use]
pub fn default_helper_socket(environment: Option<&str>) -> PathBuf {
    debug_assert!(environment.is_none_or(|e| validate_environment(e).is_ok()));
    PathBuf::from(match environment {
        Some(env) => format!(r"\\.\pipe\ferrogate-mia-{env}"),
        None => r"\\.\pipe\ferrogate-mia".to_string(),
    })
}

/// The platform's default helper listener address (macOS Unix socket):
/// `/Library/Application Support/FerroGate/run/mia[-<env>].sock`.
///
/// macOS has no `/run`, and `/var/run` is a boot-cleared tmpfs — a socket
/// parented there vanishes on every reboot and the daemon crash-loops on bind.
/// The persistent, root-owned system Application Support tree (where the config
/// and allowlist live) is used instead, in a dedicated `run/` subdirectory the
/// daemon owns ([`owned_helper_socket_dir`]): it creates it and, on every
/// start, gives it mode `0750` and the helper socket's group
/// (`crate::helper::socket_dir`).
///
/// This is what [`Config::helper_socket`] resolves to when neither
/// `helper.socket` nor `FERROGATE_HELPER_SOCKET` is set. `environment` must
/// already have passed [`validate_environment`].
#[cfg(target_os = "macos")]
#[must_use]
pub fn default_helper_socket(environment: Option<&str>) -> PathBuf {
    debug_assert!(environment.is_none_or(|e| validate_environment(e).is_ok()));
    system_config_dir()
        .join("run")
        .join(helper_socket_name(environment))
}

/// The directory the daemon itself owns for its default helper sockets, if the
/// platform has one: macOS `/Library/Application Support/FerroGate/run` (the
/// parent of [`default_helper_socket`]). The daemon re-applies its mode and
/// group on every start (`crate::helper::socket_dir`).
///
/// `None` elsewhere: on Linux `/run/ferrogate` is systemd's
/// `RuntimeDirectory=`, prepared before the privilege drop
/// (`hardening::prepare_runtime_paths`); Windows uses named pipes.
#[must_use]
pub fn owned_helper_socket_dir() -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        Some(system_config_dir().join("run"))
    }
    #[cfg(not(target_os = "macos"))]
    {
        None
    }
}

/// The platform's default helper listener address (Linux/other Unix socket):
/// `/run/ferrogate/mia[-<env>].sock`. `/run/ferrogate` is the systemd
/// `RuntimeDirectory=` of `mia.service`, recreated root-owned on every start
/// and handed to the service user before the privilege drop.
///
/// This is what [`Config::helper_socket`] resolves to when neither
/// `helper.socket` nor `FERROGATE_HELPER_SOCKET` is set. `environment` must
/// already have passed [`validate_environment`].
#[cfg(not(any(target_os = "macos", windows)))]
#[must_use]
pub fn default_helper_socket(environment: Option<&str>) -> PathBuf {
    debug_assert!(environment.is_none_or(|e| validate_environment(e).is_ok()));
    PathBuf::from("/run/ferrogate").join(helper_socket_name(environment))
}

/// The address `mia.toml` falls back to when it **yields** the well-known
/// address (`default_helper_socket(None)`) to another environment selected as
/// the host's default ([`crate::default_env`]): `mia.default.sock` beside the
/// well-known socket, or `\\.\pipe\ferrogate-mia.default` on Windows.
///
/// The `.` separator — environment-scoped addresses use `-` — makes it
/// unreachable by any environment name: every `mia-<env>.sock` /
/// `ferrogate-mia-<env>` starts with `mia-`, so not even an environment
/// literally named `default` (`mia-default.sock`) can collide with it.
#[must_use]
pub fn yielded_helper_socket() -> PathBuf {
    #[cfg(windows)]
    {
        PathBuf::from(r"\\.\pipe\ferrogate-mia.default")
    }
    #[cfg(not(windows))]
    {
        default_helper_socket(None).with_file_name("mia.default.sock")
    }
}

/// The helper address an environment binds when its `helper.socket` is unset,
/// given the host's selected default environment (`selected_default`, `None`
/// ⇒ `mia.toml`; see [`crate::default_env`]):
///
/// - no selection ⇒ [`default_helper_socket`]`(environment)`, unchanged;
/// - the selected environment ⇒ the well-known `default_helper_socket(None)`
///   (its only listener — it no longer binds `mia-<env>.sock`);
/// - `mia.toml` when another environment is selected ⇒ it yields, to
///   [`yielded_helper_socket`];
/// - any other named environment ⇒ its own `mia-<env>.sock`, unchanged.
#[must_use]
pub fn default_helper_address(
    environment: Option<&str>,
    selected_default: Option<&str>,
) -> PathBuf {
    match (environment, selected_default) {
        (env, Some(selected)) if env == Some(selected) => default_helper_socket(None),
        (None, Some(_)) => yielded_helper_socket(),
        (env, _) => default_helper_socket(env),
    }
}

/// The signed allowlist body's file name for an environment:
/// `allowlist.cbor` or `allowlist-<env>.cbor`.
fn allowlist_file_name(environment: Option<&str>) -> String {
    match environment {
        Some(env) => format!("allowlist-{env}.cbor"),
        None => "allowlist.cbor".to_string(),
    }
}

/// The platform's default location of the signed caller allowlist body:
/// `allowlist.cbor` (or `allowlist-<env>.cbor` for a named environment, so
/// side-by-side environments never share one body) in the system
/// configuration directory, beside `mia.toml`:
///
/// | OS | default environment | named environment |
/// |----|---------------------|-------------------|
/// | Linux | `/etc/ferrogate/allowlist.cbor` | `/etc/ferrogate/allowlist-<env>.cbor` |
/// | macOS | `/Library/Application Support/FerroGate/allowlist.cbor` | `…/FerroGate/allowlist-<env>.cbor` |
/// | Windows | `%ProgramData%\FerroGate\allowlist.cbor` | `%ProgramData%\FerroGate\allowlist-<env>.cbor` |
///
/// This is what [`Config::allowlist_path`] resolves to when neither
/// `allowlist.path` nor `FERROGATE_ALLOWLIST` is set. It is always the
/// administrator-managed system configuration directory — never the per-user
/// directory or a runtime tmpfs — even for a per-user configuration file. The
/// location carries no trust: the body is verified against the explicitly
/// configured `allowlist.key` (which deliberately has no default), and a
/// missing, unreadable or non-verifying body denies every caller.
/// `environment` must already have passed [`validate_environment`].
#[must_use]
pub fn default_allowlist_path(environment: Option<&str>) -> PathBuf {
    debug_assert!(environment.is_none_or(|e| validate_environment(e).is_ok()));
    system_config_dir().join(allowlist_file_name(environment))
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

/// Default maximum accepted allowlist age, in seconds (72 h). Matches the CMIS
/// issuer's default `allowlist_ttl_secs` so a freshly signed list is accepted;
/// CMIS auto-renews an aging allowlist on each fetch, keeping it inside this
/// bound as long as the host can reach CMIS.
pub const DEFAULT_ALLOWLIST_MAX_AGE_SECS: i64 = 72 * 3600;

/// Default interval between allowlist proposals when `allowlist.propose` is on.
pub const DEFAULT_ALLOWLIST_PROPOSE_INTERVAL_SECS: u64 = 300;

/// The fully parsed configuration. Every value is optional: an absent value
/// falls back to its built-in default at the point of use.
#[derive(Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
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
    /// The read-only status endpoint and log ring buffer (feature F18).
    pub status: StatusConfig,
    /// The environment this configuration belongs to (`None` ⇒ the default
    /// environment). Not a TOML key — a file cannot claim another
    /// environment's identity: the loader sets it from the `--environment`
    /// selector or, failing that, from the `mia-<env>.toml` file name (see
    /// [`environment_for_path`]). It selects the per-environment
    /// [`default_helper_socket`] and [`default_allowlist_path`].
    #[serde(skip)]
    environment: Option<String>,
    /// The host-wide default-environment selection this configuration was
    /// resolved against (unset ⇒ `mia.toml` is the default). Not a TOML key:
    /// it is host policy, set by the loader from `environments.toml` /
    /// `FERROGATE_DEFAULT_ENVIRONMENT` ([`Self::apply_default_selection`]),
    /// and decides who owns the well-known helper address
    /// ([`default_helper_address`]).
    #[serde(skip)]
    default_selection: crate::default_env::DefaultSelection,
}

/// `[cmis]` — the Central Machine Identity Service to attest to.
#[derive(Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
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
#[derive(Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct HelperConfig {
    /// Serve the helper API. `None` ⇒ enabled (the default). Set `false` to
    /// switch the helper API off: an unset `socket` no longer disables it (it
    /// falls back to [`default_helper_socket`]), so this is the one explicit
    /// off switch. It also wins over a `socket` value (from the file or
    /// `FERROGATE_HELPER_SOCKET`).
    pub enable: Option<bool>,
    /// Helper listener address — the Unix-socket path (Linux/macOS) or the
    /// named-pipe name (Windows, e.g. `\\.\pipe\ferrogate-mia`). `None` or
    /// blank ⇒ the platform default for this configuration's environment,
    /// [`default_helper_socket`].
    pub socket: Option<PathBuf>,
    /// **Unix only.** Octal socket mode as a string (e.g. `"660"`); default
    /// [`DEFAULT_SOCKET_MODE`].
    pub socket_mode: Option<String>,
    /// **Unix only.** Numeric gid to `chown` the socket to, as a string (e.g.
    /// `"555"`). Members of that group may then open the socket (with the
    /// default `0o660` mode). `None`/blank ⇒ on macOS, for a socket in the
    /// daemon's own `run/` directory, the group of the system config directory
    /// (`ferrogate-status` after a package install — see
    /// `crate::helper::socket_dir`); otherwise the socket keeps the group it is
    /// created with. A *group name* is intentionally not accepted here:
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
#[derive(Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct AllowlistConfig {
    /// Path to the signed CBOR allowlist. `None` or blank ⇒ the platform
    /// default for this configuration's environment,
    /// [`default_allowlist_path`] (resolved by [`Config::allowlist_path`]). A
    /// body that is missing, unreadable, stale or does not verify against
    /// [`key`](Self::key) denies every caller (fail closed).
    pub path: Option<PathBuf>,
    /// Trusted CMIS enrollment public key used to verify the allowlist — the
    /// trust anchor of the whole allowlist, so it has **no default**: `None`
    /// or blank ⇒ nothing can verify a body and every caller is denied (fail
    /// closed). Set explicitly whenever `path` is set (the daemon refuses to
    /// start on an explicit `path` without a key).
    pub key: Option<PathBuf>,
    /// Maximum accepted allowlist age in seconds; default
    /// [`DEFAULT_ALLOWLIST_MAX_AGE_SECS`].
    pub max_age_secs: Option<i64>,
    /// When `true`, the daemon fetches this host's signed allowlist from CMIS
    /// (the `GetAllowlist` RPC, keyed by the host's EK-derived UUID) at startup
    /// and writes it to `path` (or its default, [`Config::allowlist_path`])
    /// before loading — so the on-disk artefact stays in
    /// sync with what the operator provisioned. Requires `cmis.endpoint` +
    /// `cmis.spki_pin` and a successful attestation; a fetch failure is
    /// non-fatal and falls back to whatever is already at `path`.
    pub fetch: bool,
    /// When `true`, the daemon proposes the local callers it has observed
    /// (granted *and* denied) to CMIS (the `ProposeAllowlist` RPC). The first
    /// proposal is sent immediately at startup and every proposal includes a
    /// uid-wildcard self-registration entry for `mia`'s own binary, so a fresh
    /// host becomes visible to CMIS before any caller connects. On a host with
    /// no allowlist yet CMIS may auto-adopt the proposal (first-use bootstrap);
    /// otherwise it queues it for operator review. Requires `cmis.endpoint` +
    /// `cmis.spki_pin` and a host SVID. Opt-in (default `false`) — enable it to
    /// let a fresh host bootstrap its own allowlist instead of an operator
    /// hand-enumerating callers.
    pub propose: bool,
    /// How often (seconds) to propose the observed caller set when `propose` is
    /// enabled. `None` ⇒ [`DEFAULT_ALLOWLIST_PROPOSE_INTERVAL_SECS`].
    pub propose_interval_secs: Option<u64>,
}

/// `[attestation]` — attestation inputs.
#[derive(Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct AttestationConfig {
    /// Override the IMA runtime-measurement log path.
    pub ima_log: Option<PathBuf>,
    /// Which attestation backend the daemon uses to obtain its host SVID.
    /// Defaults to [`AttestBackend::Auto`] (real TPM when available, else the
    /// software host-key profile).
    pub backend: AttestBackend,
    /// `[attestation.tpm]` — inputs for the genuine TPM backend.
    pub tpm: TpmConfig,
}

/// `[attestation.tpm]` — configuration for the genuine TPM 2.0 backend
/// ([`AttestBackend::Tpm`]).
///
/// A hardware TPM stores its EK certificate in NV, but hypervisor vTPMs
/// (`swtpm`, vSphere) frequently do not provision one, and mia does not read NV
/// today. So the EK certificate the daemon presents to CMIS is operator-supplied
/// here: extract it once from the (v)TPM's EK-CA and point `ek_cert` at the DER.
/// Without it the `tpm` backend cannot attest (and `auto` falls back to the
/// software host-key tier).
#[derive(Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct TpmConfig {
    /// Path to the EK certificate (DER) presented to CMIS.
    pub ek_cert: Option<PathBuf>,
    /// Paths to intermediate CA certificates (DER) bridging the EK certificate
    /// to a root CMIS trusts, leaf-to-root order.
    pub ek_intermediates: Vec<PathBuf>,
}

/// `[status]` — the read-only status endpoint (feature F18) and the redacting
/// log ring buffer it serves.
///
/// The endpoint is per *process*, not per environment: in the daemon's
/// serve-all mode it is configured from the primary configuration (`mia.toml`,
/// or the file selected by `--config` / `--environment`), and a `[status]`
/// section in a discovered `mia-<env>.toml` is ignored.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct StatusConfig {
    /// Serve the status endpoint. `None` ⇒ enabled.
    pub enable: Option<bool>,
    /// Listener address: a Unix-socket path (Linux/macOS) or a named-pipe name
    /// (Windows). `None` ⇒ [`mia_status_proto::DEFAULT_ENDPOINT`].
    pub socket: Option<PathBuf>,
    /// **Unix only.** Numeric gid that owns the socket (mode `0660`), so its
    /// members may read status. Takes precedence over [`group`](Self::group).
    pub socket_gid: Option<String>,
    /// The group allowed to read status. Windows: the local group granted on
    /// the pipe DACL (plus SYSTEM and Administrators), default
    /// `FerroGateStatus`. Unix: a group *name* resolved from `/etc/group` when
    /// `socket_gid` is unset, default `ferrogate-status` (groups that live
    /// only in a directory service — e.g. macOS `dscl` groups — need
    /// `socket_gid`).
    pub group: Option<String>,
    /// Requests per second allowed per caller uid. `None` ⇒
    /// [`DEFAULT_STATUS_RATE_LIMIT`]; clamped to `1..=`[`MAX_STATUS_RATE_LIMIT`].
    pub rate_limit_per_sec: Option<u32>,
    /// Log ring-buffer capacity in records. `None` ⇒
    /// [`DEFAULT_LOG_BUFFER_RECORDS`]; `0` disables the buffer.
    pub log_buffer_records: Option<usize>,
    /// Log ring-buffer capacity in bytes. `None` ⇒
    /// [`DEFAULT_LOG_BUFFER_BYTES`]; `0` disables the buffer.
    pub log_buffer_bytes: Option<usize>,
}

/// Default group allowed to read the status endpoint (Windows local group).
#[cfg(windows)]
pub const DEFAULT_STATUS_GROUP: &str = "FerroGateStatus";

/// Default group allowed to read the status endpoint (Unix group name).
#[cfg(not(windows))]
pub const DEFAULT_STATUS_GROUP: &str = "ferrogate-status";

/// Default per-uid status request budget, requests per second.
pub const DEFAULT_STATUS_RATE_LIMIT: u32 = 10;

/// Upper bound on the per-uid status request budget.
pub const MAX_STATUS_RATE_LIMIT: u32 = 1000;

/// Default log ring-buffer capacity in records.
pub const DEFAULT_LOG_BUFFER_RECORDS: usize = 2000;

/// Default log ring-buffer capacity in bytes (1 MiB).
pub const DEFAULT_LOG_BUFFER_BYTES: usize = 1024 * 1024;

/// Hard ceiling on the log ring buffer's record capacity, whatever is
/// configured (the daemon may run under `mlockall`).
pub const MAX_LOG_BUFFER_RECORDS: usize = 100_000;

/// Hard ceiling on the log ring buffer's byte capacity (64 MiB).
pub const MAX_LOG_BUFFER_BYTES: usize = 64 * 1024 * 1024;

/// One environment variable that overrides a configuration key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnvOverride {
    /// The environment variable.
    pub var: &'static str,
    /// The dotted configuration key it overrides (e.g. `cmis.endpoint`).
    pub key: &'static str,
    /// `true` for per-environment keys that [`EnvOverrideScope::SharedOnly`]
    /// does not apply (the helper-socket path).
    pub per_environment: bool,
}

/// Table-row constructor for [`ENV_OVERRIDES`].
const fn env_override(var: &'static str, key: &'static str, per_environment: bool) -> EnvOverride {
    EnvOverride {
        var,
        key,
        per_environment,
    }
}

/// Every environment override [`Config::apply_env`] honours, in one table so
/// `mia setup --dump` can say which keys are env-controlled (a test keeps the
/// table and the overlay in sync).
pub const ENV_OVERRIDES: &[EnvOverride] = &[
    env_override("RUST_LOG", "log", false),
    env_override("FERROGATE_CMIS_ENDPOINT", "cmis.endpoint", false),
    env_override("FERROGATE_CMIS_SRV", "cmis.srv", false),
    env_override("FERROGATE_CMIS_SPKI_PIN", "cmis.spki_pin", false),
    env_override("FERROGATE_HELPER_ENABLE", "helper.enable", false),
    env_override("FERROGATE_HELPER_SOCKET", "helper.socket", true),
    env_override("FERROGATE_HELPER_SOCKET_MODE", "helper.socket_mode", false),
    env_override("FERROGATE_HELPER_SOCKET_GID", "helper.socket_gid", false),
    env_override(
        "FERROGATE_HELPER_WINDOWS_GROUP",
        "helper.windows_group",
        false,
    ),
    env_override(
        "FERROGATE_HELPER_REQUIRE_AUTHENTICODE",
        "helper.require_authenticode",
        false,
    ),
    env_override("FERROGATE_ALLOWLIST", "allowlist.path", false),
    env_override("FERROGATE_ALLOWLIST_KEY", "allowlist.key", false),
    env_override(
        "FERROGATE_ALLOWLIST_MAX_AGE_SECS",
        "allowlist.max_age_secs",
        false,
    ),
    env_override("FERROGATE_ALLOWLIST_FETCH", "allowlist.fetch", false),
    env_override("FERROGATE_ALLOWLIST_PROPOSE", "allowlist.propose", false),
    env_override(
        "FERROGATE_ALLOWLIST_PROPOSE_INTERVAL_SECS",
        "allowlist.propose_interval_secs",
        false,
    ),
    env_override("FERROGATE_IMA_LOG", "attestation.ima_log", false),
    env_override("FERROGATE_ATTEST_BACKEND", "attestation.backend", false),
    env_override("FERROGATE_TPM_EK_CERT", "attestation.tpm.ek_cert", false),
    env_override("FERROGATE_STATUS_ENABLE", "status.enable", false),
    env_override("FERROGATE_STATUS_SOCKET", "status.socket", false),
    env_override("FERROGATE_STATUS_SOCKET_GID", "status.socket_gid", false),
    env_override("FERROGATE_STATUS_GROUP", "status.group", false),
    env_override(
        "FERROGATE_STATUS_RATE_LIMIT",
        "status.rate_limit_per_sec",
        false,
    ),
    env_override(
        "FERROGATE_STATUS_LOG_RECORDS",
        "status.log_buffer_records",
        false,
    ),
    env_override(
        "FERROGATE_STATUS_LOG_BYTES",
        "status.log_buffer_bytes",
        false,
    ),
];

/// The overrides in [`ENV_OVERRIDES`] that are set (per `get`) and apply in
/// `scope` — i.e. the keys whose effective value comes from the environment.
pub fn env_overridden(
    scope: EnvOverrideScope,
    get: impl Fn(&str) -> Option<String>,
) -> Vec<EnvOverride> {
    ENV_OVERRIDES
        .iter()
        .filter(|o| !(o.per_environment && scope == EnvOverrideScope::SharedOnly))
        .filter(|o| get(o.var).is_some())
        .copied()
        .collect()
}

/// Which backend `mia` attests with to obtain its host SVID.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum AttestBackend {
    /// **Capability-aware selection** (the production default): use a real
    /// (v)TPM when one is present and usable ([`AttestBackend::Tpm`]),
    /// otherwise fall back to the software [`AttestBackend::HostKey`] profile.
    /// Unlike `Tpm`, a missing TPM is *not* fatal here — the downgrade to the
    /// host-key tier is the documented contract and is logged at `warn`.
    #[default]
    Auto,
    /// The genuine **TPM 2.0** path (feature F02): drives the kernel resource
    /// manager `/dev/tpmrm0` to produce a hardware-rooted quote. This is the
    /// strongest tier and covers hypervisor vTPMs, which present as a normal
    /// TPM device. Selecting it explicitly is fail-closed: if no usable TPM is
    /// found the daemon refuses to attest rather than silently downgrading.
    /// Linux-only.
    Tpm,
    /// The TPM-less **host-key** profile (feature F15): a hardware fingerprint
    /// plus a machine signing key. Works on every supported platform; a
    /// lower-assurance tier (no hardware root of trust) used when no TPM is
    /// available.
    HostKey,
    /// The in-process software **virtual TPM** — INSECURE, dev/test only. Runs
    /// the full TPM attestation handshake against a specially-configured dev
    /// CMIS. Requires `mia` to be built with the `virtual-tpm` cargo feature;
    /// a daemon built without it refuses to attest (fail closed) when this is
    /// selected.
    VirtualTpm,
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
    ///
    /// The host's default-environment selection
    /// ([`crate::default_env::DefaultSelection::load`]) is resolved and applied
    /// last, so an invalid selection, or an explicit `helper.socket` that
    /// claims another environment's well-known address, fails the load.
    pub fn load(
        explicit: Option<&Path>,
        environment: Option<&str>,
    ) -> anyhow::Result<(Self, Option<PathBuf>)> {
        let (mut config, source) = Self::load_file(explicit, environment)?;
        config.apply_env(EnvOverrideScope::Full)?;
        config.apply_default_selection(&crate::default_env::DefaultSelection::load()?)?;
        Ok((config, source))
    }

    /// Resolve and parse the file portion only (no env overlay), and record the
    /// environment the result belongs to: the `--environment` selector, else
    /// the one named by the loaded file ([`environment_for_path`]), else the
    /// default. Exposed for testing; [`Config::load`] is the real entry point.
    fn load_file(
        explicit: Option<&Path>,
        environment: Option<&str>,
    ) -> anyhow::Result<(Self, Option<PathBuf>)> {
        let (mut config, path) = Self::resolve_file(explicit, environment)?;
        config.environment = environment
            .map(str::to_owned)
            .or_else(|| path.as_deref().and_then(environment_for_path));
        Ok((config, path))
    }

    /// The file-resolution core of [`Self::load_file`].
    fn resolve_file(
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

    /// Parse a TOML configuration file from `path`. A file in the system
    /// configuration directory that a non-administrator could have written is
    /// refused ([`crate::system_dir::check_trusted_file`]; Windows only).
    fn from_path(path: &Path) -> anyhow::Result<Self> {
        let bytes = crate::system_dir::read_trusted(path)
            .with_context(|| format!("reading {}", path.display()))?;
        let text = String::from_utf8(bytes)
            .with_context(|| format!("reading {}: not valid UTF-8", path.display()))?;
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
        // The on/off switch applies in both scopes: a process-wide
        // FERROGATE_HELPER_ENABLE=0 is a host-wide kill switch for every
        // environment the daemon serves.
        if let Some(v) = get("FERROGATE_HELPER_ENABLE") {
            self.helper.enable = Some(parse_bool_env("FERROGATE_HELPER_ENABLE", &v)?);
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
        if let Some(v) = get("FERROGATE_ATTEST_BACKEND") {
            self.attestation.backend = match v.trim().to_ascii_lowercase().as_str() {
                "auto" => AttestBackend::Auto,
                "tpm" => AttestBackend::Tpm,
                "host-key" => AttestBackend::HostKey,
                "virtual-tpm" => AttestBackend::VirtualTpm,
                other => anyhow::bail!(
                    "FERROGATE_ATTEST_BACKEND must be \"auto\", \"tpm\", \"host-key\", or \
                     \"virtual-tpm\", got {other:?}"
                ),
            };
        }
        if let Some(v) = get("FERROGATE_TPM_EK_CERT") {
            self.attestation.tpm.ek_cert = Some(PathBuf::from(v));
        }
        self.apply_status_overrides(&get)?;
        Ok(())
    }

    /// The `[status]` slice of [`Self::apply_overrides`].
    fn apply_status_overrides(
        &mut self,
        get: impl Fn(&str) -> Option<String>,
    ) -> anyhow::Result<()> {
        if let Some(v) = get("FERROGATE_STATUS_ENABLE") {
            self.status.enable = Some(parse_bool_env("FERROGATE_STATUS_ENABLE", &v)?);
        }
        if let Some(v) = get("FERROGATE_STATUS_SOCKET") {
            self.status.socket = Some(PathBuf::from(v));
        }
        if let Some(v) = get("FERROGATE_STATUS_SOCKET_GID") {
            self.status.socket_gid = Some(v);
        }
        if let Some(v) = get("FERROGATE_STATUS_GROUP") {
            self.status.group = Some(v);
        }
        if let Some(v) = get("FERROGATE_STATUS_RATE_LIMIT") {
            let n: u32 = v
                .trim()
                .parse()
                .context("FERROGATE_STATUS_RATE_LIMIT is not an integer")?;
            self.status.rate_limit_per_sec = Some(n);
        }
        if let Some(v) = get("FERROGATE_STATUS_LOG_RECORDS") {
            let n: usize = v
                .trim()
                .parse()
                .context("FERROGATE_STATUS_LOG_RECORDS is not an integer")?;
            self.status.log_buffer_records = Some(n);
        }
        if let Some(v) = get("FERROGATE_STATUS_LOG_BYTES") {
            let n: usize = v
                .trim()
                .parse()
                .context("FERROGATE_STATUS_LOG_BYTES is not an integer")?;
            self.status.log_buffer_bytes = Some(n);
        }
        Ok(())
    }

    // ── Resolved accessors (apply built-in defaults) ────────────────────────

    /// The tracing filter directive (`log`, else `info`).
    #[must_use]
    pub fn log_directive(&self) -> &str {
        self.log.as_deref().unwrap_or("info")
    }

    /// The environment this configuration belongs to (`None` ⇒ the default
    /// environment), as recorded by the loader.
    #[must_use]
    pub fn environment(&self) -> Option<&str> {
        self.environment.as_deref()
    }

    /// Whether the helper API is served (`helper.enable`, default on).
    #[must_use]
    pub fn helper_enabled(&self) -> bool {
        self.helper.enable.unwrap_or(true)
    }

    /// The helper listener address, or `None` when the helper API is switched
    /// off (`helper.enable = false` / `FERROGATE_HELPER_ENABLE=0`).
    ///
    /// An explicit `helper.socket` (file or `FERROGATE_HELPER_SOCKET`) is used
    /// verbatim; an unset or blank one resolves to the platform default for
    /// this configuration's [`environment`](Self::environment) under the
    /// host's [`default_selection`](Self::default_selection), see
    /// [`default_helper_address`]. The daemon, `mia test` and `mia setup` all
    /// resolve the address through here, so they always agree.
    #[must_use]
    pub fn helper_socket(&self) -> Option<PathBuf> {
        if !self.helper_enabled() {
            return None;
        }
        Some(self.explicit_helper_socket().map_or_else(
            || default_helper_address(self.environment(), self.default_selection.environment()),
            Path::to_path_buf,
        ))
    }

    /// The explicit `helper.socket`, if set and not blank.
    fn explicit_helper_socket(&self) -> Option<&Path> {
        non_blank_path(self.helper.socket.as_deref())
    }

    /// The host-wide default-environment selection this configuration was
    /// resolved against (unset until [`Self::apply_default_selection`]).
    #[must_use]
    pub fn default_selection(&self) -> &crate::default_env::DefaultSelection {
        &self.default_selection
    }

    /// Whether this configuration's environment is the host's default
    /// environment — the one entitled to the well-known helper address
    /// (`mia.toml` unless another environment is selected).
    #[must_use]
    pub fn is_default_environment(&self) -> bool {
        self.default_selection.is_default(self.environment())
    }

    /// Whether this configuration's helper listener is the well-known default
    /// address (`default_helper_socket(None)`).
    #[must_use]
    pub fn serves_well_known_address(&self) -> bool {
        self.helper_socket().is_some_and(|s| {
            crate::default_env::same_helper_address(&s, &default_helper_socket(None))
        })
    }

    /// Resolve this configuration against the host's default-environment
    /// `selection` (see [`crate::default_env`]); the loaders call it last.
    ///
    /// With a selection in force, an explicit `helper.socket` that names the
    /// well-known address in any environment other than the selected one is
    /// refused — two identities must never share one address — unless the
    /// helper API is switched off here. With no selection nothing is checked,
    /// so existing deployments behave exactly as before.
    pub fn apply_default_selection(
        &mut self,
        selection: &crate::default_env::DefaultSelection,
    ) -> anyhow::Result<()> {
        self.default_selection = selection.clone();
        let Some(selected) = selection.environment() else {
            return Ok(());
        };
        if self.is_default_environment() || !self.helper_enabled() {
            return Ok(());
        }
        let well_known = default_helper_socket(None);
        if let Some(explicit) = self.explicit_helper_socket() {
            anyhow::ensure!(
                !crate::default_env::same_helper_address(explicit, &well_known),
                "helper.socket {} is the well-known default helper address, which belongs to \
                 the default environment `{selected}` ({}); environment `{}` must not serve it \
                 (two identities on one address). Unset helper.socket to use {} instead, or \
                 choose another path",
                explicit.display(),
                selection.source(),
                self.environment()
                    .unwrap_or(crate::default_env::RESERVED_ENVIRONMENT),
                default_helper_address(self.environment(), Some(selected)).display(),
            );
        }
        Ok(())
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
    /// A blank value is treated as unset. `None` ⇒ no explicit group; the
    /// daemon then applies the platform default
    /// (`crate::helper::socket_dir::plan`: on macOS the config directory's
    /// group for a socket in its own `run/` directory).
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

    /// The signed allowlist body the helper API verifies callers against.
    ///
    /// An explicit `allowlist.path` (file or `FERROGATE_ALLOWLIST`) is used
    /// verbatim; an unset or blank one resolves to the platform default for
    /// this configuration's [`environment`](Self::environment), see
    /// [`default_allowlist_path`]. Precedence: default < `allowlist.path` <
    /// `FERROGATE_ALLOWLIST`. The daemon, `mia test`, `mia setup`,
    /// `mia resync-allowlist` and `mia refresh-key` all resolve the body here,
    /// so they always agree on where it lives.
    #[must_use]
    pub fn allowlist_path(&self) -> PathBuf {
        self.explicit_allowlist_path().map_or_else(
            || default_allowlist_path(self.environment()),
            Path::to_path_buf,
        )
    }

    /// Whether [`Self::allowlist_path`] is the built-in default (no explicit,
    /// non-blank `allowlist.path` / `FERROGATE_ALLOWLIST`).
    #[must_use]
    pub fn allowlist_path_is_default(&self) -> bool {
        self.explicit_allowlist_path().is_none()
    }

    /// The trusted CMIS enrollment key that verifies the allowlist
    /// (`allowlist.key` / `FERROGATE_ALLOWLIST_KEY`), or `None` when unset or
    /// blank. Deliberately **without** a default: the key is the trust anchor,
    /// so it must be named by the operator — a key file merely appearing at a
    /// well-known path must never become trusted. With no key every caller is
    /// denied (fail closed).
    #[must_use]
    pub fn allowlist_key(&self) -> Option<&Path> {
        non_blank_path(self.allowlist.key.as_deref())
    }

    /// The explicit `allowlist.path`, if set and not blank.
    fn explicit_allowlist_path(&self) -> Option<&Path> {
        non_blank_path(self.allowlist.path.as_deref())
    }

    /// Test-only: record `environment` as the loader would, so other modules'
    /// tests can resolve per-environment defaults.
    #[cfg(test)]
    pub(crate) fn with_environment(mut self, environment: &str) -> Self {
        self.environment = Some(environment.to_owned());
        self
    }

    /// Whether the status endpoint is served (`status.enable`, default on).
    #[must_use]
    pub fn status_enabled(&self) -> bool {
        self.status.enable.unwrap_or(true)
    }

    /// The status endpoint address; default
    /// [`mia_status_proto::DEFAULT_ENDPOINT`].
    #[must_use]
    pub fn status_socket(&self) -> PathBuf {
        self.status
            .socket
            .clone()
            .unwrap_or_else(|| PathBuf::from(mia_status_proto::DEFAULT_ENDPOINT))
    }

    /// The numeric gid to own the status socket, parsed from
    /// `status.socket_gid`. A blank value is treated as unset.
    pub fn status_socket_gid(&self) -> anyhow::Result<Option<u32>> {
        match self.status.socket_gid.as_deref().map(str::trim) {
            None | Some("") => Ok(None),
            Some(s) => s
                .parse::<u32>()
                .map(Some)
                .with_context(|| format!("status.socket_gid {s:?} is not a numeric gid")),
        }
    }

    /// The group allowed to read status; default [`DEFAULT_STATUS_GROUP`].
    #[must_use]
    pub fn status_group(&self) -> &str {
        self.status
            .group
            .as_deref()
            .map(str::trim)
            .filter(|g| !g.is_empty())
            .unwrap_or(DEFAULT_STATUS_GROUP)
    }

    /// Requests per second per caller uid on the status endpoint, clamped to
    /// `1..=`[`MAX_STATUS_RATE_LIMIT`].
    #[must_use]
    pub fn status_rate_limit(&self) -> u32 {
        self.status
            .rate_limit_per_sec
            .unwrap_or(DEFAULT_STATUS_RATE_LIMIT)
            .clamp(1, MAX_STATUS_RATE_LIMIT)
    }

    /// The log ring buffer's `(records, bytes)` capacity, each clamped to its
    /// hard ceiling. Either being `0` disables the buffer.
    #[must_use]
    pub fn log_buffer_limits(&self) -> (usize, usize) {
        (
            self.status
                .log_buffer_records
                .unwrap_or(DEFAULT_LOG_BUFFER_RECORDS)
                .min(MAX_LOG_BUFFER_RECORDS),
            self.status
                .log_buffer_bytes
                .unwrap_or(DEFAULT_LOG_BUFFER_BYTES)
                .min(MAX_LOG_BUFFER_BYTES),
        )
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
    /// Resolve and load the configuration this source describes, against the
    /// host's current default-environment selection (re-read now — the
    /// SIGHUP reload path).
    pub fn load(&self) -> anyhow::Result<(Config, Option<PathBuf>)> {
        self.load_with(&crate::default_env::DefaultSelection::load()?)
    }

    /// [`Self::load`] against an already-resolved `selection`, so a daemon
    /// serving several environments resolves the selection once and applies
    /// the same one to all of them.
    pub fn load_with(
        &self,
        selection: &crate::default_env::DefaultSelection,
    ) -> anyhow::Result<(Config, Option<PathBuf>)> {
        let (mut config, path) =
            Config::load_file(self.path.as_deref(), self.environment.as_deref())?;
        let scope = if self.discovered_named_env {
            EnvOverrideScope::SharedOnly
        } else {
            EnvOverrideScope::Full
        };
        config.apply_env(scope)?;
        config.apply_default_selection(selection)?;
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

/// A configured path, unless it is blank (empty or whitespace only): a blank
/// value counts as unset, so the key's default (or absence) applies.
fn non_blank_path(path: Option<&Path>) -> Option<&Path> {
    path.filter(|p| !p.to_string_lossy().trim().is_empty())
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
        assert_eq!(config_filename(None), "mia.toml");
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
            assert!(
                validate_environment(bad).is_err(),
                "{bad:?} should be rejected"
            );
        }
    }

    #[test]
    fn classify_config_filename_classifies() {
        assert_eq!(
            classify_config_filename("mia.toml"),
            Some(ConfigFile::Default)
        );
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
            found
                .iter()
                .map(|d| d.environment.clone())
                .collect::<Vec<_>>(),
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
        assert_eq!(c.allowlist_max_age(), 72 * 3600);
        // No socket configured ⇒ the helper API is still on, at the default.
        assert!(c.helper_enabled());
        assert_eq!(c.helper_socket(), Some(default_helper_socket(None)));
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
            backend = "virtual-tpm"
        "#;
        let c = Config::from_toml(toml).unwrap();
        assert_eq!(c.log_directive(), "mia=debug,info");
        assert_eq!(
            c.cmis.endpoint.as_deref(),
            Some("https://cmis.example.com:8443")
        );
        assert_eq!(
            c.helper_socket().as_deref(),
            Some(Path::new("/run/ferrogate/mia.sock"))
        );
        assert_eq!(c.socket_mode().unwrap(), 0o640);
        assert_eq!(c.allowlist_max_age(), 3600);
        assert_eq!(
            c.allowlist.key.as_deref(),
            Some(Path::new("/etc/ferrogate/allowlist.pub"))
        );
        assert!(c.attestation.ima_log.is_some());
        assert_eq!(c.attestation.backend, AttestBackend::VirtualTpm);
    }

    #[test]
    fn attestation_backend_defaults_to_auto() {
        let c = Config::from_toml("").unwrap();
        assert_eq!(c.attestation.backend, AttestBackend::Auto);
    }

    #[test]
    fn attestation_backend_parses_tpm_and_auto() {
        let c = Config::from_toml("[attestation]\nbackend = \"tpm\"").unwrap();
        assert_eq!(c.attestation.backend, AttestBackend::Tpm);
        let c = Config::from_toml("[attestation]\nbackend = \"auto\"").unwrap();
        assert_eq!(c.attestation.backend, AttestBackend::Auto);
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
        assert_eq!(
            c.helper_socket().as_deref(),
            Some(Path::new("/from/env.sock"))
        );
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
        assert_eq!(c.helper_socket().as_deref(), Some(Path::new("/run/x.sock")));
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
        assert_eq!(
            c.helper_socket().as_deref(),
            Some(Path::new("/from/file.sock"))
        );
        assert_eq!(c.socket_mode().unwrap(), 0o600);
        assert_eq!(c.socket_gid().unwrap(), Some(777));
    }

    #[test]
    fn shared_only_scope_keeps_the_environment_default_socket() {
        // Without a file value, SharedOnly must not fill the socket from the
        // process-wide env var either: the named environment gets its own
        // per-environment default, never the default environment's path.
        let mut c = Config {
            environment: Some("staging".into()),
            ..Config::default()
        };
        let env: HashMap<&str, &str> = HashMap::from([("FERROGATE_HELPER_SOCKET", "/run/x.sock")]);
        c.apply_overrides(EnvOverrideScope::SharedOnly, |k| {
            env.get(k).map(|s| (*s).to_string())
        })
        .unwrap();
        assert_eq!(c.helper.socket, None);
        assert_eq!(
            c.helper_socket(),
            Some(default_helper_socket(Some("staging")))
        );
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
    fn status_section_parses_and_defaults() {
        let c = Config::default();
        assert!(c.status_enabled());
        assert_eq!(
            c.status_socket(),
            PathBuf::from(mia_status_proto::DEFAULT_ENDPOINT)
        );
        assert_eq!(c.status_socket_gid().unwrap(), None);
        assert_eq!(c.status_group(), DEFAULT_STATUS_GROUP);
        assert_eq!(c.status_rate_limit(), DEFAULT_STATUS_RATE_LIMIT);
        assert_eq!(
            c.log_buffer_limits(),
            (DEFAULT_LOG_BUFFER_RECORDS, DEFAULT_LOG_BUFFER_BYTES)
        );

        let c = Config::from_toml(
            "[status]\nenable = false\nsocket = '/tmp/s.sock'\nsocket_gid = '42'\n\
             group = 'ops'\nrate_limit_per_sec = 0\nlog_buffer_records = 0\n\
             log_buffer_bytes = 999999999999",
        )
        .unwrap();
        assert!(!c.status_enabled());
        assert_eq!(c.status_socket(), PathBuf::from("/tmp/s.sock"));
        assert_eq!(c.status_socket_gid().unwrap(), Some(42));
        assert_eq!(c.status_group(), "ops");
        // Clamped: a zero budget becomes 1 req/s, the byte cap hits its ceiling.
        assert_eq!(c.status_rate_limit(), 1);
        assert_eq!(c.log_buffer_limits(), (0, MAX_LOG_BUFFER_BYTES));
        // Unknown keys in [status] are rejected like everywhere else.
        assert!(Config::from_toml("[status]\nbogus = 1").is_err());
    }

    #[test]
    fn status_env_overrides_apply() {
        let mut c = Config::default();
        let env: HashMap<&str, &str> = HashMap::from([
            ("FERROGATE_STATUS_ENABLE", "0"),
            ("FERROGATE_STATUS_SOCKET", "/run/x-status.sock"),
            ("FERROGATE_STATUS_SOCKET_GID", "77"),
            ("FERROGATE_STATUS_GROUP", "staff"),
            ("FERROGATE_STATUS_RATE_LIMIT", "5"),
            ("FERROGATE_STATUS_LOG_RECORDS", "10"),
            ("FERROGATE_STATUS_LOG_BYTES", "4096"),
        ]);
        c.apply_overrides(EnvOverrideScope::Full, |k| {
            env.get(k).map(|s| (*s).to_string())
        })
        .unwrap();
        assert!(!c.status_enabled());
        assert_eq!(c.status_socket(), PathBuf::from("/run/x-status.sock"));
        assert_eq!(c.status_socket_gid().unwrap(), Some(77));
        assert_eq!(c.status_group(), "staff");
        assert_eq!(c.status_rate_limit(), 5);
        assert_eq!(c.log_buffer_limits(), (10, 4096));
    }

    #[test]
    fn env_override_table_matches_the_overlay() {
        // Every variable in ENV_OVERRIDES must actually change the config when
        // set (so `mia setup --dump` never claims an override that isn't one),
        // and `env_overridden` must report exactly the variables that are set.
        for o in ENV_OVERRIDES {
            let value = match o.var {
                "FERROGATE_HELPER_REQUIRE_AUTHENTICODE"
                | "FERROGATE_HELPER_ENABLE"
                | "FERROGATE_ALLOWLIST_FETCH"
                | "FERROGATE_ALLOWLIST_PROPOSE"
                | "FERROGATE_STATUS_ENABLE" => "1",
                "FERROGATE_ALLOWLIST_MAX_AGE_SECS"
                | "FERROGATE_ALLOWLIST_PROPOSE_INTERVAL_SECS"
                | "FERROGATE_STATUS_RATE_LIMIT"
                | "FERROGATE_STATUS_LOG_RECORDS"
                | "FERROGATE_STATUS_LOG_BYTES"
                | "FERROGATE_HELPER_SOCKET_GID"
                | "FERROGATE_STATUS_SOCKET_GID" => "7",
                "FERROGATE_ATTEST_BACKEND" => "tpm",
                _ => "x",
            };
            let mut c = Config::default();
            c.apply_overrides(EnvOverrideScope::Full, |k| {
                (k == o.var).then(|| value.to_string())
            })
            .unwrap();
            assert_ne!(c, Config::default(), "{} did not change the config", o.var);
            let reported = env_overridden(EnvOverrideScope::Full, |k| {
                (k == o.var).then(|| value.to_string())
            });
            assert_eq!(reported, vec![*o]);
        }
        // SharedOnly never reports the per-environment socket path.
        let reported = env_overridden(EnvOverrideScope::SharedOnly, |k| {
            (k == "FERROGATE_HELPER_SOCKET").then(|| "/x".to_string())
        });
        assert_eq!(reported, [] as [EnvOverride; 0]);
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

    #[test]
    fn default_helper_socket_is_platform_and_environment_scoped() {
        let default = default_helper_socket(None);
        let staging = default_helper_socket(Some("staging"));
        #[cfg(target_os = "macos")]
        {
            assert_eq!(
                default,
                Path::new("/Library/Application Support/FerroGate/run/mia.sock")
            );
            assert_eq!(
                staging,
                Path::new("/Library/Application Support/FerroGate/run/mia-staging.sock")
            );
        }
        #[cfg(windows)]
        {
            assert_eq!(default, Path::new(r"\\.\pipe\ferrogate-mia"));
            assert_eq!(staging, Path::new(r"\\.\pipe\ferrogate-mia-staging"));
        }
        #[cfg(not(any(target_os = "macos", windows)))]
        {
            assert_eq!(default, Path::new("/run/ferrogate/mia.sock"));
            assert_eq!(staging, Path::new("/run/ferrogate/mia-staging.sock"));
        }
        // Side-by-side environments never share a listener.
        assert_ne!(default, staging);
    }

    #[test]
    fn the_owned_socket_directory_holds_every_default_socket_on_macos_only() {
        let owned = owned_helper_socket_dir();
        #[cfg(target_os = "macos")]
        {
            let owned = owned.expect("macOS owns its helper socket directory");
            assert_eq!(
                owned,
                Path::new("/Library/Application Support/FerroGate/run")
            );
            for env in [None, Some("staging")] {
                assert_eq!(default_helper_socket(env).parent(), Some(owned.as_path()));
            }
        }
        #[cfg(not(target_os = "macos"))]
        assert_eq!(owned, None);
    }

    #[test]
    fn environment_for_path_follows_the_discovery_naming() {
        assert_eq!(
            environment_for_path(Path::new("/etc/ferrogate/mia.toml")),
            None
        );
        assert_eq!(
            environment_for_path(Path::new("/etc/ferrogate/mia-prod.toml")),
            Some("prod".to_string())
        );
        // Not a config name, or an invalid embedded environment ⇒ default.
        assert_eq!(environment_for_path(Path::new("/tmp/custom.toml")), None);
        assert_eq!(environment_for_path(Path::new("/tmp/mia-a b.toml")), None);
        assert_eq!(environment_for_path(Path::new("/")), None);
    }

    #[test]
    fn loader_records_the_environment_for_the_default_socket() {
        let dir = std::env::temp_dir().join(format!("mia-env-socket-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        // A file named mia-<env>.toml loaded by path takes that environment's
        // default socket — the same one serve-all discovery would give it.
        let named = dir.join("mia-qa.toml");
        std::fs::write(&named, "").unwrap();
        let (c, _) = Config::load_file(Some(&named), None).unwrap();
        assert_eq!(c.environment(), Some("qa"));
        assert_eq!(c.helper_socket(), Some(default_helper_socket(Some("qa"))));

        // Any other file name is the default environment.
        let plain = dir.join("custom.toml");
        std::fs::write(&plain, "").unwrap();
        let (c, _) = Config::load_file(Some(&plain), None).unwrap();
        assert_eq!(c.environment(), None);
        assert_eq!(c.helper_socket(), Some(default_helper_socket(None)));

        // An --environment selector wins even when no file is found.
        let (c, path) = Config::load_file(None, Some("zz-mia-unit-test-absent")).unwrap();
        assert!(path.is_none());
        assert_eq!(c.environment(), Some("zz-mia-unit-test-absent"));
        assert_eq!(
            c.helper_socket(),
            Some(default_helper_socket(Some("zz-mia-unit-test-absent")))
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn helper_socket_precedence_default_then_toml_then_env() {
        let get = |env: &'static [(&'static str, &'static str)]| {
            move |k: &str| {
                env.iter()
                    .find(|(var, _)| *var == k)
                    .map(|(_, v)| (*v).to_string())
            }
        };
        // 1. built-in default.
        let mut c = Config::from_toml("").unwrap();
        c.apply_overrides(EnvOverrideScope::Full, get(&[])).unwrap();
        assert_eq!(c.helper_socket(), Some(default_helper_socket(None)));
        // 2. the TOML value beats the default.
        let mut c = Config::from_toml("[helper]\nsocket = '/from/file.sock'").unwrap();
        c.apply_overrides(EnvOverrideScope::Full, get(&[])).unwrap();
        assert_eq!(
            c.helper_socket().as_deref(),
            Some(Path::new("/from/file.sock"))
        );
        // 3. the env var beats the TOML value.
        c.apply_overrides(
            EnvOverrideScope::Full,
            get(&[("FERROGATE_HELPER_SOCKET", "/from/env.sock")]),
        )
        .unwrap();
        assert_eq!(
            c.helper_socket().as_deref(),
            Some(Path::new("/from/env.sock"))
        );
        // A blank value (TOML or env) means "unset": the default applies.
        let c = Config::from_toml("[helper]\nsocket = '  '").unwrap();
        assert_eq!(c.helper_socket(), Some(default_helper_socket(None)));
    }

    #[test]
    fn helper_api_can_be_disabled_explicitly() {
        // `enable = false` switches the helper API off, even with a socket set.
        let c = Config::from_toml("[helper]\nenable = false\nsocket = '/run/x.sock'").unwrap();
        assert!(!c.helper_enabled());
        assert_eq!(c.helper_socket(), None);
        // `enable = true` is the default made explicit.
        let c = Config::from_toml("[helper]\nenable = true").unwrap();
        assert_eq!(c.helper_socket(), Some(default_helper_socket(None)));

        // The env var overrides the file in both directions, in both scopes
        // (a host-wide kill switch reaches every served environment).
        for scope in [EnvOverrideScope::Full, EnvOverrideScope::SharedOnly] {
            let mut c = Config::from_toml("[helper]\nenable = true").unwrap();
            c.apply_overrides(scope, |k| {
                (k == "FERROGATE_HELPER_ENABLE").then(|| "0".to_string())
            })
            .unwrap();
            assert_eq!(c.helper_socket(), None, "{scope:?}");

            let mut c = Config::from_toml("[helper]\nenable = false").unwrap();
            c.apply_overrides(scope, |k| {
                (k == "FERROGATE_HELPER_ENABLE").then(|| "yes".to_string())
            })
            .unwrap();
            assert!(c.helper_enabled(), "{scope:?}");
        }
        // A non-boolean is a loud error, not a silent default.
        let mut c = Config::default();
        assert!(c
            .apply_overrides(EnvOverrideScope::Full, |k| {
                (k == "FERROGATE_HELPER_ENABLE").then(|| "maybe".to_string())
            })
            .is_err());
    }

    #[test]
    fn environment_is_not_a_toml_key() {
        // Only the loader decides which environment a file belongs to.
        assert!(Config::from_toml("environment = 'prod'").is_err());
        assert_eq!(Config::from_toml("").unwrap().environment(), None);
    }

    /// A selection of `env` from the environment variable (no file needed).
    fn select(env: &str) -> crate::default_env::DefaultSelection {
        crate::default_env::DefaultSelection::resolve(
            Path::new("/nonexistent/environments.toml"),
            Some(env.to_string()),
        )
        .unwrap()
    }

    /// A configuration for `environment` parsed from `toml`, resolved against
    /// `selection`.
    fn resolved(
        environment: Option<&str>,
        toml: &str,
        selection: &crate::default_env::DefaultSelection,
    ) -> anyhow::Result<Config> {
        let mut c = Config::from_toml(toml).unwrap();
        c.environment = environment.map(str::to_owned);
        c.apply_default_selection(selection)?;
        Ok(c)
    }

    #[test]
    fn unset_selection_keeps_the_historical_addresses() {
        let unset = crate::default_env::DefaultSelection::unset();
        let main = resolved(None, "", &unset).unwrap();
        let prod = resolved(Some("prod"), "", &unset).unwrap();
        assert_eq!(main.helper_socket(), Some(default_helper_socket(None)));
        assert_eq!(
            prod.helper_socket(),
            Some(default_helper_socket(Some("prod")))
        );
        assert!(main.is_default_environment() && main.serves_well_known_address());
        assert!(!prod.is_default_environment() && !prod.serves_well_known_address());
        // No selection ⇒ no new collision rule: a named environment that
        // explicitly takes the well-known address keeps working as before.
        let well_known = default_helper_socket(None);
        let legacy = format!("[helper]\nsocket = '{}'", well_known.display());
        let c = resolved(Some("prod"), &legacy, &unset).unwrap();
        assert_eq!(c.helper_socket(), Some(well_known));
    }

    #[test]
    fn selected_environment_takes_the_well_known_address() {
        let sel = select("prod");
        let prod = resolved(Some("prod"), "", &sel).unwrap();
        assert!(prod.is_default_environment());
        // One listener: the well-known address, not mia-prod.sock.
        assert_eq!(prod.helper_socket(), Some(default_helper_socket(None)));
        assert!(prod.serves_well_known_address());
        // Other named environments are untouched.
        let staging = resolved(Some("staging"), "", &sel).unwrap();
        assert_eq!(
            staging.helper_socket(),
            Some(default_helper_socket(Some("staging")))
        );
        // The selected environment's own explicit socket still wins.
        let moved = resolved(Some("prod"), "[helper]\nsocket = '/tmp/prod.sock'", &sel).unwrap();
        assert_eq!(
            moved.helper_socket().as_deref(),
            Some(Path::new("/tmp/prod.sock"))
        );
        assert!(!moved.serves_well_known_address());
    }

    #[test]
    fn mia_toml_yields_to_a_distinct_address() {
        let main = resolved(None, "", &select("prod")).unwrap();
        assert!(!main.is_default_environment());
        assert_eq!(main.helper_socket(), Some(yielded_helper_socket()));
        assert!(!main.serves_well_known_address());
        // The yielded address collides with nothing an environment can get —
        // not even an environment literally named `default`.
        let yielded = yielded_helper_socket();
        assert_ne!(yielded, default_helper_socket(None));
        for env in ["default", "prod", "default.sock", "status", "a"] {
            assert_ne!(yielded, default_helper_socket(Some(env)), "{env}");
        }
        #[cfg(not(windows))]
        assert_eq!(
            yielded.parent(),
            default_helper_socket(None).parent(),
            "beside the well-known socket"
        );
    }

    #[test]
    fn explicit_well_known_socket_outside_the_default_is_rejected() {
        let sel = select("prod");
        let well_known = default_helper_socket(None);
        let claim = format!("[helper]\nsocket = '{}'", well_known.display());
        // mia.toml has yielded: it may not keep the address explicitly.
        let err = resolved(None, &claim, &sel).unwrap_err();
        assert!(err.to_string().contains("`prod`"), "{err}");
        // Nor may any other non-selected environment.
        assert!(resolved(Some("staging"), &claim, &sel).is_err());
        // The selected environment may name it explicitly.
        assert!(resolved(Some("prod"), &claim, &sel).is_ok());
        // A switched-off helper API claims nothing.
        let off = format!("{claim}\nenable = false");
        assert!(resolved(None, &off, &sel).is_ok());
        // Other explicit paths are fine.
        assert!(resolved(None, "[helper]\nsocket = '/tmp/main.sock'", &sel).is_ok());
        // The explicit check applies to FERROGATE_HELPER_SOCKET too (it lands
        // in helper.socket before the selection is applied).
        let mut c = Config::from_toml("").unwrap();
        c.apply_overrides(EnvOverrideScope::Full, |k| {
            (k == "FERROGATE_HELPER_SOCKET").then(|| well_known.display().to_string())
        })
        .unwrap();
        assert!(c.apply_default_selection(&sel).is_err());
    }

    #[test]
    fn loader_applies_the_selection_to_discovered_environments() {
        let dir = std::env::temp_dir().join(format!("mia-default-env-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let named = dir.join("mia-prod.toml");
        std::fs::write(&named, "").unwrap();
        let main = dir.join("mia.toml");
        std::fs::write(&main, "").unwrap();
        let sel = select("prod");

        let (prod, _) = ConfigSource {
            path: Some(named),
            environment: None,
            discovered_named_env: true,
        }
        .load_with(&sel)
        .unwrap();
        assert_eq!(prod.default_selection(), &sel);
        assert_eq!(prod.helper_socket(), Some(default_helper_socket(None)));

        // mia.toml, loaded the way serve-all loads it, yields.
        let (main_cfg, _) = ConfigSource {
            path: Some(main),
            environment: None,
            discovered_named_env: false,
        }
        .load_with(&sel)
        .unwrap();
        // A process-wide FERROGATE_HELPER_SOCKET would legitimately override
        // the default environment's address; only assert the yield otherwise.
        if std::env::var_os("FERROGATE_HELPER_SOCKET").is_none() {
            assert_eq!(main_cfg.helper_socket(), Some(yielded_helper_socket()));
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn default_allowlist_path_is_platform_and_environment_scoped() {
        let default = default_allowlist_path(None);
        let staging = default_allowlist_path(Some("staging"));
        #[cfg(target_os = "macos")]
        {
            assert_eq!(
                default,
                Path::new("/Library/Application Support/FerroGate/allowlist.cbor")
            );
            assert_eq!(
                staging,
                Path::new("/Library/Application Support/FerroGate/allowlist-staging.cbor")
            );
        }
        #[cfg(windows)]
        {
            assert_eq!(default, system_config_dir().join("allowlist.cbor"));
            assert_eq!(staging, system_config_dir().join("allowlist-staging.cbor"));
        }
        #[cfg(not(any(target_os = "macos", windows)))]
        {
            assert_eq!(default, Path::new("/etc/ferrogate/allowlist.cbor"));
            assert_eq!(staging, Path::new("/etc/ferrogate/allowlist-staging.cbor"));
        }
        // Beside the system config, never in the per-user directory, and side-
        // by-side environments never share one body.
        assert_eq!(default.parent(), system_config_path().parent());
        assert_eq!(staging.parent(), system_config_path().parent());
        assert_ne!(default, staging);
    }

    #[test]
    fn allowlist_path_precedence_default_then_toml_then_env() {
        let get = |env: &'static [(&'static str, &'static str)]| {
            move |k: &str| {
                env.iter()
                    .find(|(var, _)| *var == k)
                    .map(|(_, v)| (*v).to_string())
            }
        };
        // 1. built-in default, scoped by the configuration's environment.
        let mut c = Config::from_toml("").unwrap();
        c.apply_overrides(EnvOverrideScope::Full, get(&[])).unwrap();
        assert_eq!(c.allowlist_path(), default_allowlist_path(None));
        assert!(c.allowlist_path_is_default());
        let named = Config {
            environment: Some("qa".into()),
            ..Config::default()
        };
        assert_eq!(named.allowlist_path(), default_allowlist_path(Some("qa")));
        // 2. the TOML value beats the default.
        let mut c = Config::from_toml("[allowlist]\npath = '/from/file.cbor'").unwrap();
        c.apply_overrides(EnvOverrideScope::Full, get(&[])).unwrap();
        assert_eq!(c.allowlist_path(), Path::new("/from/file.cbor"));
        assert!(!c.allowlist_path_is_default());
        // 3. the env var beats the TOML value.
        c.apply_overrides(
            EnvOverrideScope::Full,
            get(&[("FERROGATE_ALLOWLIST", "/from/env.cbor")]),
        )
        .unwrap();
        assert_eq!(c.allowlist_path(), Path::new("/from/env.cbor"));
        assert!(!c.allowlist_path_is_default());
    }

    #[test]
    fn blank_allowlist_values_count_as_unset() {
        // A blank path (TOML or env) falls back to the default ...
        let c = Config::from_toml("[allowlist]\npath = '  '\nkey = ''").unwrap();
        assert!(c.allowlist_path_is_default());
        assert_eq!(c.allowlist_path(), default_allowlist_path(None));
        // ... and a blank key is no key at all (never the empty path).
        assert_eq!(c.allowlist_key(), None);
        let mut c = Config::from_toml("[allowlist]\npath = '/from/file.cbor'").unwrap();
        c.apply_overrides(EnvOverrideScope::Full, |k| {
            (k == "FERROGATE_ALLOWLIST").then(|| " ".to_string())
        })
        .unwrap();
        assert_eq!(c.allowlist_path(), default_allowlist_path(None));
    }

    #[test]
    fn allowlist_key_has_no_default() {
        // The trust anchor is never inferred from a well-known location.
        let c = Config::from_toml("").unwrap();
        assert_eq!(c.allowlist_key(), None);
        let c = Config::from_toml("[allowlist]\nkey = '/etc/ferrogate/allowlist.pub'").unwrap();
        assert_eq!(
            c.allowlist_key(),
            Some(Path::new("/etc/ferrogate/allowlist.pub"))
        );
        // The key alone is enough: the body then lives at the default.
        assert_eq!(c.allowlist_path(), default_allowlist_path(None));
    }

    #[test]
    fn loader_records_the_environment_for_the_default_allowlist() {
        let dir = std::env::temp_dir().join(format!("mia-env-allowlist-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let named = dir.join("mia-qa.toml");
        std::fs::write(&named, "").unwrap();
        let (c, _) = Config::load_file(Some(&named), None).unwrap();
        assert_eq!(c.allowlist_path(), default_allowlist_path(Some("qa")));
        let plain = dir.join("custom.toml");
        std::fs::write(&plain, "").unwrap();
        let (c, _) = Config::load_file(Some(&plain), None).unwrap();
        assert_eq!(c.allowlist_path(), default_allowlist_path(None));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
