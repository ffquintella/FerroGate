//! Configuration (F21 §1): where the admin listener is and which SPKI pins
//! authenticate it. The file holds **no secrets**.
//!
//! Sources, in increasing precedence:
//!
//! 1. the first file found among `$XDG_CONFIG_HOME/ferrogate/admin.toml`
//!    (`~/.config/ferrogate/admin.toml` when unset) and
//!    `/etc/ferrogate/admin.toml`, or the file named by `--config`;
//! 2. `FERROGATE_ADMIN_ENDPOINT` and `FERROGATE_ADMIN_SPKI_PIN` (one or more
//!    pins separated by commas or spaces; replaces the file's pins).
//!
//! ```toml
//! endpoint          = "https://127.0.0.1:8444"
//! spki_pins         = ["<sha384-hex>"]   # required; no trust on first use
//! device_token_path = ""                 # default: $XDG_STATE_HOME/ferrogate/device-token
//! refresh_secs      = 30                 # list auto-refresh (≥ 5); 0 disables
//! ```
//!
//! The TUI refuses to start without a pin, and refuses an endpoint that is
//! not `https://host:port` with an **explicit port**: without one the
//! transport would dial 8443, the main listener, whose certificate is by
//! default also the admin listener's, so the pin would match and the
//! password would reach the wrong listener. Because the endpoint and pin
//! decide who receives the administrator's password, the configuration file
//! is opened once without following a symlink, checked on the open handle
//! (regular file, bounded size, owned by the effective user or root, not
//! writable by group or others) and read from that handle; every directory
//! above it must pass the same ownership check (sticky directories excepted)
//! (Unix).
//!
//! The file checks, the endpoint check, the `admin.toml` parser and the
//! device-token file are shared with the tray admin client through
//! `ferrogate-admin-client` (T281).

use std::path::{Path, PathBuf};

use ferro_crypto::pin::SpkiPin;
use ferrogate_admin_client::config as shared;

pub use ferrogate_admin_client::endpoint::{check_endpoint, DEFAULT_ENDPOINT};
pub use ferrogate_admin_client::files::{
    open_no_follow, read_device_token, store_device_token, trusted_owner_and_mode,
};

/// Default list auto-refresh period, in seconds.
pub const DEFAULT_REFRESH_SECS: u64 = 30;
/// Shortest auto-refresh period honoured (a smaller non-zero value is raised
/// to it, so a typo cannot turn the TUI into a load generator).
pub const MIN_REFRESH_SECS: u64 = 5;

/// How to obtain a pin, printed when none is configured (`transport-tls.md`).
pub const PIN_HELP: &str = "ferrogate-tui needs the SPKI pin of the CMIS admin listener and never \
trusts a server on first use.\n\
\n\
Obtain the pin on a CMIS node from its certificate, then configure it:\n\
\n\
\x20 ferrogate spki-pin --tls-cert /etc/ferrogate/tls/cmis.crt\n\
\n\
\x20 export FERROGATE_ADMIN_SPKI_PIN=<that hex value>\n\
\x20 # or put  spki_pins = [\"<hex>\"]  in ~/.config/ferrogate/admin.toml\n\
\x20 # or in /etc/ferrogate/admin.toml\n\
\n\
See docs/transport-tls.md (\"Computing the SPKI pin\") and docs/operations.md\n\
(\"Administering approvals with ferrogate-tui\").";

/// The resolved configuration.
#[derive(Debug, Clone)]
pub struct Config {
    /// Admin listener, always `https://`.
    pub endpoint: String,
    /// Accepted SPKI pins (at least one).
    pub spki_pins: Vec<SpkiPin>,
    /// Where the device token (a throttle hint, not a credential) is kept.
    pub device_token_path: Option<PathBuf>,
    /// List auto-refresh period in seconds (0: off).
    pub refresh_secs: u64,
}

/// Why the configuration cannot be used.
#[derive(Debug)]
pub enum ConfigError {
    /// No SPKI pin anywhere: print [`PIN_HELP`] and exit.
    NoPin,
    /// Anything else, with an operator-facing message.
    Invalid(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoPin => f.write_str(PIN_HELP),
            Self::Invalid(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for ConfigError {}

impl From<shared::ConfigError> for ConfigError {
    fn from(e: shared::ConfigError) -> Self {
        match e {
            shared::ConfigError::NoPin => Self::NoPin,
            shared::ConfigError::Invalid(m) => Self::Invalid(m),
        }
    }
}

/// The configuration files to look for, in order.
#[must_use]
pub fn candidate_files(env: &dyn Fn(&str) -> Option<String>) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Some(dir) = env("XDG_CONFIG_HOME").filter(|v| !v.is_empty()) {
        out.push(PathBuf::from(dir).join("ferrogate/admin.toml"));
    } else if let Some(home) = env("HOME").filter(|v| !v.is_empty()) {
        out.push(PathBuf::from(home).join(".config/ferrogate/admin.toml"));
    }
    out.push(PathBuf::from("/etc/ferrogate/admin.toml"));
    out
}

/// The default device-token file.
fn default_device_token_path(env: &dyn Fn(&str) -> Option<String>) -> Option<PathBuf> {
    if let Some(dir) = env("XDG_STATE_HOME").filter(|v| !v.is_empty()) {
        return Some(PathBuf::from(dir).join("ferrogate/device-token"));
    }
    env("HOME")
        .filter(|v| !v.is_empty())
        .map(|h| PathBuf::from(h).join(".local/state/ferrogate/device-token"))
}

/// Read a configuration file the administrator can trust (the default files
/// and `--config`): [`ferrogate_admin_client::files::read_trusted_file`].
///
/// # Errors
/// The file cannot be opened or read, is a symlink, is too large, or fails
/// the trust check.
pub fn read_file(path: &Path) -> Result<String, ConfigError> {
    ferrogate_admin_client::files::read_trusted_file(path).map_err(ConfigError::Invalid)
}

/// Resolve the configuration from the file text (if any) and the environment.
///
/// # Errors
///
/// [`ConfigError::NoPin`] without a pin; [`ConfigError::Invalid`] for a
/// malformed file, a bad pin or a non-`https://` endpoint.
pub fn resolve(
    file: Option<&str>,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<Config, ConfigError> {
    let s = shared::resolve(file, env)?;
    Ok(Config {
        endpoint: s.endpoint,
        spki_pins: s.spki_pins,
        device_token_path: s
            .device_token_path
            .or_else(|| default_device_token_path(env)),
        refresh_secs: match s.refresh_secs.unwrap_or(DEFAULT_REFRESH_SECS) {
            0 => 0,
            secs => secs.max(MIN_REFRESH_SECS),
        },
    })
}

/// Load the configuration: `explicit` (from `--config`) or the first
/// candidate file that exists, then the environment.
///
/// # Errors
///
/// See [`resolve`] and [`read_file`].
pub fn load(explicit: Option<&Path>) -> Result<Config, ConfigError> {
    let env = |k: &str| std::env::var(k).ok();
    let text = match explicit {
        Some(path) => Some(read_file(path)?),
        None => match candidate_files(&env).into_iter().find(|p| p.exists()) {
            Some(path) => Some(read_file(&path)?),
            None => None,
        },
    };
    resolve(text.as_deref(), &env)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PIN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn env_of(pairs: &'static [(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> {
        move |k| {
            pairs
                .iter()
                .find(|(n, _)| *n == k)
                .map(|(_, v)| (*v).to_string())
        }
    }

    #[test]
    fn a_missing_pin_refuses_to_start() {
        let e = resolve(None, &env_of(&[])).unwrap_err();
        assert!(matches!(e, ConfigError::NoPin));
        assert!(e.to_string().contains("never"), "explains no TOFU");
        let e = resolve(Some("endpoint = \"https://h:1\"\n"), &env_of(&[])).unwrap_err();
        assert!(matches!(e, ConfigError::NoPin));
    }

    #[test]
    fn the_file_and_the_environment_resolve_in_order() {
        let file = format!(
            "endpoint = \"https://cmis-1:8444\"\nspki_pins = [\"{PIN}\"]\nrefresh_secs = 0\ndevice_token_path = \"/var/tmp/x\"\n"
        );
        let c = resolve(Some(&file), &env_of(&[])).unwrap();
        assert_eq!(c.endpoint, "https://cmis-1:8444");
        assert_eq!(c.spki_pins.len(), 1);
        assert_eq!(c.refresh_secs, 0);
        assert_eq!(
            c.device_token_path.as_deref(),
            Some(Path::new("/var/tmp/x"))
        );

        let c = resolve(
            Some(&file),
            &env_of(&[
                ("FERROGATE_ADMIN_ENDPOINT", "https://other:9"),
                ("FERROGATE_ADMIN_SPKI_PIN", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb, aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            ]),
        )
        .unwrap();
        assert_eq!(c.endpoint, "https://other:9");
        assert_eq!(
            c.spki_pins.len(),
            2,
            "the environment replaces the file's pins"
        );

        let c = resolve(
            None,
            &env_of(&[
                ("FERROGATE_ADMIN_SPKI_PIN", PIN),
                ("XDG_STATE_HOME", "/run/user/1000/state"),
            ]),
        )
        .unwrap();
        assert_eq!(c.endpoint, DEFAULT_ENDPOINT);
        assert_eq!(c.refresh_secs, DEFAULT_REFRESH_SECS);
        assert_eq!(
            c.device_token_path.as_deref(),
            Some(Path::new("/run/user/1000/state/ferrogate/device-token"))
        );
        let c = resolve(
            Some("refresh_secs = 1\n"),
            &env_of(&[("FERROGATE_ADMIN_SPKI_PIN", PIN)]),
        )
        .unwrap();
        assert_eq!(c.refresh_secs, MIN_REFRESH_SECS, "raised to the minimum");
    }

    #[test]
    fn plaintext_endpoints_bad_pins_and_unknown_keys_are_refused() {
        let e = resolve(
            None,
            &env_of(&[
                ("FERROGATE_ADMIN_SPKI_PIN", PIN),
                ("FERROGATE_ADMIN_ENDPOINT", "http://127.0.0.1:8444"),
            ]),
        )
        .unwrap_err();
        assert!(e.to_string().contains("https://"));
        let e = resolve(None, &env_of(&[("FERROGATE_ADMIN_SPKI_PIN", "zz")])).unwrap_err();
        assert!(e.to_string().contains("invalid SPKI pin"));
        let e = resolve(Some("password = \"x\"\n"), &env_of(&[])).unwrap_err();
        assert!(matches!(e, ConfigError::Invalid(_)));
    }

    #[test]
    fn only_files_and_directories_of_the_user_or_root_are_trusted() {
        let me = 1000;
        assert!(trusted_owner_and_mode(me, 0o100_600, me, false).is_ok());
        assert!(trusted_owner_and_mode(0, 0o100_644, me, false).is_ok());
        assert!(trusted_owner_and_mode(1001, 0o100_644, me, false).is_err());
        assert!(trusted_owner_and_mode(me, 0o100_664, me, false).is_err());
        assert!(trusted_owner_and_mode(me, 0o100_646, me, false).is_err());
        assert!(trusted_owner_and_mode(0, 0o040_755, me, true).is_ok());
        assert!(
            trusted_owner_and_mode(0, 0o041_777, me, true).is_ok(),
            "sticky /tmp"
        );
        assert!(trusted_owner_and_mode(0, 0o040_777, me, true).is_err());
        assert!(
            trusted_owner_and_mode(0, 0o041_777, me, false).is_err(),
            "sticky is for directories"
        );
        assert!(trusted_owner_and_mode(1001, 0o040_700, me, true).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn a_writable_configuration_or_directory_is_refused() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = std::env::temp_dir().join(format!(
            "ferrogate-tui-config-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.join("admin.toml");
        std::fs::write(&path, format!("spki_pins = [\"{PIN}\"]\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_file(&path).is_ok());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o664)).unwrap();
        assert!(read_file(&path).is_err(), "group-writable file");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        let e = read_file(&path).unwrap_err().to_string();
        assert!(e.contains("writable by group or others"), "{e}");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn config_files_are_looked_up_under_xdg_then_etc() {
        let files = candidate_files(&env_of(&[("XDG_CONFIG_HOME", "/home/a/.cfg")]));
        assert_eq!(
            files,
            vec![
                PathBuf::from("/home/a/.cfg/ferrogate/admin.toml"),
                PathBuf::from("/etc/ferrogate/admin.toml")
            ]
        );
        let files = candidate_files(&env_of(&[("HOME", "/home/b")]));
        assert_eq!(
            files[0],
            PathBuf::from("/home/b/.config/ferrogate/admin.toml")
        );
    }

    #[test]
    fn the_device_token_file_is_private_and_never_follows_a_symlink() {
        let dir = std::env::temp_dir().join(format!(
            "ferrogate-tui-device-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let path = dir.join("state/device-token");
        store_device_token(&path, "fgdt_abc").unwrap();
        assert_eq!(read_device_token(Some(&path)), "fgdt_abc");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert_eq!(read_device_token(Some(&path)), "", "group-readable ignored");
            let link = dir.join("link");
            std::os::unix::fs::symlink(&path, &link).unwrap();
            assert!(store_device_token(&link, "fgdt_x").is_err());
            assert_eq!(read_device_token(Some(&link)), "");
        }
        assert_eq!(read_device_token(None), "");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_endpoint_needs_https_and_an_explicit_port() {
        let env = |endpoint: &str| -> Result<Config, ConfigError> {
            resolve(None, &|k: &str| match k {
                "FERROGATE_ADMIN_SPKI_PIN" => Some(PIN.to_string()),
                "FERROGATE_ADMIN_ENDPOINT" => Some(endpoint.to_string()),
                _ => None,
            })
        };
        for ok in [
            "https://cmis-1:8444",
            "https://127.0.0.1:8444/",
            "https://[::1]:8444",
        ] {
            assert!(env(ok).is_ok(), "{ok}");
        }
        let e = env("https://cmis-1").unwrap_err().to_string();
        assert!(
            e.contains("explicit port") && e.contains("127.0.0.1:8444"),
            "{e}"
        );
        for bad in [
            "https://cmis-1:0",
            "https://admin@cmis-1:8444",
            "https://cmis-1:8444/x",
            "https://cmis-1:8444/?q=1",
            "https://:8444",
            "http://cmis-1:8444",
        ] {
            assert!(env(bad).is_err(), "{bad}");
        }
    }

    /// A fresh private directory under the temporary directory.
    #[cfg(unix)]
    fn private_dir(tag: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = std::env::temp_dir().join(format!(
            "ferrogate-tui-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_oversized_or_badly_placed_configuration_is_refused() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = private_dir("cfg-open");
        let real = dir.join("real.toml");
        std::fs::write(&real, format!("spki_pins = [\"{PIN}\"]\n")).unwrap();
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(read_file(&real).is_ok());
        // A symlink is refused (it could be swapped after a check).
        let link = dir.join("admin.toml");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let e = read_file(&link).unwrap_err().to_string();
        assert!(e.contains("symbolic link"), "{e}");
        // Too large.
        let big = dir.join("big.toml");
        std::fs::write(&big, vec![b'#'; 64 * 1024 + 1]).unwrap();
        std::fs::set_permissions(&big, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(read_file(&big).is_err());
        // A directory higher up that others can write is refused too.
        let open = dir.join("open");
        let inner = open.join("inner");
        std::fs::create_dir_all(&inner).unwrap();
        std::fs::set_permissions(&inner, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o777)).unwrap();
        let deep = inner.join("admin.toml");
        std::fs::write(&deep, format!("spki_pins = [\"{PIN}\"]\n")).unwrap();
        std::fs::set_permissions(&deep, std::fs::Permissions::from_mode(0o600)).unwrap();
        let e = read_file(&deep).unwrap_err().to_string();
        assert!(
            e.contains("open") && e.contains("writable by group or others"),
            "{e}"
        );
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(read_file(&deep).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn the_device_token_is_read_from_a_private_bounded_file_only() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = private_dir("dt-open");
        let path = dir.join("device-token");
        store_device_token(&path, "fgdt_abc").unwrap();
        assert_eq!(read_device_token(Some(&path)), "fgdt_abc");
        // A symlink swapped in at the token's place is not followed.
        let other = dir.join("other");
        std::fs::write(&other, "fgdt_planted").unwrap();
        std::fs::set_permissions(&other, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(&other, &path).unwrap();
        assert_eq!(read_device_token(Some(&path)), "");
        // More than 1 KiB is ignored, not read.
        let big = dir.join("big");
        std::fs::write(&big, vec![b'a'; 2048]).unwrap();
        std::fs::set_permissions(&big, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(read_device_token(Some(&big)), "");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
