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

use std::io::Read as _;
use std::path::{Path, PathBuf};

use ferro_crypto::pin::SpkiPin;
use serde::Deserialize;

/// The default admin listener (F20 §2).
pub const DEFAULT_ENDPOINT: &str = "https://127.0.0.1:8444";
/// Default list auto-refresh period, in seconds.
pub const DEFAULT_REFRESH_SECS: u64 = 30;
/// Shortest auto-refresh period honoured (a smaller non-zero value is raised
/// to it, so a typo cannot turn the TUI into a load generator).
pub const MIN_REFRESH_SECS: u64 = 5;
/// Longest configuration file read, in bytes.
const MAX_CONFIG_BYTES: u64 = 64 * 1024;
/// Longest device-token file read, in bytes.
const MAX_DEVICE_TOKEN_BYTES: u64 = 1024;

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

/// The configuration file as written.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    endpoint: Option<String>,
    #[serde(default)]
    spki_pins: Vec<String>,
    device_token_path: Option<String>,
    refresh_secs: Option<u64>,
}

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

/// Whether an owner and mode are trustworthy for the configuration (or its
/// directory, when `dir`): owned by the effective user or root, and not
/// writable by group or others (a sticky directory is accepted, as `/tmp`).
///
/// # Errors
///
/// A short reason when they are not.
pub fn trusted_owner_and_mode(
    uid: u32,
    mode: u32,
    euid: u32,
    dir: bool,
) -> Result<(), &'static str> {
    if uid != euid && uid != 0 {
        return Err("is owned by another user (neither you nor root)");
    }
    let sticky = mode & 0o1000 != 0;
    if mode & 0o022 != 0 && !(dir && sticky) {
        return Err("is writable by group or others");
    }
    Ok(())
}

/// Open `path` read-only without following a symbolic link in its last
/// component and without blocking on a FIFO (Unix: `O_NOFOLLOW |
/// O_NONBLOCK`). Checks then apply to the opened handle, so the file cannot
/// be swapped between the check and the read.
///
/// # Errors
///
/// The file cannot be opened, or is a symbolic link.
pub fn open_no_follow(path: &Path) -> std::io::Result<std::fs::File> {
    #[cfg(unix)]
    {
        use rustix::fs::{Mode, OFlags};
        let fd = rustix::fs::open(
            path,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|e| {
            if e == rustix::io::Errno::LOOP {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "is a symbolic link (refused)",
                )
            } else {
                std::io::Error::from(e)
            }
        })?;
        Ok(std::fs::File::from(fd))
    }
    #[cfg(not(unix))]
    {
        // No O_NOFOLLOW: refuse a link by its own metadata, then check the
        // opened handle as on Unix.
        if std::fs::symlink_metadata(path)?.file_type().is_symlink() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "is a symbolic link (refused)",
            ));
        }
        std::fs::File::open(path)
    }
}

/// Read at most `max` bytes from `file`; `None` when it holds more.
fn read_bounded(file: std::fs::File, max: u64) -> std::io::Result<Option<Vec<u8>>> {
    let mut buf = Vec::new();
    file.take(max.saturating_add(1)).read_to_end(&mut buf)?;
    let fits = u64::try_from(buf.len()).is_ok_and(|n| n <= max);
    Ok(fits.then_some(buf))
}

/// Read a configuration file the administrator can trust. It decides where
/// the password and TOTP codes go, so it is opened once without following a
/// symlink ([`open_no_follow`]), and the **opened handle** must be a regular
/// file of bounded size, owned by the effective user or root and not
/// writable by group or others; the contents are read from that handle.
/// Every directory above it (resolved) must be owned by the effective user
/// or root and not writable by group or others, unless sticky. Applies to
/// the default files and to `--config`.
///
/// # Errors
///
/// The file cannot be opened or read, is a symlink, is too large, or fails
/// the trust check.
pub fn read_file(path: &Path) -> Result<String, ConfigError> {
    let invalid =
        |e: &dyn std::fmt::Display| ConfigError::Invalid(format!("{}: {e}", path.display()));
    let file = open_no_follow(path).map_err(|e| invalid(&e))?;
    let meta = file.metadata().map_err(|e| invalid(&e))?;
    if !meta.is_file() || meta.len() > MAX_CONFIG_BYTES {
        return Err(ConfigError::Invalid(format!(
            "{} is not a regular file of at most {MAX_CONFIG_BYTES} bytes",
            path.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let euid = rustix::process::geteuid().as_raw();
        let refuse = |what: &Path, why: &str| {
            ConfigError::Invalid(format!(
                "{} {why}; refusing the configuration (it decides where your password goes)",
                what.display()
            ))
        };
        trusted_owner_and_mode(meta.uid(), meta.mode(), euid, false)
            .map_err(|why| refuse(path, why))?;
        let parent = match path.parent() {
            Some(p) if !p.as_os_str().is_empty() => p,
            _ => Path::new("."),
        };
        let dir = std::fs::canonicalize(parent).map_err(|e| invalid(&e))?;
        for ancestor in dir.ancestors() {
            let dmeta = std::fs::metadata(ancestor).map_err(|e| invalid(&e))?;
            trusted_owner_and_mode(dmeta.uid(), dmeta.mode(), euid, true)
                .map_err(|why| refuse(ancestor, why))?;
        }
    }
    let bytes = read_bounded(file, MAX_CONFIG_BYTES)
        .map_err(|e| invalid(&e))?
        .ok_or_else(|| invalid(&format!("larger than {MAX_CONFIG_BYTES} bytes")))?;
    String::from_utf8(bytes).map_err(|_| invalid(&"not UTF-8 text"))
}

/// Check an admin endpoint: `https://host:port` with an explicit, non-zero
/// port, no user information, path or query. A missing port is refused
/// rather than guessed: the transport's default (8443) is the main
/// listener, whose certificate the admin listener shares by default.
///
/// # Errors
///
/// An operator-facing reason.
pub fn check_endpoint(endpoint: &str) -> Result<(), String> {
    let shown = crate::sanitize::truncate_end(endpoint, 80);
    if endpoint.len() > 512 || !endpoint.starts_with("https://") {
        return Err(format!(
            "the admin endpoint must be an https:// URL (got `{shown}`): admin traffic is never plaintext"
        ));
    }
    let uri: tonic::transport::Uri = endpoint
        .parse()
        .map_err(|_| format!("the admin endpoint `{shown}` is not a valid URL"))?;
    let authority = uri
        .authority()
        .map(tonic::codegen::http::uri::Authority::as_str)
        .unwrap_or_default();
    if authority.contains('@') || uri.host().is_none_or(str::is_empty) {
        return Err(format!(
            "the admin endpoint `{shown}` needs a host and no user information"
        ));
    }
    if !matches!(uri.path(), "" | "/") || uri.query().is_some() {
        return Err(format!(
            "the admin endpoint `{shown}` takes no path or query (https://host:port)"
        ));
    }
    match uri.port_u16() {
        Some(p) if p != 0 => Ok(()),
        _ => Err(format!(
            "the admin endpoint `{shown}` needs an explicit port, e.g. {DEFAULT_ENDPOINT} \
             (the admin listener's default); without one the main listener (8443) would \
             receive your password"
        )),
    }
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
    let parsed: FileConfig = match file {
        Some(text) => toml::from_str(text)
            .map_err(|e| ConfigError::Invalid(format!("admin.toml: {}", e.message())))?,
        None => FileConfig::default(),
    };
    let endpoint = env("FERROGATE_ADMIN_ENDPOINT")
        .filter(|v| !v.is_empty())
        .or(parsed.endpoint)
        .unwrap_or_else(|| DEFAULT_ENDPOINT.to_string());
    check_endpoint(&endpoint).map_err(ConfigError::Invalid)?;
    let pin_texts: Vec<String> = match env("FERROGATE_ADMIN_SPKI_PIN").filter(|v| !v.is_empty()) {
        Some(v) => v
            .split(|c: char| c == ',' || c.is_whitespace())
            .filter(|p| !p.is_empty())
            .map(str::to_string)
            .collect(),
        None => parsed.spki_pins,
    };
    if pin_texts.is_empty() {
        return Err(ConfigError::NoPin);
    }
    let spki_pins = pin_texts
        .iter()
        .map(|p| {
            SpkiPin::from_hex(p).map_err(|e| {
                ConfigError::Invalid(format!(
                    "invalid SPKI pin `{}`: {e}",
                    crate::sanitize::truncate_end(p, 100)
                ))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let device_token_path = match parsed.device_token_path.filter(|p| !p.is_empty()) {
        Some(p) => Some(PathBuf::from(p)),
        None => default_device_token_path(env),
    };
    Ok(Config {
        endpoint,
        spki_pins,
        device_token_path,
        refresh_secs: match parsed.refresh_secs.unwrap_or(DEFAULT_REFRESH_SECS) {
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

/// Read the device token from `path`: opened without following a symlink,
/// and empty when absent, not a regular file, not owned by the effective
/// user, readable by group or others, larger than 1 KiB or not printable
/// ASCII. Every check applies to the opened handle.
#[must_use]
pub fn read_device_token(path: Option<&Path>) -> String {
    let Some(path) = path else {
        return String::new();
    };
    let Ok(file) = open_no_follow(path) else {
        return String::new();
    };
    let Ok(meta) = file.metadata() else {
        return String::new();
    };
    if !meta.is_file() || meta.len() > MAX_DEVICE_TOKEN_BYTES {
        return String::new();
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if meta.mode() & 0o077 != 0 || meta.uid() != rustix::process::geteuid().as_raw() {
            return String::new();
        }
    }
    let Ok(Some(bytes)) = read_bounded(file, MAX_DEVICE_TOKEN_BYTES) else {
        return String::new();
    };
    String::from_utf8(bytes)
        .map(|t| t.trim().to_string())
        .ok()
        .filter(|t| t.bytes().all(|b| b.is_ascii_graphic()))
        .unwrap_or_default()
}

/// Keep the device token in a fresh `0600` file at `path` (directory `0700`),
/// never through a symlink. Errors are returned for the caller to ignore: the
/// token is a throttle hint only.
///
/// # Errors
///
/// The directory or file cannot be created, or `path` is not a regular file.
pub fn store_device_token(path: &Path, token: &str) -> std::io::Result<()> {
    if token.is_empty() || !token.bytes().all(|b| b.is_ascii_graphic()) {
        return Ok(());
    }
    if let Some(dir) = path.parent() {
        let mut b = std::fs::DirBuilder::new();
        b.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;
            b.mode(0o700);
        }
        b.create(dir)?;
    }
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_file() => std::fs::remove_file(path)?,
        Ok(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "device token path is not a regular file",
            ))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    std::io::Write::write_all(&mut f, token.as_bytes())?;
    f.sync_all()
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
