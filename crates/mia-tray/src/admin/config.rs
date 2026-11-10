//! The admin client's configuration (F22 §2): `admin.toml` with the admin
//! endpoint and its SPKI pins, no secrets. Parsing, the environment
//! overrides and the file trust checks are shared with the TUI
//! (`ferrogate_admin_client::{config, files}`); this module picks the files.

//! Looked up in the per-user directory — `~/.config/ferrogate/` (or
//! `$XDG_CONFIG_HOME/ferrogate/`), `~/Library/Application Support/FerroGate/`,
//! `%APPDATA%\FerroGate\` — then `/etc/ferrogate/` on Unix. No pin, no
//! connection: the client never trusts a server on first use.

use std::path::{Path, PathBuf};

use ferrogate_admin_client::client::ClientConfig;
use ferrogate_admin_client::config::{
    parse_file, resolve as resolve_settings, ConfigError, FileValues, ServerChoice, ENV_ENDPOINT,
    ENV_SPKI_PIN,
};
use ferrogate_admin_client::files::{read_trusted_file, write_trusted_file, WriteError};
use ferrogate_admin_client::transport::{CONNECT_TIMEOUT, RPC_TIMEOUT};

/// The configuration file's name.
pub const FILE_NAME: &str = "admin.toml";
/// The default device-token file (beside the per-user `admin.toml`).
pub const DEVICE_TOKEN_FILE: &str = "device-token";

/// How to configure the client, shown when no pin is configured.
pub const SETUP_HELP: &str = "Enter the CMIS admin endpoint and its SPKI pin on the \
\"Admin server\" screen (\"Set up server…\"), or put them in admin.toml:\n\
\n\
\x20 endpoint  = \"https://cmis-admin.example.internal:8444\"\n\
\x20 spki_pins = [\"<sha384-hex>\"]\n\
\n\
Get the pin from operations over a trusted channel (on a CMIS node:\n\
`ferrogate spki-pin --tls-cert /etc/ferrogate/tls/cmis.crt`) and compare it.\n\
FERROGATE_ADMIN_ENDPOINT and FERROGATE_ADMIN_SPKI_PIN override the file.";

/// Where the window reads `admin.toml` and where its "admin server" screen
/// writes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Location {
    /// The per-user file, the only one the window writes (`None` without a
    /// home directory).
    pub user_file: Option<PathBuf>,
    /// The files looked up, in order (the first that exists is read).
    pub candidates: Vec<PathBuf>,
}

impl Location {
    /// The files of `os` ([`user_dir`], [`candidate_files`]).
    #[must_use]
    pub fn of(os: &str, env: &dyn Fn(&str) -> Option<String>) -> Self {
        Self {
            user_file: user_dir(os, env).map(|d| d.join(FILE_NAME)),
            candidates: candidate_files(os, env),
        }
    }

    /// The file read now: the first candidate that exists.
    #[must_use]
    pub fn in_effect(&self) -> Option<&Path> {
        self.candidates
            .iter()
            .map(PathBuf::as_path)
            .find(|p| p.exists())
    }
}

/// The file a save replaces (the per-user file) or shadows (a system one).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Current {
    /// Its path.
    pub path: PathBuf,
    /// Whether it is the per-user file, replaced by a save.
    pub is_user_file: bool,
    /// Its keys; `None` when it could not be read or parsed (nothing of it
    /// is then kept).
    pub values: Option<FileValues>,
}

/// What a save would do, read just before the screen asks to confirm it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SaveTarget {
    /// The per-user file written (`None`: no home directory, no save).
    pub path: Option<PathBuf>,
    /// The file in effect now, if any.
    pub current: Option<Current>,
    /// The per-user file exists but fails the trust checks: not replaced.
    pub refused: bool,
    /// [`ENV_ENDPOINT`] is set and wins over the file.
    pub env_endpoint: bool,
    /// [`ENV_SPKI_PIN`] is set and wins over the file.
    pub env_pin: bool,
}

/// Look at the files and the environment before a save.
#[must_use]
pub fn save_target(location: &Location, env: &dyn Fn(&str) -> Option<String>) -> SaveTarget {
    let set = |k: &str| env(k).is_some_and(|v| !v.is_empty());
    let mut refused = false;
    let current = location.in_effect().map(|path| {
        let is_user_file = location.user_file.as_deref() == Some(path);
        let values = match read_trusted_file(path) {
            Ok(text) => parse_file(&text).ok(),
            Err(why) => {
                refused = is_user_file;
                tracing::warn!(
                    event = "admin.client.config_untrusted",
                    reason = %ferrogate_admin_client::display::inert(&why, 300)
                );
                None
            }
        };
        Current {
            path: path.to_path_buf(),
            is_user_file,
            values,
        }
    });
    SaveTarget {
        path: location.user_file.clone(),
        current,
        refused,
        env_endpoint: set(ENV_ENDPOINT),
        env_pin: set(ENV_SPKI_PIN),
    }
}

/// Why [`save`] wrote nothing (`Display` is for logs).
#[derive(Debug)]
pub enum SaveError {
    /// The text did not read back as the choice (not expected).
    Render(ConfigError),
    /// The file could not be written safely.
    Write(WriteError),
}

impl std::fmt::Display for SaveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Render(e) => write!(f, "{e}"),
            Self::Write(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for SaveError {}

/// Write `choice` to the per-user file `path`, keeping `keep`'s other keys
/// ([`ServerChoice::render`]), with the shared trust rules
/// ([`write_trusted_file`]: `0600` file, private directory, atomic).
///
/// # Errors
/// Nothing was written.
pub fn save(
    path: &Path,
    choice: &ServerChoice,
    keep: Option<&FileValues>,
) -> Result<(), SaveError> {
    let text = choice.render(keep).map_err(SaveError::Render)?;
    write_trusted_file(path, &text).map_err(SaveError::Write)
}

/// The per-user configuration directory on `os` (`std::env::consts::OS`).
#[must_use]
pub fn user_dir(os: &str, env: &dyn Fn(&str) -> Option<String>) -> Option<PathBuf> {
    let var = |k: &str| env(k).filter(|v| !v.is_empty()).map(PathBuf::from);
    match os {
        "macos" => var("HOME").map(|h| h.join("Library/Application Support/FerroGate")),
        "windows" => var("APPDATA").map(|a| a.join("FerroGate")),
        _ => var("XDG_CONFIG_HOME")
            .map(|d| d.join("ferrogate"))
            .or_else(|| var("HOME").map(|h| h.join(".config/ferrogate"))),
    }
}

/// The files to look for on `os`, in order.
#[must_use]
pub fn candidate_files(os: &str, env: &dyn Fn(&str) -> Option<String>) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = user_dir(os, env)
        .map(|d| d.join(FILE_NAME))
        .into_iter()
        .collect();
    if os != "windows" {
        out.push(PathBuf::from("/etc/ferrogate").join(FILE_NAME));
    }
    out
}

/// The client configuration from the file text (if any) and the
/// environment, as the tray client kind.
///
/// # Errors
/// [`ConfigError::NoPin`] without a pin; [`ConfigError::Invalid`] otherwise.
pub fn resolve(
    file: Option<&str>,
    os: &str,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<ClientConfig, ConfigError> {
    let s = resolve_settings(file, env)?;
    Ok(ClientConfig {
        endpoint: s.endpoint,
        pins: s.spki_pins,
        device_token_path: s
            .device_token_path
            .or_else(|| user_dir(os, env).map(|d| d.join(DEVICE_TOKEN_FILE))),
        connect_timeout: CONNECT_TIMEOUT,
        rpc_timeout: RPC_TIMEOUT,
        client_kind: ferrogate_admin_client::client_kind::TRAY,
    })
}

/// Load the configuration: the first candidate file that exists (read with
/// the shared trust checks), then the environment.
///
/// # Errors
/// See [`resolve`]; a file that fails the trust checks is refused.
pub fn load() -> Result<ClientConfig, ConfigError> {
    let env = |k: &str| std::env::var(k).ok();
    let os = std::env::consts::OS;
    load_from(&Location::of(os, &env), os, &env)
}

/// [`load`] over the files of `location`.
///
/// # Errors
/// See [`resolve`]; a file that fails the trust checks is refused.
pub fn load_from(
    location: &Location,
    os: &str,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<ClientConfig, ConfigError> {
    let text = match location.in_effect() {
        Some(path) => Some(read_trusted_file(path).map_err(ConfigError::Invalid)?),
        None => None,
    };
    resolve(text.as_deref(), os, env)
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
    fn the_per_user_file_follows_the_platform_then_etc() {
        let env = env_of(&[
            ("HOME", "/home/a"),
            ("APPDATA", "C:\\Users\\a\\AppData\\Roaming"),
        ]);
        assert_eq!(
            candidate_files("linux", &env),
            vec![
                PathBuf::from("/home/a/.config/ferrogate/admin.toml"),
                PathBuf::from("/etc/ferrogate/admin.toml")
            ]
        );
        assert_eq!(
            candidate_files("macos", &env)[0],
            PathBuf::from("/home/a/Library/Application Support/FerroGate/admin.toml")
        );
        let win = candidate_files("windows", &env);
        assert_eq!(win.len(), 1, "no /etc on Windows");
        assert!(
            win[0].ends_with("FerroGate/admin.toml") || win[0].ends_with("FerroGate\\admin.toml")
        );
        let xdg = env_of(&[("HOME", "/home/a"), ("XDG_CONFIG_HOME", "/x")]);
        assert_eq!(
            candidate_files("linux", &xdg)[0],
            PathBuf::from("/x/ferrogate/admin.toml")
        );
        assert_eq!(candidate_files("linux", &env_of(&[])).len(), 1);
    }

    #[test]
    fn the_tray_kind_and_a_private_device_token_beside_the_user_file() {
        let env = env_of(&[("HOME", "/home/a"), ("FERROGATE_ADMIN_SPKI_PIN", PIN)]);
        let c = resolve(Some("endpoint = \"https://cmis:8444\"\n"), "linux", &env).unwrap();
        assert_eq!(c.client_kind, ferrogate_admin_client::client_kind::TRAY);
        assert_eq!(c.endpoint, "https://cmis:8444");
        assert_eq!(
            c.device_token_path,
            Some(PathBuf::from("/home/a/.config/ferrogate/device-token"))
        );
    }

    #[test]
    fn no_pin_means_no_connection() {
        let e = resolve(
            Some("endpoint = \"https://cmis:8444\"\n"),
            "linux",
            &env_of(&[]),
        )
        .unwrap_err();
        assert_eq!(e, ConfigError::NoPin);
        let e = resolve(
            None,
            "linux",
            &env_of(&[
                ("FERROGATE_ADMIN_SPKI_PIN", PIN),
                ("FERROGATE_ADMIN_ENDPOINT", "https://cmis"),
            ]),
        )
        .unwrap_err();
        assert!(e.to_string().contains("explicit port"), "{e}");
    }

    /// A per-user file and a "system" file, both in a private temporary
    /// directory (never the real `/etc` or home).
    fn location(dir: &Path) -> Location {
        let user = dir.join("home/ferrogate").join(FILE_NAME);
        Location {
            user_file: Some(user.clone()),
            candidates: vec![user, dir.join("etc").join(FILE_NAME)],
        }
    }

    fn no_env(_: &str) -> Option<String> {
        None
    }

    #[test]
    fn a_saved_server_is_read_back_by_the_resolver_with_private_modes() {
        let dir = tempfile::tempdir().unwrap();
        let loc = location(dir.path());
        assert!(load_from(&loc, "linux", &no_env).is_err(), "nothing yet");
        let target = save_target(&loc, &no_env);
        assert_eq!(target.current, None);
        assert!(!target.refused && !target.env_endpoint && !target.env_pin);

        let choice = ServerChoice::check("https://cmis-admin.test:8444", PIN).unwrap();
        let path = target.path.unwrap();
        save(&path, &choice, None).unwrap();
        let cfg = load_from(&loc, "linux", &no_env).unwrap();
        assert_eq!(cfg.endpoint, "https://cmis-admin.test:8444");
        assert_eq!(cfg.pins.len(), 1);
        assert_eq!(cfg.pins[0].to_hex(), PIN);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&path), 0o600);
            assert_eq!(mode(path.parent().unwrap()), 0o700);
        }
    }

    #[test]
    fn a_replaced_file_keeps_its_other_keys_and_the_environment_still_wins() {
        let dir = tempfile::tempdir().unwrap();
        let loc = location(dir.path());
        let user = loc.user_file.clone().unwrap();
        let old = format!(
            "endpoint = \"https://old:8444\"\nspki_pins = [\"{}\"]\n\
             device_token_path = \"/var/dt\"\nrefresh_secs = 5\n",
            "b".repeat(96)
        );
        write_trusted_file(&user, &old).unwrap();
        let target = save_target(&loc, &no_env);
        let current = target.current.clone().unwrap();
        assert!(current.is_user_file && !target.refused);
        let values = current.values.unwrap();
        assert_eq!(values.spki_pins, vec!["b".repeat(96)]);

        let choice = ServerChoice::check("https://new:8444", PIN).unwrap();
        save(&user, &choice, Some(&values)).unwrap();
        let cfg = load_from(&loc, "linux", &no_env).unwrap();
        assert_eq!(cfg.endpoint, "https://new:8444");
        assert_eq!(cfg.device_token_path, Some(PathBuf::from("/var/dt")));
        let back = parse_file(&read_trusted_file(&user).unwrap()).unwrap();
        assert_eq!(back.refresh_secs, Some(5));
        assert_eq!(back.spki_pins, vec![PIN.to_string()]);

        let env = env_of(&[("FERROGATE_ADMIN_ENDPOINT", "https://env:9444")]);
        let target = save_target(&loc, &env);
        assert!(target.env_endpoint && !target.env_pin);
        let cfg = load_from(&loc, "linux", &env).unwrap();
        assert_eq!(cfg.endpoint, "https://env:9444", "the environment wins");
    }

    #[test]
    fn a_system_file_is_shadowed_and_an_untrusted_user_file_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let loc = location(dir.path());
        let system = dir.path().join("etc").join(FILE_NAME);
        let text = format!("endpoint = \"https://sys:8444\"\nspki_pins = [\"{PIN}\"]\n");
        write_trusted_file(&system, &text).unwrap();
        let target = save_target(&loc, &no_env);
        let current = target.current.unwrap();
        assert_eq!(current.path, system);
        assert!(!current.is_user_file && !target.refused);
        assert!(current.values.is_some());

        // Unparsable but trusted: replaced wholesale, nothing kept.
        let user = loc.user_file.clone().unwrap();
        write_trusted_file(&user, "endpoint = [\n").unwrap();
        let target = save_target(&loc, &no_env);
        let current = target.current.unwrap();
        assert!(current.is_user_file && current.values.is_none() && !target.refused);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&user, std::fs::Permissions::from_mode(0o666)).unwrap();
            let target = save_target(&loc, &no_env);
            assert!(target.refused, "a writable user file is not replaced");
            let choice = ServerChoice::check("https://new:8444", PIN).unwrap();
            assert!(matches!(
                save(&user, &choice, None),
                Err(SaveError::Write(WriteError::Untrusted(_)))
            ));
        }
    }
}
