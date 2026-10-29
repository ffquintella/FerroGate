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
use ferrogate_admin_client::config::{resolve as resolve_settings, ConfigError};
use ferrogate_admin_client::transport::{CONNECT_TIMEOUT, RPC_TIMEOUT};

/// The configuration file's name.
pub const FILE_NAME: &str = "admin.toml";
/// The default device-token file (beside the per-user `admin.toml`).
pub const DEVICE_TOKEN_FILE: &str = "device-token";

/// How to configure the client, shown when no pin is configured.
pub const SETUP_HELP: &str = "Put the CMIS admin endpoint and its SPKI pin in admin.toml:\n\
\n\
\x20 endpoint  = \"https://cmis-admin.example.internal:8444\"\n\
\x20 spki_pins = [\"<sha384-hex>\"]\n\
\n\
Get the pin from operations over a trusted channel (on a CMIS node:\n\
`ferrogate spki-pin --tls-cert /etc/ferrogate/tls/cmis.crt`) and compare it.\n\
FERROGATE_ADMIN_ENDPOINT and FERROGATE_ADMIN_SPKI_PIN override the file.";

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
    let text = match candidate_files(os, &env).into_iter().find(|p| p.exists()) {
        Some(path) => Some(read(&path)?),
        None => None,
    };
    resolve(text.as_deref(), os, &env)
}

fn read(path: &Path) -> Result<String, ConfigError> {
    ferrogate_admin_client::files::read_trusted_file(path).map_err(ConfigError::Invalid)
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
}
