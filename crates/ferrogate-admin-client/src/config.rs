//! `admin.toml` (F21 §1, F22 §2): where the admin listener is and which SPKI
//! pins authenticate it. The file holds **no secrets**. Each front end picks
//! the file (see its own `config` module) and reads it with
//! [`crate::files::read_trusted_file`]; [`resolve`] applies the environment.

//! ```toml
//! endpoint          = "https://cmis-admin.example.internal:8444"
//! spki_pins         = ["<sha384-hex>"]   # required: no trust on first use
//! device_token_path = ""                 # throttle hint file (0600)
//! refresh_secs      = 30                 # TUI only
//! ```

use std::path::PathBuf;

use ferro_crypto::pin::SpkiPin;
use serde::Deserialize;

use crate::display::inert;
use crate::endpoint::{check_endpoint, DEFAULT_ENDPOINT};

/// Overrides the file's endpoint.
pub const ENV_ENDPOINT: &str = "FERROGATE_ADMIN_ENDPOINT";
/// Replaces the file's pins (one or more, separated by commas or spaces).
pub const ENV_SPKI_PIN: &str = "FERROGATE_ADMIN_SPKI_PIN";

/// The configuration file as written. Unknown keys are refused, so a
/// misspelt `spki_pins` cannot silently leave the client unpinned.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    endpoint: Option<String>,
    #[serde(default)]
    spki_pins: Vec<String>,
    device_token_path: Option<String>,
    refresh_secs: Option<u64>,
}

/// The resolved settings every front end shares.
#[derive(Debug, Clone)]
pub struct Settings {
    /// Admin listener, `https://host:port` (checked).
    pub endpoint: String,
    /// Accepted SPKI pins (at least one).
    pub spki_pins: Vec<SpkiPin>,
    /// Device-token file named in the file (the front end picks a default).
    pub device_token_path: Option<PathBuf>,
    /// `refresh_secs` as written (the TUI's list refresh).
    pub refresh_secs: Option<u64>,
}

/// Why the configuration cannot be used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    /// No SPKI pin anywhere: the client refuses to connect (no TOFU).
    NoPin,
    /// Anything else, with an operator-facing message.
    Invalid(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoPin => f.write_str(
                "no SPKI pin for the CMIS admin listener is configured; the client never \
                 trusts a server on first use",
            ),
            Self::Invalid(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for ConfigError {}

/// Resolve the settings from the file text (if any) and the environment:
/// [`ENV_ENDPOINT`] and [`ENV_SPKI_PIN`] take precedence over the file.
///
/// # Errors
/// [`ConfigError::NoPin`] without a pin; [`ConfigError::Invalid`] for a
/// malformed file, a bad pin or an endpoint [`check_endpoint`] refuses.
pub fn resolve(
    file: Option<&str>,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<Settings, ConfigError> {
    let parsed: FileConfig = match file {
        Some(text) => toml::from_str(text).map_err(|e| {
            ConfigError::Invalid(format!("admin.toml: {}", inert(e.message(), 200)))
        })?,
        None => FileConfig::default(),
    };
    let endpoint = env(ENV_ENDPOINT)
        .filter(|v| !v.is_empty())
        .or(parsed.endpoint)
        .unwrap_or_else(|| DEFAULT_ENDPOINT.to_string());
    check_endpoint(&endpoint).map_err(ConfigError::Invalid)?;
    let pin_texts: Vec<String> = match env(ENV_SPKI_PIN).filter(|v| !v.is_empty()) {
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
                ConfigError::Invalid(format!("invalid SPKI pin `{}`: {e}", inert(p, 100)))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Settings {
        endpoint,
        spki_pins,
        device_token_path: parsed
            .device_token_path
            .filter(|p| !p.is_empty())
            .map(PathBuf::from),
        refresh_secs: parsed.refresh_secs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const PIN: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn no_env(_: &str) -> Option<String> {
        None
    }

    #[test]
    fn a_missing_pin_refuses_to_connect() {
        assert_eq!(resolve(None, &no_env).unwrap_err(), ConfigError::NoPin);
        let e = resolve(Some("endpoint = \"https://h:1\"\n"), &no_env).unwrap_err();
        assert_eq!(e, ConfigError::NoPin);
        assert!(e.to_string().contains("never"), "explains no TOFU");
    }

    #[test]
    fn the_environment_overrides_the_file() {
        let file = format!(
            "endpoint = \"https://cmis-1:8444\"\nspki_pins = [\"{PIN}\"]\n\
             device_token_path = \"/tmp/dt\"\nrefresh_secs = 0\n"
        );
        let s = resolve(Some(&file), &no_env).unwrap();
        assert_eq!(s.endpoint, "https://cmis-1:8444");
        assert_eq!(s.spki_pins.len(), 1);
        assert_eq!(s.device_token_path, Some(PathBuf::from("/tmp/dt")));
        assert_eq!(s.refresh_secs, Some(0));
        let env = |k: &str| match k {
            ENV_ENDPOINT => Some("https://other:9".to_string()),
            ENV_SPKI_PIN => Some(format!("{PIN}, {}", "b".repeat(96))),
            _ => None,
        };
        let s = resolve(Some(&file), &env).unwrap();
        assert_eq!(s.endpoint, "https://other:9");
        assert_eq!(s.spki_pins.len(), 2);
        let s = resolve(None, &|k: &str| {
            (k == ENV_SPKI_PIN).then(|| PIN.to_string())
        })
        .unwrap();
        assert_eq!(s.endpoint, DEFAULT_ENDPOINT);
    }

    #[test]
    fn plaintext_endpoints_bad_pins_and_unknown_keys_are_refused() {
        let pin = |k: &str| (k == ENV_SPKI_PIN).then(|| PIN.to_string());
        let e = resolve(Some("endpoint = \"http://h:1\"\n"), &pin).unwrap_err();
        assert!(e.to_string().contains("https://"));
        let e = resolve(None, &|k: &str| (k == ENV_SPKI_PIN).then(|| "zz".into())).unwrap_err();
        assert!(e.to_string().contains("invalid SPKI pin"));
        let e = resolve(Some("password = \"x\"\n"), &pin).unwrap_err();
        assert!(matches!(e, ConfigError::Invalid(_)));
        let e = resolve(Some("spki_pin = [\"x\"]\n"), &pin).unwrap_err();
        assert!(matches!(e, ConfigError::Invalid(_)), "a misspelt key");
    }
}
