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

use ferro_crypto::pin::{SpkiPin, SPKI_PIN_LEN};
use serde::{Deserialize, Serialize};

use crate::display::inert;
use crate::endpoint::{check_endpoint, endpoint_problem, EndpointProblem, DEFAULT_ENDPOINT};

/// Overrides the file's endpoint.
pub const ENV_ENDPOINT: &str = "FERROGATE_ADMIN_ENDPOINT";
/// Replaces the file's pins (one or more, separated by commas or spaces).
pub const ENV_SPKI_PIN: &str = "FERROGATE_ADMIN_SPKI_PIN";
/// Hex digits in one SPKI pin (a SHA-384).
pub const PIN_HEX_LEN: usize = 2 * SPKI_PIN_LEN;

/// The configuration file as written, unchecked. Unknown keys are refused,
/// so a misspelt `spki_pins` cannot silently leave the client unpinned.
/// A front end that rewrites the file keeps the keys it does not change.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FileValues {
    /// `endpoint`, as written.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// `spki_pins`, as written.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub spki_pins: Vec<String>,
    /// `device_token_path`, as written.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_token_path: Option<String>,
    /// `refresh_secs`, as written.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_secs: Option<u64>,
}

/// Parse `admin.toml` text without checking or resolving it.
///
/// # Errors
/// [`ConfigError::Invalid`] when it is not TOML, has an unknown key or a key
/// of the wrong type.
pub fn parse_file(text: &str) -> Result<FileValues, ConfigError> {
    toml::from_str(text)
        .map_err(|e| ConfigError::Invalid(format!("admin.toml: {}", inert(e.message(), 200))))
}

/// Why a pin is refused, for front ends that word it themselves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinProblem {
    /// Nothing (or only blanks).
    Empty,
    /// Something other than hexadecimal digits.
    NotHex,
    /// Hexadecimal, but not [`PIN_HEX_LEN`] digits (the count given).
    Length(usize),
}

impl std::fmt::Display for PinProblem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => f.write_str("empty"),
            Self::NotHex => f.write_str("not hexadecimal"),
            Self::Length(n) => write!(f, "{n} hex digits, expected {PIN_HEX_LEN} (SHA-384)"),
        }
    }
}

/// Parse one SPKI pin exactly as [`resolve`] does: a SHA-384 in hex, either
/// case, surrounding blanks ignored.
///
/// # Errors
/// Why it is not one.
pub fn parse_pin(text: &str) -> Result<SpkiPin, PinProblem> {
    SpkiPin::from_hex(text).map_err(|_| {
        let t = text.trim();
        if t.is_empty() {
            PinProblem::Empty
        } else if !t.chars().all(|c| c.is_ascii_hexdigit()) {
            PinProblem::NotHex
        } else {
            PinProblem::Length(t.len())
        }
    })
}

/// Why [`ServerChoice::check`] refuses an endpoint and pin (each field's
/// first problem, so a front end can mark both at once).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ChoiceProblems {
    /// The endpoint's.
    pub endpoint: Option<EndpointProblem>,
    /// The pin's.
    pub pin: Option<PinProblem>,
}

/// An admin endpoint and one SPKI pin typed into a front end, checked as
/// [`resolve`] checks the file: what the file would say after a save.
#[derive(Debug, Clone)]
pub struct ServerChoice {
    endpoint: String,
    pin: SpkiPin,
}

impl ServerChoice {
    /// Check `endpoint` ([`check_endpoint`]'s rule) and `pin`
    /// ([`parse_pin`]); surrounding blanks are ignored.
    ///
    /// # Errors
    /// Each field's problem.
    pub fn check(endpoint: &str, pin: &str) -> Result<Self, ChoiceProblems> {
        let endpoint = endpoint.trim();
        match (endpoint_problem(endpoint), parse_pin(pin)) {
            (None, Ok(pin)) => Ok(Self {
                endpoint: endpoint.to_string(),
                pin,
            }),
            (endpoint, pin) => Err(ChoiceProblems {
                endpoint,
                pin: pin.err(),
            }),
        }
    }

    /// The endpoint.
    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// The pin, lowercase hex.
    #[must_use]
    pub fn pin_hex(&self) -> String {
        self.pin.to_hex()
    }

    /// The `admin.toml` text for this endpoint and pin, keeping `keep`'s
    /// `device_token_path` and `refresh_secs` (its pins are all replaced,
    /// comments are not kept), read back through [`resolve`] first.
    ///
    /// # Errors
    /// [`ConfigError::Invalid`] if it does not read back as this choice.
    pub fn render(&self, keep: Option<&FileValues>) -> Result<String, ConfigError> {
        let values = FileValues {
            endpoint: Some(self.endpoint.clone()),
            spki_pins: vec![self.pin.to_hex()],
            device_token_path: keep.and_then(|k| k.device_token_path.clone()),
            refresh_secs: keep.and_then(|k| k.refresh_secs),
        };
        let body = toml::to_string(&values)
            .map_err(|_| ConfigError::Invalid("admin.toml could not be written".into()))?;
        let text = format!(
            "# FerroGate admin client: the CMIS admin endpoint and its SPKI pin\n\
             # (no secrets). Compare the pin with the one operations gave you.\n{body}"
        );
        let back = resolve(Some(&text), &|_| None)?;
        if back.endpoint != self.endpoint || back.spki_pins != [self.pin] {
            return Err(ConfigError::Invalid(
                "admin.toml did not read back as written".into(),
            ));
        }
        Ok(text)
    }
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
    let parsed = match file {
        Some(text) => parse_file(text)?,
        None => FileValues::default(),
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
            parse_pin(p).map_err(|e| {
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

    #[test]
    fn a_pin_is_exactly_a_sha384_in_hex() {
        assert_eq!(parse_pin(PIN).unwrap().to_hex(), PIN);
        let upper = PIN.to_ascii_uppercase();
        assert_eq!(parse_pin(&format!(" {upper}\n")).unwrap().to_hex(), PIN);
        assert_eq!(parse_pin("").unwrap_err(), PinProblem::Empty);
        assert_eq!(parse_pin("  ").unwrap_err(), PinProblem::Empty);
        assert_eq!(
            parse_pin(&PIN[..64]).unwrap_err(),
            PinProblem::Length(64),
            "a SHA-256 is not a pin"
        );
        assert_eq!(
            parse_pin(&format!("{PIN}a")).unwrap_err(),
            PinProblem::Length(97)
        );
        assert_eq!(
            parse_pin(&format!("{PIN}aa")).unwrap_err(),
            PinProblem::Length(98)
        );
        let colons = format!("ab:{}", &PIN[3..]);
        assert_eq!(parse_pin(&colons).unwrap_err(), PinProblem::NotHex);
        assert_eq!(parse_pin(&"g".repeat(96)).unwrap_err(), PinProblem::NotHex);
    }

    #[test]
    fn a_choice_checks_both_fields_and_renders_a_file_the_resolver_reads_back() {
        let e = ServerChoice::check("http://cmis:8444", "zz").unwrap_err();
        assert_eq!(e.endpoint, Some(EndpointProblem::NotHttps));
        assert_eq!(e.pin, Some(PinProblem::NotHex));
        let e = ServerChoice::check("https://cmis", PIN).unwrap_err();
        assert_eq!((e.endpoint, e.pin), (Some(EndpointProblem::NoPort), None));

        let c =
            ServerChoice::check(" https://cmis-admin.example:8444 ", &PIN.to_uppercase()).unwrap();
        assert_eq!(c.endpoint(), "https://cmis-admin.example:8444");
        assert_eq!(c.pin_hex(), PIN, "written lowercase");
        let text = c.render(None).unwrap();
        let s = resolve(Some(&text), &no_env).unwrap();
        assert_eq!(s.endpoint, "https://cmis-admin.example:8444");
        assert_eq!(s.spki_pins.len(), 1);
        assert_eq!(s.device_token_path, None);

        // Keys this choice does not set are kept; every old pin goes.
        let old = parse_file(&format!(
            "endpoint = \"https://old:1\"\nspki_pins = [\"{}\", \"{}\"]\n\
             device_token_path = \"/var/dt\"\nrefresh_secs = 7\n",
            "b".repeat(96),
            "c".repeat(96)
        ))
        .unwrap();
        let text = c.render(Some(&old)).unwrap();
        let back = parse_file(&text).unwrap();
        assert_eq!(back.spki_pins, vec![PIN.to_string()]);
        assert_eq!(back.device_token_path.as_deref(), Some("/var/dt"));
        assert_eq!(back.refresh_secs, Some(7));
        assert_eq!(
            back.endpoint.as_deref(),
            Some("https://cmis-admin.example:8444")
        );
    }
}
