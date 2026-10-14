//! Admin-subsystem configuration (`CMIS_ADMIN_*`, F20 §2, §4, §7, §9).
//!
//! | Variable | Default | Meaning |
//! |----------|---------|---------|
//! | `CMIS_ADMIN_LISTEN` | `127.0.0.1:8444` | admin listener (TLS only; never internet-facing) |
//! | `CMIS_ADMIN_TLS_CERT` / `_KEY` | the main listener's | admin listener certificate |
//! | `CMIS_ADMIN_CLIENT_CA` | unset | require mTLS client certs from this CA (PEM) |
//! | `CMIS_LEGACY_ADMIN_ON_MAIN` | `true` | also serve the legacy admin RPCs on the main listener |
//! | `CMIS_ADMIN_STRICT_SOD` | `false` | strict separation of duties |
//! | `CMIS_ADMIN_STEP_UP_WINDOW_SECS` | `300` | step-up validity (0 = same second only) |
//! | `CMIS_ADMIN_SESSION_BIND_IP` | `true` | revoke a session used from another IP |
//! | `CMIS_ADMIN_SESSION_IDLE_SECS` | `900` | idle timeout, capped at 900 |
//! | `CMIS_ADMIN_SESSION_ABSOLUTE_SECS` | `43200` | absolute lifetime, capped at 43200 |
//! | `CMIS_ADMIN_SECRETS_KEY_FILE` | `/var/lib/ferrogate/admin/secrets.key` | TOTP sealing + server MAC key |
//! | `CMIS_AUDIT_PSEUDONYM_KEY_FILE` | `/var/lib/ferrogate/admin/audit-pseudonym.key` | audit pseudonymisation key |
//! | `CMIS_ADMIN_PEPPER_FILE` | unset | optional 32-byte password pepper (id 1) |
//! | `CMIS_ADMIN_PASSWORD_BLOCKLIST_FILE` | unset | breach corpus, one password per line |
//! | `CMIS_ADMIN_BOOTSTRAP_TOKEN_FILE` | `/var/lib/ferrogate/admin-bootstrap.token` | first-account bootstrap token |
//! | `CMIS_TRUST_DOMAIN` | `ferrogate.dev` | forbidden in passwords; WebAuthn RP ID is `ferrogate-admin.<it>` |
//! | `CMIS_ADMIN_TRAY_FIDO2_GROUPS` | empty | groups whose members must use FIDO2 from the tray (F20 §5) |
//! | `CMIS_ADMIN_WEBAUTHN_ORIGINS` | `https://<RP ID>` | origins a WebAuthn `clientDataJSON` may name |
//!
//! Argon2 parameters are not configurable from the environment: production
//! always runs the RFC 9106 values.

use std::net::SocketAddr;
use std::path::PathBuf;

use super::authz::groups;
use super::keys::{KeyFile, DEFAULT_PSEUDONYM_KEY_FILE, DEFAULT_SECRETS_KEY_FILE};
use super::password::PasswordParams;
use super::session::{MAX_ABSOLUTE_SECS, MAX_IDLE_SECS};

/// Default admin listener address.
pub const DEFAULT_LISTEN: &str = "127.0.0.1:8444";
/// Default bootstrap token path.
pub const DEFAULT_BOOTSTRAP_TOKEN_FILE: &str = "/var/lib/ferrogate/admin-bootstrap.token";
/// Default step-up window.
pub const DEFAULT_STEP_UP_WINDOW_SECS: i64 = 300;
/// Prefix of the fixed WebAuthn RP ID (`ferrogate-admin.<trust_domain>`).
pub const WEBAUTHN_RP_ID_PREFIX: &str = "ferrogate-admin.";

/// Admin-subsystem configuration.
#[derive(Debug, Clone)]
pub struct AdminConfig {
    /// Admin listener address.
    pub listen: SocketAddr,
    /// Admin listener certificate chain (PEM); `None` reuses the main one.
    pub tls_cert: Option<PathBuf>,
    /// Admin listener private key (PEM); `None` reuses the main one.
    pub tls_key: Option<PathBuf>,
    /// mTLS client CA bundle (PEM).
    pub client_ca: Option<PathBuf>,
    /// Serve the legacy admin RPCs on the main listener too.
    pub legacy_admin_on_main: bool,
    /// Strict separation of duties.
    pub strict_sod: bool,
    /// Step-up validity window in seconds.
    pub step_up_window_secs: i64,
    /// Bind sessions to the login source IP.
    pub session_bind_ip: bool,
    /// Session idle timeout (≤ 900 s).
    pub idle_timeout_secs: i64,
    /// Session absolute lifetime (≤ 43 200 s).
    pub absolute_lifetime_secs: i64,
    /// SPIFFE trust domain.
    pub trust_domain: String,
    /// Secrets key file.
    pub secrets_key: KeyFile,
    /// Audit pseudonymisation key file.
    pub pseudonym_key: KeyFile,
    /// Optional pepper file.
    pub pepper_file: Option<PathBuf>,
    /// Optional password blocklist file.
    pub blocklist_file: Option<PathBuf>,
    /// Bootstrap token file.
    pub bootstrap_token_file: PathBuf,
    /// Argon2id parameters (always the RFC 9106 defaults outside tests).
    pub password_params: PasswordParams,
    /// Built-in groups whose members, signing in from the tray admin client,
    /// must use FIDO2 (F20 §5 policy option). Empty: no such policy.
    pub tray_fido2_groups: Vec<String>,
    /// Origins accepted in WebAuthn `clientDataJSON`; empty means the
    /// default, `https://<RP ID>` (see [`Self::webauthn_origins`]).
    pub webauthn_origins: Vec<String>,
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            listen: DEFAULT_LISTEN.parse().expect("valid default address"),
            tls_cert: None,
            tls_key: None,
            client_ca: None,
            legacy_admin_on_main: true,
            strict_sod: false,
            step_up_window_secs: DEFAULT_STEP_UP_WINDOW_SECS,
            session_bind_ip: true,
            idle_timeout_secs: MAX_IDLE_SECS,
            absolute_lifetime_secs: MAX_ABSOLUTE_SECS,
            trust_domain: "ferrogate.dev".to_string(),
            secrets_key: KeyFile {
                path: PathBuf::from(DEFAULT_SECRETS_KEY_FILE),
                generate_if_missing: true,
            },
            pseudonym_key: KeyFile {
                path: PathBuf::from(DEFAULT_PSEUDONYM_KEY_FILE),
                generate_if_missing: true,
            },
            pepper_file: None,
            blocklist_file: None,
            bootstrap_token_file: PathBuf::from(DEFAULT_BOOTSTRAP_TOKEN_FILE),
            password_params: PasswordParams::default(),
            tray_fido2_groups: Vec::new(),
            webauthn_origins: Vec::new(),
        }
    }
}

/// `https://host[:port]` with a lower-case DNS host equal to `rp_id` or one
/// of its subdomains (WebAuthn: the RP ID must be a registrable suffix of
/// the origin's host). No path, query or user information.
fn valid_origin(origin: &str, rp_id: &str) -> bool {
    let Some(rest) = origin.strip_prefix("https://") else {
        return false;
    };
    let (host, port) = match rest.split_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (rest, None),
    };
    if port.is_some_and(|p| {
        p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) || p.parse::<u16>().is_err()
    }) {
        return false;
    }
    !host.is_empty()
        && host
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
        && (host == rp_id || host.ends_with(&format!(".{rp_id}")))
}

fn truthy(v: &str) -> Option<bool> {
    match v.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

impl AdminConfig {
    /// The fixed WebAuthn RP ID, `ferrogate-admin.<trust_domain>` (F20 §5).
    #[must_use]
    pub fn webauthn_rp_id(&self) -> String {
        format!("{WEBAUTHN_RP_ID_PREFIX}{}", self.trust_domain)
    }

    /// The origins accepted in WebAuthn `clientDataJSON`: the configured
    /// list, or `https://<RP ID>`.
    #[must_use]
    pub fn webauthn_origins(&self) -> Vec<String> {
        if self.webauthn_origins.is_empty() {
            vec![format!("https://{}", self.webauthn_rp_id())]
        } else {
            self.webauthn_origins.clone()
        }
    }

    /// Read the configuration from the process environment.
    pub fn from_env() -> anyhow::Result<Self> {
        Self::from_lookup(|k| std::env::var(k).ok().filter(|v| !v.is_empty()))
    }

    /// Read the configuration through `get` (testable form of
    /// [`Self::from_env`]). Malformed values are errors, never silently
    /// replaced by a weaker default.
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> anyhow::Result<Self> {
        let mut c = Self::default();
        let flag = |name: &str, default: bool| -> anyhow::Result<bool> {
            match get(name) {
                None => Ok(default),
                Some(v) => {
                    truthy(&v).ok_or_else(|| anyhow::anyhow!("{name}: not a boolean: {v:?}"))
                }
            }
        };
        let secs = |name: &str, default: i64, max: i64| -> anyhow::Result<i64> {
            match get(name) {
                None => Ok(default),
                Some(v) => {
                    let n: i64 = v
                        .trim()
                        .parse()
                        .map_err(|_| anyhow::anyhow!("{name}: not an integer: {v:?}"))?;
                    if n < 0 {
                        anyhow::bail!("{name}: must not be negative");
                    }
                    if n > max {
                        tracing::warn!(var = name, value = n, max, "capped to the maximum");
                    }
                    Ok(n.min(max))
                }
            }
        };
        if let Some(v) = get("CMIS_ADMIN_LISTEN") {
            c.listen = v
                .trim()
                .parse()
                .map_err(|e| anyhow::anyhow!("CMIS_ADMIN_LISTEN: {e}"))?;
        }
        c.tls_cert = get("CMIS_ADMIN_TLS_CERT").map(PathBuf::from);
        c.tls_key = get("CMIS_ADMIN_TLS_KEY").map(PathBuf::from);
        if c.tls_cert.is_some() != c.tls_key.is_some() {
            anyhow::bail!("CMIS_ADMIN_TLS_CERT and CMIS_ADMIN_TLS_KEY must be set together");
        }
        c.client_ca = get("CMIS_ADMIN_CLIENT_CA").map(PathBuf::from);
        c.legacy_admin_on_main = flag("CMIS_LEGACY_ADMIN_ON_MAIN", true)?;
        c.strict_sod = flag("CMIS_ADMIN_STRICT_SOD", false)?;
        c.session_bind_ip = flag("CMIS_ADMIN_SESSION_BIND_IP", true)?;
        c.step_up_window_secs = secs(
            "CMIS_ADMIN_STEP_UP_WINDOW_SECS",
            DEFAULT_STEP_UP_WINDOW_SECS,
            MAX_IDLE_SECS,
        )?;
        c.idle_timeout_secs =
            secs("CMIS_ADMIN_SESSION_IDLE_SECS", MAX_IDLE_SECS, MAX_IDLE_SECS)?.max(60);
        c.absolute_lifetime_secs = secs(
            "CMIS_ADMIN_SESSION_ABSOLUTE_SECS",
            MAX_ABSOLUTE_SECS,
            MAX_ABSOLUTE_SECS,
        )?
        .max(c.idle_timeout_secs);
        if let Some(td) = get("CMIS_TRUST_DOMAIN") {
            c.trust_domain = td;
        }
        if let Some(p) = get("CMIS_ADMIN_SECRETS_KEY_FILE") {
            c.secrets_key = KeyFile {
                path: PathBuf::from(p),
                generate_if_missing: false,
            };
        }
        if let Some(p) = get("CMIS_AUDIT_PSEUDONYM_KEY_FILE") {
            c.pseudonym_key = KeyFile {
                path: PathBuf::from(p),
                generate_if_missing: false,
            };
        }
        c.pepper_file = get("CMIS_ADMIN_PEPPER_FILE").map(PathBuf::from);
        c.blocklist_file = get("CMIS_ADMIN_PASSWORD_BLOCKLIST_FILE").map(PathBuf::from);
        if let Some(p) = get("CMIS_ADMIN_BOOTSTRAP_TOKEN_FILE") {
            c.bootstrap_token_file = PathBuf::from(p);
        }
        if let Some(list) = get("CMIS_ADMIN_TRAY_FIDO2_GROUPS") {
            for g in list.split(',').map(str::trim).filter(|g| !g.is_empty()) {
                // A typo would silently switch the policy off: refuse it.
                if !groups::ALL.contains(&g) {
                    anyhow::bail!("CMIS_ADMIN_TRAY_FIDO2_GROUPS: unknown group {g:?}");
                }
                if !c.tray_fido2_groups.iter().any(|x| x == g) {
                    c.tray_fido2_groups.push(g.to_string());
                }
            }
        }
        if let Some(list) = get("CMIS_ADMIN_WEBAUTHN_ORIGINS") {
            let rp_id = c.webauthn_rp_id();
            for o in list.split(',').map(str::trim).filter(|o| !o.is_empty()) {
                if !valid_origin(o, &rp_id) {
                    anyhow::bail!(
                        "CMIS_ADMIN_WEBAUTHN_ORIGINS: {o:?} is not an https origin on {rp_id}"
                    );
                }
                if !c.webauthn_origins.iter().any(|x| x == o) {
                    c.webauthn_origins.push(o.to_string());
                }
            }
        }
        Ok(c)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn cfg(vars: &[(&str, &str)]) -> anyhow::Result<AdminConfig> {
        let map: HashMap<String, String> = vars
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        AdminConfig::from_lookup(|k| map.get(k).cloned())
    }

    #[test]
    fn defaults_follow_the_spec() {
        let c = cfg(&[]).unwrap();
        assert_eq!(c.listen.to_string(), "127.0.0.1:8444");
        assert!(c.legacy_admin_on_main);
        assert!(!c.strict_sod);
        assert!(c.session_bind_ip);
        assert_eq!(c.step_up_window_secs, 300);
        assert_eq!(c.idle_timeout_secs, 900);
        assert_eq!(c.absolute_lifetime_secs, 43_200);
        assert_eq!(c.password_params, PasswordParams::default());
        assert!(c.secrets_key.generate_if_missing);
    }

    #[test]
    fn session_lifetimes_can_be_lowered_never_raised() {
        let c = cfg(&[
            ("CMIS_ADMIN_SESSION_IDLE_SECS", "3600"),
            ("CMIS_ADMIN_SESSION_ABSOLUTE_SECS", "999999"),
        ])
        .unwrap();
        assert_eq!(c.idle_timeout_secs, 900);
        assert_eq!(c.absolute_lifetime_secs, 43_200);
        let c = cfg(&[("CMIS_ADMIN_SESSION_IDLE_SECS", "300")]).unwrap();
        assert_eq!(c.idle_timeout_secs, 300);
    }

    #[test]
    fn toggles_and_explicit_key_files() {
        let c = cfg(&[
            ("CMIS_LEGACY_ADMIN_ON_MAIN", "false"),
            ("CMIS_ADMIN_STRICT_SOD", "1"),
            ("CMIS_ADMIN_SECRETS_KEY_FILE", "/k/s"),
        ])
        .unwrap();
        assert!(!c.legacy_admin_on_main);
        assert!(c.strict_sod);
        assert!(
            !c.secrets_key.generate_if_missing,
            "explicit files must exist"
        );
    }

    #[test]
    fn webauthn_rp_id_and_origin_follow_the_trust_domain() {
        let c = cfg(&[("CMIS_TRUST_DOMAIN", "corp.example")]).unwrap();
        assert_eq!(c.webauthn_rp_id(), "ferrogate-admin.corp.example");
        assert_eq!(
            c.webauthn_origins(),
            ["https://ferrogate-admin.corp.example"]
        );
        let c = cfg(&[
            ("CMIS_TRUST_DOMAIN", "corp.example"),
            (
                "CMIS_ADMIN_WEBAUTHN_ORIGINS",
                "https://ferrogate-admin.corp.example:8444, https://tray.ferrogate-admin.corp.example",
            ),
        ])
        .unwrap();
        assert_eq!(
            c.webauthn_origins(),
            [
                "https://ferrogate-admin.corp.example:8444",
                "https://tray.ferrogate-admin.corp.example"
            ]
        );
    }

    #[test]
    fn webauthn_origins_must_be_https_within_the_rp_id() {
        for bad in [
            "http://ferrogate-admin.ferrogate.dev",
            "https://evil.example",
            "https://ferrogate-admin.ferrogate.dev.evil.example",
            "https://xferrogate-admin.ferrogate.dev",
            "https://ferrogate-admin.ferrogate.dev/path",
            "https://ferrogate-admin.ferrogate.dev:notaport",
            "https://",
        ] {
            assert!(
                cfg(&[("CMIS_ADMIN_WEBAUTHN_ORIGINS", bad)]).is_err(),
                "{bad} must be refused"
            );
        }
    }

    #[test]
    fn tray_fido2_groups_default_empty_and_must_name_builtin_groups() {
        assert_eq!(cfg(&[]).unwrap().tray_fido2_groups.len(), 0);
        let c = cfg(&[(
            "CMIS_ADMIN_TRAY_FIDO2_GROUPS",
            " ferrogate-approvers ,ferrogate-approvers, ferrogate-account-admins",
        )])
        .unwrap();
        assert_eq!(
            c.tray_fido2_groups,
            ["ferrogate-approvers", "ferrogate-account-admins"]
        );
        assert!(
            cfg(&[("CMIS_ADMIN_TRAY_FIDO2_GROUPS", "ferrogate-aprovers")]).is_err(),
            "a typo must not silently disable the policy"
        );
    }

    #[test]
    fn malformed_values_are_errors() {
        assert!(cfg(&[("CMIS_ADMIN_STRICT_SOD", "maybe")]).is_err());
        assert!(cfg(&[("CMIS_ADMIN_STEP_UP_WINDOW_SECS", "-1")]).is_err());
        assert!(cfg(&[("CMIS_ADMIN_LISTEN", "not an address")]).is_err());
        assert!(
            cfg(&[("CMIS_ADMIN_TLS_CERT", "/c")]).is_err(),
            "cert without key"
        );
    }
}
