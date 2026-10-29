//! The TOTP seed CMIS offers at enrollment or when a factor is added (F20 §5,
//! F22 §3a): an `otpauth://totp/…` provisioning URI, held only in a wiped
//! buffer, for the front end to show once (as a QR code and as text).

//! [`TotpSeed`] has no `Debug`, `Display` or `Clone`: the seed is never
//! formatted, logged or copied by accident.

use std::ops::Range;

use zeroize::Zeroizing;

/// Longest provisioning URI accepted, in bytes.
pub const MAX_URI_LEN: usize = 512;
/// Accepted length of the base32 secret, in characters (CMIS sends 32).
pub const SECRET_CHARS: std::ops::RangeInclusive<usize> = 16..=128;

/// A TOTP provisioning URI and where its secret sits in it.
pub struct TotpSeed {
    uri: Zeroizing<String>,
    secret: Range<usize>,
}

static_assertions::assert_not_impl_any!(TotpSeed: std::fmt::Debug, std::fmt::Display, Clone);

impl TotpSeed {
    /// Take ownership of a server-supplied URI (moved, never copied) and
    /// check it: `otpauth://totp/`, bounded, printable ASCII, and a `secret`
    /// parameter in base32. `None` (the URI wiped) otherwise.
    #[must_use]
    pub fn from_uri(uri: String) -> Option<Self> {
        let uri = Zeroizing::new(uri);
        if uri.len() > MAX_URI_LEN
            || !uri.starts_with("otpauth://totp/")
            || !uri.bytes().all(|b| b.is_ascii_graphic())
        {
            return None;
        }
        let query = uri.find('?')? + 1;
        let mut at = query;
        let mut secret = None;
        for part in uri[query..].split('&') {
            if let Some(value) = part.strip_prefix("secret=") {
                let start = at + "secret=".len();
                secret = Some(start..start + value.len());
                break;
            }
            at += part.len() + 1;
        }
        let secret = secret?;
        let text = &uri[secret.clone()];
        let base32 = |b: u8| b.is_ascii_alphabetic() || (b'2'..=b'7').contains(&b);
        if !SECRET_CHARS.contains(&text.len()) || !text.bytes().all(base32) {
            return None;
        }
        Some(Self { uri, secret })
    }

    /// The whole URI (what the QR code encodes).
    #[must_use]
    pub fn uri(&self) -> &str {
        &self.uri
    }

    /// The base32 secret alone (for typing into an app by hand).
    #[must_use]
    pub fn secret_base32(&self) -> &str {
        &self.uri[self.secret.clone()]
    }

    /// The secret in upper-case groups of four, for reading aloud or typing.
    #[must_use]
    pub fn grouped(&self) -> Zeroizing<String> {
        let secret = self.secret_base32();
        let mut out = Zeroizing::new(String::with_capacity(secret.len() * 5 / 4 + 1));
        for (i, c) in secret.chars().enumerate() {
            if i > 0 && i % 4 == 0 {
                out.push(' ');
            }
            out.push(c.to_ascii_uppercase());
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const URI: &str = "otpauth://totp/FerroGate:alice?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=FerroGate&algorithm=SHA1&digits=6&period=30";

    #[test]
    fn the_secret_is_found_grouped_and_the_uri_kept_whole() {
        let seed = TotpSeed::from_uri(URI.to_string()).unwrap();
        assert_eq!(seed.uri(), URI);
        assert_eq!(seed.secret_base32(), "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP");
        assert_eq!(
            seed.grouped().as_str(),
            "JBSW Y3DP EHPK 3PXP JBSW Y3DP EHPK 3PXP"
        );
        let first = TotpSeed::from_uri(
            "otpauth://totp/x?issuer=FerroGate&secret=jbswy3dpehpk3pxp".to_string(),
        )
        .unwrap();
        assert_eq!(first.grouped().as_str(), "JBSW Y3DP EHPK 3PXP");
    }

    #[test]
    fn anything_else_is_refused() {
        for bad in [
            "otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP",
            "https://evil.example/?secret=JBSWY3DPEHPK3PXP",
            "otpauth://totp/x?issuer=FerroGate",
            "otpauth://totp/x?secret=JBSWY3DP",
            "otpauth://totp/x?secret=JBSWY3DPEHPK3PX1",
            "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&label=a b",
            "otpauth://totp/x\u{1b}[2J?secret=JBSWY3DPEHPK3PXP",
            "otpauth://totp/x",
        ] {
            assert!(TotpSeed::from_uri(bad.to_string()).is_none(), "{bad}");
        }
        let long = format!("otpauth://totp/{}?secret=JBSWY3DPEHPK3PXP", "a".repeat(600));
        assert!(TotpSeed::from_uri(long).is_none());
    }
}
