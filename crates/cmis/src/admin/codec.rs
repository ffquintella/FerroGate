//! Small text encodings used by the admin subsystem: RFC 4648 base32 (TOTP
//! secrets in `otpauth://` URIs, bootstrap and enrollment tokens) and
//! unpadded base64url (session and device tokens).

use base64::Engine as _;

const B32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// RFC 4648 base32 without padding.
pub(crate) fn base32_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(5) * 8);
    let mut buffer: u32 = 0;
    let mut bits = 0u32;
    for &byte in data {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(B32[((buffer >> bits) & 0x1f) as usize]));
        }
    }
    if bits > 0 {
        out.push(char::from(B32[((buffer << (5 - bits)) & 0x1f) as usize]));
    }
    out
}

/// Decode RFC 4648 base32 (case-insensitive, padding and separators `-`/space
/// ignored). `None` on any other character.
pub(crate) fn base32_decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() * 5 / 8);
    let mut buffer: u32 = 0;
    let mut bits = 0u32;
    for c in text.chars() {
        if matches!(c, '=' | '-' | ' ') {
            continue;
        }
        let up = c.to_ascii_uppercase();
        let v = B32.iter().position(|&b| char::from(b) == up)?;
        buffer = (buffer << 5) | u32::try_from(v).ok()?;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((buffer >> bits) & 0xff).ok()?);
        }
    }
    Some(out)
}

/// Unpadded base64url.
pub(crate) fn b64url(data: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

/// Decode unpadded base64url.
pub(crate) fn b64url_decode(text: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(text.as_bytes())
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base32_matches_rfc4648_vectors() {
        assert_eq!(base32_encode(b""), "");
        assert_eq!(base32_encode(b"f"), "MY");
        assert_eq!(base32_encode(b"fo"), "MZXQ");
        assert_eq!(base32_encode(b"foo"), "MZXW6");
        assert_eq!(base32_encode(b"foob"), "MZXW6YQ");
        assert_eq!(base32_encode(b"fooba"), "MZXW6YTB");
        assert_eq!(base32_encode(b"foobar"), "MZXW6YTBOI");
    }

    #[test]
    fn base32_round_trips_and_tolerates_case_and_separators() {
        let data = [0u8, 1, 2, 250, 251, 252, 253, 254, 255, 9, 77];
        let text = base32_encode(&data);
        assert_eq!(base32_decode(&text).unwrap(), data);
        assert_eq!(
            base32_decode(&text.to_ascii_lowercase()).unwrap(),
            data.to_vec()
        );
        assert_eq!(base32_decode("MZXW-6YTB OI==").unwrap(), b"foobar");
        assert!(base32_decode("MZ1").is_none(), "1 is not base32");
    }
}
