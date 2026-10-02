//! Escaping untrusted text for display.
//!
//! Everything the tray shows that did not come from its own string table —
//! daemon status fields, log records, `mia` command output — passes through
//! [`display_safe`] first. `egui` renders plain text (it interprets no markup),
//! so the remaining risks are layout and spoofing: control characters (line
//! breaks that fake extra log lines, terminal escapes in a copied bundle) and
//! Unicode bidirectional overrides ("Trojan Source"-style reordering). Both are
//! replaced by visible escapes, and the result is truncated to a bound.

/// Default bound for a single displayed value, in characters.
pub const MAX_FIELD_CHARS: usize = 512;

/// Bound for a whole multi-line block (command output), in characters.
pub const MAX_BLOCK_CHARS: usize = 16 * 1024;

/// Whether `c` is a bidirectional formatting character that can reorder how
/// surrounding text is displayed.
#[must_use]
pub fn is_bidi_control(c: char) -> bool {
    matches!(
        c,
        '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
    )
}

/// Render `input` on one line: control and bidi characters become visible
/// escapes (`\n`, `\t`, `\u{1b}`, …) and the result is cut to `max_chars`
/// characters (an ellipsis marks the cut).
#[must_use]
pub fn display_safe(input: &str, max_chars: usize) -> String {
    escape(input, max_chars, false)
}

/// Like [`display_safe`] but keeps line breaks (`\n`; a `\r\n` pair becomes
/// one break) for multi-line blocks such as command output.
#[must_use]
pub fn display_safe_block(input: &str, max_chars: usize) -> String {
    escape(input, max_chars, true)
}

fn escape(input: &str, max_chars: usize, keep_newlines: bool) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(input.len().min(max_chars.saturating_mul(2)));
    let mut count = 0usize;
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        if count >= max_chars {
            out.push('…');
            break;
        }
        match c {
            '\r' if keep_newlines && chars.peek() == Some(&'\n') => continue,
            '\n' if keep_newlines => out.push('\n'),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() || is_bidi_control(c) => {
                let _ = write!(out, "\\u{{{:x}}}", u32::from(c));
            }
            c => out.push(c),
        }
        count += 1;
    }
    out
}

/// Escape `&`, `<` and `>` for surfaces that interpret markup (freedesktop
/// notification bodies render a subset of HTML).
#[must_use]
pub fn escape_markup(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// Decode child-process output as UTF-8 (lossily) and make it displayable.
#[must_use]
pub fn output_text(bytes: &[u8]) -> String {
    display_safe_block(String::from_utf8_lossy(bytes).trim_end(), MAX_BLOCK_CHARS)
}

/// A compact duration: `42s`, `5m`, `3h12m`, `2d4h` (negative ⇒ `0s`).
#[must_use]
pub fn human_duration(secs: i64) -> String {
    let secs = secs.max(0);
    match secs {
        s if s < 60 => format!("{s}s"),
        s if s < 3600 => format!("{}m", s / 60),
        s if s < 86_400 => format!("{}h{}m", s / 3600, (s % 3600) / 60),
        s => format!("{}d{}h", s / 86_400, (s % 86_400) / 3600),
    }
}

/// Format Unix milliseconds as an RFC 3339 UTC timestamp with millisecond
/// precision (`2026-10-02T12:34:56.789Z`), without a date-time dependency.
#[must_use]
pub fn rfc3339_utc_ms(ts_ms: i64) -> String {
    let secs = ts_ms.div_euclid(1000);
    let ms = ts_ms.rem_euclid(1000);
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{ms:03}Z",
        tod / 3600,
        (tod % 3600) / 60,
        tod % 60
    )
}

/// Howard Hinnant's `civil_from_days`: days since 1970-01-01 → (y, m, d).
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_and_bidi_characters_are_escaped() {
        assert_eq!(display_safe("a\nb\tc", 100), "a\\nb\\tc");
        assert_eq!(display_safe("x\u{1b}[31my", 100), "x\\u{1b}[31my");
        assert_eq!(display_safe("ab\u{202E}cd", 100), "ab\\u{202e}cd");
        assert_eq!(display_safe("ok ç ü", 100), "ok ç ü");
        assert_eq!(display_safe_block("l1\r\nl2\n\u{7}", 100), "l1\nl2\n\\u{7}");
    }

    #[test]
    fn markup_is_escaped() {
        assert_eq!(
            escape_markup("<b>x</b> & <a href=y>"),
            "&lt;b&gt;x&lt;/b&gt; &amp; &lt;a href=y&gt;"
        );
    }

    #[test]
    fn output_is_bounded() {
        let long = "x".repeat(10_000);
        let s = display_safe(&long, 10);
        assert_eq!(s.chars().count(), 11);
        assert!(s.ends_with('…'));
        assert!(output_text(long.repeat(10).as_bytes()).chars().count() <= MAX_BLOCK_CHARS + 1);
        // Invalid UTF-8 is replaced, not trusted.
        assert_eq!(output_text(b"a\xffb\n"), "a\u{fffd}b");
    }

    #[test]
    fn durations_and_timestamps() {
        assert_eq!(human_duration(-5), "0s");
        assert_eq!(human_duration(42), "42s");
        assert_eq!(human_duration(300), "5m");
        assert_eq!(human_duration(3600 * 3 + 60 * 12), "3h12m");
        assert_eq!(human_duration(86_400 * 2 + 3600 * 4), "2d4h");
        assert_eq!(rfc3339_utc_ms(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(
            rfc3339_utc_ms(1_700_000_000_123),
            "2023-11-14T22:13:20.123Z"
        );
        assert_eq!(rfc3339_utc_ms(951_782_400_000), "2000-02-29T00:00:00.000Z");
        assert_eq!(rfc3339_utc_ms(-1), "1969-12-31T23:59:59.999Z");
    }

    proptest::proptest! {
        #[test]
        fn escaped_text_has_no_controls(s in ".{0,200}") {
            let out = display_safe(&s, 1000);
            proptest::prop_assert!(!out.chars().any(|c| c.is_control() || is_bidi_control(c)));
        }
    }
}
