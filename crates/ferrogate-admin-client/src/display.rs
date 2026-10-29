//! Making server- and file-supplied text inert before a UI or an error
//! message shows it (F20 §12: every server string is untrusted).
//!
//! [`inert`] writes C0, `DEL` and C1 controls as `\xNN` (so an ESC-introduced
//! terminal sequence cannot run) and bidi or zero-width format characters as
//! `⟨U+XXXX⟩`, then bounds the result by characters. Front ends with their own
//! width-aware renderer (the TUI) still sanitise at render time.

use std::fmt::Write as _;

/// The ellipsis appended to cut text.
pub const ELLIPSIS: char = '…';

/// Whether `c` is a C0, `DEL` or C1 control.
fn is_control(c: char) -> bool {
    matches!(u32::from(c), 0x00..=0x1F | 0x7F..=0x9F)
}

/// Whether `c` is an invisible format character that can reorder or hide
/// text: bidi embeddings, overrides and isolates, direction marks,
/// zero-width characters, the BOM, line/paragraph separators, tag characters
/// and variation selectors.
fn is_invisible(c: char) -> bool {
    matches!(
        u32::from(c),
        0x00AD
            | 0x034F
            | 0x061C
            | 0x115F..=0x1160
            | 0x180B..=0x180F
            | 0x200B..=0x200F
            | 0x2028..=0x202E
            | 0x2060..=0x206F
            | 0x3164
            | 0xFE00..=0xFE0F
            | 0xFEFF
            | 0xFFA0
            | 0xFFF9..=0xFFFB
            | 0xE0000..=0xE0FFF
    )
}

/// `text` with every control and invisible format character made visible,
/// cut to at most `max_chars` characters (the last one an [`ELLIPSIS`] when
/// cut).
#[must_use]
pub fn inert(text: &str, max_chars: usize) -> String {
    let mut clean = String::with_capacity(text.len().min(4 * max_chars + 4));
    for c in text.chars() {
        if is_control(c) {
            let _ = write!(clean, "\\x{:02x}", u32::from(c));
        } else if is_invisible(c) {
            let _ = write!(clean, "⟨U+{:04X}⟩", u32::from(c));
        } else {
            clean.push(c);
        }
        // Enough to decide the cut; the rest is never shown.
        if clean.chars().count() > max_chars + 16 {
            break;
        }
    }
    if clean.chars().count() <= max_chars {
        return clean;
    }
    if max_chars == 0 {
        return String::new();
    }
    let mut out: String = clean.chars().take(max_chars - 1).collect();
    out.push(ELLIPSIS);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn controls_and_format_characters_become_visible_text() {
        assert_eq!(inert("bad\u{1b}[2Jvalue", 64), "bad\\x1b[2Jvalue");
        assert_eq!(inert("a\u{202e}b", 64), "a⟨U+202E⟩b");
        assert_eq!(inert("x\u{9b}y\u{7f}", 64), "x\\x9by\\x7f");
        assert_eq!(inert("zero\u{200b}width", 64), "zero⟨U+200B⟩width");
        assert_eq!(inert("plain text é", 64), "plain text é");
    }

    #[test]
    fn long_text_is_cut_with_an_ellipsis() {
        assert_eq!(inert("abcdef", 4), "abc…");
        assert_eq!(inert("abcd", 4), "abcd");
        assert_eq!(inert("abc", 0), "");
        let huge = "\u{1b}".repeat(100_000);
        assert!(inert(&huge, 10).chars().count() <= 10);
    }
}
