//! Safe rendering of untrusted text (F21 §7).
//!
//! Paths, product names, user names, hostnames, reasons, notes and server
//! error reasons originate on hosts or from other people. Every one of them
//! goes through [`display`] before it reaches a ratatui `Span`, so nothing a
//! host or another administrator typed can drive the administrator's
//! terminal:
//!
//! - C0 controls (U+0000–U+001F), `DEL` (U+007F) and C1 controls
//!   (U+0080–U+009F, which include the 8-bit `CSI`, `OSC`, `DCS` and `ST`
//!   introducers) become visible `\xNN` escapes. An `ESC` therefore shows as
//!   `\x1b` and the rest of its sequence (`]52;c;…` for an OSC 52 clipboard
//!   write, `]8;;url` for an OSC 8 hyperlink, `[2J` for a CSI) is left as inert
//!   printable text; its `BEL` or `ESC \` terminator is escaped too.
//! - Every Unicode `Default_Ignorable_Code_Point` — bidirectional overrides,
//!   embeddings and isolates (U+202A–U+202E, U+2066–U+2069, the
//!   Trojan-Source class), direction marks (U+200E, U+200F, U+061C),
//!   zero-width characters (U+200B–U+200D, U+2060–U+206F, U+FEFF), the soft
//!   hyphen, variation selectors (U+FE00–U+FE0F, U+180B–U+180F), the Hangul
//!   fillers (U+115F, U+1160, U+3164, U+FFA0) and the tag block
//!   (U+E0000–U+E0FFF, "ASCII smuggling") — plus the line and paragraph
//!   separators (U+2028, U+2029) and the interlinear annotation controls
//!   (U+FFF9–U+FFFB) are shown as `⟨U+202E⟩`, so `/usr/bin/ssh⟨U+3164⟩` can
//!   never pass for `/usr/bin/ssh`.
//!
//! [`width`], [`truncate_middle`], [`truncate_end`] and [`wrap`] measure the
//! cleaned text **per grapheme, exactly as ratatui's buffer does** (a
//! single-byte grapheme is one cell, otherwise its `unicode-width` plus the
//! halfwidth sound marks), so a fitted cell never spills into the next column
//! and a wrapped line is never clipped. Paths get an ellipsis in the middle so
//! both the root and the file name stay visible.
//!
//! The output never contains a C0 or C1 code point, so ratatui (which
//! interprets no markup) only ever draws inert characters. The property test
//! below feeds arbitrary bytes and strings and checks exactly that.

use std::fmt::Write as _;

use unicode_segmentation::UnicodeSegmentation as _;
use unicode_width::UnicodeWidthStr as _;

/// The ellipsis used by the truncation helpers (display width 1).
pub const ELLIPSIS: char = '…';

/// Whether `c` must never reach the terminal as itself.
fn is_control(c: char) -> bool {
    matches!(c, '\u{0}'..='\u{1f}' | '\u{7f}'..='\u{9f}')
}

/// Whether `c` is an invisible or direction-changing character shown as
/// `⟨U+XXXX⟩`.
fn is_invisible(c: char) -> bool {
    matches!(
        c,
        // Default_Ignorable_Code_Point (Unicode DerivedCoreProperties).
        '\u{00AD}'
            | '\u{034F}'
            | '\u{061C}'
            | '\u{115F}'..='\u{1160}'
            | '\u{17B4}'..='\u{17B5}'
            | '\u{180B}'..='\u{180F}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{206F}'
            | '\u{3164}'
            | '\u{FE00}'..='\u{FE0F}'
            | '\u{FEFF}'
            | '\u{FFA0}'
            | '\u{FFF0}'..='\u{FFF8}'
            | '\u{1BCA0}'..='\u{1BCA3}'
            | '\u{1D173}'..='\u{1D17A}'
            | '\u{E0000}'..='\u{E0FFF}'
            // Line and paragraph separators, interlinear annotations.
            | '\u{2028}'..='\u{2029}'
            | '\u{FFF9}'..='\u{FFFB}'
    )
}

/// `text` made safe for a terminal (see the module documentation). Total and
/// allocation-bounded: the output is at most ten times the input length.
#[must_use]
pub fn display(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if is_control(c) {
            // `\x1b`, `\x07`, `\x9b` …: visible, never interpreted.
            let _ = write!(out, "\\x{:02x}", u32::from(c));
        } else if is_invisible(c) {
            let _ = write!(out, "⟨U+{:04X}⟩", u32::from(c));
        } else {
            out.push(c);
        }
    }
    out
}

/// Cells one grapheme occupies, as ratatui's buffer counts them
/// (`ratatui_core::buffer::CellWidth`): one for a single byte, otherwise its
/// `unicode-width` plus one per halfwidth (han)dakuten mark.
fn cell_width(g: &str) -> usize {
    if g.len() == 1 {
        return 1;
    }
    g.width()
        + g.chars()
            .filter(|c| matches!(c, '\u{FF9E}' | '\u{FF9F}'))
            .count()
}

/// Display width of already-sanitised text, in terminal cells.
#[must_use]
pub fn width(text: &str) -> usize {
    text.graphemes(true).map(cell_width).sum()
}

/// Keep the longest prefix of `text` (whole graphemes) that fits in `max`
/// columns.
fn prefix_fitting(text: &str, max: usize) -> (&str, usize) {
    let mut used = 0;
    let mut end = 0;
    for (i, g) in text.grapheme_indices(true) {
        let w = cell_width(g);
        if used + w > max {
            break;
        }
        used += w;
        end = i + g.len();
    }
    (&text[..end], used)
}

/// Keep the longest suffix of `text` (whole graphemes) that fits in `max`
/// columns.
fn suffix_fitting(text: &str, max: usize) -> (&str, usize) {
    let mut used = 0;
    let mut start = text.len();
    for (i, g) in text.grapheme_indices(true).rev() {
        let w = cell_width(g);
        if used + w > max {
            break;
        }
        used += w;
        start = i;
    }
    (&text[start..], used)
}

/// Sanitise `text` and fit it in `max` columns, cutting the end and adding an
/// ellipsis when it does not fit.
#[must_use]
pub fn truncate_end(text: &str, max: usize) -> String {
    let clean = display(text);
    if width(&clean) <= max {
        return clean;
    }
    if max == 0 {
        return String::new();
    }
    let (head, _) = prefix_fitting(&clean, max - 1);
    let mut out = head.to_string();
    out.push(ELLIPSIS);
    out
}

/// Sanitise `text` and fit it in `max` columns with an ellipsis in the middle
/// (for paths: the root and the file name both stay visible).
#[must_use]
pub fn truncate_middle(text: &str, max: usize) -> String {
    let clean = display(text);
    if width(&clean) <= max {
        return clean;
    }
    if max == 0 {
        return String::new();
    }
    let budget = max - 1;
    // Favour the tail (the file name) when the budget is odd.
    let tail_budget = budget.div_ceil(2);
    let (tail, tail_used) = suffix_fitting(&clean, tail_budget);
    let (head, _) = prefix_fitting(&clean, budget - tail_used);
    let mut out = String::with_capacity(head.len() + tail.len() + 3);
    out.push_str(head);
    out.push(ELLIPSIS);
    out.push_str(tail);
    out
}

/// Sanitise `text` and split it into lines of at most `max` columns (detail
/// views show long values such as paths and hashes in full, wrapped).
#[must_use]
pub fn wrap(text: &str, max: usize) -> Vec<String> {
    let clean = display(text);
    let max = max.max(1);
    let mut lines = Vec::new();
    let mut rest = clean.as_str();
    while !rest.is_empty() {
        let (head, _) = prefix_fitting(rest, max);
        if head.is_empty() {
            // A single grapheme wider than the column: take it anyway.
            let first = rest.graphemes(true).next().map_or(rest.len(), str::len);
            lines.push(rest[..first].to_string());
            rest = &rest[first..];
        } else {
            lines.push(head.to_string());
            rest = &rest[head.len()..];
        }
    }
    if lines.is_empty() {
        lines.push(String::new());
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const ESC: char = '\u{1b}';

    /// Whether `s` carries anything a terminal could interpret.
    fn has_control(s: &str) -> bool {
        s.chars().any(|c| is_control(c) || is_invisible(c))
    }

    #[test]
    fn the_unit_table_escapes_every_dangerous_class() {
        let table: &[(&str, &str)] = &[
            ("plain /usr/bin/tool", "plain /usr/bin/tool"),
            // CSI: clear screen and move the cursor.
            ("a\u{1b}[2J\u{1b}[Hb", "a\\x1b[2J\\x1b[Hb"),
            // OSC 52 clipboard write terminated by BEL.
            (
                "\u{1b}]52;c;Y3VybCBldmlsLnNo\u{7}",
                "\\x1b]52;c;Y3VybCBldmlsLnNo\\x07",
            ),
            // OSC 8 hyperlink terminated by ST (ESC \).
            (
                "\u{1b}]8;;https://evil\u{1b}\\click\u{1b}]8;;\u{1b}\\",
                "\\x1b]8;;https://evil\\x1b\\click\\x1b]8;;\\x1b\\",
            ),
            // DCS and the 8-bit C1 introducers.
            ("\u{1b}Pq#0\u{1b}\\", "\\x1bPq#0\\x1b\\"),
            ("x\u{9b}31my", "x\\x9b31my"),
            ("\u{9d}0;title\u{9c}", "\\x9d0;title\\x9c"),
            // NUL, DEL, newline, tab, carriage return.
            ("a\u{0}b\u{7f}c", "a\\x00b\\x7fc"),
            ("l1\nl2\r\tz", "l1\\x0al2\\x0d\\x09z"),
            // Trojan-Source bidi override and isolates.
            ("/tmp/\u{202E}gpj.exe", "/tmp/⟨U+202E⟩gpj.exe"),
            ("\u{2066}a\u{2069}", "⟨U+2066⟩a⟨U+2069⟩"),
            ("\u{200F}rtl", "⟨U+200F⟩rtl"),
            // Zero-width characters and the BOM.
            ("zo\u{200B}om", "zo⟨U+200B⟩om"),
            ("\u{FEFF}x\u{2060}y", "⟨U+FEFF⟩x⟨U+2060⟩y"),
            // Tag characters ("ASCII smuggling").
            ("ok\u{E0041}", "ok⟨U+E0041⟩"),
            // Hangul filler and variation selectors (look-alike paths).
            ("/usr/bin/ssh\u{3164}", "/usr/bin/ssh⟨U+3164⟩"),
            ("❤\u{FE0F}", "❤⟨U+FE0F⟩"),
            ("a\u{034F}b\u{180B}", "a⟨U+034F⟩b⟨U+180B⟩"),
            // Ordinary non-ASCII text is kept.
            ("Zoom – Café 日本", "Zoom – Café 日本"),
        ];
        for (input, want) in table {
            let got = display(input);
            assert_eq!(&got, want, "input {input:?}");
            assert!(!has_control(&got), "{got:?}");
        }
    }

    #[test]
    fn truncation_is_width_aware_and_keeps_both_ends_of_a_path() {
        let path = "/Applications/Zoom.app/Contents/MacOS/zoom.us";
        let t = truncate_middle(path, 20);
        assert_eq!(width(&t), 20, "{t}");
        assert!(t.starts_with("/Applicat"), "{t}");
        assert!(t.ends_with("zoom.us"), "{t}");
        assert!(t.contains(ELLIPSIS));
        assert_eq!(truncate_middle("short", 20), "short");
        assert_eq!(truncate_end("abcdef", 4), "abc…");
        assert_eq!(truncate_end("abcdef", 0), "");
        // Wide characters never overflow the column.
        let wide = truncate_end("日本語のパス", 5);
        assert!(width(&wide) <= 5, "{wide}");
        let wide = truncate_middle("日本語のパス名前", 7);
        assert!(width(&wide) <= 7, "{wide}");
        // Escapes are counted after sanitising.
        let esc = truncate_end("\u{1b}[31mred", 6);
        assert!(!has_control(&esc));
        assert!(width(&esc) <= 6);
    }

    #[test]
    fn wrap_splits_by_width_and_sanitises() {
        let sha = "a".repeat(96);
        let lines = wrap(&sha, 40);
        assert_eq!(lines.len(), 3);
        assert!(lines.iter().all(|l| width(l) <= 40));
        assert_eq!(lines.concat(), sha);
        let lines = wrap("x\u{1b}y", 3);
        assert_eq!(lines.concat(), "x\\x1by");
        assert_eq!(wrap("", 10), vec![String::new()]);
    }

    #[test]
    fn oversize_server_strings_are_cut_without_panicking() {
        let huge = "\u{1b}[".repeat(50_000) + &"é".repeat(50_000);
        let t = truncate_middle(&huge, 30);
        assert!(width(&t) <= 30);
        assert!(!has_control(&t));
    }

    /// Width as ratatui's buffer lays it out: render on a wide line and
    /// count the cells up to the last one written.
    fn ratatui_width(text: &str) -> usize {
        use ratatui::buffer::Buffer;
        use ratatui::layout::Rect;
        let mut buf = Buffer::empty(Rect::new(0, 0, 400, 1));
        let (x, _) = buf.set_stringn(0, 0, text, 400, ratatui::style::Style::default());
        usize::from(x)
    }

    /// Pieces whose width as a sequence differs from the sum of their
    /// characters (emoji presentation, modifiers, ZWJ, lam-alef, combining
    /// and halfwidth sound marks, wide CJK).
    fn tricky() -> impl Strategy<Value = String> {
        let pieces = prop::sample::select(vec![
            "❤\u{FE0F}",
            "👍🏽",
            "👩\u{200D}💻",
            "لا",
            "e\u{301}",
            "ｶﾞ",
            "日本",
            "a",
            "/",
            "🇧🇷",
            "\u{1b}[",
            "\u{3164}",
            "x\u{20DD}",
        ]);
        prop::collection::vec(pieces, 0..80).prop_map(|v| v.concat())
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(2_000))]

        /// Fitted text never exceeds its column as ratatui draws it, and our
        /// measure agrees with ratatui's.
        #[test]
        fn fitted_text_never_spills_out_of_its_column(text in tricky(), max in 1usize..60) {
            for out in [truncate_end(&text, max), truncate_middle(&text, max)] {
                prop_assert!(width(&out) <= max, "{:?} -> {:?}", text, out);
                prop_assert_eq!(width(&out), ratatui_width(&out), "{:?}", out);
            }
            for line in wrap(&text, max.max(2)) {
                prop_assert!(width(&line) <= max.max(2) || line.graphemes(true).count() == 1);
                prop_assert_eq!(width(&line), ratatui_width(&line));
            }
        }

        /// Fuzz-style: arbitrary bytes (decoded lossily, as any server
        /// string arrives through prost's UTF-8 check) never leave an ESC,
        /// a C0/C1 control or an invisible character in the output.
        #[test]
        fn arbitrary_bytes_never_emit_a_control(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
            let text = String::from_utf8_lossy(&bytes);
            let out = display(&text);
            prop_assert!(!has_control(&out), "{:?}", out);
            prop_assert!(!out.contains(ESC), "an ESC reached the output");
        }

        /// Arbitrary Unicode strings, through every helper.
        #[test]
        fn arbitrary_strings_never_emit_a_control(text in any::<String>(), max in 0usize..120) {
            for out in [display(&text), truncate_end(&text, max), truncate_middle(&text, max)] {
                prop_assert!(!has_control(&out), "{:?}", out);
            }
            prop_assert!(width(&truncate_end(&text, max)) <= max);
            prop_assert!(width(&truncate_middle(&text, max)) <= max);
            for line in wrap(&text, max.max(2)) {
                prop_assert!(!has_control(&line));
            }
        }
    }
}
