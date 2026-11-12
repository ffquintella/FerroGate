//! Tray icon bitmaps, drawn in code (no image files, no decoder dependency).
//!
//! A filled, anti-aliased disc in the state colour with a thin dark rim (so
//! it reads on light and dark menu bars) and one glyph over it — ✓ ! × – or
//! three dots — so the state never rests on colour alone (F23 §2). The
//! icon is static: nothing blinks.

use crate::model::{Glyph, IconColor, Presentation};

/// Icon edge length in pixels.
pub const SIZE: u32 = 32;

/// RGB for each colour.
#[must_use]
pub fn rgb(color: IconColor) -> [u8; 3] {
    match color {
        IconColor::Grey => [0x8e, 0x8e, 0x93],
        IconColor::Blue => [0x0a, 0x84, 0xff],
        IconColor::Green => [0x30, 0xd1, 0x58],
        IconColor::Yellow => [0xff, 0xcc, 0x00],
        IconColor::Red => [0xff, 0x3b, 0x30],
    }
}

/// The glyph's colour on `color`: dark on the light discs, white on the
/// others (at least 3:1 against the disc either way).
#[must_use]
pub fn glyph_rgb(color: IconColor) -> [u8; 3] {
    match color {
        IconColor::Green | IconColor::Yellow => [0x1c, 0x1c, 0x1e],
        IconColor::Grey | IconColor::Blue | IconColor::Red => [0xff, 0xff, 0xff],
    }
}

/// The window badge's background for `color`: the icon colour, darkened
/// where white text would not reach 4.5:1 (WCAG 1.4.3).
#[must_use]
pub fn badge_rgb(color: IconColor) -> [u8; 3] {
    match color {
        IconColor::Grey => [0x5f, 0x63, 0x68],
        IconColor::Blue => [0x0a, 0x5c, 0xc2],
        IconColor::Green => rgb(IconColor::Green),
        IconColor::Yellow => rgb(IconColor::Yellow),
        IconColor::Red => [0xc6, 0x28, 0x28],
    }
}

/// The WCAG contrast ratio of two sRGB colours (1 to 21).
#[must_use]
pub fn contrast(a: [u8; 3], b: [u8; 3]) -> f32 {
    let lum = |c: [u8; 3]| {
        let lin = |v: u8| {
            let s = f32::from(v) / 255.0;
            if s <= 0.039_28 {
                s / 12.92
            } else {
                ((s + 0.055) / 1.055).powf(2.4)
            }
        };
        0.2126 * lin(c[0]) + 0.7152 * lin(c[1]) + 0.0722 * lin(c[2])
    };
    let (la, lb) = (lum(a), lum(b));
    (la.max(lb) + 0.05) / (la.min(lb) + 0.05)
}

/// Coverage of pixel (`px`, `py`) by a disc of `radius` centred at
/// (`cx`, `cy`), with one pixel of anti-aliasing.
fn coverage(px: f32, py: f32, cx: f32, cy: f32, radius: f32) -> f32 {
    let dist = ((px - cx).powi(2) + (py - cy).powi(2)).sqrt();
    (radius + 0.5 - dist).clamp(0.0, 1.0)
}

/// Coverage of pixel `at` by a stroke of half-width `half` from `from` to
/// `to`.
fn stroke(at: (f32, f32), from: (f32, f32), to: (f32, f32), half: f32) -> f32 {
    let (dx, dy) = (to.0 - from.0, to.1 - from.1);
    let len2 = dx * dx + dy * dy;
    let along = if len2 > 0.0 {
        (((at.0 - from.0) * dx + (at.1 - from.1) * dy) / len2).clamp(0.0, 1.0)
    } else {
        0.0
    };
    coverage(at.0, at.1, from.0 + along * dx, from.1 + along * dy, half)
}

/// Coverage of pixel `p` by `glyph` (centre near 15.5).
fn glyph_coverage(glyph: Glyph, p: (f32, f32)) -> f32 {
    const W: f32 = 1.7;
    match glyph {
        Glyph::Check => {
            stroke(p, (9.5, 16.5), (13.5, 20.5), W).max(stroke(p, (13.5, 20.5), (21.5, 11.0), W))
        }
        Glyph::Cross => {
            stroke(p, (10.5, 10.5), (20.5, 20.5), W).max(stroke(p, (20.5, 10.5), (10.5, 20.5), W))
        }
        Glyph::Bang => {
            stroke(p, (15.5, 8.5), (15.5, 17.0), W).max(coverage(p.0, p.1, 15.5, 21.5, W + 0.2))
        }
        Glyph::Dash => stroke(p, (10.0, 15.5), (21.0, 15.5), W),
        Glyph::Busy => [9.5_f32, 15.5, 21.5]
            .iter()
            .map(|x| coverage(p.0, p.1, *x, 15.5, W + 0.3))
            .fold(0.0, f32::max),
    }
}

/// Quantise a `[0, 1]` intensity to a byte.
fn to_u8(v: f32) -> u8 {
    // Clamped to [0, 255] first, so the cast neither truncates nor wraps.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let byte = (v.clamp(0.0, 1.0) * 255.0).round() as u8;
    byte
}

/// RGBA pixels (row-major, `SIZE × SIZE × 4`) for `look`.
#[must_use]
pub fn rgba(look: Presentation) -> Vec<u8> {
    let edge = SIZE as usize;
    #[allow(clippy::cast_precision_loss)] // 32 is exact in f32
    let size = SIZE as f32;
    let centre = size / 2.0 - 0.5;
    let outer = size / 2.0 - 2.0;
    let inner = outer - 1.5;
    let base = rgb(look.color).map(|v| f32::from(v) / 255.0);
    let ink = glyph_rgb(look.color).map(|v| f32::from(v) / 255.0);
    let mut out = vec![0u8; edge * edge * 4];
    for row in 0..edge {
        for col in 0..edge {
            #[allow(clippy::cast_precision_loss)] // < 32, exact
            let (fx, fy) = (col as f32, row as f32);
            let rim = coverage(fx, fy, centre, centre, outer);
            let body = coverage(fx, fy, centre, centre, inner);
            // The rim is a 35% darker shade of the colour.
            let shade = 0.65 + 0.35 * body;
            let g = glyph_coverage(look.glyph, (fx, fy)) * body;
            let mix = |i: usize| base[i] * shade * (1.0 - g) + ink[i] * g;
            let pixel = [mix(0), mix(1), mix(2), rim];
            let at = (row * edge + col) * 4;
            out[at..at + 4].copy_from_slice(&pixel.map(to_u8));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::presentation;
    use mia_status_proto::AgentState;

    fn px(buf: &[u8], x: u32, y: u32) -> [u8; 4] {
        let i = ((y * SIZE + x) * 4) as usize;
        [buf[i], buf[i + 1], buf[i + 2], buf[i + 3]]
    }

    #[test]
    fn icons_have_the_state_colour_and_transparent_corners() {
        for state in AgentState::ALL {
            let p = presentation(state);
            let buf = rgba(p);
            assert_eq!(buf.len(), (SIZE * SIZE * 4) as usize);
            assert_eq!(px(&buf, 0, 0)[3], 0, "corner transparent");
            // Sample below every glyph.
            let sample = px(&buf, SIZE / 2, SIZE - 6);
            assert_eq!(sample[3], 255);
            assert_eq!(sample[..3], rgb(p.color), "{state:?}");
        }
    }

    /// Badge text reaches WCAG AA (4.5:1); icon glyphs reach 3:1 (1.4.11).
    #[test]
    fn badge_text_and_glyphs_have_enough_contrast() {
        use IconColor::{Blue, Green, Grey, Red, Yellow};
        for c in [Grey, Blue, Green, Yellow, Red] {
            let text = contrast(badge_rgb(c), glyph_rgb(c));
            assert!(text >= 4.5, "{c:?} badge {text}");
            let glyph = contrast(rgb(c), glyph_rgb(c));
            assert!(glyph >= 3.0, "{c:?} glyph {glyph}");
        }
        assert!((contrast([0, 0, 0], [255, 255, 255]) - 21.0).abs() < 0.01);
    }

    /// Two states with the same colour still look different, so the state
    /// never rests on colour alone.
    #[test]
    fn every_glyph_is_drawn_and_distinct() {
        let glyphs = [
            Glyph::Check,
            Glyph::Busy,
            Glyph::Bang,
            Glyph::Cross,
            Glyph::Dash,
        ];
        let draw = |g| {
            rgba(Presentation {
                color: IconColor::Grey,
                glyph: g,
            })
        };
        for (i, a) in glyphs.iter().enumerate() {
            for b in &glyphs[i + 1..] {
                assert_ne!(draw(*a), draw(*b), "{a:?} vs {b:?}");
            }
        }
        // Not configured and not running share grey but not the glyph.
        assert_ne!(
            rgba(presentation(AgentState::NotConfigured)),
            rgba(presentation(AgentState::NotRunning))
        );
        // The "!" is inked in the middle.
        let bang = draw(Glyph::Bang);
        assert_eq!(px(&bang, 15, 12)[..3], [255, 255, 255]);
    }
}
