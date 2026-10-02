//! Tray icon bitmaps, drawn in code (no image files, no decoder dependency).
//!
//! A filled, anti-aliased disc in the state colour with a thin dark rim (so
//! it reads on light and dark menu bars), an optional white "!" badge
//! (`NotConfigured`), and a dimmed second frame for the animated
//! (`Attesting`) state.

use crate::model::{IconColor, Presentation};

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

/// Coverage of pixel (`px`, `py`) by a disc of `radius` centred at
/// (`centre`, `centre`), with one pixel of anti-aliasing.
fn coverage(px: f32, py: f32, centre: f32, radius: f32) -> f32 {
    let dist = ((px - centre).powi(2) + (py - centre).powi(2)).sqrt();
    (radius + 0.5 - dist).clamp(0.0, 1.0)
}

/// Quantise a `[0, 1]` intensity to a byte.
fn to_u8(v: f32) -> u8 {
    // Clamped to [0, 255] first, so the cast neither truncates nor wraps.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let byte = (v.clamp(0.0, 1.0) * 255.0).round() as u8;
    byte
}

/// RGBA pixels (row-major, `SIZE × SIZE × 4`) for `look`; `frame` alternates
/// the animated state between full and dimmed.
#[must_use]
pub fn rgba(look: Presentation, frame: u32) -> Vec<u8> {
    let edge = SIZE as usize;
    #[allow(clippy::cast_precision_loss)] // 32 is exact in f32
    let size = SIZE as f32;
    let centre = size / 2.0 - 0.5;
    let outer = size / 2.0 - 2.0;
    let inner = outer - 1.5;
    let fill = if look.animated && frame % 2 == 1 {
        0.55
    } else {
        1.0
    };
    let base = rgb(look.color).map(|v| f32::from(v) / 255.0);
    let mut out = vec![0u8; edge * edge * 4];
    for row in 0..edge {
        for col in 0..edge {
            #[allow(clippy::cast_precision_loss)] // < 32, exact
            let (fx, fy) = (col as f32, row as f32);
            let rim = coverage(fx, fy, centre, outer);
            let body = coverage(fx, fy, centre, inner);
            // The rim is a 35% darker shade of the colour.
            let shade = (0.65 + 0.35 * body) * fill;
            let mut pixel = [base[0] * shade, base[1] * shade, base[2] * shade, rim];
            if look.badge {
                // A white "!" (bar + dot) in the centre.
                let bar = (fx - centre).abs() <= 1.6 && fy >= centre - 8.0 && fy <= centre + 2.5;
                let dot = coverage(fx, fy - 6.0, centre, 1.8) > 0.5;
                if bar || dot {
                    pixel = [1.0, 1.0, 1.0, rim];
                }
            }
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
            let buf = rgba(p, 0);
            assert_eq!(buf.len(), (SIZE * SIZE * 4) as usize);
            assert_eq!(px(&buf, 0, 0)[3], 0, "corner transparent");
            // Sample off-centre (the badge sits in the middle).
            let sample = px(&buf, SIZE / 2 + 7, SIZE / 2);
            assert_eq!(sample[3], 255);
            assert_eq!(sample[..3], rgb(p.color), "{state:?}");
        }
    }

    #[test]
    fn the_badge_and_animation_change_pixels() {
        let plain = rgba(presentation(AgentState::NotRunning), 0);
        let badged = rgba(presentation(AgentState::NotConfigured), 0);
        assert_ne!(plain, badged);
        assert_eq!(px(&badged, SIZE / 2, SIZE / 2 - 3)[..3], [255, 255, 255]);
        let a = presentation(AgentState::Attesting);
        assert_ne!(rgba(a, 0), rgba(a, 1));
        let h = presentation(AgentState::Healthy);
        assert_eq!(rgba(h, 0), rgba(h, 1), "only the animated state pulses");
    }
}
