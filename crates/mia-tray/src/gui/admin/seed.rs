//! Painting a TOTP seed (F22 §3a): the QR code as filled squares, and the
//! secret one character at a time, so no `egui` galley (and so no galley
//! cache entry) ever holds the secret, or any part longer than a character.

use eframe::egui;
use zeroize::Zeroize as _;

use crate::admin::seed::{QrMatrix, SeedDisplay};

/// Pixels per QR module.
const MODULE: f32 = 4.0;
/// Light modules around the code (the QR quiet zone).
const QUIET: usize = 4;
/// Groups of four characters per line of text.
const GROUPS_PER_LINE: usize = 4;

/// `n` as pixels (small counts only).
fn px(n: usize) -> f32 {
    f32::from(u16::try_from(n).unwrap_or(u16::MAX))
}

/// Paint `seed`: the QR code, then the text when shown.
pub(super) fn paint(ui: &mut egui::Ui, seed: &SeedDisplay<'_>) {
    if let Some(qr) = seed.qr {
        paint_qr(ui, qr);
    }
    if let Some(text) = seed.text {
        ui.add_space(4.0);
        paint_chars(ui, text);
    }
}

fn paint_qr(ui: &mut egui::Ui, qr: &QrMatrix) {
    let side = px(qr.width() + 2 * QUIET) * MODULE;
    let (rect, _) = ui.allocate_exact_size(egui::vec2(side, side), egui::Sense::hover());
    let painter = ui.painter_at(rect);
    // Dark on white whatever the theme: scanners expect it.
    painter.rect_filled(rect, 0.0, egui::Color32::WHITE);
    for y in 0..qr.width() {
        for x in 0..qr.width() {
            if qr.is_dark(x, y) {
                let min = rect.min + egui::vec2(px(x + QUIET), px(y + QUIET)) * MODULE;
                painter.rect_filled(
                    egui::Rect::from_min_size(min, egui::vec2(MODULE, MODULE)),
                    0.0,
                    egui::Color32::BLACK,
                );
            }
        }
    }
}

/// Paint `text` (groups of four separated by spaces) one glyph per galley,
/// four groups per line.
fn paint_chars(ui: &mut egui::Ui, text: &str) {
    let font = egui::TextStyle::Monospace.resolve(ui.style());
    let color = ui.visuals().strong_text_color();
    let advance = font.size * 0.75;
    let line_chars = GROUPS_PER_LINE * 5;
    let chars = text.chars().count();
    let lines = chars.div_ceil(line_chars).max(1);
    let size = egui::vec2(px(line_chars) * advance, px(lines) * font.size * 1.5);
    let (rect, _) = ui.allocate_exact_size(size, egui::Sense::hover());
    let painter = ui.painter_at(rect);
    let mut glyph = [0u8; 4];
    for (i, c) in text.chars().enumerate() {
        if c == ' ' {
            continue;
        }
        let (line, col) = (i / line_chars, i % line_chars);
        let pos = rect.min + egui::vec2(px(col) * advance, px(line) * font.size * 1.5);
        painter.text(
            pos,
            egui::Align2::LEFT_TOP,
            c.encode_utf8(&mut glyph),
            font.clone(),
            color,
        );
    }
    glyph.zeroize();
}
