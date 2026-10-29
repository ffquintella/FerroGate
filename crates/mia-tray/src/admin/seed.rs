//! A TOTP seed on screen (F22 §3a): the QR code of its provisioning URI and,
//! on request, the secret as text, for the administrator's authenticator
//! app. Shown once: the wizard or panel that holds it drops it (wiped) when
//! it closes, locks, or the seed is used.

//! The matrix and the text live in wiped buffers and have no `Debug`,
//! `Display` or `Clone`. The window paints the modules as rectangles and the
//! text one character at a time, so `egui`'s galley cache never holds the
//! secret as a string. The QR encoder's own scratch buffers are freed
//! unwiped (the residual exposure F22 records).

use ferrogate_admin_client::totp::TotpSeed;
use qrcode::{Color, EcLevel, QrCode};
use zeroize::Zeroizing;

/// A QR code as a square of modules (`1` dark), row by row.
pub struct QrMatrix {
    width: usize,
    modules: Zeroizing<Vec<u8>>,
}

static_assertions::assert_not_impl_any!(QrMatrix: std::fmt::Debug, std::fmt::Display, Clone);

impl QrMatrix {
    /// Encode `text` (error correction M). `None` when it does not fit.
    #[must_use]
    pub fn encode(text: &str) -> Option<Self> {
        let code = QrCode::with_error_correction_level(text.as_bytes(), EcLevel::M).ok()?;
        let width = code.width();
        let mut modules = Zeroizing::new(Vec::with_capacity(width * width));
        for y in 0..width {
            for x in 0..width {
                modules.push(u8::from(code[(x, y)] == Color::Dark));
            }
        }
        Some(Self { width, modules })
    }

    /// Modules per side.
    #[must_use]
    pub fn width(&self) -> usize {
        self.width
    }

    /// Whether the module at column `x`, row `y` is dark (outside: light).
    #[must_use]
    pub fn is_dark(&self, x: usize, y: usize) -> bool {
        x < self.width && y < self.width && self.modules[y * self.width + x] == 1
    }
}

/// A seed being shown: only its QR matrix and grouped text are kept (the
/// URI itself is wiped once they are made).
pub struct ShownSeed {
    qr: Option<QrMatrix>,
    text: Zeroizing<String>,
    text_shown: bool,
}

static_assertions::assert_not_impl_any!(ShownSeed: std::fmt::Debug, std::fmt::Display, Clone);

/// What the window paints, borrowed from the [`ShownSeed`].
pub struct SeedDisplay<'a> {
    /// The QR code, when the URI fits one.
    pub qr: Option<&'a QrMatrix>,
    /// The secret in groups of four, when the administrator asked for it.
    pub text: Option<&'a str>,
}

impl ShownSeed {
    /// Prepare `seed` for display (QR first; the text stays hidden).
    #[must_use]
    pub fn new(seed: TotpSeed) -> Self {
        let qr = QrMatrix::encode(seed.uri());
        let text = seed.grouped();
        drop(seed);
        Self {
            qr,
            text,
            text_shown: false,
        }
    }

    /// Show or hide the secret as text.
    pub fn toggle_text(&mut self) {
        self.text_shown = !self.text_shown;
    }

    /// Whether the text is shown.
    #[must_use]
    pub fn text_shown(&self) -> bool {
        self.text_shown
    }

    /// What to paint.
    #[must_use]
    pub fn display(&self) -> SeedDisplay<'_> {
        SeedDisplay {
            qr: self.qr.as_ref(),
            text: self.text_shown.then_some(self.text.as_str()),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A provisioning URI shaped like CMIS's.
    pub(crate) const URI: &str = "otpauth://totp/FerroGate:alice?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=FerroGate&algorithm=SHA1&digits=6&period=30";
    /// Its secret.
    pub(crate) const SECRET: &str = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";

    pub(crate) fn seed() -> TotpSeed {
        TotpSeed::from_uri(URI.to_string()).unwrap()
    }

    #[test]
    fn the_qr_code_is_square_and_has_its_finder_patterns() {
        let qr = QrMatrix::encode(URI).unwrap();
        let w = qr.width();
        assert!(w >= 21 && (w - 17).is_multiple_of(4), "a QR version: {w}");
        // Finder patterns: dark corners, a light ring inside.
        for (x, y) in [(0, 0), (w - 1, 0), (0, w - 1)] {
            assert!(qr.is_dark(x, y), "corner {x},{y}");
        }
        assert!(!qr.is_dark(1, 1));
        assert!(qr.is_dark(3, 3), "the finder's centre");
        assert!(!qr.is_dark(w, 0) && !qr.is_dark(0, w), "outside is light");
        assert!(QrMatrix::encode(&"x".repeat(4000)).is_none(), "too long");
    }

    #[test]
    fn the_text_is_hidden_until_asked_for() {
        let mut shown = ShownSeed::new(seed());
        assert!(shown.display().qr.is_some());
        assert!(shown.display().text.is_none());
        shown.toggle_text();
        assert_eq!(
            shown.display().text,
            Some("JBSW Y3DP EHPK 3PXP JBSW Y3DP EHPK 3PXP")
        );
        assert!(shown.text_shown());
        let qr = shown.display().qr.unwrap();
        let again = QrMatrix::encode(URI).unwrap();
        assert_eq!(qr.width(), again.width());
        assert!(qr.modules == again.modules, "the URI is what is encoded");
    }
}
