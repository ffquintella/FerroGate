//! The operating system a binary lives on (F19 §2 `platform`).

/// Platform codes stored in the ledger and carried in `AppRequestDoc`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Platform {
    /// Linux.
    Linux,
    /// macOS.
    MacOs,
    /// Windows.
    Windows,
}

impl Platform {
    /// Wire and ledger code: 1 linux, 2 macos, 3 windows.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Linux => 1,
            Self::MacOs => 2,
            Self::Windows => 3,
        }
    }

    /// The platform of a code, if known.
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Linux),
            2 => Some(Self::MacOs),
            3 => Some(Self::Windows),
            _ => None,
        }
    }

    /// The platform this build runs on (other Unix systems use the Linux
    /// rules: case-sensitive byte paths).
    #[must_use]
    pub const fn current() -> Self {
        if cfg!(windows) {
            Self::Windows
        } else if cfg!(target_os = "macos") {
            Self::MacOs
        } else {
            Self::Linux
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_round_trip() {
        for p in [Platform::Linux, Platform::MacOs, Platform::Windows] {
            assert_eq!(Platform::from_code(p.code()), Some(p));
        }
        assert_eq!(Platform::from_code(0), None);
        assert_eq!(Platform::from_code(4), None);
    }
}
