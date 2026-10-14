//! Declared versions and display strings (F19 §4.3).
//!
//! A declared version is a claim the binary (or its package) makes about
//! itself: untrusted, display only, never a policy input. Every string read
//! from a binary is cleaned the same way: trimmed, control and invisible
//! formatting characters removed, truncated to its limit. A value that is
//! empty after cleaning is dropped, never "repaired".

/// Where the declared version came from (F19 §4.3 `version_source`). The
/// sources are tried in this order of preference; the first hit wins.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum VersionSource {
    /// No version: the lineage revision is displayed instead.
    #[default]
    None,
    /// PE `VS_FIXEDFILEINFO.dwProductVersion`.
    PeFixed,
    /// PE `StringFileInfo` `ProductVersion` (else `FileVersion`).
    PeString,
    /// Bundle `CFBundleShortVersionString`.
    PlistShort,
    /// Bundle `CFBundleVersion`.
    PlistBundle,
    /// ELF `.note.package` (FDO package metadata).
    ElfNotePackage,
    /// dpkg database.
    Dpkg,
    /// rpm database (deferred, F19-OQ6; never produced yet).
    Rpm,
}

impl VersionSource {
    /// Wire and ledger code (0 to 7).
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::None => 0,
            Self::PeFixed => 1,
            Self::PeString => 2,
            Self::PlistShort => 3,
            Self::PlistBundle => 4,
            Self::ElfNotePackage => 5,
            Self::Dpkg => 6,
            Self::Rpm => 7,
        }
    }

    /// The source of a code, if known.
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::None),
            1 => Some(Self::PeFixed),
            2 => Some(Self::PeString),
            3 => Some(Self::PlistShort),
            4 => Some(Self::PlistBundle),
            5 => Some(Self::ElfNotePackage),
            6 => Some(Self::Dpkg),
            7 => Some(Self::Rpm),
            _ => None,
        }
    }
}

/// Longest declared version, in characters.
pub const MAX_VERSION_CHARS: usize = 64;
/// Longest product, company or package name, in characters.
pub const MAX_NAME_CHARS: usize = 128;
/// Longest bundle identifier, in characters.
pub const MAX_BUNDLE_ID_CHARS: usize = 255;

/// Display metadata of a binary. All fields are untrusted.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct VersionInfo {
    /// Declared version (≤ 64 characters).
    pub declared_version: Option<String>,
    /// Where it came from; [`VersionSource::None`] when absent.
    pub source: VersionSource,
    /// Product name (PE `ProductName`, bundle `CFBundleName`).
    pub product_name: Option<String>,
    /// Company name (PE `CompanyName`), display only.
    pub company_name: Option<String>,
    /// macOS bundle identifier.
    pub bundle_id: Option<String>,
    /// Package name (ELF note or dpkg).
    pub package_name: Option<String>,
}

/// Whether `c` is an invisible formatting character that could disguise a
/// displayed string (zero-width characters, bidirectional overrides and
/// isolates, the byte-order mark).
fn is_invisible_format(c: char) -> bool {
    matches!(c,
        '\u{00ad}'
        | '\u{061c}'
        | '\u{180e}'
        | '\u{200b}'..='\u{200f}'
        | '\u{202a}'..='\u{202e}'
        | '\u{2060}'..='\u{2064}'
        | '\u{2066}'..='\u{206f}'
        | '\u{feff}')
}

/// Clean an untrusted display string: remove control and invisible
/// formatting characters, trim, truncate to `max_chars`. `None` when nothing
/// is left.
#[must_use]
pub fn clean(raw: &str, max_chars: usize) -> Option<String> {
    let kept: String = raw
        .chars()
        .filter(|c| !c.is_control() && !is_invisible_format(*c))
        .collect();
    let trimmed: String = kept.trim().chars().take(max_chars).collect();
    let trimmed = trimmed.trim_end();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

/// The displayed version of a binary (F19 §1): `"<declared> (r<N>)"` when it
/// declares a version, else `"r<N>"`.
#[must_use]
pub fn display_version(declared: Option<&str>, revision: u32) -> String {
    match declared.and_then(|d| clean(d, MAX_VERSION_CHARS)) {
        Some(v) => format!("{v} (r{revision})"),
        None => format!("r{revision}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strings_are_cleaned_and_bounded() {
        assert_eq!(clean("  1.2.3\n", 64).as_deref(), Some("1.2.3"));
        assert_eq!(clean("1.\u{0}2\u{1b}[31m", 64).as_deref(), Some("1.2[31m"));
        assert_eq!(
            clean("evil\u{202e}exe.txt", 64).as_deref(),
            Some("evilexe.txt")
        );
        assert_eq!(clean("\u{200b}\t ", 64), None);
        assert_eq!(clean(&"9".repeat(100), 64).unwrap().len(), 64);
        assert_eq!(clean("ação", 3).as_deref(), Some("açã"));
    }

    #[test]
    fn display_version_falls_back_to_the_revision() {
        assert_eq!(display_version(Some("2.5.1"), 3), "2.5.1 (r3)");
        assert_eq!(display_version(None, 1), "r1");
        assert_eq!(display_version(Some(" \u{7} "), 2), "r2");
    }

    #[test]
    fn codes_round_trip() {
        for code in 0..=7 {
            assert_eq!(VersionSource::from_code(code).unwrap().code(), code);
        }
        assert_eq!(VersionSource::from_code(8), None);
    }
}
