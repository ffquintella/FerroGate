//! macOS bundle `Info.plist` (F19 §4.3, version sources 3 and 4).
//!
//! When the executable is `<X>.app/Contents/MacOS/<name>`, the bundle's
//! `Contents/Info.plist` declares its version. The plist (XML or binary) is
//! read with the event-stream reader of the `plist` crate, which keeps its
//! own stack on the heap; this module bounds the nesting depth and the number
//! of events itself, and only looks at the root dictionary's string values.
//!
//! The plist is a second file, read by a root daemon at a path derived from
//! the user-supplied executable, so it is opened defensively: the last
//! component must not be a symbolic link, the opened file must be the one
//! that was looked up, have a single link, and be owned by root or by the
//! executable's owner. The values are display data only.

use std::fs::File;
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};

use plist::stream::{Event, Reader};

use crate::bytes::{Budget, ParseError};
use crate::limits::Limits;

/// Most plist events examined.
const MAX_EVENTS: usize = 100_000;

/// What a bundle's `Info.plist` declares. All values are untrusted.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BundleInfo {
    /// `CFBundleExecutable`.
    pub executable: Option<String>,
    /// `CFBundleShortVersionString` (version source 3).
    pub short_version: Option<String>,
    /// `CFBundleVersion` (version source 4).
    pub bundle_version: Option<String>,
    /// `CFBundleIdentifier`.
    pub identifier: Option<String>,
    /// `CFBundleName`.
    pub name: Option<String>,
}

/// The `Info.plist` path and executable name for an executable inside an
/// app bundle (`<X>.app/Contents/MacOS/<name>`), else `None`.
#[must_use]
pub fn info_plist_for(exe: &Path) -> Option<(PathBuf, String)> {
    let name = exe.file_name()?.to_str()?.to_string();
    let macos = exe.parent()?;
    let contents = macos.parent()?;
    let app = contents.parent()?;
    let is_app = app
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("app"));
    (macos.file_name()? == "MacOS" && contents.file_name()? == "Contents" && is_app)
        .then(|| (contents.join("Info.plist"), name))
}

/// Parse an `Info.plist` (XML or binary) and keep the root dictionary's
/// string values of interest. Nesting deeper than `max_depth` is refused.
pub fn parse_info_plist(bytes: &[u8], max_depth: usize) -> Result<BundleInfo, ParseError> {
    let budget = Budget::new(&Limits {
        max_depth,
        ..Limits::default()
    });
    parse_with(bytes, &budget)
}

pub(crate) fn parse_with(bytes: &[u8], budget: &Budget) -> Result<BundleInfo, ParseError> {
    let mut info = BundleInfo::default();
    let mut depth = 0usize;
    let mut key: Option<String> = None;
    let mut expect_key = true;
    for (count, event) in Reader::new(Cursor::new(bytes)).enumerate() {
        if count >= MAX_EVENTS {
            return Err(ParseError::Malformed("plist too many events"));
        }
        if count.is_multiple_of(1024) {
            budget.check_time()?;
        }
        let event = event.map_err(|_| ParseError::Malformed("plist"))?;
        match event {
            Event::StartDictionary(_) | Event::StartArray(_) => {
                if depth == 0 && !matches!(event, Event::StartDictionary(_)) {
                    return Err(ParseError::Malformed("plist root"));
                }
                if depth == 1 {
                    // A collection as a value: its key is consumed.
                    key = None;
                    expect_key = true;
                }
                depth += 1;
                if depth > budget.max_depth {
                    return Err(ParseError::TooDeep);
                }
            }
            Event::EndCollection => {
                depth = depth.checked_sub(1).ok_or(ParseError::Malformed("plist"))?;
                if depth == 0 {
                    break;
                }
            }
            Event::String(s) if depth == 1 => {
                if expect_key {
                    key = Some(s.into_owned());
                    expect_key = false;
                } else {
                    let value = s.into_owned();
                    let slot = match key.take().as_deref() {
                        Some("CFBundleExecutable") => Some(&mut info.executable),
                        Some("CFBundleShortVersionString") => Some(&mut info.short_version),
                        Some("CFBundleVersion") => Some(&mut info.bundle_version),
                        Some("CFBundleIdentifier") => Some(&mut info.identifier),
                        Some("CFBundleName") => Some(&mut info.name),
                        _ => None,
                    };
                    if let Some(slot) = slot {
                        *slot = Some(value);
                    }
                    expect_key = true;
                }
            }
            _ if depth == 0 => return Err(ParseError::Malformed("plist root")),
            _ if depth == 1 => {
                if expect_key {
                    return Err(ParseError::Malformed("plist key"));
                }
                key = None;
                expect_key = true;
            }
            _ => {}
        }
    }
    Ok(info)
}

/// Read the `Info.plist` of the bundle containing `exe`, when `exe` is the
/// bundle's main executable (`CFBundleExecutable`). `exe_owner` is the uid
/// owning the executable; the plist must be owned by it or by root.
pub fn read_info_plist(
    exe: &Path,
    limits: &Limits,
    exe_owner: Option<u32>,
) -> Result<Option<BundleInfo>, ParseError> {
    read_within(
        exe,
        &Budget::new(limits),
        limits.max_metadata_bytes,
        exe_owner,
    )
}

pub(crate) fn read_within(
    exe: &Path,
    budget: &Budget,
    max_bytes: u64,
    exe_owner: Option<u32>,
) -> Result<Option<BundleInfo>, ParseError> {
    let Some((plist_path, exe_name)) = info_plist_for(exe) else {
        return Ok(None);
    };
    let looked_up = match std::fs::symlink_metadata(&plist_path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    if !looked_up.file_type().is_file() {
        return Err(ParseError::Malformed("Info.plist is not a regular file"));
    }
    let file = File::open(&plist_path)?;
    let opened = file.metadata()?;
    check_same_file(&looked_up, &opened, exe_owner)?;
    if opened.len() > max_bytes {
        return Err(ParseError::TooMuchData);
    }
    let mut bytes = Vec::new();
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max_bytes {
        return Err(ParseError::TooMuchData);
    }
    let info = parse_with(&bytes, budget)?;
    Ok((info.executable.as_deref() == Some(exe_name.as_str())).then_some(info))
}

#[cfg(unix)]
fn check_same_file(
    looked_up: &std::fs::Metadata,
    opened: &std::fs::Metadata,
    exe_owner: Option<u32>,
) -> Result<(), ParseError> {
    use std::os::unix::fs::MetadataExt;
    if looked_up.dev() != opened.dev() || looked_up.ino() != opened.ino() || !opened.is_file() {
        return Err(ParseError::Malformed("Info.plist changed while opening"));
    }
    if opened.nlink() != 1 {
        return Err(ParseError::Malformed("Info.plist has several links"));
    }
    if let Some(owner) = exe_owner {
        if opened.uid() != owner && opened.uid() != 0 {
            return Err(ParseError::Malformed("Info.plist owner"));
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_same_file(
    _looked_up: &std::fs::Metadata,
    opened: &std::fs::Metadata,
    _exe_owner: Option<u32>,
) -> Result<(), ParseError> {
    if !opened.is_file() {
        return Err(ParseError::Malformed("Info.plist is not a regular file"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const XML: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleExecutable</key><string>Tool</string>
  <key>CFBundleIdentifier</key><string>com.example.tool</string>
  <key>LSEnvironment</key><dict><key>CFBundleVersion</key><string>nested</string></dict>
  <key>CFBundleName</key><string>Tool</string>
  <key>NSHighResolutionCapable</key><true/>
  <key>CFBundleShortVersionString</key><string>3.1.4</string>
  <key>CFBundleVersion</key><string>314</string>
</dict></plist>"#;

    #[test]
    fn xml_plists_yield_root_strings_only() {
        let info = parse_info_plist(XML.as_bytes(), 16).unwrap();
        assert_eq!(info.executable.as_deref(), Some("Tool"));
        assert_eq!(info.identifier.as_deref(), Some("com.example.tool"));
        assert_eq!(info.short_version.as_deref(), Some("3.1.4"));
        assert_eq!(
            info.bundle_version.as_deref(),
            Some("314"),
            "not the nested one"
        );
        assert_eq!(info.name.as_deref(), Some("Tool"));
    }

    #[test]
    fn binary_plists_parse_the_same() {
        let value = plist::Value::from_reader(Cursor::new(XML.as_bytes())).unwrap();
        let mut bin = Vec::new();
        value.to_writer_binary(&mut bin).unwrap();
        assert!(bin.starts_with(b"bplist00"));
        assert_eq!(
            parse_info_plist(&bin, 16).unwrap(),
            parse_info_plist(XML.as_bytes(), 16).unwrap()
        );
    }

    #[test]
    fn deep_garbage_and_non_dict_roots_are_refused() {
        let deep = format!(
            "<plist><dict><key>a</key>{}{}</dict></plist>",
            "<array>".repeat(10_000),
            "</array>".repeat(10_000)
        );
        assert!(matches!(
            parse_info_plist(deep.as_bytes(), 16),
            Err(ParseError::TooDeep)
        ));
        assert!(parse_info_plist(b"<plist><array/></plist>", 16).is_err());
        assert!(parse_info_plist(b"bplist00\xff\xff", 16).is_err());
        assert!(parse_info_plist(b"\x00\x01garbage", 16).is_err());
        for cut in (0..XML.len()).step_by(7) {
            let _ = parse_info_plist(&XML.as_bytes()[..cut], 16);
        }
    }

    #[test]
    fn bundle_paths_are_recognised() {
        let (plist, name) =
            info_plist_for(Path::new("/Applications/Tool.app/Contents/MacOS/Tool")).unwrap();
        assert_eq!(
            plist,
            Path::new("/Applications/Tool.app/Contents/Info.plist")
        );
        assert_eq!(name, "Tool");
        assert!(info_plist_for(Path::new("/usr/local/bin/tool")).is_none());
        assert!(info_plist_for(Path::new("/Applications/Tool/Contents/MacOS/Tool")).is_none());
    }
}
