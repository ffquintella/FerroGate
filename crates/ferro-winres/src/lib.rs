//! Embed the FerroGate icon into Windows executables at build time.
//!
//! Windows shows an executable's icon — in Explorer, Task Manager (including
//! the process behind the `mia` service), the Start menu and "Apps &
//! features" — from an `RT_GROUP_ICON` resource linked into the PE file. This
//! crate converts a `.ico` file into a compiled resource file (`.res`) in pure
//! Rust and tells Cargo to pass it to the linker, so no resource compiler
//! (rc.exe, llvm-rc, windres) is needed on the build host.
//!
//! Use it from a `build.rs`:
//!
//! ```no_run
//! ferro_winres::embed_icon_for_windows_bins("../mia-tray/dist/icons/ferrogate-mia.ico")
//!     .expect("embed the Windows icon");
//! ```
//!
//! On any target other than `windows`/`msvc` the call only registers the
//! `rerun-if-changed` hint and does nothing else.

#![forbid(unsafe_code)]

use std::fmt;
use std::path::{Path, PathBuf};

/// Win32 resource type `RT_ICON`.
const RT_ICON: u16 = 3;
/// Win32 resource type `RT_GROUP_ICON`.
const RT_GROUP_ICON: u16 = 14;
/// Resource ID of the icon group. Explorer uses the group with the lowest ID
/// as the application icon.
const GROUP_ID: u16 = 1;
/// `MOVEABLE | DISCARDABLE` (`0x1010`), the flags rc.exe gives icon images.
const ICON_FLAGS: u16 = 0x1010;
/// `MOVEABLE | PURE | DISCARDABLE` (`0x1030`), the flags rc.exe gives groups.
const GROUP_FLAGS: u16 = 0x1030;
/// `MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL)`.
const LANG_NEUTRAL: u16 = 0;
/// Size of an `ICONDIR` header (`.ico` file and group resource alike).
const ICONDIR_LEN: usize = 6;
/// Size of an `ICONDIRENTRY` in a `.ico` file.
const ICO_ENTRY_LEN: usize = 16;
/// Size of a `GRPICONDIRENTRY` in an `RT_GROUP_ICON` resource.
const GROUP_ENTRY_LEN: usize = 14;

/// Why an icon could not be turned into a resource file.
#[derive(Debug)]
pub enum Error {
    /// Reading the `.ico` or writing the `.res` failed.
    Io(std::io::Error),
    /// The `.ico` file is malformed; the message says how.
    InvalidIco(&'static str),
    /// A required Cargo build-script variable is missing.
    MissingEnv(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::InvalidIco(why) => write!(f, "invalid .ico file: {why}"),
            Self::MissingEnv(var) => {
                write!(f, "{var} is not set (not running under a build script?)")
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// One image of an `.ico` file.
#[derive(Debug, Clone, PartialEq, Eq)]
struct IconImage {
    width: u8,
    height: u8,
    color_count: u8,
    planes: u16,
    bit_count: u16,
    data: Vec<u8>,
}

fn u16_at(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

/// Parse a `.ico` file into its images, checking every offset against the
/// buffer (the input is a repository file, but a bad one must fail the build
/// with a message, not a panic).
fn parse_ico(ico: &[u8]) -> Result<Vec<IconImage>, Error> {
    if ico.len() < ICONDIR_LEN {
        return Err(Error::InvalidIco("shorter than its header"));
    }
    if u16_at(ico, 0) != 0 || u16_at(ico, 2) != 1 {
        return Err(Error::InvalidIco("not an icon (ICONDIR reserved/type)"));
    }
    let count = usize::from(u16_at(ico, 4));
    if count == 0 {
        return Err(Error::InvalidIco("contains no images"));
    }
    let entries_end = ICONDIR_LEN + count * ICO_ENTRY_LEN;
    if ico.len() < entries_end {
        return Err(Error::InvalidIco("directory runs past the end of the file"));
    }
    (0..count)
        .map(|i| {
            let e = ICONDIR_LEN + i * ICO_ENTRY_LEN;
            let size = usize::try_from(u32_at(ico, e + 8))
                .map_err(|_| Error::InvalidIco("image size overflows"))?;
            let offset = usize::try_from(u32_at(ico, e + 12))
                .map_err(|_| Error::InvalidIco("image offset overflows"))?;
            let end = offset
                .checked_add(size)
                .ok_or(Error::InvalidIco("image range overflows"))?;
            if size == 0 || offset < entries_end || end > ico.len() {
                return Err(Error::InvalidIco("image lies outside the file"));
            }
            Ok(IconImage {
                width: ico[e],
                height: ico[e + 1],
                color_count: ico[e + 2],
                planes: u16_at(ico, e + 4),
                bit_count: u16_at(ico, e + 6),
                data: ico[offset..end].to_vec(),
            })
        })
        .collect()
}

/// Append one resource (header with ordinal type and name, then the data,
/// padded to a 4-byte boundary) to a `.res` buffer.
fn push_resource(
    out: &mut Vec<u8>,
    kind: u16,
    id: u16,
    flags: u16,
    data: &[u8],
) -> Result<(), Error> {
    let data_len = u32::try_from(data.len()).map_err(|_| Error::InvalidIco("image too large"))?;
    out.extend_from_slice(&data_len.to_le_bytes()); // DataSize
    out.extend_from_slice(&32u32.to_le_bytes()); // HeaderSize
    out.extend_from_slice(&[0xFF, 0xFF]);
    out.extend_from_slice(&kind.to_le_bytes()); // TYPE (ordinal)
    out.extend_from_slice(&[0xFF, 0xFF]);
    out.extend_from_slice(&id.to_le_bytes()); // NAME (ordinal)
    out.extend_from_slice(&0u32.to_le_bytes()); // DataVersion
    out.extend_from_slice(&flags.to_le_bytes()); // MemoryFlags
    out.extend_from_slice(&LANG_NEUTRAL.to_le_bytes()); // LanguageId
    out.extend_from_slice(&0u32.to_le_bytes()); // Version
    out.extend_from_slice(&0u32.to_le_bytes()); // Characteristics
    out.extend_from_slice(data);
    while !out.len().is_multiple_of(4) {
        out.push(0);
    }
    Ok(())
}

/// Build a compiled resource file (`.res`) holding the icon of `ico` as icon
/// group 1, one `RT_ICON` per image (IDs 1..=n).
///
/// # Errors
///
/// [`Error::InvalidIco`] when `ico` is not a well-formed `.ico` file.
pub fn ico_to_res(ico: &[u8]) -> Result<Vec<u8>, Error> {
    let images = parse_ico(ico)?;
    let count = u16::try_from(images.len()).map_err(|_| Error::InvalidIco("too many images"))?;

    // A .res file starts with an empty 32-byte resource entry.
    let mut out = Vec::new();
    push_resource(&mut out, 0, 0, 0, &[])?;
    // push_resource wrote TYPE/NAME as 0xFFFF 0x0000, as the null entry wants.

    let mut group = Vec::with_capacity(ICONDIR_LEN + images.len() * GROUP_ENTRY_LEN);
    group.extend_from_slice(&0u16.to_le_bytes());
    group.extend_from_slice(&1u16.to_le_bytes());
    group.extend_from_slice(&count.to_le_bytes());
    for (id, image) in (1u16..).zip(&images) {
        push_resource(&mut out, RT_ICON, id, ICON_FLAGS, &image.data)?;
        let len =
            u32::try_from(image.data.len()).map_err(|_| Error::InvalidIco("image too large"))?;
        group.extend_from_slice(&[image.width, image.height, image.color_count, 0]);
        group.extend_from_slice(&image.planes.to_le_bytes());
        group.extend_from_slice(&image.bit_count.to_le_bytes());
        group.extend_from_slice(&len.to_le_bytes());
        group.extend_from_slice(&id.to_le_bytes());
    }
    push_resource(&mut out, RT_GROUP_ICON, GROUP_ID, GROUP_FLAGS, &group)?;
    Ok(out)
}

/// From a build script: when the crate is being built for a Windows MSVC
/// target, compile `ico` (relative to the crate's manifest directory) into a
/// `.res` file under `OUT_DIR` and link it into every binary of the package.
///
/// On other targets it only emits `rerun-if-changed`, so the call can stay
/// unconditional in `build.rs`.
///
/// # Errors
///
/// [`Error::MissingEnv`] outside a build script, [`Error::Io`] when the icon
/// cannot be read or the `.res` written, [`Error::InvalidIco`] for a bad icon.
pub fn embed_icon_for_windows_bins(ico: impl AsRef<Path>) -> Result<(), Error> {
    let manifest_dir =
        std::env::var_os("CARGO_MANIFEST_DIR").ok_or(Error::MissingEnv("CARGO_MANIFEST_DIR"))?;
    let ico_path = PathBuf::from(manifest_dir).join(ico);
    println!("cargo:rerun-if-changed={}", ico_path.display());

    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    if os != "windows" || env != "msvc" {
        return Ok(());
    }

    let res = ico_to_res(&std::fs::read(&ico_path)?)?;
    let out_dir = std::env::var_os("OUT_DIR").ok_or(Error::MissingEnv("OUT_DIR"))?;
    let res_path = PathBuf::from(out_dir).join("ferrogate-icon.res");
    std::fs::write(&res_path, res)?;
    // link.exe and lld-link both accept a .res file as an input.
    println!("cargo:rustc-link-arg-bins={}", res_path.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A two-image `.ico` with recognisable payloads.
    fn sample_ico() -> Vec<u8> {
        let a = b"\x89PNGimage-a".to_vec();
        let b = b"BMPimage-bb!".to_vec();
        let mut ico = vec![0, 0, 1, 0, 2, 0];
        let first = u32::try_from(ICONDIR_LEN + 2 * ICO_ENTRY_LEN).unwrap();
        for (w, data, off) in [
            (16u8, &a, first),
            (0u8, &b, first + u32::try_from(a.len()).unwrap()),
        ] {
            ico.extend_from_slice(&[w, w, 0, 0, 1, 0, 32, 0]);
            ico.extend_from_slice(&u32::try_from(data.len()).unwrap().to_le_bytes());
            ico.extend_from_slice(&off.to_le_bytes());
        }
        ico.extend_from_slice(&a);
        ico.extend_from_slice(&b);
        ico
    }

    /// Walk a `.res` buffer into (type, name, flags, data) tuples.
    fn entries(res: &[u8]) -> Vec<(u16, u16, u16, Vec<u8>)> {
        let mut at = 0;
        let mut out = Vec::new();
        while at < res.len() {
            let size = u32_at(res, at) as usize;
            assert_eq!(u32_at(res, at + 4), 32, "header size");
            assert_eq!(u16_at(res, at + 8), 0xFFFF);
            assert_eq!(u16_at(res, at + 12), 0xFFFF);
            let kind = u16_at(res, at + 10);
            let name = u16_at(res, at + 14);
            let flags = u16_at(res, at + 20);
            out.push((kind, name, flags, res[at + 32..at + 32 + size].to_vec()));
            at += (32 + size).div_ceil(4) * 4;
        }
        assert_eq!(at, res.len(), "entries end on the buffer's end");
        out
    }

    #[test]
    fn res_holds_each_image_and_a_group_pointing_at_them() {
        let res = ico_to_res(&sample_ico()).unwrap();
        let e = entries(&res);
        assert_eq!(e.len(), 4, "null entry + 2 icons + group");
        assert_eq!(e[0], (0, 0, 0, vec![]));
        assert_eq!(e[1], (RT_ICON, 1, ICON_FLAGS, b"\x89PNGimage-a".to_vec()));
        assert_eq!(e[2], (RT_ICON, 2, ICON_FLAGS, b"BMPimage-bb!".to_vec()));
        let (kind, id, flags, group) = &e[3];
        assert_eq!((*kind, *id, *flags), (RT_GROUP_ICON, GROUP_ID, GROUP_FLAGS));
        assert_eq!(group.len(), ICONDIR_LEN + 2 * GROUP_ENTRY_LEN);
        assert_eq!((u16_at(group, 2), u16_at(group, 4)), (1, 2));
        let second = ICONDIR_LEN + GROUP_ENTRY_LEN;
        assert_eq!(group[second], 0, "256-px image keeps width 0");
        assert_eq!(u16_at(group, second + 6), 32, "bit count");
        assert_eq!(u32_at(group, second + 8), 12, "bytes in resource");
        assert_eq!(u16_at(group, second + 12), 2, "points at RT_ICON 2");
    }

    #[test]
    fn malformed_icons_are_refused() {
        assert!(matches!(ico_to_res(b"\0\0\x01"), Err(Error::InvalidIco(_))));
        assert!(
            matches!(ico_to_res(&[0, 0, 2, 0, 1, 0]), Err(Error::InvalidIco(_))),
            "cursor, not icon"
        );
        assert!(
            matches!(ico_to_res(&[0, 0, 1, 0, 0, 0]), Err(Error::InvalidIco(_))),
            "no images"
        );
        let mut truncated = sample_ico();
        truncated.truncate(truncated.len() - 1);
        assert!(matches!(ico_to_res(&truncated), Err(Error::InvalidIco(_))));
        let mut bad_offset = sample_ico();
        bad_offset[18..22].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(ico_to_res(&bad_offset), Err(Error::InvalidIco(_))));
    }

    #[test]
    fn the_shipped_ferrogate_icon_converts() {
        let ico = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../mia-tray/dist/icons/ferrogate-mia.ico"
        ))
        .unwrap();
        let images = parse_ico(&ico).unwrap();
        assert!(images.len() >= 3, "16/32/48 px at least");
        let res = ico_to_res(&ico).unwrap();
        assert_eq!(entries(&res).len(), images.len() + 2);
    }
}
