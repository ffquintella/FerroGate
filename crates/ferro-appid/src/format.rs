//! Executable format detection from magic numbers (F19 §2 `format`).

use std::io::{Read, Seek};

use crate::bytes::{Budget, Fields, ParseError, Source};
use crate::limits::Limits;

/// Executable format codes stored in the ledger and carried in
/// `AppRequestDoc`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BinaryFormat {
    /// ELF (Linux and other Unix systems).
    Elf,
    /// Mach-O, thin or universal (macOS).
    MachO,
    /// PE / COFF (Windows).
    Pe,
    /// Anything else (scripts, unknown formats).
    Other,
}

impl BinaryFormat {
    /// Wire and ledger code: 1 elf, 2 macho, 3 pe, 9 other.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Elf => 1,
            Self::MachO => 2,
            Self::Pe => 3,
            Self::Other => 9,
        }
    }

    /// The format of a code, if known.
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Elf),
            2 => Some(Self::MachO),
            3 => Some(Self::Pe),
            9 => Some(Self::Other),
            _ => None,
        }
    }
}

/// Mach-O magic numbers as read big-endian from the first four bytes.
const MACHO_MAGICS: [u32; 4] = [0xfeed_face, 0xcefa_edfe, 0xfeed_facf, 0xcffa_edfe];
/// Universal (fat) magic numbers, 32- and 64-bit offsets.
pub(crate) const FAT_MAGIC: u32 = 0xcafe_babe;
pub(crate) const FAT_MAGIC_64: u32 = 0xcafe_babf;
/// Most slices a universal binary may declare. Java class files share the
/// `0xcafebabe` magic but carry their class-file version (45 and up) there.
pub(crate) const MAX_FAT_ARCHS: u32 = 20;

/// Detect the format of `data` (the whole file or its beginning).
#[must_use]
pub fn detect(data: &[u8]) -> BinaryFormat {
    let len = data.len() as u64;
    let mut budget = Budget::new(&Limits::default());
    let mut cursor = std::io::Cursor::new(data);
    let mut src = Source::new(&mut cursor, len, &mut budget);
    detect_in(&mut src).unwrap_or(BinaryFormat::Other)
}

/// Detect the format of the file behind `src`.
pub(crate) fn detect_in<R: Read + Seek>(
    src: &mut Source<'_, R>,
) -> Result<BinaryFormat, ParseError> {
    let head = src.read_prefix(0, 64)?;
    let f = Fields::new(&head, false);
    let Ok(magic) = f.u32(0) else {
        return Ok(BinaryFormat::Other);
    };
    if head.starts_with(b"\x7fELF") {
        return Ok(BinaryFormat::Elf);
    }
    if MACHO_MAGICS.contains(&magic) {
        return Ok(BinaryFormat::MachO);
    }
    if (magic == FAT_MAGIC || magic == FAT_MAGIC_64)
        && f.u32(4).is_ok_and(|n| (1..=MAX_FAT_ARCHS).contains(&n))
    {
        return Ok(BinaryFormat::MachO);
    }
    if head.starts_with(b"MZ") {
        let e_lfanew = Fields::le(&head).u32(0x3c)?;
        if src
            .read_at(u64::from(e_lfanew), 4)
            .is_ok_and(|sig| sig == b"PE\0\0")
        {
            return Ok(BinaryFormat::Pe);
        }
    }
    Ok(BinaryFormat::Other)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn magics_are_recognised() {
        assert_eq!(detect(b"\x7fELF\x02\x01\x01"), BinaryFormat::Elf);
        assert_eq!(
            detect(&[0xcf, 0xfa, 0xed, 0xfe, 0, 0, 0, 0]),
            BinaryFormat::MachO
        );
        assert_eq!(
            detect(&[0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 2]),
            BinaryFormat::MachO
        );
        // A Java class file (major version 52) is not a universal binary.
        assert_eq!(
            detect(&[0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 52]),
            BinaryFormat::Other
        );
        assert_eq!(detect(b"#!/bin/sh\n"), BinaryFormat::Other);
        assert_eq!(detect(b""), BinaryFormat::Other);
        // MZ without a PE header (or with e_lfanew out of range) is not PE.
        let mut mz = vec![0u8; 64];
        mz[..2].copy_from_slice(b"MZ");
        mz[0x3c..0x40].copy_from_slice(&0xffff_fff0u32.to_le_bytes());
        assert_eq!(detect(&mz), BinaryFormat::Other);
        let mut pe = vec![0u8; 0x48];
        pe[..2].copy_from_slice(b"MZ");
        pe[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
        pe[0x40..0x44].copy_from_slice(b"PE\0\0");
        assert_eq!(detect(&pe), BinaryFormat::Pe);
    }

    #[test]
    fn codes_round_trip() {
        for f in [
            BinaryFormat::Elf,
            BinaryFormat::MachO,
            BinaryFormat::Pe,
            BinaryFormat::Other,
        ] {
            assert_eq!(BinaryFormat::from_code(f.code()), Some(f));
        }
        assert_eq!(BinaryFormat::from_code(4), None);
    }
}
