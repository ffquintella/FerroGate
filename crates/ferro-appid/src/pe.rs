//! PE version resource and certificate table (F19 §4.3 version sources 2
//! and 1, §4.4 signature presence).
//!
//! The parser follows the headers to the resource directory, walks exactly
//! three levels (`RT_VERSION` → first name → first language) to the
//! `VS_VERSIONINFO` block, and reads `StringFileInfo` and
//! `VS_FIXEDFILEINFO`. Every offset is checked; every read goes through the
//! bounded [`Source`]. Nothing outside the headers, the resource directory
//! entries it follows and the version block is read.

use std::io::{Read, Seek};

use crate::bytes::{align_up, Fields, ParseError, Source};

/// `RT_VERSION` resource type id.
const RT_VERSION: u32 = 16;
/// Largest version resource read.
const MAX_VERSION_RESOURCE: usize = 1024 * 1024;
/// Most entries one resource directory may declare.
const MAX_DIR_ENTRIES: usize = 4096;
/// Most sections read from the section table.
const MAX_SECTIONS: usize = 96;
/// Most `VS_VERSIONINFO` blocks visited.
const MAX_BLOCKS: usize = 4096;
const FIXED_FILE_INFO_SIGNATURE: u32 = 0xfeef_04bd;
const DIR_RESOURCE: usize = 2;
const DIR_SECURITY: usize = 4;

/// What the version resource declares.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct PeVersion {
    pub(crate) product_version: Option<String>,
    pub(crate) file_version: Option<String>,
    pub(crate) product_name: Option<String>,
    pub(crate) company_name: Option<String>,
    /// `dwProductVersionMS/LS` as `a.b.c.d`.
    pub(crate) fixed_product_version: Option<String>,
}

/// Facts read from a PE file.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct PeFacts {
    /// The version resource, when present and well formed.
    pub(crate) version: Option<PeVersion>,
    /// An Authenticode certificate table is present (validity is decided by
    /// `ferro_winauth`, not here).
    pub(crate) has_certificate_table: bool,
}

struct Section {
    virtual_address: u32,
    virtual_size: u32,
    raw_size: u32,
    raw_pointer: u32,
}

/// Read the PE facts of the file behind `src`.
pub(crate) fn facts<R: Read + Seek>(src: &mut Source<'_, R>) -> Result<PeFacts, ParseError> {
    let dos = src.read_at(0, 64)?;
    if !dos.starts_with(b"MZ") {
        return Err(ParseError::Malformed("dos header"));
    }
    let pe_at = u64::from(Fields::le(&dos).u32(0x3c)?);
    let coff = src.read_at(pe_at, 24)?;
    if !coff.starts_with(b"PE\0\0") {
        return Err(ParseError::Malformed("pe signature"));
    }
    let c = Fields::le(&coff);
    let sections = usize::from(c.u16(6)?);
    let opt_size = usize::from(c.u16(20)?);
    if sections > MAX_SECTIONS {
        return Err(ParseError::Malformed("section count"));
    }
    let opt = src.read_at(pe_at + 24, opt_size)?;
    let o = Fields::le(&opt);
    let (count_at, dirs_at) = match o.u16(0)? {
        0x10b => (92, 96),
        0x20b => (108, 112),
        _ => return Err(ParseError::Malformed("optional header magic")),
    };
    let dir_count = usize::try_from(o.u32(count_at)?).unwrap_or(0).min(16);
    let dir = |i: usize| -> Result<(u32, u32), ParseError> {
        if i >= dir_count {
            return Ok((0, 0));
        }
        Ok((o.u32(dirs_at + i * 8)?, o.u32(dirs_at + i * 8 + 4)?))
    };
    let (res_rva, res_size) = dir(DIR_RESOURCE)?;
    let (_, cert_size) = dir(DIR_SECURITY)?;

    let table = src.read_at(pe_at + 24 + opt_size as u64, sections * 40)?;
    let t = Fields::le(&table);
    let mut secs = Vec::with_capacity(sections);
    for i in 0..sections {
        let b = i * 40;
        secs.push(Section {
            virtual_size: t.u32(b + 8)?,
            virtual_address: t.u32(b + 12)?,
            raw_size: t.u32(b + 16)?,
            raw_pointer: t.u32(b + 20)?,
        });
    }

    let version = if res_rva != 0 && res_size != 0 {
        version_resource(src, &secs, res_rva, res_size)?
    } else {
        None
    };
    Ok(PeFacts {
        version,
        has_certificate_table: cert_size > 0,
    })
}

/// File offset of `rva`, if it lies in a section's raw data.
fn rva_to_offset(secs: &[Section], rva: u32) -> Option<u64> {
    secs.iter().find_map(|s| {
        let delta = rva.checked_sub(s.virtual_address)?;
        let span = s.virtual_size.max(s.raw_size);
        (delta < span && delta < s.raw_size).then(|| u64::from(s.raw_pointer) + u64::from(delta))
    })
}

/// Follow `RT_VERSION` → first name → first language to the version block.
fn version_resource<R: Read + Seek>(
    src: &mut Source<'_, R>,
    secs: &[Section],
    res_rva: u32,
    res_size: u32,
) -> Result<Option<PeVersion>, ParseError> {
    let base = rva_to_offset(secs, res_rva).ok_or(ParseError::Malformed("resource rva"))?;
    // Level 1: the RT_VERSION entry; levels 2 and 3: the first entry.
    let mut rel = 0u32;
    for level in 0..3 {
        let wanted = (level == 0).then_some(RT_VERSION);
        let Some(target) = dir_entry(src, base, res_size, rel, wanted)? else {
            return Ok(None);
        };
        let is_dir = target & 0x8000_0000 != 0;
        if (level < 2 && !is_dir) || (level == 2 && is_dir) {
            return Err(ParseError::Malformed("resource tree"));
        }
        rel = target & 0x7fff_ffff;
    }
    // IMAGE_RESOURCE_DATA_ENTRY: OffsetToData (an RVA), Size.
    if rel.checked_add(16).is_none_or(|end| end > res_size) {
        return Err(ParseError::Malformed("resource data entry"));
    }
    let entry = src.read_at(base + u64::from(rel), 16)?;
    let e = Fields::le(&entry);
    let (data_rva, size) = (e.u32(0)?, usize::try_from(e.u32(4)?).unwrap_or(usize::MAX));
    if size > MAX_VERSION_RESOURCE {
        return Err(ParseError::Malformed("version resource too large"));
    }
    let at = rva_to_offset(secs, data_rva).ok_or(ParseError::Malformed("version rva"))?;
    let data = src.read_at(at, size)?;
    parse_version_info(&data).map(Some)
}

/// Find an entry of the resource directory at `rel`: the id-entry `id` when
/// given, else the first entry. Returns its `OffsetToData`.
fn dir_entry<R: Read + Seek>(
    src: &mut Source<'_, R>,
    base: u64,
    res_size: u32,
    rel: u32,
    id: Option<u32>,
) -> Result<Option<u32>, ParseError> {
    if rel.checked_add(16).is_none_or(|end| end > res_size) {
        return Err(ParseError::Malformed("resource directory"));
    }
    let head = src.read_at(base + u64::from(rel), 16)?;
    let h = Fields::le(&head);
    let entries = usize::from(h.u16(12)?) + usize::from(h.u16(14)?);
    if entries == 0 {
        return Ok(None);
    }
    if entries > MAX_DIR_ENTRIES {
        return Err(ParseError::Malformed("resource directory"));
    }
    let len = u32::try_from(entries * 8).map_err(|_| ParseError::TooMuchData)?;
    if (rel + 16).checked_add(len).is_none_or(|end| end > res_size) {
        return Err(ParseError::Malformed("resource directory"));
    }
    let list = src.read_at(base + u64::from(rel) + 16, entries * 8)?;
    let l = Fields::le(&list);
    for i in 0..entries {
        let (name, target) = (l.u32(i * 8)?, l.u32(i * 8 + 4)?);
        let matches = match id {
            // Id entries have the high bit of the name clear.
            Some(want) => name & 0x8000_0000 == 0 && name == want,
            None => true,
        };
        if matches {
            return Ok(Some(target));
        }
    }
    Ok(None)
}

/// One `VS_VERSIONINFO`-style block.
struct Block<'b> {
    key: String,
    /// The value bytes (binary) or the UTF-16 text up to its terminator.
    value: &'b [u8],
    text: bool,
    children: (usize, usize),
}

/// Parse the block at `off`, bounded by `end`.
fn block(buf: &[u8], off: usize, end: usize) -> Result<(Block<'_>, usize), ParseError> {
    let f = Fields::le(buf);
    let length = usize::from(f.u16(off)?);
    let value_len = usize::from(f.u16(off + 2)?);
    let text = f.u16(off + 4)? == 1;
    let block_end = off.checked_add(length).ok_or(ParseError::Truncated)?;
    if length < 6 || block_end > end {
        return Err(ParseError::Malformed("version block"));
    }
    let (key, key_end) = utf16z(&buf[..block_end], off + 6)?;
    let value_at = align_up(key_end, 4)?.min(block_end);
    let value_bytes = if text {
        value_len.saturating_mul(2)
    } else {
        value_len
    };
    let value_end = value_at.saturating_add(value_bytes).min(block_end);
    let value = &buf[value_at..value_end];
    let children_at = align_up(value_end, 4)?.min(block_end);
    let next = align_up(block_end, 4)?.min(end);
    Ok((
        Block {
            key,
            value,
            text,
            children: (children_at, block_end),
        },
        next,
    ))
}

/// A NUL-terminated UTF-16LE string at `off`; returns it and the offset
/// after its terminator.
fn utf16z(buf: &[u8], off: usize) -> Result<(String, usize), ParseError> {
    let f = Fields::le(buf);
    let mut units = Vec::new();
    let mut at = off;
    loop {
        let u = f.u16(at)?;
        at += 2;
        if u == 0 {
            break;
        }
        units.push(u);
        if units.len() > 512 {
            return Err(ParseError::Malformed("version key"));
        }
    }
    Ok((String::from_utf16_lossy(&units), at))
}

/// Text value of a string block, up to its terminator.
fn text_value(value: &[u8]) -> String {
    let (pairs, _) = value.as_chunks::<2>();
    let units: Vec<u16> = pairs
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .take_while(|u| *u != 0)
        .collect();
    String::from_utf16_lossy(&units)
}

/// Parse a `VS_VERSIONINFO` resource.
pub(crate) fn parse_version_info(buf: &[u8]) -> Result<PeVersion, ParseError> {
    let (root, _) = block(buf, 0, buf.len())?;
    if root.key != "VS_VERSION_INFO" {
        return Err(ParseError::Malformed("version root"));
    }
    let mut out = PeVersion::default();
    if root.value.len() >= 52 {
        let v = Fields::le(root.value);
        if v.u32(0)? == FIXED_FILE_INFO_SIGNATURE {
            let (ms, ls) = (v.u32(16)?, v.u32(20)?);
            out.fixed_product_version = Some(format!(
                "{}.{}.{}.{}",
                ms >> 16,
                ms & 0xffff,
                ls >> 16,
                ls & 0xffff
            ));
        }
    }
    let mut visited = 0usize;
    // Children of the root: StringFileInfo / VarFileInfo.
    let (mut at, end) = root.children;
    while at < end {
        let (info, next) = block(buf, at, end)?;
        visited += 1;
        if info.key == "StringFileInfo" {
            // Children: one StringTable per language; then its strings.
            let (mut t_at, t_end) = info.children;
            while t_at < t_end {
                let (table, t_next) = block(buf, t_at, t_end)?;
                let (mut s_at, s_end) = table.children;
                while s_at < s_end {
                    let (s, s_next) = block(buf, s_at, s_end)?;
                    visited += 1;
                    if visited > MAX_BLOCKS {
                        return Err(ParseError::Malformed("version blocks"));
                    }
                    if s.text {
                        let slot = match s.key.as_str() {
                            "ProductVersion" => Some(&mut out.product_version),
                            "FileVersion" => Some(&mut out.file_version),
                            "ProductName" => Some(&mut out.product_name),
                            "CompanyName" => Some(&mut out.company_name),
                            _ => None,
                        };
                        if let Some(slot) = slot {
                            if slot.is_none() {
                                *slot = Some(text_value(s.value));
                            }
                        }
                    }
                    s_at = advance(s_at, s_next)?;
                }
                t_at = advance(t_at, t_next)?;
            }
        }
        at = advance(at, next)?;
    }
    Ok(out)
}

/// Move to the next sibling, refusing a block that does not advance.
fn advance(at: usize, next: usize) -> Result<usize, ParseError> {
    if next <= at {
        return Err(ParseError::Malformed("version block length"));
    }
    Ok(next)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_length_and_overlong_blocks_are_refused() {
        assert!(parse_version_info(&[0, 0, 0, 0, 0, 0]).is_err());
        assert!(parse_version_info(&[0xff, 0xff, 0, 0, 1, 0, b'V', 0]).is_err());
        assert!(parse_version_info(&[]).is_err());
    }
}
