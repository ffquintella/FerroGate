//! ELF `.note.package` (F19 §4.3, version source 5).
//!
//! The FDO "package metadata for core files" note: owner `FDO`, type
//! `0xcafe1a7e`, a JSON descriptor `{"type", "name", "version", …}` of at most
//! 4 KiB. Notes are found through `SHT_NOTE` sections and, for stripped
//! binaries, `PT_NOTE` program headers. Only headers and note regions are
//! read, through the bounded [`Source`].

use std::io::{Read, Seek};

use crate::bytes::{align_up, to_usize, Fields, ParseError, Source};

/// FDO package-metadata note type.
const NT_FDO_PACKAGING_METADATA: u32 = 0xcafe_1a7e;
/// Largest package-metadata descriptor (F19 §4.3).
const MAX_DESC: usize = 4096;
/// Largest note region read.
const MAX_REGION: usize = 64 * 1024;
/// Most note regions examined.
const MAX_REGIONS: usize = 64;
/// Most section or program headers read.
const MAX_HEADERS: usize = 4096;
const SHT_NOTE: u32 = 7;
const PT_NOTE: u32 = 4;

/// Package metadata declared in an ELF note.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct PackageNote {
    pub(crate) name: Option<String>,
    pub(crate) version: Option<String>,
}

/// Layout of one ELF class.
struct Layout {
    little_endian: bool,
    is64: bool,
}

impl Layout {
    fn word(&self, f: &Fields<'_>, off32: usize, off64: usize) -> Result<u64, ParseError> {
        if self.is64 {
            f.u64(off64)
        } else {
            f.u32(off32).map(u64::from)
        }
    }
}

/// A note region: file offset, size, alignment.
type Region = (u64, u64, u64);

/// Find the package note of the ELF file behind `src`, if any.
pub(crate) fn package_note<R: Read + Seek>(
    src: &mut Source<'_, R>,
) -> Result<Option<PackageNote>, ParseError> {
    let head = src.read_prefix(0, 64)?;
    if !head.starts_with(b"\x7fELF") {
        return Err(ParseError::Malformed("elf header"));
    }
    let layout = Layout {
        is64: match head.get(4) {
            Some(1) => false,
            Some(2) => true,
            _ => return Err(ParseError::Malformed("elf class")),
        },
        little_endian: match head.get(5) {
            Some(1) => true,
            Some(2) => false,
            _ => return Err(ParseError::Malformed("elf data encoding")),
        },
    };
    let f = Fields::new(&head, layout.little_endian);
    let (phoff, shoff) = (layout.word(&f, 0x1c, 0x20)?, layout.word(&f, 0x20, 0x28)?);
    let (ph_at, sh_at) = if layout.is64 {
        (0x36, 0x3a)
    } else {
        (0x2a, 0x2e)
    };
    let (phentsize, phnum) = (f.u16(ph_at)?, f.u16(ph_at + 2)?);
    let (shentsize, shnum) = (f.u16(sh_at)?, f.u16(sh_at + 2)?);

    let mut regions: Vec<Region> = Vec::new();
    // Section headers: sh_type, sh_offset, sh_size, sh_addralign.
    let (sh_size, sh_fields) = if layout.is64 {
        (64, (4, 24, 32, 48))
    } else {
        (40, (4, 16, 20, 32))
    };
    collect_regions(
        src,
        &layout,
        shoff,
        shentsize,
        shnum,
        sh_size,
        SHT_NOTE,
        sh_fields,
        &mut regions,
    )?;
    // Program headers: p_type, p_offset, p_filesz, p_align.
    let (ph_size, ph_fields) = if layout.is64 {
        (56, (0, 8, 32, 48))
    } else {
        (32, (0, 4, 16, 28))
    };
    collect_regions(
        src,
        &layout,
        phoff,
        phentsize,
        phnum,
        ph_size,
        PT_NOTE,
        ph_fields,
        &mut regions,
    )?;

    for (offset, size, align) in regions.into_iter().take(MAX_REGIONS) {
        src.budget.check_time()?;
        let size = to_usize(size)?.min(MAX_REGION);
        let data = src.read_at(offset, size)?;
        let note_align = if align == 8 { 8 } else { 4 };
        if let Some(desc) = find_note(&data, layout.little_endian, note_align)? {
            return parse_descriptor(desc, src.budget.max_depth).map(Some);
        }
    }
    Ok(None)
}

/// Add the regions of the header table at `table_off` whose type is
/// `wanted`. `fields` are the offsets of (type, offset, size, align).
#[allow(clippy::too_many_arguments)]
fn collect_regions<R: Read + Seek>(
    src: &mut Source<'_, R>,
    layout: &Layout,
    table_off: u64,
    entsize: u16,
    count: u16,
    min_entsize: usize,
    wanted: u32,
    fields: (usize, usize, usize, usize),
    out: &mut Vec<Region>,
) -> Result<(), ParseError> {
    // 0 means "none"; 0xffff (PN_XNUM / SHN_XINDEX) defers the count to
    // section 0, which no binary needs for its notes: skip the table.
    if table_off == 0 || count == 0 || count == 0xffff {
        return Ok(());
    }
    let entsize = usize::from(entsize);
    let count = usize::from(count);
    if entsize < min_entsize || count > MAX_HEADERS {
        return Err(ParseError::Malformed("elf header table"));
    }
    let table = src.read_at(table_off, entsize * count)?;
    for i in 0..count {
        let entry = Fields::new(&table[i * entsize..(i + 1) * entsize], layout.little_endian);
        let (t, o, s, a) = fields;
        if entry.u32(t)? != wanted {
            continue;
        }
        let (offset, size, align) = if layout.is64 {
            (entry.u64(o)?, entry.u64(s)?, entry.u64(a)?)
        } else {
            (
                u64::from(entry.u32(o)?),
                u64::from(entry.u32(s)?),
                u64::from(entry.u32(a)?),
            )
        };
        if size > 0 && !out.contains(&(offset, size, align)) {
            out.push((offset, size, align));
        }
    }
    Ok(())
}

/// The descriptor of the first FDO package note in a note region.
fn find_note(data: &[u8], little_endian: bool, align: usize) -> Result<Option<&[u8]>, ParseError> {
    let f = Fields::new(data, little_endian);
    let mut off = 0usize;
    while data.len().saturating_sub(off) >= 12 {
        let namesz = to_usize(u64::from(f.u32(off)?))?;
        let descsz = to_usize(u64::from(f.u32(off + 4)?))?;
        let kind = f.u32(off + 8)?;
        let name_at = off + 12;
        let desc_at = name_at
            .checked_add(align_up(namesz, align)?)
            .ok_or(ParseError::Truncated)?;
        let next = desc_at
            .checked_add(align_up(descsz, align)?)
            .ok_or(ParseError::Truncated)?;
        let name = f.slice(name_at, namesz)?;
        if kind == NT_FDO_PACKAGING_METADATA && name == b"FDO\0" {
            if descsz > MAX_DESC {
                return Err(ParseError::Malformed("package note too large"));
            }
            return Ok(Some(f.slice(desc_at, descsz)?));
        }
        if next <= off {
            return Err(ParseError::Malformed("elf note"));
        }
        off = next;
    }
    Ok(None)
}

/// Parse the JSON descriptor (NUL-padded), bounding its nesting first.
fn parse_descriptor(desc: &[u8], max_depth: usize) -> Result<PackageNote, ParseError> {
    let end = desc.iter().position(|b| *b == 0).unwrap_or(desc.len());
    let json = &desc[..end];
    if json_depth(json) > max_depth {
        return Err(ParseError::TooDeep);
    }
    let value: serde_json::Value =
        serde_json::from_slice(json).map_err(|_| ParseError::Malformed("package note json"))?;
    let obj = value
        .as_object()
        .ok_or(ParseError::Malformed("package note json"))?;
    let text = |k: &str| {
        obj.get(k)
            .and_then(serde_json::Value::as_str)
            .map(str::to_string)
    };
    Ok(PackageNote {
        name: text("name"),
        version: text("version"),
    })
}

/// Maximum nesting of JSON arrays and objects, ignoring brackets in strings.
fn json_depth(json: &[u8]) -> usize {
    let (mut depth, mut max, mut in_string, mut escaped) = (0usize, 0usize, false, false);
    for &b in json {
        if in_string {
            match (escaped, b) {
                (true, _) => escaped = false,
                (false, b'\\') => escaped = true,
                (false, b'"') => in_string = false,
                _ => {}
            }
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'{' | b'[' => {
                depth += 1;
                max = max.max(depth);
            }
            b'}' | b']' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    max
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_depth_ignores_strings() {
        assert_eq!(json_depth(br#"{"a":"[[[{{"}"#), 1);
        assert_eq!(json_depth(br#"{"a":[{"b":[]}]}"#), 4);
        assert_eq!(json_depth(br#"{"a":"\"[["}"#), 1);
    }

    #[test]
    fn deep_or_bad_descriptors_are_refused() {
        let deep = format!("{}{}", "[".repeat(40), "]".repeat(40));
        assert!(matches!(
            parse_descriptor(deep.as_bytes(), 16),
            Err(ParseError::TooDeep)
        ));
        assert!(parse_descriptor(b"[1,2]", 16).is_err());
        assert!(parse_descriptor(b"{nope", 16).is_err());
        let ok = parse_descriptor(
            b"{\"type\":\"deb\",\"name\":\"tool\",\"version\":\"1.2\"}\0\0",
            16,
        )
        .unwrap();
        assert_eq!(ok.name.as_deref(), Some("tool"));
        assert_eq!(ok.version.as_deref(), Some("1.2"));
    }

    #[test]
    fn note_walking_rejects_overflowing_sizes() {
        let mut data = Vec::new();
        data.extend_from_slice(&u32::MAX.to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&1u32.to_le_bytes());
        assert!(find_note(&data, true, 4).is_err());
    }
}
