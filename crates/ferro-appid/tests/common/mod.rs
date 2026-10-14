//! Minimal, hand-built fixture binaries: just enough structure for the
//! parsers under test (no toolchain or checked-in blobs needed).

#![allow(dead_code)] // each test file uses a subset of the builders.

/// Put a little- or big-endian integer at `off`.
fn put(buf: &mut [u8], off: usize, bytes: &[u8]) {
    buf[off..off + bytes.len()].copy_from_slice(bytes);
}

fn pad4(b: &mut Vec<u8>) {
    while !b.len().is_multiple_of(4) {
        b.push(0);
    }
}

/// An FDO `.note.package` note carrying `json`.
fn package_note(json: &str, le: bool) -> Vec<u8> {
    let u32b = |v: u32| if le { v.to_le_bytes() } else { v.to_be_bytes() };
    let desc_len = u32::try_from(json.len() + 1).unwrap();
    let mut n = Vec::new();
    n.extend(u32b(4));
    n.extend(u32b(desc_len));
    n.extend(u32b(0xcafe_1a7e));
    n.extend(b"FDO\0");
    n.extend(json.as_bytes());
    n.push(0);
    pad4(&mut n);
    n
}

/// ELF64 little-endian with a `.note.package` section (found through the
/// section headers).
pub(crate) fn elf64_with_package_note(json: &str) -> Vec<u8> {
    let note = package_note(json, true);
    let shstrtab = b"\0.note.package\0.shstrtab\0";
    let note_off = 64;
    let shstr_off = note_off + note.len();
    let sh_off = (shstr_off + shstrtab.len()).div_ceil(8) * 8;
    let mut f = vec![0u8; sh_off + 3 * 64];
    put(&mut f, 0, b"\x7fELF\x02\x01\x01");
    put(&mut f, 16, &2u16.to_le_bytes());
    put(&mut f, 18, &0x3eu16.to_le_bytes());
    put(&mut f, 20, &1u32.to_le_bytes());
    put(&mut f, 0x28, &(sh_off as u64).to_le_bytes());
    put(&mut f, 0x34, &64u16.to_le_bytes());
    put(&mut f, 0x3a, &64u16.to_le_bytes());
    put(&mut f, 0x3c, &3u16.to_le_bytes());
    put(&mut f, 0x3e, &2u16.to_le_bytes());
    put(&mut f, note_off, &note);
    put(&mut f, shstr_off, shstrtab);
    let sh = |i: usize| sh_off + i * 64;
    put(&mut f, sh(1), &1u32.to_le_bytes());
    put(&mut f, sh(1) + 4, &7u32.to_le_bytes());
    put(&mut f, sh(1) + 24, &(note_off as u64).to_le_bytes());
    put(&mut f, sh(1) + 32, &(note.len() as u64).to_le_bytes());
    put(&mut f, sh(1) + 48, &4u64.to_le_bytes());
    put(&mut f, sh(2), &15u32.to_le_bytes());
    put(&mut f, sh(2) + 4, &3u32.to_le_bytes());
    put(&mut f, sh(2) + 24, &(shstr_off as u64).to_le_bytes());
    put(&mut f, sh(2) + 32, &(shstrtab.len() as u64).to_le_bytes());
    f
}

/// ELF32 big-endian, stripped of section headers, with the note reachable
/// only through a `PT_NOTE` program header.
pub(crate) fn elf32be_with_program_note(json: &str) -> Vec<u8> {
    let note = package_note(json, false);
    let mut f = vec![0u8; 52 + 32];
    put(&mut f, 0, b"\x7fELF\x01\x02\x01");
    put(&mut f, 16, &2u16.to_be_bytes());
    put(&mut f, 0x1c, &52u32.to_be_bytes());
    put(&mut f, 0x28, &52u16.to_be_bytes());
    put(&mut f, 0x2a, &32u16.to_be_bytes());
    put(&mut f, 0x2c, &1u16.to_be_bytes());
    put(&mut f, 52, &4u32.to_be_bytes());
    put(&mut f, 56, &84u32.to_be_bytes());
    put(
        &mut f,
        68,
        &u32::try_from(note.len()).unwrap().to_be_bytes(),
    );
    put(&mut f, 80, &4u32.to_be_bytes());
    f.extend(note);
    f
}

/// One `VS_VERSIONINFO`-style block.
fn vs_block(key: &str, value: &[u8], value_len: u16, text: bool, children: &[Vec<u8>]) -> Vec<u8> {
    let mut b = vec![0u8; 6];
    for u in key.encode_utf16() {
        b.extend(u.to_le_bytes());
    }
    b.extend([0, 0]);
    pad4(&mut b);
    b.extend(value);
    for c in children {
        pad4(&mut b);
        b.extend(c);
    }
    let len = u16::try_from(b.len()).unwrap();
    put(&mut b, 0, &len.to_le_bytes());
    put(&mut b, 2, &value_len.to_le_bytes());
    put(&mut b, 4, &u16::from(text).to_le_bytes());
    b
}

fn vs_string(key: &str, value: &str) -> Vec<u8> {
    let mut v = Vec::new();
    for u in value.encode_utf16() {
        v.extend(u.to_le_bytes());
    }
    v.extend([0, 0]);
    let chars = u16::try_from(value.encode_utf16().count() + 1).unwrap();
    vs_block(key, &v, chars, true, &[])
}

/// A `VS_VERSIONINFO` with fixed product version 2.5.1.0 and, when
/// `strings`, a `StringFileInfo` table.
pub(crate) fn version_info(strings: &[(&str, &str)]) -> Vec<u8> {
    let mut fixed = vec![0u8; 52];
    put(&mut fixed, 0, &0xfeef_04bdu32.to_le_bytes());
    put(&mut fixed, 4, &0x0001_0000u32.to_le_bytes());
    put(&mut fixed, 8, &((2u32 << 16) | 5).to_le_bytes());
    put(&mut fixed, 12, &((1u32 << 16) | 7).to_le_bytes());
    put(&mut fixed, 16, &((2u32 << 16) | 5).to_le_bytes());
    put(&mut fixed, 20, &(1u32 << 16).to_le_bytes());
    let mut children = Vec::new();
    if !strings.is_empty() {
        let table: Vec<Vec<u8>> = strings.iter().map(|(k, v)| vs_string(k, v)).collect();
        let table = vs_block("040904b0", &[], 0, true, &table);
        children.push(vs_block("StringFileInfo", &[], 0, true, &[table]));
    }
    vs_block("VS_VERSION_INFO", &fixed, 52, false, &children)
}

/// A PE32+ image with one `.rsrc` section holding `version` (if any) and,
/// when `signed`, a certificate table.
pub(crate) fn pe(version: Option<&[u8]>, signed: bool) -> Vec<u8> {
    let mut rsrc = vec![0u8; 0x58];
    if let Some(vs) = version {
        put(&mut rsrc, 14, &1u16.to_le_bytes());
        put(&mut rsrc, 0x10, &16u32.to_le_bytes());
        put(&mut rsrc, 0x14, &(0x8000_0000u32 | 0x18).to_le_bytes());
        put(&mut rsrc, 0x18 + 14, &1u16.to_le_bytes());
        put(&mut rsrc, 0x28, &1u32.to_le_bytes());
        put(&mut rsrc, 0x2c, &(0x8000_0000u32 | 0x30).to_le_bytes());
        put(&mut rsrc, 0x30 + 14, &1u16.to_le_bytes());
        put(&mut rsrc, 0x40, &0x409u32.to_le_bytes());
        put(&mut rsrc, 0x44, &0x48u32.to_le_bytes());
        put(&mut rsrc, 0x48, &(0x1000u32 + 0x58).to_le_bytes());
        put(
            &mut rsrc,
            0x4c,
            &u32::try_from(vs.len()).unwrap().to_le_bytes(),
        );
        rsrc.extend(vs);
    }
    pad4(&mut rsrc);
    let rsrc_len = u32::try_from(rsrc.len()).unwrap();
    let mut f = vec![0u8; 0x200];
    put(&mut f, 0, b"MZ");
    put(&mut f, 0x3c, &0x40u32.to_le_bytes());
    put(&mut f, 0x40, b"PE\0\0");
    put(&mut f, 0x44, &0x8664u16.to_le_bytes());
    put(&mut f, 0x46, &1u16.to_le_bytes());
    put(&mut f, 0x54, &240u16.to_le_bytes());
    put(&mut f, 0x56, &0x22u16.to_le_bytes());
    let opt = 0x58;
    put(&mut f, opt, &0x20bu16.to_le_bytes());
    put(&mut f, opt + 108, &16u32.to_le_bytes());
    if version.is_some() {
        put(&mut f, opt + 112 + 16, &0x1000u32.to_le_bytes());
        put(&mut f, opt + 112 + 20, &rsrc_len.to_le_bytes());
    }
    let cert_off = 0x200 + rsrc.len();
    if signed {
        put(
            &mut f,
            opt + 112 + 32,
            &u32::try_from(cert_off).unwrap().to_le_bytes(),
        );
        put(&mut f, opt + 112 + 36, &16u32.to_le_bytes());
    }
    let sec = opt + 240;
    put(&mut f, sec, b".rsrc\0\0\0");
    put(&mut f, sec + 8, &rsrc_len.to_le_bytes());
    put(&mut f, sec + 12, &0x1000u32.to_le_bytes());
    put(&mut f, sec + 16, &rsrc_len.to_le_bytes());
    put(&mut f, sec + 20, &0x200u32.to_le_bytes());
    f.extend(rsrc);
    if signed {
        f.extend(16u32.to_le_bytes());
        f.extend(0x0200u16.to_le_bytes());
        f.extend(2u16.to_le_bytes());
        f.extend([0xab; 8]);
    }
    f
}

/// A thin 64-bit little-endian Mach-O executable, with or without
/// `LC_CODE_SIGNATURE`.
pub(crate) fn macho64(signed: bool) -> Vec<u8> {
    let mut cmds = Vec::new();
    cmds.extend(0x1bu32.to_le_bytes());
    cmds.extend(24u32.to_le_bytes());
    cmds.extend([0x11; 16]);
    if signed {
        cmds.extend(0x1du32.to_le_bytes());
        cmds.extend(16u32.to_le_bytes());
        cmds.extend(4096u32.to_le_bytes());
        cmds.extend(64u32.to_le_bytes());
    }
    let mut f = vec![0u8; 32];
    put(&mut f, 0, &[0xcf, 0xfa, 0xed, 0xfe]);
    put(&mut f, 4, &0x0100_000cu32.to_le_bytes());
    put(&mut f, 12, &2u32.to_le_bytes());
    put(&mut f, 16, &(1 + u32::from(signed)).to_le_bytes());
    put(
        &mut f,
        20,
        &u32::try_from(cmds.len()).unwrap().to_le_bytes(),
    );
    f.extend(cmds);
    f.extend([0x90; 64]);
    f
}

/// A universal binary of `slices`, each at a 4 KiB-aligned offset.
pub(crate) fn fat(slices: &[Vec<u8>]) -> Vec<u8> {
    let mut f = vec![0u8; 8 + 20 * slices.len()];
    put(&mut f, 0, &0xcafe_babeu32.to_be_bytes());
    put(
        &mut f,
        4,
        &u32::try_from(slices.len()).unwrap().to_be_bytes(),
    );
    let mut offset = 4096usize;
    let mut body = Vec::new();
    for (i, s) in slices.iter().enumerate() {
        let e = 8 + i * 20;
        put(&mut f, e, &0x0100_000cu32.to_be_bytes());
        put(&mut f, e + 8, &u32::try_from(offset).unwrap().to_be_bytes());
        put(
            &mut f,
            e + 12,
            &u32::try_from(s.len()).unwrap().to_be_bytes(),
        );
        put(&mut f, e + 16, &12u32.to_be_bytes());
        body.push((offset, s.clone()));
        offset = (offset + s.len()).div_ceil(4096) * 4096;
    }
    for (at, s) in body {
        f.resize(at, 0);
        f.extend(s);
    }
    f
}
