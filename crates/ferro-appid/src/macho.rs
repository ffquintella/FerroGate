//! Mach-O code-signature presence (F19 §4.4). Validity is decided by the
//! macOS verifier (`ferro-macsign`, Phase 2); here only the load commands
//! are read, through the bounded [`Source`], to see whether every slice
//! carries an `LC_CODE_SIGNATURE`.

use std::io::{Read, Seek};

use crate::bytes::{to_usize, Fields, ParseError, Source};
use crate::format::{FAT_MAGIC, FAT_MAGIC_64, MAX_FAT_ARCHS};

const LC_CODE_SIGNATURE: u32 = 0x1d;
/// Most load commands walked per slice.
const MAX_COMMANDS: usize = 4096;
/// Largest load-command area read per slice.
const MAX_COMMANDS_BYTES: usize = 4 * 1024 * 1024;

/// Whether every slice of the Mach-O file behind `src` has a code signature.
pub(crate) fn has_code_signature<R: Read + Seek>(
    src: &mut Source<'_, R>,
) -> Result<bool, ParseError> {
    let head = src.read_prefix(0, 8)?;
    let magic = Fields::new(&head, false).u32(0)?;
    if magic != FAT_MAGIC && magic != FAT_MAGIC_64 {
        return slice_signed(src, 0);
    }
    let count = Fields::new(&head, false).u32(4)?;
    if count == 0 || count > MAX_FAT_ARCHS {
        return Err(ParseError::Malformed("fat header"));
    }
    let entry = if magic == FAT_MAGIC_64 { 32 } else { 20 };
    let count = to_usize(u64::from(count))?;
    let archs = src.read_at(8, count * entry)?;
    let a = Fields::new(&archs, false);
    for i in 0..count {
        let offset = if magic == FAT_MAGIC_64 {
            a.u64(i * entry + 8)?
        } else {
            u64::from(a.u32(i * entry + 8)?)
        };
        if !slice_signed(src, offset)? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Whether the thin Mach-O image at `offset` has `LC_CODE_SIGNATURE`.
fn slice_signed<R: Read + Seek>(src: &mut Source<'_, R>, offset: u64) -> Result<bool, ParseError> {
    let head = src.read_at(offset, 32)?;
    let (little_endian, header_size) = match Fields::new(&head, false).u32(0)? {
        0xfeed_face => (false, 28),
        0xcefa_edfe => (true, 28),
        0xfeed_facf => (false, 32),
        0xcffa_edfe => (true, 32),
        _ => return Err(ParseError::Malformed("mach-o slice")),
    };
    let h = Fields::new(&head, little_endian);
    let ncmds = to_usize(u64::from(h.u32(16)?))?;
    let sizeofcmds = to_usize(u64::from(h.u32(20)?))?;
    if ncmds > MAX_COMMANDS || sizeofcmds > MAX_COMMANDS_BYTES {
        return Err(ParseError::Malformed("load commands"));
    }
    let cmds = src.read_at(offset + header_size, sizeofcmds)?;
    let c = Fields::new(&cmds, little_endian);
    let mut at = 0usize;
    for _ in 0..ncmds {
        let cmd = c.u32(at)?;
        let size = to_usize(u64::from(c.u32(at + 4)?))?;
        if size < 8 || size % 4 != 0 {
            return Err(ParseError::Malformed("load command size"));
        }
        if cmd == LC_CODE_SIGNATURE {
            return Ok(true);
        }
        at = at.checked_add(size).ok_or(ParseError::Truncated)?;
    }
    Ok(false)
}
