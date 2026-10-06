//! Owner and DACL policy for FerroGate's administrator-only directories and
//! files (the MIA system configuration directory, `%ProgramData%\FerroGate`).
//!
//! Pure data, parsing and decision logic, no FFI, so it compiles (and is
//! unit-tested) on every platform: the binary SID / ACL / ACE parsers
//! ([`parse_sid`], [`parse_acl`], [`parse_ace`]), the object-kind check
//! ([`check_object`]) and the ownership/DACL policy ([`check_admin_only`]). The
//! Windows FFI that opens an object without following reparse points, reads
//! its owner, DACL and link count, and applies [`ADMIN_ONLY_DIR_SDDL`] through
//! the same handle lives in `file_security` (`cfg(windows)`).
//!
//! ## Why
//!
//! `%ProgramData%` lets `BUILTIN\Users` create files and folders in every
//! subfolder that inherits its DACL, and makes the creator the owner of what
//! they create. A directory made there with a plain `CreateDirectory` therefore
//! lets any local user plant a file that a `LocalSystem` service would later
//! load. [`check_admin_only`] is the test the daemon applies before trusting
//! such a file or directory.
//!
//! ## The rule
//!
//! An object is *administrator-only* when
//!
//! - its owner is SYSTEM or `BUILTIN\Administrators` (the owner holds implicit
//!   `WRITE_DAC`, so any other owner could grant itself write access later);
//! - it has a DACL (a NULL DACL grants everyone full control);
//! - no ACE that applies to the object itself grants a [`WRITE_RIGHTS`] bit,
//!   after generic-right mapping, to any SID other than SYSTEM or
//!   Administrators.
//!
//! Deny ACEs grant nothing and are skipped; they are never credited with
//! cancelling an allow ACE. Inherit-only ACEs do not apply to the object
//! itself and are skipped; the children they would reach are checked on their
//! own. Object and callback allow ACEs are treated as unconditional grants. Any
//! other ACE type that carries a write bit is refused, so an ACE this code
//! does not understand fails closed.
//!
//! `TrustedInstaller` is deliberately not trusted: nothing under
//! `%ProgramData%\FerroGate` is serviced by Windows, so an object owned by it
//! there is unexpected.

use std::fmt;

/// `NT AUTHORITY\SYSTEM` (`LocalSystem`), the account the `mia` service runs as.
pub const SID_LOCAL_SYSTEM: &str = "S-1-5-18";
/// `BUILTIN\Administrators`.
pub const SID_BUILTIN_ADMINISTRATORS: &str = "S-1-5-32-544";
/// `BUILTIN\Users`.
pub const SID_BUILTIN_USERS: &str = "S-1-5-32-545";
/// `NT AUTHORITY\Authenticated Users`.
pub const SID_AUTHENTICATED_USERS: &str = "S-1-5-11";
/// `CREATOR OWNER`: a placeholder replaced by the creator's SID on inheritance.
pub const SID_CREATOR_OWNER: &str = "S-1-3-0";

/// The SIDs that may own, or hold write access to, an administrator-only
/// object.
pub const TRUSTED_SIDS: [&str; 2] = [SID_LOCAL_SYSTEM, SID_BUILTIN_ADMINISTRATORS];

/// The security descriptor of an administrator-only directory, in SDDL:
/// owner `BUILTIN\Administrators`; a **protected** DACL (nothing inherited from
/// `%ProgramData%`) granting SYSTEM and Administrators full control, inherited
/// by every file and subdirectory (`OICI`). No other principal has any access —
/// not even read, because the MIA keeps its machine key there on Windows.
///
/// The installers apply the same DACL with
/// `icacls <dir> /inheritance:r /grant:r *S-1-5-18:(OI)(CI)F *S-1-5-32-544:(OI)(CI)F`.
pub const ADMIN_ONLY_DIR_SDDL: &str = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

/// `ACCESS_ALLOWED_ACE_TYPE`.
pub const ACCESS_ALLOWED_ACE_TYPE: u8 = 0x00;
/// `ACCESS_DENIED_ACE_TYPE`.
pub const ACCESS_DENIED_ACE_TYPE: u8 = 0x01;
/// `ACCESS_ALLOWED_COMPOUND_ACE_TYPE` (server impersonation; carries two SIDs
/// and is not parsed, so it is judged as an unrecognised ACE).
pub const ACCESS_ALLOWED_COMPOUND_ACE_TYPE: u8 = 0x04;
/// `ACCESS_ALLOWED_OBJECT_ACE_TYPE`.
pub const ACCESS_ALLOWED_OBJECT_ACE_TYPE: u8 = 0x05;
/// `ACCESS_DENIED_OBJECT_ACE_TYPE`.
pub const ACCESS_DENIED_OBJECT_ACE_TYPE: u8 = 0x06;
/// `ACCESS_ALLOWED_CALLBACK_ACE_TYPE` (conditional ACE).
pub const ACCESS_ALLOWED_CALLBACK_ACE_TYPE: u8 = 0x09;
/// `ACCESS_DENIED_CALLBACK_ACE_TYPE`.
pub const ACCESS_DENIED_CALLBACK_ACE_TYPE: u8 = 0x0A;
/// `ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE`.
pub const ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE: u8 = 0x0B;
/// `ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE`.
pub const ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE: u8 = 0x0C;

/// `INHERIT_ONLY_ACE`: the ACE applies only to children, not to the object
/// that carries it.
pub const INHERIT_ONLY_ACE: u8 = 0x08;

/// `FILE_WRITE_DATA` (on a directory, `FILE_ADD_FILE`).
pub const FILE_WRITE_DATA: u32 = 0x0000_0002;
/// `FILE_APPEND_DATA` (on a directory, `FILE_ADD_SUBDIRECTORY`).
pub const FILE_APPEND_DATA: u32 = 0x0000_0004;
/// `FILE_WRITE_EA`.
pub const FILE_WRITE_EA: u32 = 0x0000_0010;
/// `FILE_DELETE_CHILD`.
pub const FILE_DELETE_CHILD: u32 = 0x0000_0040;
/// `FILE_WRITE_ATTRIBUTES`.
pub const FILE_WRITE_ATTRIBUTES: u32 = 0x0000_0100;
/// `DELETE`.
pub const DELETE: u32 = 0x0001_0000;
/// `WRITE_DAC`.
pub const WRITE_DAC: u32 = 0x0004_0000;
/// `WRITE_OWNER`.
pub const WRITE_OWNER: u32 = 0x0008_0000;

/// `GENERIC_ALL`.
pub const GENERIC_ALL: u32 = 0x1000_0000;
/// `GENERIC_EXECUTE`.
pub const GENERIC_EXECUTE: u32 = 0x2000_0000;
/// `GENERIC_WRITE`.
pub const GENERIC_WRITE: u32 = 0x4000_0000;
/// `GENERIC_READ`.
pub const GENERIC_READ: u32 = 0x8000_0000;

/// `FILE_ALL_ACCESS` — what `GENERIC_ALL` maps to on a file or directory.
pub const FILE_ALL_ACCESS: u32 = 0x001F_01FF;
/// `FILE_GENERIC_WRITE` — what `GENERIC_WRITE` maps to.
pub const FILE_GENERIC_WRITE: u32 = 0x0012_0116;
/// `FILE_GENERIC_READ` — what `GENERIC_READ` maps to.
pub const FILE_GENERIC_READ: u32 = 0x0012_0089;
/// `FILE_GENERIC_EXECUTE` — what `GENERIC_EXECUTE` maps to.
pub const FILE_GENERIC_EXECUTE: u32 = 0x0012_00A0;

/// Every right that lets a principal change an object's contents, its
/// children, its attributes, its DACL or owner, or delete it. Holding any of
/// them disqualifies a principal other than SYSTEM or Administrators.
pub const WRITE_RIGHTS: u32 = FILE_WRITE_DATA
    | FILE_APPEND_DATA
    | FILE_WRITE_EA
    | FILE_DELETE_CHILD
    | FILE_WRITE_ATTRIBUTES
    | DELETE
    | WRITE_DAC
    | WRITE_OWNER;

/// One ACE of a DACL, as the Windows FFI reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ace {
    /// `ACE_HEADER.AceType`.
    pub ace_type: u8,
    /// `ACE_HEADER.AceFlags` (`OBJECT_INHERIT_ACE`, [`INHERIT_ONLY_ACE`], …).
    pub flags: u8,
    /// The access mask, possibly holding generic rights.
    pub mask: u32,
    /// The trustee as an SDDL SID string (`S-1-5-32-545`), or `None` when the
    /// ACE layout was not understood.
    pub sid: Option<String>,
}

/// The owner and DACL of a file or directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityFacts {
    /// The owner SID string, or `None` if the descriptor has no owner.
    pub owner: Option<String>,
    /// The DACL's ACEs in order, or `None` for a NULL DACL (full access for
    /// everyone). An empty vector is an empty DACL (no access for anyone but
    /// the owner's implicit rights).
    pub dacl: Option<Vec<Ace>>,
}

/// Why an object is not administrator-only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AclViolation {
    /// The security descriptor names no owner.
    MissingOwner,
    /// The owner is neither SYSTEM nor Administrators.
    UntrustedOwner {
        /// The owner SID.
        sid: String,
    },
    /// The object has a NULL DACL, which grants everyone full control.
    NullDacl,
    /// An allow ACE grants a write right to an untrusted SID.
    WritableBy {
        /// The trustee SID.
        sid: String,
        /// The write rights it holds (generic rights mapped).
        rights: u32,
    },
    /// An ACE whose type or layout is not understood carries a write right.
    UnrecognisedAce {
        /// `ACE_HEADER.AceType`.
        ace_type: u8,
        /// The write rights it carries (generic rights mapped).
        rights: u32,
    },
}

impl fmt::Display for AclViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingOwner => f.write_str("its security descriptor has no owner"),
            Self::UntrustedOwner { sid } => write!(
                f,
                "it is owned by {} rather than SYSTEM or BUILTIN\\Administrators",
                describe_sid(sid)
            ),
            Self::NullDacl => f.write_str("it has a NULL DACL, which grants everyone full control"),
            Self::WritableBy { sid, rights } => write!(
                f,
                "its DACL lets {} modify it (write rights 0x{rights:08X})",
                describe_sid(sid)
            ),
            Self::UnrecognisedAce { ace_type, rights } => write!(
                f,
                "its DACL holds an ACE of unrecognised type 0x{ace_type:02X} carrying write \
                 rights 0x{rights:08X}"
            ),
        }
    }
}

impl std::error::Error for AclViolation {}

/// Replace the generic rights in `mask` with the file-specific rights they map
/// to (`GENERIC_WRITE` ⇒ [`FILE_GENERIC_WRITE`], …).
#[must_use]
pub fn map_generic_file_rights(mask: u32) -> u32 {
    let mut specific = mask & !(GENERIC_ALL | GENERIC_EXECUTE | GENERIC_WRITE | GENERIC_READ);
    if mask & GENERIC_ALL != 0 {
        specific |= FILE_ALL_ACCESS;
    }
    if mask & GENERIC_EXECUTE != 0 {
        specific |= FILE_GENERIC_EXECUTE;
    }
    if mask & GENERIC_WRITE != 0 {
        specific |= FILE_GENERIC_WRITE;
    }
    if mask & GENERIC_READ != 0 {
        specific |= FILE_GENERIC_READ;
    }
    specific
}

/// Whether `sid` is SYSTEM or Administrators.
#[must_use]
pub fn is_trusted_sid(sid: &str) -> bool {
    TRUSTED_SIDS.contains(&sid)
}

/// How an ACE type is judged.
enum AceClass {
    /// Grants its mask to its SID (object and callback variants included).
    Allow,
    /// Denies; never grants anything.
    Deny,
    /// Anything else: compound, audit/alarm/label types, unknown types.
    Other,
}

fn classify(ace_type: u8) -> AceClass {
    match ace_type {
        ACCESS_ALLOWED_ACE_TYPE
        | ACCESS_ALLOWED_OBJECT_ACE_TYPE
        | ACCESS_ALLOWED_CALLBACK_ACE_TYPE
        | ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE => AceClass::Allow,
        ACCESS_DENIED_ACE_TYPE
        | ACCESS_DENIED_OBJECT_ACE_TYPE
        | ACCESS_DENIED_CALLBACK_ACE_TYPE
        | ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE => AceClass::Deny,
        _ => AceClass::Other,
    }
}

/// Decide whether an object with `facts` is administrator-only (see the
/// module docs for the rule). Returns the first violation found: the owner is
/// judged first, then the DACL's ACEs in order.
///
/// # Errors
///
/// The [`AclViolation`] that disqualifies the object.
pub fn check_admin_only(facts: &SecurityFacts) -> Result<(), AclViolation> {
    let owner = facts.owner.as_deref().ok_or(AclViolation::MissingOwner)?;
    if !is_trusted_sid(owner) {
        return Err(AclViolation::UntrustedOwner {
            sid: owner.to_string(),
        });
    }
    let dacl = facts.dacl.as_deref().ok_or(AclViolation::NullDacl)?;
    for ace in dacl {
        if ace.flags & INHERIT_ONLY_ACE != 0 {
            continue;
        }
        let rights = map_generic_file_rights(ace.mask) & WRITE_RIGHTS;
        if rights == 0 {
            continue;
        }
        match (classify(ace.ace_type), ace.sid.as_deref()) {
            (AceClass::Deny, _) => {}
            (AceClass::Allow, Some(sid)) if is_trusted_sid(sid) => {}
            (AceClass::Allow, Some(sid)) => {
                return Err(AclViolation::WritableBy {
                    sid: sid.to_string(),
                    rights,
                })
            }
            (AceClass::Allow | AceClass::Other, _) => {
                return Err(AclViolation::UnrecognisedAce {
                    ace_type: ace.ace_type,
                    rights,
                })
            }
        }
    }
    Ok(())
}

/// `sid` with the well-known account name appended, for messages
/// (`S-1-5-32-545 (BUILTIN\Users)`). Names are English labels, not a lookup.
fn describe_sid(sid: &str) -> String {
    let name = match sid {
        SID_LOCAL_SYSTEM => "NT AUTHORITY\\SYSTEM",
        SID_BUILTIN_ADMINISTRATORS => "BUILTIN\\Administrators",
        SID_BUILTIN_USERS => "BUILTIN\\Users",
        SID_AUTHENTICATED_USERS => "NT AUTHORITY\\Authenticated Users",
        SID_CREATOR_OWNER => "CREATOR OWNER",
        "S-1-1-0" => "Everyone",
        "S-1-3-4" => "OWNER RIGHTS",
        "S-1-5-4" => "NT AUTHORITY\\INTERACTIVE",
        "S-1-5-19" => "NT AUTHORITY\\LOCAL SERVICE",
        "S-1-5-20" => "NT AUTHORITY\\NETWORK SERVICE",
        "S-1-5-32-547" => "BUILTIN\\Power Users",
        _ => return sid.to_string(),
    };
    format!("{sid} ({name})")
}

/// `READ_CONTROL`.
pub const READ_CONTROL: u32 = 0x0002_0000;
/// `SYNCHRONIZE`.
pub const SYNCHRONIZE: u32 = 0x0010_0000;
/// `FILE_READ_ATTRIBUTES`.
pub const FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;
/// `FILE_ATTRIBUTE_DIRECTORY`.
pub const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
/// `FILE_ATTRIBUTE_REPARSE_POINT`: a symbolic link, junction, mount point or
/// any other reparse point.
pub const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
/// `FILE_FLAG_OPEN_REPARSE_POINT`: open a reparse point itself, never its
/// target.
pub const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
/// `FILE_FLAG_BACKUP_SEMANTICS`: needed to open a directory handle.
pub const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;

/// What `GetFileInformationByHandle` reports about an open object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjectInfo {
    /// `dwFileAttributes`.
    pub attributes: u32,
    /// `nNumberOfLinks`: how many names (hard links) the file has.
    pub links: u32,
}

impl ObjectInfo {
    /// Whether the object is a directory.
    #[must_use]
    pub fn is_directory(self) -> bool {
        self.attributes & FILE_ATTRIBUTE_DIRECTORY != 0
    }

    /// Whether the object is a reparse point (symbolic link, junction, …).
    #[must_use]
    pub fn is_reparse_point(self) -> bool {
        self.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
}

/// What a trusted object is expected to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectKind {
    /// A directory.
    Directory,
    /// A regular file.
    File,
}

/// Why an object is not a plain object of the expected [`ObjectKind`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectViolation {
    /// It is a symbolic link, junction or other reparse point.
    ReparsePoint,
    /// A directory was expected.
    NotADirectory,
    /// A file was expected.
    NotAFile,
    /// The file has more than one name.
    HardLinked {
        /// `nNumberOfLinks`.
        links: u32,
    },
}

impl fmt::Display for ObjectViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReparsePoint => {
                f.write_str("it is a symbolic link, junction or other reparse point")
            }
            Self::NotADirectory => f.write_str("it is not a directory"),
            Self::NotAFile => f.write_str("it is not a regular file"),
            Self::HardLinked { links } => write!(
                f,
                "it has {links} hard links (a link planted beside another file shares that \
                 file's owner and DACL)"
            ),
        }
    }
}

impl std::error::Error for ObjectViolation {}

/// Decide whether `info` describes a plain object of `kind`: never a reparse
/// point; a directory or a non-directory as `kind` says; and a file with
/// exactly one name, because a hard link to a file elsewhere carries that
/// file's owner and DACL and could have been planted before the directory was
/// made administrator-only.
///
/// # Errors
///
/// The [`ObjectViolation`] that disqualifies the object.
pub fn check_object(kind: ObjectKind, info: ObjectInfo) -> Result<(), ObjectViolation> {
    if info.is_reparse_point() {
        return Err(ObjectViolation::ReparsePoint);
    }
    match kind {
        ObjectKind::Directory if !info.is_directory() => Err(ObjectViolation::NotADirectory),
        ObjectKind::File if info.is_directory() => Err(ObjectViolation::NotAFile),
        ObjectKind::File if info.links > 1 => {
            Err(ObjectViolation::HardLinked { links: info.links })
        }
        _ => Ok(()),
    }
}

/// The highest sub-authority count a SID may have (`SID_MAX_SUB_AUTHORITIES`).
const SID_MAX_SUB_AUTHORITIES: u8 = 15;

/// The SDDL string form (as `ConvertSidToStringSidW` writes it) of the binary
/// SID at the start of `bytes`, and the SID's length in bytes; `None` unless
/// `bytes` starts with a complete revision-1 SID.
///
/// Layout: revision (1 byte), sub-authority count (1), identifier authority
/// (6, big-endian), then each sub-authority (4, little-endian). An authority
/// of 2^32 or more is written in hex, as Windows does.
#[must_use]
pub fn parse_sid(bytes: &[u8]) -> Option<(String, usize)> {
    use std::fmt::Write as _;
    let (&revision, &count) = (bytes.first()?, bytes.get(1)?);
    if revision != 1 || count > SID_MAX_SUB_AUTHORITIES {
        return None;
    }
    let len = 8 + 4 * usize::from(count);
    let sid = bytes.get(..len)?;
    let authority = sid[2..8]
        .iter()
        .fold(0u64, |acc, byte| (acc << 8) | u64::from(*byte));
    let mut text = if authority >> 32 == 0 {
        format!("S-1-{authority}")
    } else {
        format!("S-1-0x{authority:012X}")
    };
    for sub in sid[8..].as_chunks::<4>().0 {
        let _ = write!(text, "-{}", u32::from_le_bytes(*sub));
    }
    Some((text, len))
}

/// The little-endian `u16` at `offset`, if `bytes` holds it.
fn u16_at(bytes: &[u8], offset: usize) -> Option<u16> {
    let b = bytes.get(offset..offset.checked_add(2)?)?;
    Some(u16::from_le_bytes([b[0], b[1]]))
}

/// The little-endian `u32` at `offset`, if `bytes` holds it.
fn u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    let b = bytes.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// The ACE [`parse_acl`] emits where the ACL is malformed: an unrecognised
/// type with every right, which [`check_admin_only`] refuses.
fn malformed_ace() -> Ace {
    Ace {
        ace_type: u8::MAX,
        flags: 0,
        mask: u32::MAX,
        sid: None,
    }
}

/// Decode one ACE from its bytes, `ACE_HEADER` included (`AceType`,
/// `AceFlags`, `AceSize`, then the access mask).
///
/// The SID is located for the allow and deny types the policy reads: right
/// after the mask for the basic and callback types (a callback ACE's
/// application data follows the SID); after the mask, a 4-byte flags word and
/// each GUID those flags announce (`ACE_OBJECT_TYPE_PRESENT` = 1,
/// `ACE_INHERITED_OBJECT_TYPE_PRESENT` = 2) for the object types. An ACE too
/// short for its mask gets an all-ones mask, and any SID that is missing,
/// truncated or of another type is `None`; [`check_admin_only`] refuses
/// either whenever it could grant a write right, so a parse gap fails closed.
#[must_use]
pub fn parse_ace(bytes: &[u8]) -> Ace {
    let ace_type = bytes.first().copied().unwrap_or(u8::MAX);
    let sid_offset = match ace_type {
        ACCESS_ALLOWED_ACE_TYPE
        | ACCESS_DENIED_ACE_TYPE
        | ACCESS_ALLOWED_CALLBACK_ACE_TYPE
        | ACCESS_DENIED_CALLBACK_ACE_TYPE => Some(8),
        ACCESS_ALLOWED_OBJECT_ACE_TYPE
        | ACCESS_DENIED_OBJECT_ACE_TYPE
        | ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE
        | ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE => u32_at(bytes, 8).map(|object_flags| {
            12 + if object_flags & 1 != 0 { 16 } else { 0 }
                + if object_flags & 2 != 0 { 16 } else { 0 }
        }),
        _ => None,
    };
    Ace {
        ace_type,
        flags: bytes.get(1).copied().unwrap_or(0),
        mask: u32_at(bytes, 4).unwrap_or(u32::MAX),
        sid: sid_offset
            .and_then(|offset| bytes.get(offset..))
            .and_then(parse_sid)
            .map(|(sid, _)| sid),
    }
}

/// The ACEs of the binary ACL in `bytes` — an 8-byte `ACL` header
/// (`AclRevision`, `Sbz1`, `AclSize`, `AceCount`, `Sbz2`) followed by its ACEs —
/// in order. A header that does not fit, or an ACE that is shorter than its
/// header or runs past `AclSize`, ends the list with an ACE that
/// [`check_admin_only`] refuses, so a malformed ACL fails closed.
#[must_use]
pub fn parse_acl(bytes: &[u8]) -> Vec<Ace> {
    let (Some(size), Some(count)) = (u16_at(bytes, 2), u16_at(bytes, 4)) else {
        return vec![malformed_ace()];
    };
    let Some(acl) = bytes.get(..usize::from(size)).filter(|acl| acl.len() >= 8) else {
        return vec![malformed_ace()];
    };
    let mut aces = Vec::with_capacity(usize::from(count));
    let mut offset = 8usize;
    for _ in 0..count {
        let ace = u16_at(acl, offset + 2)
            .map(usize::from)
            .filter(|&ace_size| ace_size >= 4)
            .and_then(|ace_size| acl.get(offset..offset + ace_size));
        let Some(ace) = ace else {
            aces.push(malformed_ace());
            break;
        };
        aces.push(parse_ace(ace));
        offset += ace.len();
    }
    aces
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE`.
    const OICI: u8 = 0x03;
    /// `INHERITED_ACE`.
    const INHERITED: u8 = 0x10;
    /// A local user account.
    const USER: &str = "S-1-5-21-1111111111-2222222222-3333333333-1001";

    fn ace(ace_type: u8, flags: u8, mask: u32, sid: &str) -> Ace {
        Ace {
            ace_type,
            flags,
            mask,
            sid: Some(sid.to_string()),
        }
    }

    fn allow(mask: u32, sid: &str) -> Ace {
        ace(ACCESS_ALLOWED_ACE_TYPE, 0, mask, sid)
    }

    /// The DACL [`ADMIN_ONLY_DIR_SDDL`] produces.
    fn hardened() -> Vec<Ace> {
        vec![
            ace(
                ACCESS_ALLOWED_ACE_TYPE,
                OICI,
                FILE_ALL_ACCESS,
                SID_LOCAL_SYSTEM,
            ),
            ace(
                ACCESS_ALLOWED_ACE_TYPE,
                OICI,
                FILE_ALL_ACCESS,
                SID_BUILTIN_ADMINISTRATORS,
            ),
        ]
    }

    fn facts(owner: &str, dacl: Vec<Ace>) -> SecurityFacts {
        SecurityFacts {
            owner: Some(owner.to_string()),
            dacl: Some(dacl),
        }
    }

    #[test]
    fn system_and_administrators_only_is_accepted() {
        assert_eq!(
            check_admin_only(&facts(SID_BUILTIN_ADMINISTRATORS, hardened())),
            Ok(())
        );
        assert_eq!(
            check_admin_only(&facts(SID_LOCAL_SYSTEM, hardened())),
            Ok(())
        );
        // A file inside the hardened directory carries the same ACEs as
        // inherited ones.
        let inherited = vec![
            ace(
                ACCESS_ALLOWED_ACE_TYPE,
                INHERITED,
                FILE_ALL_ACCESS,
                SID_LOCAL_SYSTEM,
            ),
            ace(
                ACCESS_ALLOWED_ACE_TYPE,
                INHERITED,
                FILE_ALL_ACCESS,
                SID_BUILTIN_ADMINISTRATORS,
            ),
        ];
        assert_eq!(
            check_admin_only(&facts(SID_LOCAL_SYSTEM, inherited)),
            Ok(())
        );
    }

    #[test]
    fn users_write_ace_is_rejected() {
        let mut dacl = hardened();
        dacl.push(allow(FILE_WRITE_DATA, SID_BUILTIN_USERS));
        assert_eq!(
            check_admin_only(&facts(SID_BUILTIN_ADMINISTRATORS, dacl)),
            Err(AclViolation::WritableBy {
                sid: SID_BUILTIN_USERS.into(),
                rights: FILE_WRITE_DATA,
            })
        );
    }

    #[test]
    fn programdata_default_users_ace_is_rejected() {
        // %ProgramData%'s `BUILTIN\Users:(CI)(WD,AD,WEA,WA)`, as inherited by
        // a subfolder: create files / folders, write EA and attributes.
        let mut dacl = hardened();
        dacl.push(ace(
            ACCESS_ALLOWED_ACE_TYPE,
            0x02 | INHERITED,
            0x0000_0116,
            SID_BUILTIN_USERS,
        ));
        let err = check_admin_only(&facts(SID_BUILTIN_ADMINISTRATORS, dacl)).unwrap_err();
        assert!(
            matches!(err, AclViolation::WritableBy { ref sid, .. } if sid == SID_BUILTIN_USERS)
        );
    }

    #[test]
    fn authenticated_users_append_is_rejected() {
        let mut dacl = hardened();
        dacl.push(allow(FILE_APPEND_DATA, SID_AUTHENTICATED_USERS));
        assert_eq!(
            check_admin_only(&facts(SID_LOCAL_SYSTEM, dacl)),
            Err(AclViolation::WritableBy {
                sid: SID_AUTHENTICATED_USERS.into(),
                rights: FILE_APPEND_DATA,
            })
        );
    }

    #[test]
    fn read_only_grants_to_others_are_accepted() {
        let mut dacl = hardened();
        dacl.push(allow(
            FILE_GENERIC_READ | FILE_GENERIC_EXECUTE,
            SID_BUILTIN_USERS,
        ));
        dacl.push(allow(GENERIC_READ, SID_AUTHENTICATED_USERS));
        assert_eq!(check_admin_only(&facts(SID_LOCAL_SYSTEM, dacl)), Ok(()));
    }

    #[test]
    fn creator_owner_inherit_only_is_ignored() {
        let mut dacl = hardened();
        dacl.push(ace(
            ACCESS_ALLOWED_ACE_TYPE,
            OICI | INHERIT_ONLY_ACE,
            GENERIC_ALL,
            SID_CREATOR_OWNER,
        ));
        assert_eq!(check_admin_only(&facts(SID_LOCAL_SYSTEM, dacl)), Ok(()));
    }

    #[test]
    fn creator_owner_applying_to_the_object_is_rejected() {
        let mut dacl = hardened();
        dacl.push(ace(
            ACCESS_ALLOWED_ACE_TYPE,
            OICI,
            GENERIC_ALL,
            SID_CREATOR_OWNER,
        ));
        assert!(matches!(
            check_admin_only(&facts(SID_LOCAL_SYSTEM, dacl)),
            Err(AclViolation::WritableBy { .. })
        ));
    }

    #[test]
    fn deny_aces_are_ignored() {
        let mut dacl = vec![ace(
            ACCESS_DENIED_ACE_TYPE,
            0,
            GENERIC_ALL,
            SID_BUILTIN_USERS,
        )];
        dacl.extend(hardened());
        for deny in [
            ACCESS_DENIED_OBJECT_ACE_TYPE,
            ACCESS_DENIED_CALLBACK_ACE_TYPE,
            ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE,
        ] {
            dacl.push(ace(deny, 0, FILE_ALL_ACCESS, USER));
        }
        assert_eq!(check_admin_only(&facts(SID_LOCAL_SYSTEM, dacl)), Ok(()));
    }

    #[test]
    fn a_deny_does_not_cancel_an_allow() {
        // Windows would evaluate the deny first; the check still refuses the
        // allow rather than reason about ACE order.
        let dacl = vec![
            ace(ACCESS_DENIED_ACE_TYPE, 0, FILE_WRITE_DATA, USER),
            allow(FILE_WRITE_DATA, USER),
        ];
        assert!(check_admin_only(&facts(SID_LOCAL_SYSTEM, dacl)).is_err());
    }

    #[test]
    fn user_owner_is_rejected_even_with_a_clean_dacl() {
        assert_eq!(
            check_admin_only(&facts(USER, hardened())),
            Err(AclViolation::UntrustedOwner { sid: USER.into() })
        );
        assert_eq!(
            check_admin_only(&SecurityFacts {
                owner: None,
                dacl: Some(hardened()),
            }),
            Err(AclViolation::MissingOwner)
        );
    }

    #[test]
    fn trusted_installer_is_not_trusted() {
        const TRUSTED_INSTALLER: &str =
            "S-1-5-80-956008885-3418522649-1831038044-1851417049-2131838526";
        assert!(check_admin_only(&facts(TRUSTED_INSTALLER, hardened())).is_err());
    }

    #[test]
    fn null_dacl_is_rejected_and_empty_dacl_accepted() {
        assert_eq!(
            check_admin_only(&SecurityFacts {
                owner: Some(SID_LOCAL_SYSTEM.into()),
                dacl: None,
            }),
            Err(AclViolation::NullDacl)
        );
        assert_eq!(check_admin_only(&facts(SID_LOCAL_SYSTEM, vec![])), Ok(()));
    }

    #[test]
    fn unknown_ace_type_with_write_rights_is_rejected() {
        let mut dacl = hardened();
        dacl.push(ace(0x42, 0, WRITE_DAC, SID_LOCAL_SYSTEM));
        assert_eq!(
            check_admin_only(&facts(SID_LOCAL_SYSTEM, dacl)),
            Err(AclViolation::UnrecognisedAce {
                ace_type: 0x42,
                rights: WRITE_DAC,
            })
        );
        // The compound ACE is not parsed, so it is unrecognised too.
        let dacl = vec![ace(
            ACCESS_ALLOWED_COMPOUND_ACE_TYPE,
            0,
            GENERIC_WRITE,
            USER,
        )];
        assert!(matches!(
            check_admin_only(&facts(SID_LOCAL_SYSTEM, dacl)),
            Err(AclViolation::UnrecognisedAce { ace_type: 0x04, .. })
        ));
    }

    #[test]
    fn unknown_ace_type_without_write_rights_is_ignored() {
        let mut dacl = hardened();
        dacl.push(ace(0x11, 0, 0x0000_0001, "S-1-16-12288")); // a mandatory label
        assert_eq!(check_admin_only(&facts(SID_LOCAL_SYSTEM, dacl)), Ok(()));
    }

    #[test]
    fn allow_ace_with_unparsed_sid_fails_closed() {
        let mut dacl = hardened();
        dacl.push(Ace {
            ace_type: ACCESS_ALLOWED_ACE_TYPE,
            flags: 0,
            mask: FILE_WRITE_DATA,
            sid: None,
        });
        assert!(matches!(
            check_admin_only(&facts(SID_LOCAL_SYSTEM, dacl)),
            Err(AclViolation::UnrecognisedAce { .. })
        ));
    }

    #[test]
    fn object_and_callback_allows_are_grants() {
        for allow_type in [
            ACCESS_ALLOWED_OBJECT_ACE_TYPE,
            ACCESS_ALLOWED_CALLBACK_ACE_TYPE,
            ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE,
        ] {
            let dacl = vec![ace(allow_type, 0, DELETE, USER)];
            assert_eq!(
                check_admin_only(&facts(SID_LOCAL_SYSTEM, dacl)),
                Err(AclViolation::WritableBy {
                    sid: USER.into(),
                    rights: DELETE,
                }),
                "ACE type 0x{allow_type:02X}"
            );
        }
    }

    #[test]
    fn generic_rights_are_mapped() {
        assert_eq!(map_generic_file_rights(GENERIC_ALL), FILE_ALL_ACCESS);
        assert_eq!(map_generic_file_rights(GENERIC_WRITE), FILE_GENERIC_WRITE);
        assert_eq!(map_generic_file_rights(GENERIC_READ), FILE_GENERIC_READ);
        assert_eq!(
            map_generic_file_rights(GENERIC_EXECUTE | FILE_WRITE_DATA),
            FILE_GENERIC_EXECUTE | FILE_WRITE_DATA
        );
        // GENERIC_WRITE and GENERIC_ALL grant write; GENERIC_READ/EXECUTE do not.
        for (mask, writes) in [
            (GENERIC_WRITE, true),
            (GENERIC_ALL, true),
            (GENERIC_READ, false),
            (GENERIC_EXECUTE, false),
        ] {
            let result = check_admin_only(&facts(SID_LOCAL_SYSTEM, vec![allow(mask, USER)]));
            assert_eq!(result.is_err(), writes, "mask 0x{mask:08X}");
        }
    }

    #[test]
    fn every_write_right_is_refused_on_its_own() {
        for bit in [
            FILE_WRITE_DATA,
            FILE_APPEND_DATA,
            FILE_WRITE_EA,
            FILE_DELETE_CHILD,
            FILE_WRITE_ATTRIBUTES,
            DELETE,
            WRITE_DAC,
            WRITE_OWNER,
        ] {
            let result = check_admin_only(&facts(SID_LOCAL_SYSTEM, vec![allow(bit, USER)]));
            assert!(result.is_err(), "right 0x{bit:08X}");
        }
    }

    #[test]
    fn violations_name_the_principal() {
        let msg = AclViolation::WritableBy {
            sid: SID_BUILTIN_USERS.into(),
            rights: FILE_WRITE_DATA,
        }
        .to_string();
        assert!(msg.contains("S-1-5-32-545 (BUILTIN\\Users)"), "{msg}");
        let msg = AclViolation::UntrustedOwner { sid: USER.into() }.to_string();
        assert!(msg.contains(USER), "{msg}");
    }

    #[test]
    fn sddl_is_protected_and_grants_only_system_and_administrators() {
        assert!(ADMIN_ONLY_DIR_SDDL.starts_with("O:BAD:P"));
        let aces: Vec<&str> = ADMIN_ONLY_DIR_SDDL
            .split('(')
            .skip(1)
            .map(|a| a.trim_end_matches(')'))
            .collect();
        assert_eq!(aces, ["A;OICI;FA;;;SY", "A;OICI;FA;;;BA"]);
    }

    /// The binary form of a SID: revision 1, `authority`, `subs`.
    fn sid_bytes(authority: u64, subs: &[u32]) -> Vec<u8> {
        let mut out = vec![1, u8::try_from(subs.len()).unwrap()];
        out.extend_from_slice(&authority.to_be_bytes()[2..]);
        for sub in subs {
            out.extend_from_slice(&sub.to_le_bytes());
        }
        out
    }

    /// An ACE: header (`ace_type`, `flags`, size), `mask`, then `body`.
    fn ace_bytes(ace_type: u8, flags: u8, mask: u32, body: &[u8]) -> Vec<u8> {
        let size = u16::try_from(8 + body.len()).unwrap();
        let mut out = vec![ace_type, flags];
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&mask.to_le_bytes());
        out.extend_from_slice(body);
        out
    }

    /// An ACL holding `aces`, with `count` as its `AceCount`.
    fn acl_bytes(aces: &[Vec<u8>], count: u16) -> Vec<u8> {
        let body: Vec<u8> = aces.concat();
        let size = u16::try_from(8 + body.len()).unwrap();
        let mut out = vec![2, 0];
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&count.to_le_bytes());
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(&body);
        out
    }

    #[test]
    fn sids_render_as_windows_writes_them() {
        assert_eq!(
            parse_sid(&sid_bytes(5, &[18])),
            Some((SID_LOCAL_SYSTEM.to_string(), 12))
        );
        assert_eq!(
            parse_sid(&sid_bytes(5, &[32, 544])).map(|(s, _)| s),
            Some(SID_BUILTIN_ADMINISTRATORS.to_string())
        );
        assert_eq!(
            parse_sid(&sid_bytes(
                5,
                &[21, 1_111_111_111, 2_222_222_222, 3_333_333_333, 1001]
            ))
            .map(|(s, _)| s),
            Some(USER.to_string())
        );
        assert_eq!(
            parse_sid(&sid_bytes(0x0000_1234_5678_9ABC, &[1])).map(|(s, _)| s),
            Some("S-1-0x123456789ABC-1".to_string())
        );
        // Trailing bytes (a callback ACE's application data) are not part of it.
        let mut with_tail = sid_bytes(1, &[0]);
        with_tail.extend_from_slice(&[0xAA; 7]);
        assert_eq!(parse_sid(&with_tail), Some(("S-1-1-0".to_string(), 12)));
    }

    #[test]
    fn malformed_sids_are_rejected() {
        assert_eq!(parse_sid(&[]), None);
        let mut bad_revision = sid_bytes(5, &[18]);
        bad_revision[0] = 2;
        assert_eq!(parse_sid(&bad_revision), None);
        let mut too_many = sid_bytes(5, &[18]);
        too_many[1] = 16;
        assert_eq!(parse_sid(&too_many), None);
        let truncated = sid_bytes(5, &[32, 544]);
        assert_eq!(parse_sid(&truncated[..truncated.len() - 1]), None);
    }

    #[test]
    fn basic_ace_is_decoded() {
        let ace = parse_ace(&ace_bytes(
            ACCESS_ALLOWED_ACE_TYPE,
            0x13,
            FILE_ALL_ACCESS,
            &sid_bytes(5, &[18]),
        ));
        assert_eq!(
            ace,
            Ace {
                ace_type: ACCESS_ALLOWED_ACE_TYPE,
                flags: 0x13,
                mask: FILE_ALL_ACCESS,
                sid: Some(SID_LOCAL_SYSTEM.into()),
            }
        );
    }

    #[test]
    fn object_ace_sid_follows_the_announced_guids() {
        let sid = sid_bytes(5, &[32, 545]);
        for (object_flags, guids) in [(0u32, 0usize), (1, 1), (2, 1), (3, 2)] {
            let mut body = object_flags.to_le_bytes().to_vec();
            body.extend(std::iter::repeat_n(0x5A, 16 * guids));
            body.extend_from_slice(&sid);
            for ace_type in [
                ACCESS_ALLOWED_OBJECT_ACE_TYPE,
                ACCESS_DENIED_OBJECT_ACE_TYPE,
                ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE,
                ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE,
            ] {
                let ace = parse_ace(&ace_bytes(ace_type, 0, WRITE_DAC, &body));
                assert_eq!(
                    ace.sid.as_deref(),
                    Some(SID_BUILTIN_USERS),
                    "type 0x{ace_type:02X}, object flags {object_flags}"
                );
                assert_eq!(ace.mask, WRITE_DAC);
            }
        }
        // Flags announce a GUID the ACE does not hold: no SID, so a write
        // grant is refused rather than attributed to the wrong trustee.
        let mut body = 3u32.to_le_bytes().to_vec();
        body.extend_from_slice(&sid);
        let ace = parse_ace(&ace_bytes(
            ACCESS_ALLOWED_OBJECT_ACE_TYPE,
            0,
            WRITE_DAC,
            &body,
        ));
        assert_eq!(ace.sid, None);
        assert!(check_admin_only(&facts(SID_LOCAL_SYSTEM, vec![ace])).is_err());
    }

    #[test]
    fn callback_ace_sid_is_read_before_its_application_data() {
        let mut body = sid_bytes(5, &[11]);
        body.extend_from_slice(b"artx\x01\x00\x00\x00"); // conditional-expression data
        for ace_type in [
            ACCESS_ALLOWED_CALLBACK_ACE_TYPE,
            ACCESS_DENIED_CALLBACK_ACE_TYPE,
        ] {
            let ace = parse_ace(&ace_bytes(ace_type, 0, FILE_APPEND_DATA, &body));
            assert_eq!(ace.sid.as_deref(), Some(SID_AUTHENTICATED_USERS));
        }
        let allow = parse_ace(&ace_bytes(
            ACCESS_ALLOWED_CALLBACK_ACE_TYPE,
            0,
            FILE_APPEND_DATA,
            &body,
        ));
        assert!(matches!(
            check_admin_only(&facts(SID_LOCAL_SYSTEM, vec![allow])),
            Err(AclViolation::WritableBy { .. })
        ));
    }

    #[test]
    fn truncated_aces_fail_closed() {
        // Too short for a mask: every right, no SID.
        let ace = parse_ace(&[ACCESS_ALLOWED_ACE_TYPE, 0, 6, 0, 0xFF, 0xFF]);
        assert_eq!(ace.mask, u32::MAX);
        assert_eq!(ace.sid, None);
        // A mask but a truncated SID.
        let sid = sid_bytes(5, &[32, 545]);
        let ace = parse_ace(&ace_bytes(
            ACCESS_ALLOWED_ACE_TYPE,
            0,
            FILE_WRITE_DATA,
            &sid[..sid.len() - 2],
        ));
        assert_eq!(ace.sid, None);
        assert!(check_admin_only(&facts(SID_LOCAL_SYSTEM, vec![ace])).is_err());
        // An object ACE too short for its flags word.
        let ace = parse_ace(&ace_bytes(
            ACCESS_ALLOWED_OBJECT_ACE_TYPE,
            0,
            DELETE,
            &[1, 0],
        ));
        assert_eq!(ace.sid, None);
        assert!(check_admin_only(&facts(SID_LOCAL_SYSTEM, vec![ace])).is_err());
    }

    #[test]
    fn acls_are_decoded_in_order() {
        let system = ace_bytes(
            ACCESS_ALLOWED_ACE_TYPE,
            0x03,
            FILE_ALL_ACCESS,
            &sid_bytes(5, &[18]),
        );
        let admins = ace_bytes(
            ACCESS_ALLOWED_ACE_TYPE,
            0x03,
            FILE_ALL_ACCESS,
            &sid_bytes(5, &[32, 544]),
        );
        let aces = parse_acl(&acl_bytes(&[system, admins], 2));
        assert_eq!(aces, hardened());
        assert_eq!(parse_acl(&acl_bytes(&[], 0)), vec![]);
    }

    #[test]
    fn malformed_acls_fail_closed() {
        let system = ace_bytes(
            ACCESS_ALLOWED_ACE_TYPE,
            0,
            FILE_ALL_ACCESS,
            &sid_bytes(5, &[18]),
        );
        // AceCount claims more ACEs than AclSize holds.
        let aces = parse_acl(&acl_bytes(std::slice::from_ref(&system), 2));
        assert_eq!(aces.len(), 2);
        assert_eq!(aces[1].ace_type, u8::MAX);
        assert!(check_admin_only(&facts(SID_LOCAL_SYSTEM, aces)).is_err());
        // AclSize larger than the buffer, or a header that does not fit.
        let mut acl = acl_bytes(&[system], 1);
        acl.truncate(acl.len() - 1);
        assert!(check_admin_only(&facts(SID_LOCAL_SYSTEM, parse_acl(&acl))).is_err());
        assert!(check_admin_only(&facts(SID_LOCAL_SYSTEM, parse_acl(&[2, 0, 8]))).is_err());
        // An ACE whose size is smaller than its own header.
        let mut acl = acl_bytes(&[vec![ACCESS_ALLOWED_ACE_TYPE, 0, 0, 0]], 1);
        acl[10] = 2;
        assert!(check_admin_only(&facts(SID_LOCAL_SYSTEM, parse_acl(&acl))).is_err());
    }

    #[test]
    fn objects_must_be_plain_and_of_the_expected_kind() {
        let dir = ObjectInfo {
            attributes: FILE_ATTRIBUTE_DIRECTORY,
            links: 1,
        };
        let file = ObjectInfo {
            attributes: 0x20, // FILE_ATTRIBUTE_ARCHIVE
            links: 1,
        };
        assert_eq!(check_object(ObjectKind::Directory, dir), Ok(()));
        assert_eq!(check_object(ObjectKind::File, file), Ok(()));
        assert_eq!(
            check_object(ObjectKind::File, dir),
            Err(ObjectViolation::NotAFile)
        );
        assert_eq!(
            check_object(ObjectKind::Directory, file),
            Err(ObjectViolation::NotADirectory)
        );
        let junction = ObjectInfo {
            attributes: FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT,
            links: 1,
        };
        assert_eq!(
            check_object(ObjectKind::Directory, junction),
            Err(ObjectViolation::ReparsePoint)
        );
        let symlink = ObjectInfo {
            attributes: FILE_ATTRIBUTE_REPARSE_POINT,
            links: 1,
        };
        assert_eq!(
            check_object(ObjectKind::File, symlink),
            Err(ObjectViolation::ReparsePoint)
        );
        let hard_linked = ObjectInfo { links: 2, ..file };
        assert_eq!(
            check_object(ObjectKind::File, hard_linked),
            Err(ObjectViolation::HardLinked { links: 2 })
        );
    }
}
