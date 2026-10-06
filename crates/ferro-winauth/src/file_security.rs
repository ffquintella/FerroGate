//! Windows FFI for administrator-only directories and files.
//!
//! Everything works on one handle, opened without following reparse points
//! ([`open_no_follow`]), so what is judged is what is changed or read:
//!
//! - [`object_info`] — attributes and hard-link count of the open object;
//! - [`security_of`] — its owner and DACL, decoded by the pure parsers in
//!   [`crate::file_acl`] for [`crate::file_acl::check_admin_only`];
//! - [`create_admin_only_dir`] — create a directory whose security descriptor
//!   is [`ADMIN_ONLY_DIR_SDDL`] from the start (no window with an inherited
//!   DACL);
//! - [`set_admin_only`] — give an open directory that owner and protected
//!   DACL, either on the object alone (`SetKernelObjectSecurity`) or also
//!   re-deriving the inherited ACEs of what lies below (`SetSecurityInfo`);
//! - [`set_administrators_owner`] — make `BUILTIN\Administrators` the owner of
//!   an open file.
//!
//! [`read_security`] is the by-path convenience: open without following, then
//! [`security_of`].

use std::ffi::c_void;
use std::fs::File;
use std::io;
use std::os::windows::ffi::OsStrExt as _;
use std::os::windows::fs::OpenOptionsExt as _;
use std::os::windows::io::AsRawHandle as _;
use std::path::Path;
use std::ptr;

use windows_sys::Win32::Foundation::{LocalFree, ERROR_SUCCESS, HANDLE, WIN32_ERROR};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, ConvertStringSidToSidW, GetSecurityInfo,
    SetSecurityInfo, SDDL_REVISION_1, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    GetLengthSid, GetSecurityDescriptorDacl, GetSecurityDescriptorOwner, IsValidSid,
    SetKernelObjectSecurity, ACL, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION, PSID, SECURITY_ATTRIBUTES,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateDirectoryW, GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
};

use crate::file_acl::{
    parse_acl, parse_sid, ObjectInfo, SecurityFacts, ADMIN_ONLY_DIR_SDDL,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES, READ_CONTROL,
    SID_BUILTIN_ADMINISTRATORS,
};

/// Memory a Win32 API allocated with `LocalAlloc` (a security descriptor or a
/// SID), released with `LocalFree` when dropped.
struct LocalBox(*mut c_void);

impl Drop for LocalBox {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the pointer came from an API documented to allocate it
            // with `LocalAlloc`, and this guard is its only owner, so it is
            // freed exactly once.
            unsafe { LocalFree(self.0) };
        }
    }
}

/// `path` as a NUL-terminated UTF-16 string. A path with an interior NUL is
/// refused rather than silently truncated.
fn wide_path(path: &Path) -> io::Result<Vec<u16>> {
    let wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    if wide.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path contains a NUL character",
        ));
    }
    Ok(wide.into_iter().chain([0]).collect())
}

/// A `WIN32_ERROR` status as an `io::Error`.
fn win32_error(status: WIN32_ERROR) -> io::Error {
    io::Error::from_raw_os_error(status.cast_signed())
}

/// The raw handle of `file`, for the Win32 calls below.
fn handle(file: &File) -> HANDLE {
    file.as_raw_handle() as HANDLE
}

/// Open the existing file or directory at `path` with exactly `access`, never
/// following a reparse point: a symbolic link or junction opens as itself
/// (`FILE_FLAG_OPEN_REPARSE_POINT`), so [`object_info`] reports it and nothing
/// done through the handle reaches its target. `FILE_FLAG_BACKUP_SEMANTICS`
/// lets directories open; it grants nothing by itself.
///
/// # Errors
///
/// The `CreateFileW` failure (`NotFound`, `PermissionDenied`, …).
pub fn open_no_follow(path: &Path, access: u32) -> io::Result<File> {
    std::fs::OpenOptions::new()
        .access_mode(access)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

/// Attributes and hard-link count of the open object
/// (`GetFileInformationByHandle`). The handle needs `FILE_READ_ATTRIBUTES`.
///
/// # Errors
///
/// The `GetFileInformationByHandle` failure.
pub fn object_info(file: &File) -> io::Result<ObjectInfo> {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: the handle is open for the duration of the call, and `info` is
    // a valid, writable BY_HANDLE_FILE_INFORMATION.
    if unsafe { GetFileInformationByHandle(handle(file), &mut info) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(ObjectInfo {
        attributes: info.dwFileAttributes,
        links: info.nNumberOfLinks,
    })
}

/// The owner and DACL of the open object. The handle needs `READ_CONTROL`.
///
/// # Errors
///
/// The `GetSecurityInfo` failure.
pub fn security_of(file: &File) -> io::Result<SecurityFacts> {
    let mut owner: PSID = ptr::null_mut();
    let mut dacl: *mut ACL = ptr::null_mut();
    let mut descriptor: *mut c_void = ptr::null_mut();
    // SAFETY: the handle is open with READ_CONTROL for the duration of the
    // call and every out-pointer is valid. On success `descriptor` is a
    // `LocalAlloc`ed self-relative descriptor that `owner` and `dacl` point
    // into; the guard keeps it alive until both have been copied out.
    let status = unsafe {
        GetSecurityInfo(
            handle(file),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            ptr::null_mut(),
            &mut dacl,
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    let _descriptor = LocalBox(descriptor);
    if status != ERROR_SUCCESS {
        return Err(win32_error(status));
    }
    // An owner that is missing or does not parse is reported as no owner,
    // which the policy refuses.
    let owner = if owner.is_null() {
        None
    } else {
        // SAFETY: `owner` points to a SID inside the live descriptor.
        let len = unsafe {
            if IsValidSid(owner) == 0 {
                0
            } else {
                GetLengthSid(owner) as usize
            }
        };
        // SAFETY: a valid SID spans exactly `GetLengthSid` bytes, all inside
        // the descriptor; an invalid one gives an empty slice.
        let bytes = unsafe { std::slice::from_raw_parts(owner.cast_const().cast::<u8>(), len) };
        parse_sid(bytes).map(|(sid, _)| sid)
    };
    // A null DACL pointer is a NULL DACL: full access for everyone. The policy
    // refuses it.
    let dacl = if dacl.is_null() {
        None
    } else {
        // SAFETY: `dacl` points to an ACL header inside the live descriptor.
        let size = unsafe { ptr::read_unaligned(dacl.cast_const()) }.AclSize;
        // SAFETY: the OS built the descriptor, so the ACL spans `AclSize`
        // bytes from its header, all inside the descriptor.
        let bytes = unsafe {
            std::slice::from_raw_parts(dacl.cast_const().cast::<u8>(), usize::from(size))
        };
        Some(parse_acl(bytes))
    };
    Ok(SecurityFacts { owner, dacl })
}

/// The owner and DACL of the object at `path`, read without following a
/// reparse point ([`open_no_follow`] with `READ_CONTROL`).
///
/// # Errors
///
/// Opening the object or reading its descriptor failing.
pub fn read_security(path: &Path) -> io::Result<SecurityFacts> {
    security_of(&open_no_follow(path, READ_CONTROL | FILE_READ_ATTRIBUTES)?)
}

/// [`ADMIN_ONLY_DIR_SDDL`] as a security descriptor.
fn admin_only_descriptor() -> io::Result<LocalBox> {
    let sddl: Vec<u16> = ADMIN_ONLY_DIR_SDDL.encode_utf16().chain([0]).collect();
    let mut descriptor: *mut c_void = ptr::null_mut();
    // SAFETY: `sddl` is NUL-terminated; on success `descriptor` is a
    // `LocalAlloc`ed descriptor owned by the returned guard.
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(LocalBox(descriptor))
}

/// Create the directory `path` (its parent must exist) with the
/// [`ADMIN_ONLY_DIR_SDDL`] security descriptor, applied atomically by
/// `CreateDirectoryW`. A reparse point already at `path` makes it fail with
/// `AlreadyExists`; it is never followed.
///
/// # Errors
///
/// `AlreadyExists` when something is already at `path`; `ERROR_INVALID_OWNER`
/// (1307) when the caller cannot name Administrators as owner, i.e. is not
/// elevated; any other `CreateDirectoryW` failure.
pub fn create_admin_only_dir(path: &Path) -> io::Result<()> {
    let wide = wide_path(path)?;
    let descriptor = admin_only_descriptor()?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    // SAFETY: `wide` is NUL-terminated; `attributes` and the descriptor it
    // points to outlive the call.
    if unsafe { CreateDirectoryW(wide.as_ptr(), &attributes) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Give the open directory the owner (`BUILTIN\Administrators`) and the
/// protected DACL of [`ADMIN_ONLY_DIR_SDDL`], through its handle — never a
/// path, so a directory swapped for a junction after it was opened is not
/// what changes. The handle needs `WRITE_DAC | WRITE_OWNER`; callers open it
/// with [`open_no_follow`] and check [`object_info`] first.
///
/// With `propagate == false` only the directory itself changes
/// (`SetKernelObjectSecurity`): its children keep their ACEs. With
/// `propagate == true` (`SetSecurityInfo`) Windows also re-derives the
/// inherited ACEs of everything below it; callers do that only once the tree
/// below holds no reparse point.
///
/// # Errors
///
/// The `SetKernelObjectSecurity` / `SetSecurityInfo` failure.
pub fn set_admin_only(file: &File, propagate: bool) -> io::Result<()> {
    let descriptor = admin_only_descriptor()?;
    let info = OWNER_SECURITY_INFORMATION
        | DACL_SECURITY_INFORMATION
        | PROTECTED_DACL_SECURITY_INFORMATION;
    if !propagate {
        // SAFETY: the handle is open with WRITE_DAC | WRITE_OWNER and the
        // descriptor is valid for the duration of the call.
        if unsafe { SetKernelObjectSecurity(handle(file), info, descriptor.0) } == 0 {
            return Err(io::Error::last_os_error());
        }
        return Ok(());
    }
    let mut owner: PSID = ptr::null_mut();
    let mut dacl: *mut ACL = ptr::null_mut();
    let mut present = 0;
    let mut defaulted = 0;
    // SAFETY: `descriptor` is a valid descriptor kept alive until the end of
    // this function; both calls store pointers into it.
    let ok = unsafe {
        GetSecurityDescriptorOwner(descriptor.0, &mut owner, &mut defaulted) != 0
            && GetSecurityDescriptorDacl(descriptor.0, &mut present, &mut dacl, &mut defaulted) != 0
    };
    if !ok {
        return Err(io::Error::last_os_error());
    }
    if owner.is_null() || present == 0 || dacl.is_null() {
        return Err(io::Error::other(
            "internal: the administrator-only SDDL lacks an owner or a DACL",
        ));
    }
    // SAFETY: the handle is open with WRITE_DAC | WRITE_OWNER; `owner` and
    // `dacl` point into `descriptor`, alive across the call.
    let status = unsafe {
        SetSecurityInfo(
            handle(file),
            SE_FILE_OBJECT,
            info,
            owner,
            ptr::null_mut(),
            dacl,
            ptr::null(),
        )
    };
    if status != ERROR_SUCCESS {
        return Err(win32_error(status));
    }
    Ok(())
}

/// Make `BUILTIN\Administrators` the owner of the open object, leaving its
/// DACL alone, through its handle. The handle needs `WRITE_OWNER`. An elevated
/// administrator's token can name Administrators as owner, so no privilege is
/// needed beyond that.
///
/// # Errors
///
/// The `SetSecurityInfo` failure (`ERROR_INVALID_OWNER` when the caller is
/// not elevated).
pub fn set_administrators_owner(file: &File) -> io::Result<()> {
    let text: Vec<u16> = SID_BUILTIN_ADMINISTRATORS
        .encode_utf16()
        .chain([0])
        .collect();
    let mut sid: PSID = ptr::null_mut();
    // SAFETY: `text` is NUL-terminated; on success `sid` is a `LocalAlloc`ed
    // SID owned by the guard below.
    if unsafe { ConvertStringSidToSidW(text.as_ptr(), &mut sid) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let sid = LocalBox(sid);
    // SAFETY: the handle is open with WRITE_OWNER; `sid` stays alive across
    // the call.
    let status = unsafe {
        SetSecurityInfo(
            handle(file),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            sid.0,
            ptr::null_mut(),
            ptr::null(),
            ptr::null(),
        )
    };
    if status != ERROR_SUCCESS {
        return Err(win32_error(status));
    }
    Ok(())
}
