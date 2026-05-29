//! Windows implementation of the caller-attestation FFI. See crate docs.

use std::ffi::{c_void, OsStr, OsString};
use std::io;
use std::mem::size_of;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::io::RawHandle;
use std::path::{Path, PathBuf};
use std::ptr;

use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::WinTrust::{
    WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_FILE_INFO,
    WTD_CHOICE_FILE, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
};
use windows_sys::Win32::Security::{
    GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, LookupAccountNameW,
    TokenUser, PSID, SECURITY_ATTRIBUTES, SID_NAME_USE, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::System::Pipes::GetNamedPipeClientProcessId;
use windows_sys::Win32::System::Threading::{
    OpenProcess, OpenProcessToken, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
};

/// SDDL DACL template: grant generic read/write to SYSTEM (`SY`), the local
/// Administrators group (`BA`), and the caller-supplied group SID. No other
/// principal is granted access.
const SDDL_TEMPLATE: &str = "D:(A;;GRGW;;;SY)(A;;GRGW;;;BA)(A;;GRGW;;;{SID})";

/// The PID of the process connected to `handle`, a named-pipe **server**
/// instance with a client attached.
pub fn client_process_id(handle: RawHandle) -> io::Result<u32> {
    let mut pid: u32 = 0;
    // SAFETY: `handle` is a live named-pipe server handle owned by the caller
    // (tokio keeps it valid for the connection); the call writes the client
    // PID through `&mut pid`.
    let ok = unsafe { GetNamedPipeClientProcessId(handle as HANDLE, &mut pid) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(pid)
}

/// Open a process for limited query, run `f` with its handle, and always close
/// the handle afterwards.
fn with_process<T>(pid: u32, f: impl FnOnce(HANDLE) -> io::Result<T>) -> io::Result<T> {
    // SAFETY: a straightforward `OpenProcess` call; the returned handle is
    // closed below regardless of `f`'s outcome.
    let proc = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if proc.is_null() {
        return Err(io::Error::last_os_error());
    }
    let out = f(proc);
    // SAFETY: `proc` is a valid handle returned by `OpenProcess`.
    unsafe { CloseHandle(proc) };
    out
}

/// The full on-disk image path of `pid`.
pub fn process_image_path(pid: u32) -> io::Result<PathBuf> {
    with_process(pid, |proc| {
        let mut buf = vec![0u16; 32768];
        let mut len = buf.len() as u32;
        // SAFETY: `proc` is valid; `buf`/`len` describe a writable buffer and
        // its capacity, which the call fills and updates.
        let ok = unsafe { QueryFullProcessImageNameW(proc, 0, buf.as_mut_ptr(), &mut len) };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(PathBuf::from(OsString::from_wide(&buf[..len as usize])))
    })
}

/// The RID (last sub-authority) of `pid`'s token user SID — the Windows
/// analogue of a Unix uid for the allowlist.
pub fn process_user_rid(pid: u32) -> io::Result<u32> {
    with_process(pid, |proc| {
        let mut token: HANDLE = ptr::null_mut();
        // SAFETY: `proc` is valid; we receive the token handle by out-param.
        let ok = unsafe { OpenProcessToken(proc, TOKEN_QUERY, &mut token) };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        let result = token_user_rid(token);
        // SAFETY: `token` was produced by `OpenProcessToken`.
        unsafe { CloseHandle(token) };
        result
    })
}

fn token_user_rid(token: HANDLE) -> io::Result<u32> {
    // First call sizes the buffer (expected to fail with insufficient buffer).
    let mut needed: u32 = 0;
    // SAFETY: a null buffer with size 0 makes the call report the required
    // size in `needed`.
    unsafe { GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &mut needed) };
    if needed == 0 {
        return Err(io::Error::last_os_error());
    }
    // Back the buffer with `u64`s so it is 8-byte aligned for the `TOKEN_USER`
    // (which contains pointers) the call writes into it.
    let words = (needed as usize).div_ceil(8);
    let mut buf = vec![0u64; words];
    // SAFETY: `buf` holds at least `needed` bytes; the call fills it with a
    // TOKEN_USER.
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            buf.as_mut_ptr().cast::<c_void>(),
            needed,
            &mut needed,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: on success `buf` begins with a valid, suitably aligned TOKEN_USER
    // whose `User.Sid` points into the same buffer.
    let sid: PSID = unsafe { (*buf.as_ptr().cast::<TOKEN_USER>()).User.Sid };
    rid_from_sid(sid)
}

fn rid_from_sid(sid: PSID) -> io::Result<u32> {
    if sid.is_null() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "null SID"));
    }
    // SAFETY: `sid` is a valid SID; the count pointer is valid for the SID's
    // lifetime and dereferenced once.
    let count = unsafe { *GetSidSubAuthorityCount(sid) };
    if count == 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "empty SID"));
    }
    // SAFETY: index is in range `0..count`; the returned pointer is valid.
    let rid = unsafe { *GetSidSubAuthority(sid, u32::from(count - 1)) };
    Ok(rid)
}

/// Verify the Authenticode signature / Code-Integrity trust of the file at
/// `path`. Returns `Ok(true)` only when the OS trust provider validates it.
pub fn verify_authenticode(path: &Path) -> io::Result<bool> {
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();

    // SAFETY: zeroed is a valid initial state for these C structs; we set the
    // mandatory fields before use.
    let mut file_info: WINTRUST_FILE_INFO = unsafe { std::mem::zeroed() };
    file_info.cbStruct = size_of::<WINTRUST_FILE_INFO>() as u32;
    file_info.pcwszFilePath = wide.as_ptr();

    // SAFETY: see above.
    let mut wtd: WINTRUST_DATA = unsafe { std::mem::zeroed() };
    wtd.cbStruct = size_of::<WINTRUST_DATA>() as u32;
    wtd.dwUIChoice = WTD_UI_NONE;
    wtd.fdwRevocationChecks = WTD_REVOKE_NONE;
    wtd.dwUnionChoice = WTD_CHOICE_FILE;
    wtd.dwStateAction = WTD_STATEACTION_VERIFY;
    wtd.Anonymous.pFile = &mut file_info;

    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    // SAFETY: `wtd`/`file_info`/`action` are valid, initialized, and outlive
    // both calls; the second call (STATEACTION_CLOSE) frees provider state
    // allocated by the first.
    let status = unsafe {
        WinVerifyTrust(
            INVALID_HANDLE_VALUE,
            &mut action,
            ptr::from_mut(&mut wtd).cast::<c_void>(),
        )
    };
    wtd.dwStateAction = WTD_STATEACTION_CLOSE;
    // SAFETY: as above; releases the state allocated by the verify call. The
    // fresh `&mut wtd` borrow also makes the field write above observably used.
    unsafe {
        WinVerifyTrust(
            INVALID_HANDLE_VALUE,
            &mut action,
            ptr::from_mut(&mut wtd).cast::<c_void>(),
        )
    };

    Ok(status == 0)
}

/// Create a named-pipe server instance at `addr`. When `group` is `Some`, the
/// pipe is created with a DACL granting access only to that local group (plus
/// SYSTEM and Administrators); otherwise the default pipe security applies.
///
/// `first` must be `true` for the first instance of a pipe name and `false`
/// for every subsequent instance.
pub fn create_server_pipe(
    addr: &OsStr,
    first: bool,
    group: Option<&str>,
) -> io::Result<NamedPipeServer> {
    let mut opts = ServerOptions::new();
    opts.first_pipe_instance(first);

    let Some(group) = group else {
        return opts.create(addr);
    };

    let sid = lookup_group_sid_string(group)?;
    let sddl = SDDL_TEMPLATE.replace("{SID}", &sid);
    let wide: Vec<u16> = sddl.encode_utf16().chain([0]).collect();

    let mut psd: *mut c_void = ptr::null_mut();
    // SAFETY: parses the SDDL string into a security descriptor allocated by
    // the OS; on success `psd` is non-null and freed below.
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide.as_ptr(),
            SDDL_REVISION_1,
            &mut psd,
            ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }

    let mut sa = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: psd,
        bInheritHandle: 0,
    };
    // SAFETY: `sa` references a valid security descriptor that lives until
    // after `create_with_security_attributes_raw` returns.
    let pipe = unsafe {
        opts.create_with_security_attributes_raw(addr, ptr::from_mut(&mut sa).cast::<c_void>())
    };
    // SAFETY: `psd` was allocated by the conversion call above.
    unsafe { LocalFree(psd) };
    pipe
}

/// Resolve a local group name to its SID, formatted as an SDDL `S-...` string.
fn lookup_group_sid_string(group: &str) -> io::Result<String> {
    let name: Vec<u16> = group.encode_utf16().chain([0]).collect();
    let mut sid_len: u32 = 0;
    let mut dom_len: u32 = 0;
    let mut use_kind: SID_NAME_USE = 0;
    // First call sizes the SID and domain buffers (expected to fail).
    // SAFETY: null buffers with zero sizes request the required lengths.
    unsafe {
        LookupAccountNameW(
            ptr::null(),
            name.as_ptr(),
            ptr::null_mut(),
            &mut sid_len,
            ptr::null_mut(),
            &mut dom_len,
            &mut use_kind,
        )
    };
    if sid_len == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut sid = vec![0u8; sid_len as usize];
    let mut domain = vec![0u16; dom_len as usize];
    // SAFETY: buffers are sized per the first call.
    let ok = unsafe {
        LookupAccountNameW(
            ptr::null(),
            name.as_ptr(),
            sid.as_mut_ptr().cast::<c_void>(),
            &mut sid_len,
            domain.as_mut_ptr(),
            &mut dom_len,
            &mut use_kind,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }

    let mut sid_str: *mut u16 = ptr::null_mut();
    // SAFETY: `sid` holds a valid SID; the call allocates a string we free.
    let ok = unsafe { ConvertSidToStringSidW(sid.as_mut_ptr().cast::<c_void>(), &mut sid_str) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `sid_str` is a valid, NUL-terminated wide string.
    let s = unsafe {
        let mut len = 0usize;
        while *sid_str.add(len) != 0 {
            len += 1;
        }
        OsString::from_wide(std::slice::from_raw_parts(sid_str, len))
    };
    // SAFETY: `sid_str` was allocated by `ConvertSidToStringSidW`.
    unsafe { LocalFree(sid_str.cast::<c_void>()) };
    s.into_string()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "non-UTF-16 SID string"))
}
