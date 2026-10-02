//! Access masks and the SDDL DACL for FerroGate's named pipes.
//!
//! Pure data, no FFI, so it compiles (and is unit-tested) on every platform.
//!
//! On a named pipe, `GENERIC_WRITE` maps to `FILE_GENERIC_WRITE`, which
//! includes `FILE_APPEND_DATA` — the same bit as `FILE_CREATE_PIPE_INSTANCE`.
//! A principal holding it can create an *additional server instance* of the
//! pipe and answer other users' connections. Client principals therefore get
//! [`PIPE_CLIENT_ACCESS`] (read + write data, no instance creation); only the
//! server side (SYSTEM, Administrators, and the pipe's owner — the account
//! running the server) keeps `GENERIC_WRITE`.

/// `FILE_READ_DATA`.
const FILE_READ_DATA: u32 = 0x0000_0001;
/// `FILE_WRITE_DATA`.
pub const FILE_WRITE_DATA: u32 = 0x0000_0002;
/// `FILE_APPEND_DATA` — on a named pipe, `FILE_CREATE_PIPE_INSTANCE`.
pub const FILE_CREATE_PIPE_INSTANCE: u32 = 0x0000_0004;
/// `FILE_READ_EA`.
const FILE_READ_EA: u32 = 0x0000_0008;
/// `FILE_READ_ATTRIBUTES`.
const FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;
/// `READ_CONTROL`.
const READ_CONTROL: u32 = 0x0002_0000;
/// `SYNCHRONIZE`.
const SYNCHRONIZE: u32 = 0x0010_0000;
/// `GENERIC_READ`: what a client asks for in `CreateFileW`; the pipe maps it
/// to `FILE_GENERIC_READ`.
pub const GENERIC_READ: u32 = 0x8000_0000;

/// `FILE_GENERIC_READ` — the specific rights `GENERIC_READ` maps to on a pipe.
const FILE_GENERIC_READ: u32 =
    READ_CONTROL | FILE_READ_DATA | FILE_READ_ATTRIBUTES | FILE_READ_EA | SYNCHRONIZE;

/// The rights granted to the pipe's client group: `FILE_GENERIC_READ |
/// FILE_WRITE_DATA` (`0x0012008B`). Deliberately excludes
/// `FILE_CREATE_PIPE_INSTANCE`, `FILE_WRITE_ATTRIBUTES` and `FILE_WRITE_EA`.
pub const PIPE_CLIENT_ACCESS: u32 = FILE_GENERIC_READ | FILE_WRITE_DATA;

/// The desired access a pipe client must request in `CreateFileW` so it
/// stays within [`PIPE_CLIENT_ACCESS`]. Requesting `GENERIC_WRITE` instead
/// would ask for `FILE_APPEND_DATA` too and be denied.
pub const PIPE_CLIENT_DESIRED_ACCESS: u32 = GENERIC_READ | FILE_WRITE_DATA;

/// `SECURITY_IDENTIFICATION` impersonation level for `SECURITY_SQOS` client
/// flags: a pipe server — including one squatting the name — may learn the
/// client's identity but never impersonate it.
pub const SECURITY_IDENTIFICATION: u32 = 0x0001_0000;

/// The pipe DACL in SDDL, with the client group's SID string in place of
/// `group_sid`:
///
/// - `SY` (SYSTEM), `BA` (Administrators), `OW` (Owner Rights — the account
///   that created the pipe, i.e. the server) get `GRGW`, so the server can
///   create further instances;
/// - the client group gets [`PIPE_CLIENT_ACCESS`] only.
///
/// No other principal is granted access.
#[must_use]
pub fn pipe_sddl(group_sid: &str) -> String {
    format!(
        "D:(A;;GRGW;;;SY)(A;;GRGW;;;BA)(A;;GRGW;;;OW)(A;;0x{PIPE_CLIENT_ACCESS:08X};;;{group_sid})"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_access_is_read_plus_write_data() {
        assert_eq!(PIPE_CLIENT_ACCESS, 0x0012_008B);
    }

    #[test]
    fn client_access_cannot_create_pipe_instances() {
        // Nor any write right beyond the data itself.
        const FILE_WRITE_EA: u32 = 0x0000_0010;
        const FILE_WRITE_ATTRIBUTES: u32 = 0x0000_0100;
        const WRITE_DAC: u32 = 0x0004_0000;
        const WRITE_OWNER: u32 = 0x0008_0000;
        assert_eq!(PIPE_CLIENT_ACCESS & FILE_CREATE_PIPE_INSTANCE, 0);
        assert_eq!(
            PIPE_CLIENT_ACCESS & (FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES | WRITE_DAC | WRITE_OWNER),
            0
        );
    }

    #[test]
    fn desired_access_has_no_generic_write() {
        const GENERIC_WRITE: u32 = 0x4000_0000;
        assert_eq!(PIPE_CLIENT_DESIRED_ACCESS & GENERIC_WRITE, 0);
        assert_eq!(PIPE_CLIENT_DESIRED_ACCESS & FILE_CREATE_PIPE_INSTANCE, 0);
    }

    #[test]
    fn sddl_grants_group_only_client_access() {
        let sddl = pipe_sddl("S-1-5-21-1-2-3-1001");
        assert_eq!(
            sddl,
            "D:(A;;GRGW;;;SY)(A;;GRGW;;;BA)(A;;GRGW;;;OW)(A;;0x0012008B;;;S-1-5-21-1-2-3-1001)"
        );
        // The group SID appears in exactly one ACE, and that ACE has no GW.
        let group_ace = sddl
            .split(')')
            .find(|ace| ace.contains("S-1-5-21-1-2-3-1001"))
            .expect("group ACE");
        assert!(!group_ace.contains("GW"));
        assert!(!group_ace.contains("GA"));
    }
}
