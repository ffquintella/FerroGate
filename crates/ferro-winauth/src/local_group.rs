//! Create the local groups the MIA's pipe DACLs name (`FerroGateClients` for
//! the helper pipe, `FerroGateStatus` for the status pipe) when they are
//! missing.
//!
//! A pipe whose DACL names a group that does not resolve cannot be created
//! (`ERROR_NONE_MAPPED`), so a host installed from the bare MSI — which, unlike
//! the Chocolatey package, did not create the groups — served no status
//! endpoint at all. The service (LocalSystem) and `mia service secure-config`
//! (run elevated by the installers) now create them.
//!
//! Only a plain local name is ever created: a name with a domain or UPN part
//! (`DOMAIN\group`, `group@domain`) names an account this host does not own,
//! and an existing account of that name — group, alias or user — is left
//! alone. The new group is empty; membership stays an administrator's choice.

/// Why [`ensure_local_group`] would refuse to create a group of this name, or
/// `None` when it may. Pure, so the policy is tested on every platform.
#[must_use]
pub fn creatable_name_problem(name: &str) -> Option<&'static str> {
    if name.trim().is_empty() {
        return Some("the group name is empty");
    }
    if name.trim() != name {
        return Some("the group name has leading or trailing spaces");
    }
    // Local group names may not exceed 256 characters nor contain these
    // (see the NetLocalGroupAdd / LOCALGROUP_INFO_1 documentation).
    if name.chars().count() > 256 {
        return Some("the group name is longer than 256 characters");
    }
    if name.contains(['\\', '@']) {
        return Some("the group name has a domain part; only local groups are created");
    }
    if name
        .chars()
        .any(|c| c.is_control() || "\"/[]:|<>+=;,?*".contains(c))
    {
        return Some("the group name contains a character Windows does not allow");
    }
    if name.chars().all(|c| c == '.' || c == ' ') {
        return Some("the group name consists only of periods and spaces");
    }
    None
}

/// What [`ensure_local_group`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupOutcome {
    /// The name already resolved to an account; nothing was changed.
    Exists,
    /// The local group was created (empty).
    Created,
}

#[cfg(windows)]
pub use imp::ensure_local_group;

#[cfg(windows)]
mod imp {
    use std::io;
    use std::ptr;

    use windows_sys::Win32::Foundation::{ERROR_ALIAS_EXISTS, ERROR_NONE_MAPPED};
    use windows_sys::Win32::NetworkManagement::NetManagement::{
        NERR_GroupExists, NERR_Success, NetLocalGroupAdd, LOCALGROUP_INFO_1,
    };

    use super::{creatable_name_problem, GroupOutcome};

    /// Make sure the local group `name` exists, creating it (empty, with
    /// `comment`) when the name resolves to no account. Needs Administrator
    /// rights (or LocalSystem) to create; an existing name needs none.
    ///
    /// # Errors
    ///
    /// `InvalidInput` for a name [`creatable_name_problem`] refuses, or the
    /// lookup / `NetLocalGroupAdd` error (e.g. access denied when not
    /// elevated).
    pub fn ensure_local_group(name: &str, comment: &str) -> io::Result<GroupOutcome> {
        match crate::imp::lookup_group_sid_string(name) {
            Ok(_) => return Ok(GroupOutcome::Exists),
            Err(e) if e.raw_os_error() == Some(ERROR_NONE_MAPPED.cast_signed()) => {}
            Err(e) => return Err(e),
        }
        if let Some(problem) = creatable_name_problem(name) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("not creating local group {name:?}: {problem}"),
            ));
        }
        let mut wide_name: Vec<u16> = name.encode_utf16().chain([0]).collect();
        let mut wide_comment: Vec<u16> = comment.encode_utf16().chain([0]).collect();
        let info = LOCALGROUP_INFO_1 {
            lgrpi1_name: wide_name.as_mut_ptr(),
            lgrpi1_comment: wide_comment.as_mut_ptr(),
        };
        let mut parm_err: u32 = 0;
        // SAFETY: `info` points at two NUL-terminated UTF-16 buffers that
        // outlive the call; level 1 matches LOCALGROUP_INFO_1; a null server
        // name means the local computer; `parm_err` is a valid out-pointer.
        let status = unsafe {
            NetLocalGroupAdd(
                ptr::null(),
                1,
                ptr::from_ref(&info).cast::<u8>(),
                &mut parm_err,
            )
        };
        if status == NERR_Success {
            Ok(GroupOutcome::Created)
        } else if status == NERR_GroupExists || status == ERROR_ALIAS_EXISTS {
            // Lost a race with another creator: the group exists now.
            Ok(GroupOutcome::Exists)
        } else {
            Err(io::Error::from_raw_os_error(status.cast_signed()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::creatable_name_problem;

    #[test]
    fn plain_local_names_are_creatable() {
        for name in ["FerroGateClients", "FerroGateStatus", "ops team", "a.b-c_d"] {
            assert_eq!(creatable_name_problem(name), None, "{name}");
        }
    }

    #[test]
    fn domain_names_and_bad_characters_are_refused() {
        for name in [
            "",
            "  ",
            " lead",
            "trail ",
            "CORP\\FerroGateClients",
            "clients@corp.example",
            "a/b",
            "a*b",
            "a:b",
            "a\nb",
            "...",
        ] {
            assert!(creatable_name_problem(name).is_some(), "{name:?}");
        }
        assert!(creatable_name_problem(&"x".repeat(257)).is_some());
        assert!(creatable_name_problem(&"x".repeat(256)).is_none());
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::{ensure_local_group, GroupOutcome};

    #[test]
    fn an_existing_account_is_left_alone_without_elevation() {
        // "SYSTEM" always resolves (NT AUTHORITY\SYSTEM) and is not localized,
        // so this needs no rights and changes nothing.
        assert_eq!(
            ensure_local_group("SYSTEM", "").unwrap(),
            GroupOutcome::Exists
        );
    }

    #[test]
    fn a_missing_domain_qualified_name_is_refused() {
        let err = ensure_local_group(r"NO-SUCH-DOMAIN-FG\NoSuchGroupFG", "").unwrap_err();
        assert!(
            err.kind() == std::io::ErrorKind::InvalidInput || err.raw_os_error().is_some(),
            "{err}"
        );
    }
}
