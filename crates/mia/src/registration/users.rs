//! Local user lookups for registration requests (F19 §7.2 `target_user`,
//! `requested_by`). Names come from the system user database
//! (`getpwuid_r`/`getpwnam_r` through `nix`), never from the caller.

/// Longest user name carried in a request (F19 §7.2).
const MAX_NAME_CHARS: usize = 256;

/// The user name of `uid`, or `None` when the user database has no entry
/// (the request then carries an empty name; CMIS treats it as absent).
#[must_use]
pub fn name_of(uid: u32) -> Option<String> {
    #[cfg(unix)]
    {
        let user = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid))
            .ok()
            .flatten()?;
        valid(&user.name).then_some(user.name)
    }
    #[cfg(not(unix))]
    {
        let _ = uid;
        None
    }
}

/// The uid of the user called `name`.
#[must_use]
pub fn uid_of(name: &str) -> Option<u32> {
    #[cfg(unix)]
    {
        if !valid(name) {
            return None;
        }
        nix::unistd::User::from_name(name)
            .ok()
            .flatten()
            .map(|u| u.uid.as_raw())
    }
    #[cfg(not(unix))]
    {
        let _ = name;
        None
    }
}

fn valid(name: &str) -> bool {
    !name.is_empty()
        && name.chars().count() <= MAX_NAME_CHARS
        && !name.chars().any(char::is_control)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn root_resolves_both_ways() {
        let name = name_of(0).expect("uid 0 has a passwd entry");
        assert_eq!(uid_of(&name), Some(0));
        assert_eq!(uid_of("no such user \u{7}"), None);
        assert_eq!(uid_of(""), None);
    }
}
