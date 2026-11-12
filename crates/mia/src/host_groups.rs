//! The local groups the agent's Windows pipe DACLs name, and creating them
//! when they are missing.
//!
//! The status pipe grants read access to `status.group` (default
//! `FerroGateStatus`) and the helper pipe, when `helper.windows_group` is set,
//! to that group (conventionally `FerroGateClients`). A DACL naming a group
//! that does not resolve cannot be built, so the pipe is never created: the
//! service keeps running but `mia status` and the tray see no agent. The
//! Chocolatey package used to be the only thing creating these groups; a host
//! installed or upgraded from the bare MSI had none of the newer ones.
//!
//! Now the Windows service creates the groups its configuration names at
//! every start, and `mia service secure-config` — run elevated by the MSI and
//! the Chocolatey package — creates them plus the two defaults. Creation is
//! limited to plain local names (see
//! `ferro_winauth::local_group::creatable_name_problem`) and leaves any
//! existing account alone; groups are created empty, so this grants nobody
//! anything.

use crate::config::{Config, DEFAULT_STATUS_GROUP};

/// The conventional helper-pipe group (`helper.windows_group`), created by
/// the installers so an administrator only has to add client accounts.
pub const DEFAULT_HELPER_GROUP: &str = "FerroGateClients";

/// One local group the agent needs, with the comment it is created with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequiredGroup {
    /// The local group name.
    pub name: String,
    /// The group description shown in Computer Management.
    pub comment: &'static str,
}

const HELPER_COMMENT: &str = "FerroGate MIA helper-API clients";
const STATUS_COMMENT: &str = "FerroGate MIA status readers (mia-tray)";

fn push_unique(out: &mut Vec<RequiredGroup>, name: &str, comment: &'static str) {
    let name = name.trim();
    if name.is_empty() || out.iter().any(|g| g.name.eq_ignore_ascii_case(name)) {
        return;
    }
    out.push(RequiredGroup {
        name: name.to_string(),
        comment,
    });
}

/// The groups `configs` name: each enabled status endpoint's `status.group`
/// and each `helper.windows_group`. With `include_defaults`, also the two
/// conventional groups (what the installers create). Names are deduplicated
/// case-insensitively, as Windows account names are.
#[must_use]
pub fn required_groups<'a>(
    configs: impl IntoIterator<Item = &'a Config>,
    include_defaults: bool,
) -> Vec<RequiredGroup> {
    let mut out = Vec::new();
    if include_defaults {
        push_unique(&mut out, DEFAULT_HELPER_GROUP, HELPER_COMMENT);
        push_unique(&mut out, DEFAULT_STATUS_GROUP, STATUS_COMMENT);
    }
    for config in configs {
        if let Some(group) = config.helper.windows_group.as_deref() {
            push_unique(&mut out, group, HELPER_COMMENT);
        }
        if config.status_enabled() {
            push_unique(&mut out, config.status_group(), STATUS_COMMENT);
        }
    }
    out
}

/// What happened to one group in [`ensure`].
#[derive(Debug)]
pub enum GroupReport {
    /// It already existed.
    Exists(String),
    /// It was created.
    Created(String),
    /// It could not be created; the pipe that names it will not come up.
    Failed(String, std::io::Error),
}

/// Create each missing group in `groups` (Windows; elsewhere a no-op that
/// returns nothing). Needs Administrator rights or LocalSystem to create.
#[must_use]
pub fn ensure(groups: &[RequiredGroup]) -> Vec<GroupReport> {
    #[cfg(windows)]
    {
        use ferro_winauth::local_group::{ensure_local_group, GroupOutcome};
        groups
            .iter()
            .map(|g| match ensure_local_group(&g.name, g.comment) {
                Ok(GroupOutcome::Exists) => GroupReport::Exists(g.name.clone()),
                Ok(GroupOutcome::Created) => GroupReport::Created(g.name.clone()),
                Err(e) => GroupReport::Failed(g.name.clone(), e),
            })
            .collect()
    }
    #[cfg(not(windows))]
    {
        let _ = groups;
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(groups: &[RequiredGroup]) -> Vec<&str> {
        groups.iter().map(|g| g.name.as_str()).collect()
    }

    #[test]
    fn a_default_config_needs_only_the_status_group() {
        let c = Config::from_toml("").unwrap();
        assert_eq!(names(&required_groups([&c], false)), [DEFAULT_STATUS_GROUP]);
    }

    #[test]
    fn installers_also_get_the_conventional_helper_group() {
        let c = Config::from_toml("").unwrap();
        assert_eq!(
            names(&required_groups([&c], true)),
            [DEFAULT_HELPER_GROUP, DEFAULT_STATUS_GROUP]
        );
        assert_eq!(
            names(&required_groups(std::iter::empty(), true)),
            [DEFAULT_HELPER_GROUP, DEFAULT_STATUS_GROUP]
        );
    }

    #[test]
    fn configured_groups_are_collected_once_across_environments() {
        let a = Config::from_toml("[helper]\nwindows_group = \"AppClients\"\n").unwrap();
        let b = Config::from_toml(
            "[helper]\nwindows_group = \"appclients\"\n[status]\ngroup = \"Ops\"\n",
        )
        .unwrap();
        assert_eq!(
            names(&required_groups([&a, &b], false)),
            ["AppClients", DEFAULT_STATUS_GROUP, "Ops"]
        );
    }

    #[test]
    fn a_disabled_status_endpoint_needs_no_group() {
        let c = Config::from_toml("[status]\nenable = false\ngroup = \"Ops\"\n").unwrap();
        assert!(required_groups([&c], false).is_empty());
    }
}
