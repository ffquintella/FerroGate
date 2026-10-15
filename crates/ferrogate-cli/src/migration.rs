//! `ferrogate admin migrate-allowlists` and `ferrogate admin
//! set-allowlist-mode`: the F19 §11 migration from legacy allowlists to
//! approvals.
//!
//! - `migrate-allowlists [--dry-run]` → `ImportLegacyAllowlists`. Every
//!   legacy entry becomes an any-path, manual-each-time approval without
//!   expiry ("legacy, no expiry"), and an import whose entry left the legacy
//!   body is revoked; the dry run prints the same report and writes
//!   nothing. Re-running creates and revokes nothing new.
//! - `set-allowlist-mode legacy|approvals [--yes] [--allow-unimported]` →
//!   `SetAllowlistMode`, always first as a dry run so the operator sees what
//!   the switch changes. Switching to `approvals` with legacy entries not
//!   imported is refused unless `--allow-unimported`; switching back to
//!   `legacy` (a rollback) asks for confirmation, or needs `--yes` when
//!   standard input is not a terminal.
//!
//! Both need a platform operator and a recent step-up (the shared
//! dispatcher in [`crate::admin`] handles `step_up_required`). Arguments are
//! parsed before any sign-in, so a typo never costs a TOTP code.

use ferro_proto::admin_v1::{
    ImportLegacyAllowlistsRequest, ImportLegacyAllowlistsResponse, SetAllowlistModeRequest,
};

use crate::admin::{printable, Admin, Prompter};
use crate::rpc_err;

/// The usage lines of the two commands (part of `ferrogate admin help`).
pub(crate) const USAGE: &str = "\
\x20 migrate-allowlists [--dry-run]  import every legacy allowlist entry as an\n\
\x20                               approval (legacy, no expiry); --dry-run only reports\n\
\x20 set-allowlist-mode legacy|approvals [--yes] [--allow-unimported]\n\
\x20                               switch the cluster's allowlist mode (F19 §11);\n\
\x20                               going back to legacy asks for confirmation";

/// Wire code of a mode name.
fn mode_code(name: &str) -> anyhow::Result<u32> {
    Ok(match name {
        "legacy" => 1,
        "approvals" => 2,
        other => anyhow::bail!("unknown allowlist mode `{other}` (legacy, approvals)"),
    })
}

/// Name of a mode code.
pub(crate) fn mode_name(code: u32) -> &'static str {
    match code {
        1 => "legacy",
        2 => "approvals",
        _ => "?",
    }
}

/// A parsed migration command.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Command {
    /// `migrate-allowlists`.
    Import {
        /// Report only.
        dry_run: bool,
    },
    /// `set-allowlist-mode`.
    SetMode {
        /// Target mode code.
        mode: u32,
        /// Confirm a rollback without asking.
        yes: bool,
        /// Switch to approvals although entries are not imported.
        allow_unimported: bool,
    },
}

/// Parses `migrate-allowlists …` / `set-allowlist-mode …` without touching
/// the network.
pub(crate) fn parse(sub: &str, args: &[String]) -> anyhow::Result<Command> {
    let mut positional = Vec::new();
    let (mut dry_run, mut yes, mut allow_unimported) = (false, false, false);
    for a in args {
        match (sub, a.as_str()) {
            ("migrate-allowlists", "--dry-run") => dry_run = true,
            ("set-allowlist-mode", "--yes" | "-y") => yes = true,
            ("set-allowlist-mode", "--allow-unimported") => allow_unimported = true,
            (_, flag) if flag.starts_with('-') => {
                anyhow::bail!("unknown option {flag} for `admin {sub}`\n\n{USAGE}")
            }
            _ => positional.push(a.as_str()),
        }
    }
    match sub {
        "migrate-allowlists" if positional.is_empty() => Ok(Command::Import { dry_run }),
        "set-allowlist-mode" => match positional.as_slice() {
            [mode] => Ok(Command::SetMode {
                mode: mode_code(mode)?,
                yes,
                allow_unimported,
            }),
            _ => anyhow::bail!("set-allowlist-mode needs exactly one of legacy, approvals"),
        },
        _ => anyhow::bail!("`admin {sub}` takes no positional argument\n\n{USAGE}"),
    }
}

/// Runs a parsed migration command on a signed-in admin client.
pub(crate) async fn run(
    admin: &mut Admin,
    cmd: Command,
    prompter: &Prompter,
) -> anyhow::Result<()> {
    match cmd {
        Command::Import { dry_run } => import(admin, dry_run).await,
        Command::SetMode {
            mode,
            yes,
            allow_unimported,
        } => set_mode(admin, mode, yes, allow_unimported, prompter).await,
    }
}

fn print_report(r: &ImportLegacyAllowlistsResponse) {
    if r.dry_run {
        println!("dry run: nothing was written");
    }
    for h in &r.hosts {
        let host = printable(&h.host_uuid);
        if !h.skipped.is_empty() {
            println!(
                "host {host}: skipped ({}), nothing imported{}",
                printable(&h.skipped),
                if h.stale_imports > 0 {
                    format!(
                        "; {} earlier import(s) left open until the body is fixed or deleted",
                        h.stale_imports
                    )
                } else {
                    String::new()
                }
            );
            continue;
        }
        if r.dry_run {
            println!(
                "host {host}: {} to create, {} already imported, {} stale import(s) to revoke",
                h.entries_to_create, h.entries_already_imported, h.stale_imports
            );
        } else {
            println!(
                "host {host}: {} approvals created, {} already imported, {} stale import(s) \
                 revoked{}",
                h.approvals_created,
                h.entries_already_imported,
                h.imports_revoked,
                if h.allowlist_generation == 0 {
                    String::new()
                } else {
                    format!(" (allowlist generation {})", h.allowlist_generation)
                }
            );
        }
        if h.entries_revoked > 0 {
            println!(
                "  {} entr(y/ies) of the body were revoked after an earlier import and are \
                 not recreated (register them anew if still wanted)",
                h.entries_revoked
            );
        }
        for e in &h.entries {
            println!(
                "  uid={:<7} bin_sha={}  legacy, no expiry{}",
                e.uid.map_or_else(|| "*".to_string(), |u| u.to_string()),
                printable(&e.bin_sha),
                if e.revoked {
                    "  [revoked]"
                } else if e.already_imported {
                    "  [already imported]"
                } else {
                    ""
                }
            );
        }
    }
    if r.hosts_truncated || r.entries_truncated {
        println!("(report truncated; the totals are complete)");
    }
    if r.dry_run {
        println!(
            "total: {} to create, {} already imported, {} stale import(s) to revoke, {} host(s) \
             skipped",
            r.entries_to_create, r.entries_already_imported, r.stale_imports, r.hosts_skipped
        );
        println!("Run `ferrogate admin migrate-allowlists` without --dry-run to import.");
    } else {
        println!(
            "total: {} approvals created, {} already imported, {} stale import(s) revoked, {} \
             host(s) skipped",
            r.approvals_created, r.entries_already_imported, r.imports_revoked, r.hosts_skipped
        );
        if r.stale_imports > 0 {
            println!(
                "{} stale import(s) stay open on skipped hosts: fix or delete those legacy \
                 bodies, then re-run",
                r.stale_imports
            );
        }
    }
}

async fn import(admin: &mut Admin, dry_run: bool) -> anyhow::Result<()> {
    let r = admin
        .import_legacy_allowlists(ImportLegacyAllowlistsRequest {
            idempotency_key: uuid::Uuid::new_v4().to_string(),
            dry_run,
        })
        .await
        .map_err(rpc_err)?
        .into_inner();
    print_report(&r);
    Ok(())
}

async fn set_mode(
    admin: &mut Admin,
    mode: u32,
    yes: bool,
    allow_unimported: bool,
    prompter: &Prompter,
) -> anyhow::Result<()> {
    let request = |dry_run: bool| SetAllowlistModeRequest {
        idempotency_key: uuid::Uuid::new_v4().to_string(),
        mode,
        dry_run,
        confirm_rollback: !dry_run && mode == 1,
        allow_unimported,
    };
    let dry = admin
        .set_allowlist_mode(request(true))
        .await
        .map_err(rpc_err)?
        .into_inner();
    if dry.previous_mode == mode {
        println!(
            "allowlist mode is already {}; nothing changed",
            mode_name(mode)
        );
        return Ok(());
    }
    if mode == 2 && dry.stale_imports > 0 {
        anyhow::bail!(
            "{} legacy import(s) are still open although their entry left the legacy \
             allowlist; run `ferrogate admin migrate-allowlists` (it revokes them) first",
            dry.stale_imports
        );
    }
    if mode == 2 && dry.hosts_not_imported > 0 {
        eprintln!(
            "warning: {} legacy entr(y/ies) on {} host(s) have no approval; in approvals mode \
             those callers are denied",
            dry.entries_not_imported, dry.hosts_not_imported
        );
        if !allow_unimported {
            anyhow::bail!(
                "run `ferrogate admin migrate-allowlists` first, or pass --allow-unimported"
            );
        }
    }
    if mode == 1 {
        println!("rolling back to legacy mode: the preserved legacy allowlists are served again.");
        println!(
            "  {} approval(s) created since the switch will not be reflected (their callers \
             are denied);",
            dry.approvals_not_reflected
        );
        println!(
            "  {} legacy import(s) revoked or expired since the import are admitted again.",
            dry.imports_readmitted
        );
        if !yes {
            if !prompter.is_tty() {
                anyhow::bail!("a rollback needs confirmation: re-run with --yes");
            }
            if !prompter.confirm("Switch the cluster back to legacy mode?")? {
                anyhow::bail!("rollback cancelled; nothing changed");
            }
        }
    }
    let r = admin
        .set_allowlist_mode(request(false))
        .await
        .map_err(rpc_err)?
        .into_inner();
    println!(
        "allowlist mode: {} -> {}",
        mode_name(r.previous_mode),
        mode_name(r.mode)
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(s: &str) -> Vec<String> {
        s.split_whitespace().map(str::to_string).collect()
    }

    #[test]
    fn commands_parse_before_any_sign_in() {
        assert_eq!(
            parse("migrate-allowlists", &args("--dry-run")).unwrap(),
            Command::Import { dry_run: true }
        );
        assert_eq!(
            parse("migrate-allowlists", &[]).unwrap(),
            Command::Import { dry_run: false }
        );
        assert_eq!(
            parse("set-allowlist-mode", &args("legacy --yes")).unwrap(),
            Command::SetMode {
                mode: 1,
                yes: true,
                allow_unimported: false
            }
        );
        assert_eq!(
            parse("set-allowlist-mode", &args("--allow-unimported approvals")).unwrap(),
            Command::SetMode {
                mode: 2,
                yes: false,
                allow_unimported: true
            }
        );
        assert!(parse("set-allowlist-mode", &args("sideways")).is_err());
        assert!(parse("set-allowlist-mode", &[]).is_err());
        assert!(parse("set-allowlist-mode", &args("legacy approvals")).is_err());
        assert!(parse("migrate-allowlists", &args("--yes")).is_err());
        assert!(parse("migrate-allowlists", &args("now")).is_err());
        assert_eq!(mode_name(2), "approvals");
        assert_eq!(mode_name(0), "?");
    }
}
