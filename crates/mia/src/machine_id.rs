//! `mia machine-id` — print this host's machine identity.
//!
//! The machine id is the `<uuid>` in this host's SPIFFE id
//! `spiffe://<trust-domain>/host/<uuid>` — the value CMIS keys the host's
//! signed allowlist and host SVID under. It is derived *locally* from the
//! hardware fingerprint (feature F15):
//!
//! ```text
//! uuid = host_uuid_from_ek_digest( SHA-384(board_serial ‖ platform_uuid ‖ disk_serial) )
//! ```
//!
//! This command is read-only and offline: it collects the fingerprint and
//! prints the derived identity. It never contacts CMIS, reads the daemon's
//! config, or touches the running agent — so it works before enrollment and
//! needs only the ability to read the platform's hardware identifiers.
//!
//! Default output is the bare UUID on one line so it composes in scripts:
//!
//! ```sh
//! ferrogate allowlist set --host "$(mia machine-id)" --bin /usr/bin/app
//! ```
//!
//! `--verbose` additionally prints the SHA-384 fingerprint and the raw hardware
//! facts the fingerprint is built from.

use anyhow::Context as _;

const USAGE: &str = "usage: mia machine-id [--verbose]";

/// Run the `mia machine-id` subcommand. `args` is everything after `machine-id`
/// on the command line.
pub fn run(args: &[String]) -> anyhow::Result<()> {
    let Some(verbose) = parse(args)? else {
        print_help();
        return Ok(());
    };

    // Derive the identity locally from the hardware fingerprint — the same
    // derivation the daemon's host-key attestation and `resync-allowlist` use,
    // so the printed UUID is exactly the `host/<uuid>` CMIS keys this host under.
    let facts =
        ferro_machineid::collect_facts().context("collecting this host's hardware fingerprint")?;
    let fingerprint = facts.fingerprint();
    let uuid = ferro_svid::host_uuid_from_ek_digest(fingerprint.as_bytes()).to_string();

    // A fingerprint built from missing identifiers still yields a deterministic
    // UUID, but it may not be the one CMIS enrolled (and is a weaker identity).
    // Warn on stderr so stdout stays a clean, scriptable value either way.
    if !facts.is_complete() {
        eprintln!(
            "warning: incomplete hardware identifiers (board serial and/or platform UUID are \
             empty); this UUID may not match the one CMIS enrolled for this host."
        );
    }

    if verbose {
        println!("machine-id:  {uuid}");
        println!("fingerprint: {}", fingerprint.to_hex());
        println!("facts:");
        println!("  board-serial:  {}", show(&facts.board_serial));
        println!("  platform-uuid: {}", show(&facts.platform_uuid));
        println!("  disk-serial:   {}", show(&facts.disk_serial));
    } else {
        println!("{uuid}");
    }
    Ok(())
}

/// Parse the command's flags. `Ok(None)` means `--help` was requested (the
/// caller prints the help text); `Ok(Some(verbose))` carries the parsed flags.
fn parse(args: &[String]) -> anyhow::Result<Option<bool>> {
    let mut verbose = false;
    for arg in args {
        match arg.as_str() {
            "-h" | "--help" => return Ok(None),
            "-v" | "--verbose" => verbose = true,
            other => anyhow::bail!("unknown option: {other}\n\n{USAGE}"),
        }
    }
    Ok(Some(verbose))
}

/// Render a hardware identifier for the verbose view, marking an empty one
/// explicitly rather than printing a blank value.
fn show(value: &str) -> &str {
    if value.is_empty() {
        "(empty)"
    } else {
        value
    }
}

fn print_help() {
    println!(
        "mia machine-id — print this host's machine identity\n\
         \n\
         {USAGE}\n\
         \n\
         Prints the <uuid> in this host's SPIFFE id spiffe://<trust-domain>/host/<uuid>,\n\
         derived locally from the hardware fingerprint (feature F15). This is the\n\
         value CMIS keys the host's signed allowlist and host SVID under, e.g.\n\
         \n\
         \x20 ferrogate allowlist set --host \"$(mia machine-id)\" --bin /usr/bin/app\n\
         \n\
         Read-only and offline: it never contacts CMIS or touches the daemon.\n\
         \n\
         options:\n\
         \x20 -v, --verbose  also print the SHA-384 fingerprint and the raw hardware\n\
         \x20                facts (board serial, platform UUID, disk serial)\n\
         \x20 -h, --help     show this help"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_defaults_to_non_verbose() {
        assert_eq!(parse(&[]).unwrap(), Some(false));
    }

    #[test]
    fn parse_accepts_verbose_flags() {
        assert_eq!(parse(&["--verbose".to_string()]).unwrap(), Some(true));
        assert_eq!(parse(&["-v".to_string()]).unwrap(), Some(true));
    }

    #[test]
    fn parse_help_short_circuits() {
        assert_eq!(parse(&["--help".to_string()]).unwrap(), None);
        assert_eq!(parse(&["-h".to_string()]).unwrap(), None);
    }

    #[test]
    fn parse_rejects_unknown_flags() {
        assert!(parse(&["--bogus".to_string()]).is_err());
    }

    #[test]
    fn show_marks_empty_values() {
        assert_eq!(show(""), "(empty)");
        assert_eq!(show("ABC123"), "ABC123");
    }
}
