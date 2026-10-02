//! The `mia-tray` binary's own arguments: a closed set.
//!
//! `mia-tray` with no argument runs the tray icon. The tray opens its windows
//! by re-running its own executable with `--window <kind>`, a [`WindowKind`]
//! from a closed set — never with text taken from a menu, a log or the
//! daemon.

use crate::model::WindowKind;

/// What to run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// The tray icon (default).
    Tray,
    /// One window.
    Window(WindowKind),
    /// Print usage.
    Help,
    /// Print the version.
    Version,
}

/// Usage text.
pub const USAGE: &str = "usage: mia-tray [--window <status|recovery|self-test|setup|setup-pins|setup-attestation|logs>]\n\
\n\
FerroGate MIA tray companion. Without arguments it shows the tray icon; the\n\
tray opens its windows with --window. Set MIA_TRAY_LOG (tracing directive,\n\
default info) for its own diagnostics on stderr.";

/// Parse the arguments after the program name.
pub fn parse<I, S>(args: I) -> Result<Mode, String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let args: Vec<String> = args.into_iter().map(|a| a.as_ref().to_string()).collect();
    match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        [] => Ok(Mode::Tray),
        ["-h" | "--help"] => Ok(Mode::Help),
        ["-V" | "--version"] => Ok(Mode::Version),
        ["--window", kind] => WindowKind::from_arg(kind)
            .map(Mode::Window)
            .ok_or_else(|| format!("unknown window kind\n\n{USAGE}")),
        _ => Err(format!("unrecognised arguments\n\n{USAGE}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arguments_are_a_closed_set() {
        assert_eq!(parse::<_, &str>([]), Ok(Mode::Tray));
        assert_eq!(parse(["--help"]), Ok(Mode::Help));
        assert_eq!(parse(["-V"]), Ok(Mode::Version));
        assert_eq!(
            parse(["--window", "logs"]),
            Ok(Mode::Window(WindowKind::Logs))
        );
        assert!(parse(["--window", "../../x"]).is_err());
        assert!(parse(["--window"]).is_err());
        assert!(parse(["--window", "logs", "extra"]).is_err());
        assert!(parse(["status"]).is_err());
    }
}
