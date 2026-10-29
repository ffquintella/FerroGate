//! The `mia-tray-admin` binary's own arguments: a closed set.
//!
//! The tray starts the admin client with a fixed command line and nothing
//! flows back (F22 §1): no argument ever carries text from a menu, a log or
//! the daemon, and none carries a credential.

use crate::actions::EnvName;

/// What to run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mode {
    /// The administrator window, optionally for one environment.
    Run {
        /// The environment whose CMIS to sign in to, when several are
        /// configured.
        environment: Option<EnvName>,
    },
    /// Print usage.
    Help,
    /// Print the version.
    Version,
}

/// Usage text.
pub const USAGE: &str = "usage: mia-tray-admin [--environment <name>]\n\
\n\
FerroGate administrator client. Sign in to CMIS with your password and a\n\
second factor to approve applications. Credentials are kept in memory only\n\
and wiped on sign-out, lock and exit. Set MIA_TRAY_LOG (tracing directive,\n\
default info) for diagnostics on stderr.";

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
        [] => Ok(Mode::Run { environment: None }),
        ["-h" | "--help"] => Ok(Mode::Help),
        ["-V" | "--version"] => Ok(Mode::Version),
        ["--environment", name] => EnvName::parse(name)
            .map(|env| Mode::Run {
                environment: Some(env),
            })
            .map_err(|_| format!("invalid environment name\n\n{USAGE}")),
        _ => Err(format!("unrecognised arguments\n\n{USAGE}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arguments_are_a_closed_set() {
        assert_eq!(parse::<_, &str>([]), Ok(Mode::Run { environment: None }));
        assert_eq!(parse(["--help"]), Ok(Mode::Help));
        assert_eq!(parse(["-V"]), Ok(Mode::Version));
        let Ok(Mode::Run {
            environment: Some(env),
        }) = parse(["--environment", "prod"])
        else {
            panic!("a valid environment is accepted");
        };
        assert_eq!(env.as_str(), "prod");
        assert!(parse(["--environment", "--reload"]).is_err());
        assert!(parse(["--environment", "../x"]).is_err());
        assert!(parse(["--environment"]).is_err());
        assert!(parse(["--environment", "prod", "extra"]).is_err());
        assert!(parse(["--window", "logs"]).is_err());
        assert!(parse(["--password", "hunter2"]).is_err());
    }

    #[test]
    fn a_rejected_argument_is_never_echoed() {
        let err = parse(["--password", "hunter2-secret"]).unwrap_err();
        assert!(!err.contains("hunter2-secret"));
    }
}
