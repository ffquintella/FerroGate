//! The tray → window control pipe (F23 §3): the tray keeps the stdin of
//! the one main window (and of the admin client) and writes one command per
//! line, so a second "open" raises the window instead of starting another.
//!
//! A closed set of commands, parsed from bounded lines; anything else is
//! ignored. Nothing here can run a command or reach the network.

use std::io::BufRead;

use crate::model::WindowKind;
use crate::notice::Notice;

/// Longest line accepted, in bytes (a notice is far shorter).
pub const MAX_LINE: usize = 4096;

/// One command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// Raise the window and show this tab.
    Show(WindowKind),
    /// Raise the window as it is (the admin client).
    Focus,
    /// Mirror a notice in the window's status bar.
    Notice(Notice),
}

/// The line for `cmd` (newline included).
#[must_use]
pub fn encode(cmd: &Command) -> String {
    match cmd {
        Command::Show(kind) => format!("show {}\n", kind.as_arg()),
        Command::Focus => "focus\n".to_string(),
        Command::Notice(n) => format!("notice {}\n", n.to_wire()),
    }
}

/// Parse one line (without its newline); `None` for anything outside the
/// closed set.
#[must_use]
pub fn decode(line: &str) -> Option<Command> {
    if line.len() > MAX_LINE {
        return None;
    }
    let line = line.trim_end_matches(['\r', '\n']);
    match line.split_once(' ') {
        Some(("show", kind)) => WindowKind::from_arg(kind).map(Command::Show),
        Some(("notice", json)) => Notice::from_wire(json).map(Command::Notice),
        None if line == "focus" => Some(Command::Focus),
        _ => None,
    }
}

/// Read commands from `reader` until it ends, handing each to `on`; an
/// oversized line is skipped whole, never split into commands.
pub fn read_commands(mut reader: impl BufRead, mut on: impl FnMut(Command)) {
    let mut buf = Vec::new();
    loop {
        buf.clear();
        // At most one byte past the limit is kept; the rest of a long line
        // is drained below.
        let limit = u64::try_from(MAX_LINE + 1).unwrap_or(u64::MAX);
        match std::io::Read::take(&mut reader, limit).read_until(b'\n', &mut buf) {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
        if buf.last() != Some(&b'\n') && buf.len() > MAX_LINE {
            // Too long: discard up to the next newline.
            let mut rest = Vec::new();
            loop {
                rest.clear();
                match std::io::Read::take(&mut reader, limit).read_until(b'\n', &mut rest) {
                    Ok(0) | Err(_) => return,
                    Ok(_) if rest.last() == Some(&b'\n') => break,
                    Ok(_) => {}
                }
            }
            continue;
        }
        if let Some(cmd) = std::str::from_utf8(&buf).ok().and_then(decode) {
            on(cmd);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i18n::Lang;

    #[test]
    fn commands_round_trip() {
        let notice = Notice::pending_approvals(2, Lang::Es, 7);
        for cmd in [
            Command::Show(WindowKind::SetupPins),
            Command::Focus,
            Command::Notice(notice),
        ] {
            let line = encode(&cmd);
            assert!(line.ends_with('\n') && line.matches('\n').count() == 1);
            assert_eq!(decode(&line), Some(cmd));
        }
    }

    #[test]
    fn anything_else_is_ignored() {
        for line in [
            "",
            "show",
            "show ../../etc",
            "show status extra",
            "run mia",
            "focus now",
            "notice {",
            "SHOW status",
        ] {
            assert_eq!(decode(line), None, "{line}");
        }
    }

    #[test]
    fn a_stream_yields_its_commands_and_skips_oversized_lines() {
        let long = "x".repeat(MAX_LINE * 3);
        let input = format!("show logs\n{long}\nfocus\nbogus\nshow status");
        let mut got = Vec::new();
        read_commands(input.as_bytes(), |c| got.push(c));
        assert_eq!(
            got,
            vec![
                Command::Show(WindowKind::Logs),
                Command::Focus,
                Command::Show(WindowKind::Status)
            ]
        );
    }
}
