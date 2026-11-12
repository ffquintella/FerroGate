//! Platform-independent pieces of a *blocking* named-pipe client: the
//! local-pipe-name check and a deadline for exchanges on handles that have no
//! read timeout. Pure `std`, no FFI, so it compiles and is unit-tested on
//! every platform; both Windows openers refuse names failing
//! [`is_local_pipe_name`].

use std::ffi::OsStr;
use std::io;
use std::time::Duration;

/// The only accepted pipe-name prefix: a pipe on the local machine.
pub const LOCAL_PIPE_PREFIX: &str = r"\\.\pipe\";

/// The longest accepted full pipe name, in UTF-16 units (the Win32 limit).
pub const MAX_PIPE_NAME_LEN: usize = 256;

/// Whether `name` is a local named pipe, `\\.\pipe\<name>` (prefix case
/// ignored), that `CreateFileW` cannot resolve to anything but a local pipe.
///
/// Fails closed on: a remote `\\host\pipe\…`, the `\\?\` form, any file path;
/// a name holding `\`, `/` or NUL, or equal to `.`/`..` (Win32 normalises
/// `\\.\pipe\..\C:\x` to the *file* `\\.\C:\x`); an empty, non-Unicode or
/// over-long ([`MAX_PIPE_NAME_LEN`]) name.
#[must_use]
pub fn is_local_pipe_name(name: &OsStr) -> bool {
    let Some(name) = name.to_str() else {
        return false;
    };
    let Some(prefix) = name.get(..LOCAL_PIPE_PREFIX.len()) else {
        return false;
    };
    if !prefix.eq_ignore_ascii_case(LOCAL_PIPE_PREFIX) {
        return false;
    }
    let rest = &name[LOCAL_PIPE_PREFIX.len()..];
    !rest.is_empty()
        && rest != "."
        && rest != ".."
        && !rest.contains(['\\', '/', '\0'])
        && name.encode_utf16().count() <= MAX_PIPE_NAME_LEN
}

/// The error for a name that fails [`is_local_pipe_name`]. The name itself is
/// not quoted: it comes from configuration or the environment.
#[must_use]
pub fn not_a_local_pipe() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        r"not a local named pipe (expected \\.\pipe\<name>)",
    )
}

/// Run `f` on a helper thread, giving up after `timeout`: a synchronous pipe
/// handle has no read timeout, so a silent (hung or squatting) server would
/// block forever. The abandoned thread ends when the server closes its end.
///
/// # Errors
///
/// `TimedOut` after `timeout`, the error of `f`, or a spawn/panic error.
pub fn with_deadline<T: Send + 'static>(
    timeout: Duration,
    f: impl FnOnce() -> io::Result<T> + Send + 'static,
) -> io::Result<T> {
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("ferrogate-pipe-io".into())
        .spawn(move || {
            // The receiver is gone after a timeout; nothing left to tell.
            let _ = tx.send(f());
        })?;
    match rx.recv_timeout(timeout) {
        Ok(result) => result,
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "the pipe server did not answer in time",
        )),
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            Err(io::Error::other("the pipe exchange thread panicked"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(name: &str) -> bool {
        is_local_pipe_name(OsStr::new(name))
    }

    #[test]
    fn local_pipe_names_are_accepted() {
        assert!(ok(r"\\.\pipe\ferrogate-mia"));
        assert!(ok(r"\\.\pipe\ferrogate-mia-hml"));
        assert!(ok(r"\\.\pipe\ferrogate-mia.default"));
        assert!(ok(r"\\.\PIPE\ferrogate-mia"));
        assert!(ok(r"\\.\Pipe\x"));
    }

    #[test]
    fn files_remote_pipes_and_traversal_are_refused() {
        for name in [
            "",
            r"C:\ProgramData\FerroGate\mia.toml",
            r"\\server\pipe\ferrogate-mia",
            r"\\?\pipe\ferrogate-mia",
            r"//./pipe/ferrogate-mia",
            r"\\.\pipe\",
            r"\\.\pipe\.",
            r"\\.\pipe\..",
            r"\\.\pipe\..\C:\Windows\win.ini",
            r"\\.\pipe\a\b",
            r"\\.\pipe\a/b",
            "\\\\.\\pipe\\a\0b",
            r"\\.\pip\x",
            "/run/ferrogate/mia.sock",
        ] {
            assert!(!ok(name), "{name:?} must be refused");
        }
    }

    #[test]
    fn overlong_names_are_refused() {
        let at_limit = format!(
            "{LOCAL_PIPE_PREFIX}{}",
            "a".repeat(MAX_PIPE_NAME_LEN - LOCAL_PIPE_PREFIX.len())
        );
        assert!(ok(&at_limit));
        assert!(!ok(&format!("{at_limit}a")));
    }

    #[test]
    fn a_silent_peer_times_out_and_answers_pass_through() {
        let started = std::time::Instant::now();
        let err = with_deadline(Duration::from_millis(50), || {
            std::thread::sleep(Duration::from_secs(5));
            Ok(())
        })
        .expect_err("must time out");
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(4));

        assert_eq!(
            with_deadline(Duration::from_secs(5), || Ok(7)).expect("answer"),
            7
        );
        let err = with_deadline::<()>(Duration::from_secs(5), || {
            Err(io::Error::from(io::ErrorKind::BrokenPipe))
        })
        .expect_err("error passes through");
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
    }
}
