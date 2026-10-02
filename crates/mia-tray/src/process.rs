//! Running a child process with **bounded output and a deadline**.
//!
//! Every `mia` (or service-manager / elevation) invocation goes through
//! [`run_bounded`]: stdin is closed, stdout and stderr are captured up to a
//! byte cap each (the rest is drained and discarded so the child never blocks
//! on a full pipe), and the child is killed when the deadline passes. The tray
//! therefore never hangs on, or buffers unbounded output from, a child.

use std::io::Read;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

/// Output and time bounds for one child.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Bytes kept from stdout and from stderr (each).
    pub max_output: usize,
    /// Wall-clock deadline; the child is killed when it passes.
    pub timeout: Duration,
}

impl Limits {
    /// Short read-only commands (`mia status`, `mia machine-id`, `--check`).
    pub const QUICK: Self = Self {
        max_output: 256 * 1024,
        timeout: Duration::from_secs(20),
    };
    /// Network-bound commands (`mia test`, resync, apply with a key fetch).
    pub const NETWORK: Self = Self {
        max_output: 512 * 1024,
        timeout: Duration::from_secs(90),
    };
    /// Commands behind an OS consent prompt: the person needs time to answer.
    pub const ELEVATED: Self = Self {
        max_output: 512 * 1024,
        timeout: Duration::from_secs(300),
    };
}

/// What a bounded run produced.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Captured {
    /// The exit code (`None` if killed by a signal or by the deadline).
    pub code: Option<i32>,
    /// Captured stdout (at most [`Limits::max_output`] bytes).
    pub stdout: Vec<u8>,
    /// Captured stderr (at most [`Limits::max_output`] bytes).
    pub stderr: Vec<u8>,
    /// Some output was discarded because it exceeded the cap.
    pub truncated: bool,
    /// The deadline passed and the child was killed.
    pub timed_out: bool,
}

impl Captured {
    /// Exited with status 0.
    #[must_use]
    pub fn success(&self) -> bool {
        self.code == Some(0) && !self.timed_out
    }
}

/// Read `r` to EOF keeping at most `cap` bytes; returns (kept, truncated).
fn read_capped(mut r: impl Read, cap: usize) -> (Vec<u8>, bool) {
    let mut kept = Vec::new();
    let mut truncated = false;
    let mut buf = [0u8; 8192];
    loop {
        match r.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                let room = cap.saturating_sub(kept.len());
                if n > room {
                    truncated = true;
                }
                kept.extend_from_slice(&buf[..n.min(room)]);
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
    (kept, truncated)
}

/// Run `cmd` to completion under `limits`. `cmd`'s stdio is overridden (stdin
/// null, stdout/stderr piped). Returns an error only if the child could not be
/// started.
pub fn run_bounded(mut cmd: Command, limits: Limits) -> std::io::Result<Captured> {
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn()?;
    let (tx, rx) = mpsc::channel::<(bool, Vec<u8>, bool)>();
    for (is_out, pipe) in [
        (
            true,
            child
                .stdout
                .take()
                .map(|p| Box::new(p) as Box<dyn Read + Send>),
        ),
        (
            false,
            child
                .stderr
                .take()
                .map(|p| Box::new(p) as Box<dyn Read + Send>),
        ),
    ] {
        if let Some(pipe) = pipe {
            let tx = tx.clone();
            let cap = limits.max_output;
            std::thread::spawn(move || {
                let (kept, truncated) = read_capped(pipe, cap);
                let _ = tx.send((is_out, kept, truncated));
            });
        }
    }
    drop(tx);

    let deadline = Instant::now() + limits.timeout;
    let mut timed_out = false;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break Some(status);
        }
        if Instant::now() >= deadline {
            timed_out = true;
            break None;
        }
        std::thread::sleep(Duration::from_millis(25));
    };
    if timed_out {
        match child.kill() {
            Ok(()) => {
                let _ = child.wait();
            }
            Err(e) => {
                // E.g. `pkexec` has become the root `mia` it launched and
                // cannot be signalled by this user: never block on it — reap
                // it in the background and report the timeout now.
                tracing::warn!(error = %e, "a timed-out child could not be stopped; not waiting for it");
                std::thread::spawn(move || {
                    let _ = child.wait();
                });
            }
        }
    }

    let mut out = Captured {
        code: if timed_out {
            None
        } else {
            status.and_then(|s| s.code())
        },
        timed_out,
        ..Captured::default()
    };
    // A grandchild may keep a pipe open after the child exits; never wait on
    // it for long (the reader thread is then abandoned, its memory bounded).
    let drain_deadline = Instant::now() + Duration::from_secs(2);
    while let Some(left) = drain_deadline.checked_duration_since(Instant::now()) {
        match rx.recv_timeout(left) {
            Ok((true, kept, t)) => {
                out.stdout = kept;
                out.truncated |= t;
            }
            Ok((false, kept, t)) => {
                out.stderr = kept;
                out.truncated |= t;
            }
            Err(_) => break,
        }
    }
    Ok(out)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn sh(script: &str) -> Command {
        let mut c = Command::new("/bin/sh");
        c.arg("-c").arg(script);
        c
    }

    #[test]
    fn captures_output_and_exit_code() {
        let r = run_bounded(sh("echo out; echo err >&2; exit 3"), Limits::QUICK).unwrap();
        assert_eq!(r.code, Some(3));
        assert_eq!(r.stdout, b"out\n");
        assert_eq!(r.stderr, b"err\n");
        assert!(!r.success() && !r.timed_out && !r.truncated);
    }

    #[test]
    fn output_is_capped_and_the_child_is_drained() {
        let limits = Limits {
            max_output: 1000,
            timeout: Duration::from_secs(20),
        };
        // 2 MB of output must neither block the child nor be kept.
        let r = run_bounded(sh("head -c 2000000 /dev/zero"), limits).unwrap();
        assert!(r.success());
        assert_eq!(r.stdout.len(), 1000);
        assert!(r.truncated);
    }

    #[test]
    fn the_deadline_kills_the_child() {
        let limits = Limits {
            max_output: 1000,
            timeout: Duration::from_millis(300),
        };
        let started = Instant::now();
        let r = run_bounded(sh("exec sleep 30"), limits).unwrap();
        assert!(r.timed_out);
        assert_eq!(r.code, None);
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    #[test]
    fn a_missing_program_is_an_error() {
        assert!(run_bounded(Command::new("/nonexistent/mia-tray-test"), Limits::QUICK).is_err());
    }
}
