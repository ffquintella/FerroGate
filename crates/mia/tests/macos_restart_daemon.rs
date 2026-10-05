//! Behaviour of the macOS package's `restart-daemon` script
//! (`dist/macos-scripts/restart-daemon`, run by `postinstall`), driven against
//! a stub `launchctl` that records its calls. Runs on any Unix: the script is
//! POSIX `sh` and only reaches launchd through `launchctl` on `PATH`.
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

const SCRIPT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/dist/macos-scripts/restart-daemon"
);
const SERVICE: &str = "system/com.ferrogate.mia";

/// A stub `launchctl`: `print` succeeds while `loaded` exists, `bootout`
/// removes it, `bootstrap` creates it (or fails while `fail-bootstrap`
/// exists). Every call is appended to `calls`.
const STUB: &str = r#"#!/bin/sh
echo "$*" >> "$STUB_DIR/calls"
case "$1" in
  print) [ -f "$STUB_DIR/loaded" ] ;;
  bootout) rm -f "$STUB_DIR/loaded" ;;
  bootstrap) [ -f "$STUB_DIR/fail-bootstrap" ] && exit 5; touch "$STUB_DIR/loaded" ;;
esac
"#;

struct Harness {
    dir: PathBuf,
}

impl Harness {
    fn new(name: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("mia-restart-daemon-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let stub = dir.join("launchctl");
        std::fs::write(&stub, STUB).unwrap();
        std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();
        Self { dir }
    }

    fn touch(&self, name: &str) -> PathBuf {
        let p = self.dir.join(name);
        std::fs::write(&p, b"").unwrap();
        p
    }

    fn plist(&self) -> PathBuf {
        self.dir.join("com.ferrogate.mia.plist")
    }

    /// Run the script; returns (stdout, launchctl calls).
    fn run(&self) -> (String, Vec<String>) {
        let path = format!(
            "{}:{}",
            self.dir.display(),
            std::env::var("PATH").unwrap_or_default()
        );
        let out = Command::new(SCRIPT)
            .arg(self.plist())
            .env("PATH", path)
            .env("STUB_DIR", &self.dir)
            .output()
            .expect("restart-daemon runs");
        assert!(out.status.success(), "restart-daemon must always exit 0");
        let calls = std::fs::read_to_string(self.dir.join("calls")).unwrap_or_default();
        (
            String::from_utf8(out.stdout).unwrap().trim().to_string(),
            calls.lines().map(str::to_string).collect(),
        )
    }

    fn is_loaded(&self) -> bool {
        Path::exists(&self.dir.join("loaded"))
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[test]
fn script_is_executable() {
    // postinstall invokes it directly; pkgbuild keeps the mode from the tree.
    let mode = std::fs::metadata(SCRIPT).unwrap().permissions().mode();
    assert_ne!(mode & 0o111, 0, "restart-daemon must be executable");
}

#[test]
fn unloaded_daemon_is_left_unloaded() {
    let h = Harness::new("unloaded");
    h.touch("com.ferrogate.mia.plist");
    let (out, calls) = h.run();
    assert_eq!(out, "not-loaded");
    assert_eq!(calls, [format!("print {SERVICE}")]);
    assert!(!h.is_loaded());
}

#[test]
fn loaded_daemon_is_booted_out_then_bootstrapped_from_the_plist() {
    let h = Harness::new("loaded");
    h.touch("loaded");
    let plist = h.touch("com.ferrogate.mia.plist");
    let (out, calls) = h.run();
    assert_eq!(out, "restarted");
    assert_eq!(
        calls,
        [
            format!("print {SERVICE}"),
            format!("bootout {SERVICE}"),
            format!("print {SERVICE}"),
            format!("bootstrap system {}", plist.display()),
        ]
    );
    assert!(h.is_loaded());
}

#[test]
fn missing_plist_never_tears_down_the_running_daemon() {
    let h = Harness::new("noplist");
    h.touch("loaded");
    let (out, calls) = h.run();
    assert_eq!(out, "failed");
    assert_eq!(calls, [format!("print {SERVICE}")]);
    assert!(h.is_loaded());
}

#[test]
fn failed_bootstrap_is_retried_then_reported_without_failing() {
    let h = Harness::new("bootfail");
    h.touch("loaded");
    h.touch("fail-bootstrap");
    h.touch("com.ferrogate.mia.plist");
    let (out, calls) = h.run();
    assert_eq!(out, "failed");
    assert_eq!(
        calls.iter().filter(|c| c.starts_with("bootstrap ")).count(),
        3
    );
}
