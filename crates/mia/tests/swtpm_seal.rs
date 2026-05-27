//! PCR-bound sealing against a software TPM (`swtpm`), feature F04.
//!
//! Seals a secret to PCRs {0,4,7,8}, unseals it (success), then extends a
//! sealed PCR to simulate a boot-state change and shows the secret no longer
//! unseals — the cache-invalidation property the SVID local cache relies on.
//!
//! Linux-only and requires `swtpm` on `PATH`; skipped otherwise.
#![cfg(target_os = "linux")]

use std::net::TcpStream;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use mia::seal::{seal_secret, seal_svid, unseal_secret, unseal_svid};
use mia::tpm::TpmEngine;

use tss_esapi::handles::PcrHandle;
use tss_esapi::interface_types::algorithm::HashingAlgorithm;
use tss_esapi::structures::{Digest, DigestValues};
use tss_esapi::tcti_ldr::TctiNameConf;

struct Swtpm {
    child: Child,
    port: u16,
    _state: TempDir,
}

struct TempDir(std::path::PathBuf);
impl TempDir {
    fn new(tag: &str) -> std::io::Result<Self> {
        let mut p = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        p.push(format!("ferrogate-{tag}-{nanos}"));
        std::fs::create_dir_all(&p)?;
        Ok(Self(p))
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn which(bin: &str) -> Option<()> {
    Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {bin}"))
        .status()
        .ok()
        .filter(std::process::ExitStatus::success)
        .map(|_| ())
}

impl Swtpm {
    fn start(port: u16) -> Option<Self> {
        which("swtpm")?;
        let state = TempDir::new("swtpm-seal").ok()?;
        let child = Command::new("swtpm")
            .args([
                "socket",
                "--tpm2",
                "--server",
                &format!("type=tcp,port={port},bindaddr=127.0.0.1"),
                "--ctrl",
                &format!("type=tcp,port={},bindaddr=127.0.0.1", port + 1),
                "--tpmstate",
                &format!("dir={}", state.0.display()),
                "--flags",
                "not-need-init,startup-clear",
            ])
            .spawn()
            .ok()?;
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if TcpStream::connect(("127.0.0.1", port)).is_ok() {
                return Some(Self {
                    child,
                    port,
                    _state: state,
                });
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let mut me = Self {
            child,
            port,
            _state: state,
        };
        me.kill();
        None
    }

    fn tcti(&self) -> TctiNameConf {
        format!("swtpm:host=127.0.0.1,port={}", self.port)
            .parse()
            .expect("valid swtpm TCTI")
    }

    fn kill(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
impl Drop for Swtpm {
    fn drop(&mut self) {
        self.kill();
    }
}

fn extend_pcr4(engine: &mut TpmEngine) {
    let mut values = DigestValues::new();
    values.set(
        HashingAlgorithm::Sha384,
        Digest::try_from(vec![0x11u8; 48]).unwrap(),
    );
    let ctx = engine.context_mut();
    ctx.execute_with_nullauth_session(|ctx| ctx.pcr_extend(PcrHandle::Pcr4, values))
        .expect("pcr_extend");
}

#[test]
fn seal_unseal_roundtrips_and_pcr_change_invalidates() {
    let Some(swtpm) = Swtpm::start(2341) else {
        eprintln!("swtpm not available; skipping");
        return;
    };
    let mut engine = TpmEngine::new(swtpm.tcti()).expect("open swtpm");

    let secret = [0xABu8; 32];
    let sealed = seal_secret(&mut engine, &secret).expect("seal");

    // Same PCR state -> unseal succeeds and matches.
    let recovered = unseal_secret(&mut engine, &sealed).expect("unseal");
    assert_eq!(recovered, secret);

    // Change the boot state -> the policy no longer satisfies -> unseal fails.
    extend_pcr4(&mut engine);
    assert!(
        unseal_secret(&mut engine, &sealed).is_err(),
        "unseal must fail after a sealed PCR changes"
    );
}

#[test]
fn seal_svid_blob_roundtrips() {
    let Some(swtpm) = Swtpm::start(2351) else {
        eprintln!("swtpm not available; skipping");
        return;
    };
    let mut engine = TpmEngine::new(swtpm.tcti()).expect("open swtpm");

    let svid = b"compact.jws.svid.and.composite.key.material".repeat(64);
    let sealed = seal_svid(&mut engine, &svid).expect("seal svid");
    let recovered = unseal_svid(&mut engine, &sealed).expect("unseal svid");
    assert_eq!(recovered, svid);
}
