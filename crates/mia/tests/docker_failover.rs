//! Behaviour tests: SRV-discovered CMIS fail-over with **real containers**.
//!
//! A 3-node CMIS cluster (one shared TLS identity ⇒ one SPKI pin), a DNS server
//! publishing `_cmis._tcp.fg.test`, and a probe container driving the production
//! [`mia::endpoint::CmisResolver`] with a real RPC every 500 ms. The test then
//! stops, pauses and kills nodes and asserts the probe is always served by a live
//! one, notices the loss quickly, and returns to the preferred node on recovery.
//!
//! # These tests are expensive and are never part of `make test`
//!
//! They build two images and boot a Raft cluster, so they are `#[ignore]`d. Run
//! them on demand or at release time:
//!
//! ```text
//! make test-failover            # or: cargo test -p mia --test docker_failover -- --ignored --nocapture
//! ```
//!
//! CI runs them from `.github/workflows/failover.yml` on release tags and by
//! manual dispatch only. Environment knobs: `IMAGE` / `PROBE_IMAGE` (use prebuilt
//! images instead of building), `FAILOVER_KEEP=1` (leave the stack up for
//! debugging).

use std::path::{Path, PathBuf};
use std::process::Command;

use std::time::{Duration, Instant};

const PROJECT: &str = "fgfo";
const PREFERRED: &str = "cmis1.fg.test";

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

/// Run a command, returning stdout; panic with its stderr on failure.
fn run(cmd: &str, args: &[&str]) -> String {
    let out = Command::new(cmd)
        .args(args)
        .output()
        .unwrap_or_else(|e| panic!("cannot run {cmd}: {e}"));
    assert!(
        out.status.success(),
        "`{cmd} {}` failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn docker(args: &[&str]) -> String {
    run("docker", args)
}

/// One parsed probe line.
#[derive(Debug, Clone)]
struct Sample {
    ok: bool,
    /// Unix ms.
    at: u128,
    /// Serving endpoint (OK) or error text (ERR).
    detail: String,
    elapsed_ms: u128,
}

fn parse(line: &str) -> Option<Sample> {
    let mut it = line.splitn(3, ' ');
    let kind = it.next()?;
    let at = it.next()?.parse().ok()?;
    let rest = it.next()?;
    let (detail, ms) = rest.rsplit_once(' ')?;
    Some(Sample {
        ok: kind == "OK",
        at,
        detail: detail.to_string(),
        elapsed_ms: ms.parse().ok()?,
    })
}

fn now_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis()
}

/// All probe samples so far.
fn samples() -> Vec<Sample> {
    let out = Command::new("docker")
        .args(["logs", "fgfo-probe"])
        .output()
        .expect("docker logs");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    text.lines().filter_map(parse).collect()
}

/// Poll until a sample at/after `since` satisfies `pred`; returns it and how long
/// it took. Panics with the recent samples on timeout.
fn wait_for(
    what: &str,
    since: u128,
    timeout: Duration,
    pred: impl Fn(&Sample) -> bool,
) -> (Sample, Duration) {
    let started = Instant::now();
    loop {
        if let Some(s) = samples().into_iter().find(|s| s.at >= since && pred(s)) {
            return (s, started.elapsed());
        }
        if started.elapsed() > timeout {
            let tail: Vec<_> = samples().into_iter().rev().take(8).collect();
            panic!("timed out after {timeout:?} waiting for: {what}\nlast samples: {tail:#?}");
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

fn served_by_other_than_preferred(s: &Sample) -> bool {
    s.ok && !s.detail.contains(PREFERRED)
}

/// Assert no probe attempt failed at/after `since`: while any node lives, the
/// resolver must keep serving.
fn assert_no_errors_since(since: u128, context: &str) {
    let errs: Vec<_> = samples()
        .into_iter()
        .filter(|s| s.at >= since && !s.ok)
        .collect();
    assert!(errs.is_empty(), "{context}: probe saw errors: {errs:#?}");
}

struct Stack {
    compose: Vec<String>,
    envs: Vec<(String, String)>,
    keep: bool,
}

impl Stack {
    fn compose(&self, args: &[&str]) -> String {
        let mut cmd = Command::new("docker");
        cmd.args(&self.compose).args(args);
        for (k, v) in &self.envs {
            cmd.env(k, v);
        }
        let out = cmd.output().expect("docker compose");
        assert!(
            out.status.success(),
            "docker compose {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    }
}

impl Drop for Stack {
    fn drop(&mut self) {
        if self.keep {
            eprintln!("FAILOVER_KEEP=1: leaving project `{PROJECT}` up");
            return;
        }
        let mut cmd = Command::new("docker");
        cmd.args(&self.compose)
            .args(["down", "-v", "--remove-orphans"]);
        for (k, v) in &self.envs {
            cmd.env(k, v);
        }
        let _ = cmd.output();
    }
}

/// Generate the shared CMIS identity (one cert for every node ⇒ one pin);
/// return the SPKI pin hex. Uses rcgen so the test needs no `openssl` binary.
fn make_identity(dir: &Path) -> String {
    let ck = rcgen::generate_simple_self_signed(vec![
        "cmis.fg.test".to_string(),
        "cmis1.fg.test".to_string(),
        "cmis2.fg.test".to_string(),
        "cmis3.fg.test".to_string(),
    ])
    .expect("self-signed cert");
    let (crt, key) = (dir.join("cmis.crt"), dir.join("cmis.key"));
    std::fs::write(&crt, ck.cert.pem()).unwrap();
    std::fs::write(&key, ck.signing_key.serialize_pem()).unwrap();
    // Readable by the non-root user inside the CMIS image.
    run(
        "chmod",
        &["644", key.to_str().unwrap(), crt.to_str().unwrap()],
    );
    ferro_crypto::pin::SpkiPin::from_certificate_der(ck.cert.der().as_ref())
        .unwrap()
        .to_hex()
}

fn build_images(root: &Path) -> (String, String) {
    let img = std::env::var("IMAGE").unwrap_or_else(|_| {
        docker(&[
            "build",
            "--platform",
            "linux/amd64",
            "-f",
            "docker/ferrogate.Dockerfile",
            "-t",
            "ferrogate:failover-test",
            root.to_str().unwrap(),
        ]);
        "ferrogate:failover-test".into()
    });
    let probe = std::env::var("PROBE_IMAGE").unwrap_or_else(|_| {
        docker(&[
            "build",
            "-f",
            "docker/failover-test/probe.Dockerfile",
            "-t",
            "ferrogate-failover-probe:failover-test",
            root.to_str().unwrap(),
        ]);
        "ferrogate-failover-probe:failover-test".into()
    });
    (img, probe)
}

#[test]
#[allow(clippy::too_many_lines)] // one linear scenario script
#[ignore = "expensive: builds images and boots a 3-node CMIS cluster in Docker; run via `make test-failover` or at release"]
fn srv_failover_survives_loss_of_nodes() {
    let root = repo_root();
    // Relative paths (compose file, Dockerfiles) resolve from the repo root.
    std::env::set_current_dir(&root).unwrap();
    let tls = std::env::temp_dir().join(format!("fgfo-tls-{}", std::process::id()));
    std::fs::create_dir_all(&tls).unwrap();
    let pin = make_identity(&tls);
    let (image, probe_image) = build_images(&root);

    let stack = Stack {
        compose: [
            "compose",
            "-p",
            PROJECT,
            "-f",
            "docker/failover-test/docker-compose.yml",
        ]
        .map(String::from)
        .to_vec(),
        envs: vec![
            ("IMAGE".into(), image),
            ("PROBE_IMAGE".into(), probe_image),
            ("TLS_DIR".into(), tls.to_string_lossy().into_owned()),
            ("PIN".into(), pin),
        ],
        keep: std::env::var("FAILOVER_KEEP").is_ok_and(|v| v == "1"),
    };
    let _ = Command::new("docker")
        .args(&stack.compose)
        .args(["down", "-v", "--remove-orphans"])
        .output();
    stack.compose(&["up", "-d", "--build"]);

    // ── 0. baseline: cluster boots, the SRV-preferred node serves ────────────
    let (first, took) = wait_for("first successful probe", 0, Duration::from_secs(180), |s| {
        s.ok
    });
    eprintln!("baseline: served by {} after {took:?}", first.detail);
    assert!(
        first.detail.contains(PREFERRED),
        "preferred node should serve first: {first:?}"
    );

    // ── 1. hard-kill the preferred node ──────────────────────────────────────
    let t = now_ms();
    docker(&["kill", "fgfo-cmis1"]);
    let (s, took) = wait_for(
        "fail-over after kill",
        t,
        Duration::from_secs(30),
        served_by_other_than_preferred,
    );
    eprintln!(
        "kill: failed over to {} in {took:?} (probe call took {} ms)",
        s.detail, s.elapsed_ms
    );
    assert!(
        took < Duration::from_secs(15),
        "fail-over too slow: {took:?}"
    );
    std::thread::sleep(Duration::from_secs(5));
    assert_no_errors_since(t, "after killing the preferred node");

    // ── 2. recovery: preferred node returns and takes traffic back ───────────
    let t = now_ms();
    docker(&["start", "fgfo-cmis1"]);
    let (_, took) = wait_for(
        "preferred node serving again",
        t,
        Duration::from_secs(150),
        |s| s.ok && s.detail.contains(PREFERRED),
    );
    eprintln!("recovery: preferred node serving again after {took:?}");

    // ── 3. hung node: process frozen (TCP accepts, nothing answers) ──────────
    let t = now_ms();
    docker(&["pause", "fgfo-cmis1"]);
    let (s, took) = wait_for(
        "fail-over from a paused node",
        t,
        Duration::from_secs(40),
        served_by_other_than_preferred,
    );
    eprintln!("pause: failed over to {} in {took:?}", s.detail);
    assert!(
        took < Duration::from_secs(20),
        "hung-node detection too slow: {took:?}"
    );
    std::thread::sleep(Duration::from_secs(5));
    assert_no_errors_since(t, "while the preferred node is paused");
    docker(&["unpause", "fgfo-cmis1"]);
    wait_for(
        "preferred node back after unpause",
        now_ms(),
        Duration::from_secs(120),
        |s| s.ok && s.detail.contains(PREFERRED),
    );

    // ── 4. two of three nodes lost: the last one must still serve ────────────
    let t = now_ms();
    docker(&["kill", "fgfo-cmis1", "fgfo-cmis2"]);
    wait_for("served by the last node", t, Duration::from_secs(40), |s| {
        s.ok && s.detail.contains("cmis3.fg.test")
    });
    std::thread::sleep(Duration::from_secs(5));
    assert_no_errors_since(t + 15_000, "with a single node left");

    // ── 5. total outage is reported, and service resumes when nodes return ───
    let t = now_ms();
    docker(&["kill", "fgfo-cmis3"]);
    wait_for(
        "probe reports an error with every node down",
        t,
        Duration::from_secs(40),
        |s| !s.ok,
    );
    let t = now_ms();
    docker(&["start", "fgfo-cmis1", "fgfo-cmis2", "fgfo-cmis3"]);
    wait_for(
        "service resumes after the outage",
        t,
        Duration::from_secs(180),
        |s| s.ok,
    );
    eprintln!("all failover scenarios passed");
}
