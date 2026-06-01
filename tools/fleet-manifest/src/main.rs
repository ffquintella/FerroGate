//! `fleet-manifest` — offline tool to build and sign a FerroGate fleet manifest
//! (feature F13).
//!
//! The manifest enumerates the SHA-384 hashes of every EK certificate an
//! operator has approved for zero-touch enrolment. CMIS checks a host's EK hash
//! against the active manifest at the start of `Attest`, before any TPM
//! verification work runs.
//!
//! The signing key is derived **deterministically** from a 32-byte master seed,
//! so the only secret at rest is that seed; the expanded private key is never
//! written to disk. Production root-key handling (sealing / Shamir split) is the
//! F14 ceremony's job — this tool is the everyday "add/remove a host and
//! re-sign" workflow.
//!
//! ## Subcommands
//!
//! ```text
//! keygen [--seed <hex32>]                       generate/derive a publisher key
//! new    --version N --trust-domain D [--issued-at TS] [--out F]
//! add    --manifest F --ek <hex|@file> [--ek …]  add EK hash(es)
//! remove --manifest F --ek <hex>                 remove an EK hash
//! sign   --manifest F --seed <hex32|@file> --kid K [--out F]
//! verify --signed F --kid K --pub <hex|@file>
//! show   (--manifest F | --signed F)
//! ```
//!
//! `<hex|@file>` accepts an inline lowercase-hex value or `@path` to read it
//! from a file (whitespace-trimmed).

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context as _, Result};
use cmis::fleet_manifest::{FleetManifest, SignedFleetManifest};
use ferro_attest::TrustedKeys;
use ferro_crypto::composite::{CompositePublicKey, CompositeSecretKey};
use rand_core::{OsRng, RngCore as _};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("fleet-manifest: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: &[String]) -> Result<()> {
    let (cmd, rest) = args
        .split_first()
        .ok_or_else(|| anyhow!("missing subcommand\n\n{USAGE}"))?;
    let opts = Opts::parse(rest)?;
    match cmd.as_str() {
        "keygen" => cmd_keygen(&opts),
        "new" => cmd_new(&opts),
        "add" => cmd_add(&opts),
        "remove" => cmd_remove(&opts),
        "sign" => cmd_sign(&opts),
        "verify" => cmd_verify(&opts),
        "show" => cmd_show(&opts),
        "-h" | "--help" | "help" => {
            println!("{USAGE}");
            Ok(())
        }
        other => Err(anyhow!("unknown subcommand {other:?}\n\n{USAGE}")),
    }
}

const USAGE: &str = "\
fleet-manifest — build and sign a FerroGate fleet manifest (F13)

USAGE:
  fleet-manifest keygen [--seed <hex32>]
  fleet-manifest new    --version N --trust-domain D [--issued-at TS] [--out F]
  fleet-manifest add    --manifest F --ek <hex|@file> [--ek …]
  fleet-manifest remove --manifest F --ek <hex>
  fleet-manifest sign   --manifest F --seed <hex32|@file> --kid K [--out F]
  fleet-manifest verify --signed F --kid K --pub <hex|@file>
  fleet-manifest show   (--manifest F | --signed F)";

// ---------------------------------------------------------------------------
// Minimal option parsing: repeated `--flag value` pairs (`--ek` may repeat).
// ---------------------------------------------------------------------------

struct Opts {
    single: BTreeMap<String, String>,
    multi: Vec<(String, String)>,
}

impl Opts {
    fn parse(args: &[String]) -> Result<Self> {
        let mut single = BTreeMap::new();
        let mut multi = Vec::new();
        let mut it = args.iter();
        while let Some(flag) = it.next() {
            let key = flag
                .strip_prefix("--")
                .ok_or_else(|| anyhow!("expected --flag, got {flag:?}"))?;
            let value = it
                .next()
                .ok_or_else(|| anyhow!("flag --{key} needs a value"))?;
            multi.push((key.to_string(), value.clone()));
            single.insert(key.to_string(), value.clone());
        }
        Ok(Self { single, multi })
    }

    fn get(&self, key: &str) -> Result<&str> {
        self.single
            .get(key)
            .map(String::as_str)
            .ok_or_else(|| anyhow!("missing required --{key}"))
    }

    fn opt(&self, key: &str) -> Option<&str> {
        self.single.get(key).map(String::as_str)
    }

    fn all(&self, key: &str) -> Vec<&str> {
        self.multi
            .iter()
            .filter(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Value loading helpers.
// ---------------------------------------------------------------------------

/// Resolve an inline value or `@path` reference, trimming whitespace.
fn resolve(value: &str) -> Result<String> {
    if let Some(path) = value.strip_prefix('@') {
        let raw = std::fs::read_to_string(path).with_context(|| format!("read {path}"))?;
        Ok(raw.trim().to_string())
    } else {
        Ok(value.trim().to_string())
    }
}

/// Decode an EK hash argument and re-encode it canonically (lowercase hex of
/// exactly 48 bytes), rejecting anything else.
fn canonical_ek(value: &str) -> Result<String> {
    let s = resolve(value)?;
    let bytes = hex::decode(&s).with_context(|| format!("ek hash {s:?} is not hex"))?;
    if bytes.len() != 48 {
        bail!("ek hash must be 48 bytes (SHA-384), got {}", bytes.len());
    }
    Ok(hex::encode(bytes))
}

/// Resolve a 32-byte master seed from an inline hex value or `@path`.
fn resolve_seed(value: &str) -> Result<[u8; 32]> {
    let s = resolve(value)?;
    let bytes = hex::decode(&s).context("seed is not hex")?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow!("seed must be 32 bytes (64 hex chars)"))?;
    Ok(arr)
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

fn read_manifest(path: &str) -> Result<FleetManifest> {
    let bytes = std::fs::read(path).with_context(|| format!("read {path}"))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parse manifest {path}"))
}

fn write_manifest(path: &str, manifest: &FleetManifest) -> Result<()> {
    let json = serde_json::to_vec_pretty(manifest).context("encode manifest")?;
    std::fs::write(path, json).with_context(|| format!("write {path}"))
}

/// Write to `--out <file>` if present, else to stdout.
fn emit(opts: &Opts, bytes: &[u8]) -> Result<()> {
    if let Some(path) = opts.opt("out") {
        std::fs::write(path, bytes).with_context(|| format!("write {path}"))?;
        eprintln!("wrote {} bytes to {path}", bytes.len());
    } else {
        use std::io::Write as _;
        std::io::stdout().write_all(bytes)?;
        if !bytes.ends_with(b"\n") {
            println!();
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Subcommands.
// ---------------------------------------------------------------------------

fn cmd_keygen(opts: &Opts) -> Result<()> {
    let seed = if let Some(v) = opts.opt("seed") {
        resolve_seed(v)?
    } else {
        let mut s = [0u8; 32];
        OsRng.fill_bytes(&mut s);
        s
    };
    let (_sk, pk) = CompositeSecretKey::from_seed(&seed);
    println!("seed   {}", hex::encode(seed));
    println!("pubkey {}", hex::encode(pk.to_concat_bytes()));
    eprintln!(
        "\nStore the seed offline. Configure the pubkey into CMIS as \
         CMIS_FLEET_SIGNER_PUB and pick a kid for CMIS_FLEET_SIGNER_KID / \
         `sign --kid`."
    );
    Ok(())
}

fn cmd_new(opts: &Opts) -> Result<()> {
    let version: u64 = opts.get("version")?.parse().context("--version")?;
    let trust_domain = opts.get("trust-domain")?.to_string();
    let issued_at = match opts.opt("issued-at") {
        Some(v) => v.parse().context("--issued-at")?,
        None => now_unix(),
    };
    let manifest = FleetManifest {
        version,
        trust_domain,
        issued_at,
        enrolled_ek_sha384: Vec::new(),
    };
    match opts.opt("out") {
        Some(path) => {
            write_manifest(path, &manifest)?;
            eprintln!("wrote manifest v{version} to {path}");
            Ok(())
        }
        None => emit(opts, &serde_json::to_vec_pretty(&manifest)?),
    }
}

fn cmd_add(opts: &Opts) -> Result<()> {
    let path = opts.get("manifest")?;
    let mut manifest = read_manifest(path)?;
    let eks = opts.all("ek");
    if eks.is_empty() {
        bail!("add needs at least one --ek <hex|@file>");
    }
    let mut added = 0usize;
    for ek in eks {
        let canon = canonical_ek(ek)?;
        if manifest.enrolled_ek_sha384.iter().any(|e| e == &canon) {
            eprintln!("already enrolled: {canon}");
        } else {
            manifest.enrolled_ek_sha384.push(canon);
            added += 1;
        }
    }
    manifest.enrolled_ek_sha384.sort();
    write_manifest(path, &manifest)?;
    eprintln!(
        "added {added}; manifest now has {} enrolled host(s)",
        manifest.enrolled_ek_sha384.len()
    );
    Ok(())
}

fn cmd_remove(opts: &Opts) -> Result<()> {
    let path = opts.get("manifest")?;
    let mut manifest = read_manifest(path)?;
    let target = canonical_ek(opts.get("ek")?)?;
    let before = manifest.enrolled_ek_sha384.len();
    manifest.enrolled_ek_sha384.retain(|e| e != &target);
    let removed = before - manifest.enrolled_ek_sha384.len();
    if removed == 0 {
        bail!("ek hash not present in manifest: {target}");
    }
    write_manifest(path, &manifest)?;
    eprintln!(
        "removed {target}; manifest now has {} enrolled host(s)",
        manifest.enrolled_ek_sha384.len()
    );
    Ok(())
}

fn cmd_sign(opts: &Opts) -> Result<()> {
    let manifest = read_manifest(opts.get("manifest")?)?;
    // Re-resolve every EK hash to reject a hand-edited manifest before signing.
    for ek in &manifest.enrolled_ek_sha384 {
        canonical_ek(ek)?;
    }
    let seed = resolve_seed(opts.get("seed")?)?;
    let kid = opts.get("kid")?.to_string();
    let (sk, _pk) = CompositeSecretKey::from_seed(&seed);
    let signed = SignedFleetManifest::sign(manifest, kid, &sk).context("sign manifest")?;
    let json = serde_json::to_vec_pretty(&signed).context("encode signed manifest")?;
    emit(opts, &json)
}

fn cmd_verify(opts: &Opts) -> Result<()> {
    let bytes = std::fs::read(opts.get("signed")?).context("read signed manifest")?;
    let signed = SignedFleetManifest::from_json(&bytes).context("parse signed manifest")?;
    let kid = opts.get("kid")?;
    if signed.signer_kid != kid {
        bail!(
            "signer_kid mismatch: manifest says {:?}, expected {kid:?}",
            signed.signer_kid
        );
    }
    let pub_bytes = hex::decode(resolve(opts.get("pub")?)?).context("--pub is not hex")?;
    let pk = CompositePublicKey::from_concat_bytes(&pub_bytes)
        .map_err(|e| anyhow!("--pub: {e}"))?;
    let mut trust = TrustedKeys::new();
    trust.add(kid, pk);
    let manifest = signed.verify(&trust).context("signature verification")?;
    println!(
        "OK  v{}  trust-domain={}  {} enrolled host(s)",
        manifest.version,
        manifest.trust_domain,
        manifest.enrolled_ek_sha384.len()
    );
    Ok(())
}

fn cmd_show(opts: &Opts) -> Result<()> {
    let manifest = if let Some(path) = opts.opt("signed") {
        let bytes = std::fs::read(path).with_context(|| format!("read {path}"))?;
        SignedFleetManifest::from_json(&bytes)?.manifest
    } else if let Some(path) = opts.opt("manifest") {
        read_manifest(path)?
    } else {
        bail!("show needs --manifest <file> or --signed <file>");
    };
    println!("version       {}", manifest.version);
    println!("trust_domain  {}", manifest.trust_domain);
    println!("issued_at     {}", manifest.issued_at);
    println!("enrolled      {}", manifest.enrolled_ek_sha384.len());
    for ek in &manifest.enrolled_ek_sha384 {
        println!("  {ek}");
    }
    Ok(())
}
