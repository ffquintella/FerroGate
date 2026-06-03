//! `offline-signer` — the FerroGate air-gapped root-key ceremony tool (F14).
//!
//! This binary runs on a hardened, network-less laptop inside a Faraday-shielded
//! room. It drives every step of the annual root rotation:
//!
//! ```text
//! keygen   [--seed <hex32>] --kid K                 derive a root/personal key
//! pubkey   --seed <hex32|@file>                      print the derived pubkey
//! split    --seed <..> --root-kid K --holder N ...   3-of-5 sealed share media
//! combine  --share @f ... | --in-dir D               reconstruct the root seed
//! cross-sign --old-seed <..> --old-kid K \           old↔new cross-sign bundle
//!            --new-seed <..> --new-kid K [--window-days 90]
//! verify-cross --bundle F                            check both directions
//! jwks     --bundle F                                publishable newer-preferred JWKS
//! minutes-new   ... --participant 'name|role|kid|pub' build unsigned minutes
//! minutes-sign  --minutes F --kid K --seed <..>      append a participant signature
//! minutes-verify --minutes F                         require all participants signed
//! destroy  --share @f ...                            zeroize + verify media
//! verify-destruction --share @f ...                  re-audit destroyed media
//! dry-run  --work-dir D                              full ceremony, end to end
//! ```
//!
//! `<hex|@file>` accepts an inline value or `@path` (whitespace-trimmed). All
//! artefacts are plain JSON so they can be photographed, hashed, and entered
//! into the ceremony minutes.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::path::Path;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context as _, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use ferro_ceremony::crosssign::DEFAULT_WINDOW_SECS;
use ferro_ceremony::{
    destroy_media, ArtefactDigest, CeremonyKind, CeremonyMinutes, CrossSignBundle, Participant,
    SealedShare, SealedShareSet, SignedMinutes,
};
use ferro_crypto::composite::{CompositePublicKey, CompositeSecretKey, COMPOSITE_PK_LEN};
use rand_core::{OsRng, RngCore as _};
use sha3::{Digest, Sha3_256};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("offline-signer: {e:#}");
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
        "pubkey" => cmd_pubkey(&opts),
        "split" => cmd_split(&opts),
        "combine" => cmd_combine(&opts),
        "cross-sign" => cmd_cross_sign(&opts),
        "verify-cross" => cmd_verify_cross(&opts),
        "jwks" => cmd_jwks(&opts),
        "minutes-new" => cmd_minutes_new(&opts),
        "minutes-sign" => cmd_minutes_sign(&opts),
        "minutes-verify" => cmd_minutes_verify(&opts),
        "destroy" => cmd_destroy(&opts),
        "verify-destruction" => cmd_verify_destruction(&opts),
        "dry-run" => cmd_dry_run(&opts),
        "-h" | "--help" | "help" => {
            println!("{USAGE}");
            Ok(())
        }
        other => Err(anyhow!("unknown subcommand {other:?}\n\n{USAGE}")),
    }
}

const USAGE: &str = "\
offline-signer — FerroGate air-gapped root-key ceremony tool (F14)

USAGE:
  offline-signer keygen [--seed <hex32>] --kid K
  offline-signer pubkey --seed <hex32|@file>
  offline-signer split  --seed <hex32|@file> --root-kid K --holder N [--holder N ...]
                        [--threshold 3] [--created TS] --out-dir DIR
  offline-signer combine (--share @file [--share @file ...] | --in-dir DIR)
  offline-signer cross-sign --old-seed <..> --old-kid K --new-seed <..> --new-kid K
                        [--window-start TS] [--window-days 90] [--out F]
  offline-signer verify-cross --bundle F
  offline-signer jwks   --bundle F [--out F]
  offline-signer minutes-new --ceremony-id ID --kind rotation|share-refresh|destruction
                        --location L --trust-domain D [--occurred-at TS]
                        [--old-root-kid K] [--new-root-kid K] [--threshold 3] [--total 5]
                        --participant 'name|role|kid|<pubhex|@file>' [--participant ...]
                        [--artefact 'label|@file' ...] [--notes TEXT] [--out F]
  offline-signer minutes-sign  --minutes F --kid K --seed <hex32|@file> [--out F]
  offline-signer minutes-verify --minutes F
  offline-signer destroy --share @file [--share @file ...] [--at TS] [--out F]
  offline-signer verify-destruction --share @file [--share @file ...]
  offline-signer dry-run --work-dir DIR";

// ---------------------------------------------------------------------------
// Option parsing (repeated `--flag value`; some flags may repeat).
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
// Value helpers.
// ---------------------------------------------------------------------------

/// Resolve an inline value or `@path`, trimming whitespace.
fn resolve(value: &str) -> Result<String> {
    if let Some(path) = value.strip_prefix('@') {
        let raw = std::fs::read_to_string(path).with_context(|| format!("read {path}"))?;
        Ok(raw.trim().to_string())
    } else {
        Ok(value.trim().to_string())
    }
}

/// Resolve a 32-byte seed from hex or `@path`.
fn resolve_seed(value: &str) -> Result<[u8; 32]> {
    let s = resolve(value)?;
    let bytes = hex::decode(&s).context("seed is not hex")?;
    bytes
        .try_into()
        .map_err(|_| anyhow!("seed must be 32 bytes (64 hex chars)"))
}

/// Resolve a composite public key from hex or `@path`.
fn resolve_pub(value: &str) -> Result<CompositePublicKey> {
    let s = resolve(value)?;
    let bytes = hex::decode(&s).context("pubkey is not hex")?;
    if bytes.len() != COMPOSITE_PK_LEN {
        bail!(
            "composite pubkey must be {COMPOSITE_PK_LEN} bytes ({} hex chars), got {}",
            COMPOSITE_PK_LEN * 2,
            bytes.len()
        );
    }
    CompositePublicKey::from_concat_bytes(&bytes).map_err(|e| anyhow!("pubkey: {e}"))
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
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

fn sha3_256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha3_256::digest(bytes))
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
    let kid = opts.get("kid")?;
    let (_sk, pk) = CompositeSecretKey::from_seed(&seed);
    println!("kid    {kid}");
    println!("seed   {}", hex::encode(seed));
    println!("pubkey {}", hex::encode(pk.to_concat_bytes()));
    eprintln!(
        "\nStore the seed offline (it is the only secret at rest). The pubkey is \
         what goes into the ceremony minutes and the cross-sign bundle."
    );
    Ok(())
}

fn cmd_pubkey(opts: &Opts) -> Result<()> {
    let seed = resolve_seed(opts.get("seed")?)?;
    let (_sk, pk) = CompositeSecretKey::from_seed(&seed);
    let bytes = pk.to_concat_bytes();
    println!("hex    {}", hex::encode(&bytes));
    println!("b64    {}", STANDARD.encode(&bytes));
    Ok(())
}

fn cmd_split(opts: &Opts) -> Result<()> {
    let seed = resolve_seed(opts.get("seed")?)?;
    let root_kid = opts.get("root-kid")?.to_string();
    let holders: Vec<String> = opts
        .all("holder")
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    if holders.is_empty() {
        bail!("split needs at least one --holder NAME");
    }
    let threshold: usize = match opts.opt("threshold") {
        Some(v) => v.parse().context("--threshold")?,
        None => 3,
    };
    let created = match opts.opt("created") {
        Some(v) => v.parse().context("--created")?,
        None => now_unix(),
    };
    let out_dir = opts.get("out-dir")?;
    std::fs::create_dir_all(out_dir).with_context(|| format!("create {out_dir}"))?;

    let set = SealedShareSet::seal(&root_kid, &seed, threshold, &holders, created)
        .map_err(|e| anyhow!("seal shares: {e}"))?;

    for share in &set.shares {
        let safe_holder: String = share
            .holder
            .chars()
            .map(|c| if c.is_alphanumeric() { c } else { '_' })
            .collect();
        let name = format!("share-{}-{safe_holder}.json", share.index);
        let path = Path::new(out_dir).join(&name);
        std::fs::write(&path, share.to_json().map_err(|e| anyhow!("encode: {e}"))?)
            .with_context(|| format!("write {}", path.display()))?;
        eprintln!(
            "sealed share {} for {} -> {}",
            share.index,
            share.holder,
            path.display()
        );
    }
    eprintln!(
        "\n{}-of-{} split of root {root_kid} complete. Distribute one medium per holder; \
         confidentiality rests on the threshold and physical custody.",
        threshold,
        holders.len()
    );
    Ok(())
}

fn load_shares(opts: &Opts) -> Result<Vec<SealedShare>> {
    let mut shares = Vec::new();
    if let Some(dir) = opts.opt("in-dir") {
        let mut paths: Vec<_> = std::fs::read_dir(dir)
            .with_context(|| format!("read dir {dir}"))?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().is_some_and(|x| x == "json"))
            .collect();
        paths.sort();
        for p in paths {
            let bytes = std::fs::read(&p).with_context(|| format!("read {}", p.display()))?;
            shares
                .push(SealedShare::from_json(&bytes).map_err(|e| anyhow!("{}: {e}", p.display()))?);
        }
    }
    for v in opts.all("share") {
        let path = v.strip_prefix('@').unwrap_or(v);
        let bytes = std::fs::read(path).with_context(|| format!("read {path}"))?;
        shares.push(SealedShare::from_json(&bytes).map_err(|e| anyhow!("{path}: {e}"))?);
    }
    if shares.is_empty() {
        bail!("provide --share @file (repeatable) or --in-dir DIR");
    }
    Ok(shares)
}

fn cmd_combine(opts: &Opts) -> Result<()> {
    let shares = load_shares(opts)?;
    let seed = SealedShareSet::combine(&shares).map_err(|e| anyhow!("combine: {e}"))?;
    let (_sk, pk) = CompositeSecretKey::from_seed(&seed);
    println!(
        "recovered {} share(s) -> root {}",
        shares.len(),
        shares[0].root_kid
    );
    println!("seed   {}", hex::encode(*seed));
    println!("pubkey {}", hex::encode(pk.to_concat_bytes()));
    Ok(())
}

#[allow(clippy::similar_names)]
fn cmd_cross_sign(opts: &Opts) -> Result<()> {
    let old_seed = resolve_seed(opts.get("old-seed")?)?;
    let new_seed = resolve_seed(opts.get("new-seed")?)?;
    let old_kid = opts.get("old-kid")?.to_string();
    let new_kid = opts.get("new-kid")?.to_string();
    let window_start = match opts.opt("window-start") {
        Some(v) => v.parse().context("--window-start")?,
        None => now_unix(),
    };
    let window_secs = match opts.opt("window-days") {
        Some(v) => v.parse::<i64>().context("--window-days")? * 24 * 60 * 60,
        None => DEFAULT_WINDOW_SECS,
    };
    let (old_sk, old_pk) = CompositeSecretKey::from_seed(&old_seed);
    let (new_sk, new_pk) = CompositeSecretKey::from_seed(&new_seed);
    let bundle = CrossSignBundle::create(
        &old_sk,
        &old_kid,
        &old_pk,
        &new_sk,
        &new_kid,
        &new_pk,
        window_start,
        window_secs,
    )
    .map_err(|e| anyhow!("cross-sign: {e}"))?;
    bundle.verify().map_err(|e| anyhow!("self-check: {e}"))?;
    emit(opts, &bundle.to_json().map_err(|e| anyhow!("encode: {e}"))?)
}

fn cmd_verify_cross(opts: &Opts) -> Result<()> {
    let bytes = std::fs::read(opts.get("bundle")?).context("read bundle")?;
    let bundle = CrossSignBundle::from_json(&bytes).map_err(|e| anyhow!("parse: {e}"))?;
    bundle
        .verify()
        .map_err(|e| anyhow!("verification failed: {e}"))?;
    println!(
        "OK  both directions verify\n  old {} <-> new {}\n  window [{}, {})",
        bundle.old_kid, bundle.new_kid, bundle.window_start, bundle.window_end
    );
    Ok(())
}

fn cmd_jwks(opts: &Opts) -> Result<()> {
    let bytes = std::fs::read(opts.get("bundle")?).context("read bundle")?;
    let bundle = CrossSignBundle::from_json(&bytes).map_err(|e| anyhow!("parse: {e}"))?;
    bundle
        .verify()
        .map_err(|e| anyhow!("bundle does not verify: {e}"))?;
    let new_pk = resolve_pub_b64(&bundle.new_pub)?;
    let old_pk = resolve_pub_b64(&bundle.old_pub)?;
    // Newer preferred: the incoming root is stamped with the window start; the
    // outgoing root keeps the older stamp so verifiers list the new one first.
    let keys = vec![
        ferro_svid::Jwk::from_public_key_at(&bundle.new_kid, &new_pk, bundle.window_start),
        ferro_svid::Jwk::from_public_key_at(&bundle.old_kid, &old_pk, bundle.window_start - 1),
    ];
    let set = ferro_svid::JwkSet { keys, crl: None };
    let json = serde_json::to_vec_pretty(&set).context("encode jwks")?;
    emit(opts, &json)
}

fn resolve_pub_b64(b64: &str) -> Result<CompositePublicKey> {
    let bytes = STANDARD.decode(b64.as_bytes()).context("pub base64")?;
    CompositePublicKey::from_concat_bytes(&bytes).map_err(|e| anyhow!("pub: {e}"))
}

fn parse_participant(spec: &str) -> Result<Participant> {
    let parts: Vec<&str> = spec.splitn(4, '|').collect();
    if parts.len() != 4 {
        bail!("participant must be 'name|role|kid|<pubhex|@file>', got {spec:?}");
    }
    let pk = resolve_pub(parts[3])?;
    Ok(Participant {
        name: parts[0].trim().to_string(),
        role: parts[1].trim().to_string(),
        kid: parts[2].trim().to_string(),
        pubkey: STANDARD.encode(pk.to_concat_bytes()),
    })
}

fn parse_kind(s: &str) -> Result<CeremonyKind> {
    match s {
        "rotation" => Ok(CeremonyKind::Rotation),
        "share-refresh" => Ok(CeremonyKind::ShareRefresh),
        "destruction" => Ok(CeremonyKind::Destruction),
        other => bail!("--kind must be rotation|share-refresh|destruction, got {other:?}"),
    }
}

fn cmd_minutes_new(opts: &Opts) -> Result<()> {
    let participants: Vec<Participant> = opts
        .all("participant")
        .iter()
        .map(|s| parse_participant(s))
        .collect::<Result<_>>()?;
    if participants.is_empty() {
        bail!("minutes-new needs at least one --participant");
    }
    let mut artefacts = Vec::new();
    for spec in opts.all("artefact") {
        let (label, file) = spec
            .split_once('|')
            .ok_or_else(|| anyhow!("artefact must be 'label|@file', got {spec:?}"))?;
        let path = file.strip_prefix('@').unwrap_or(file);
        let bytes = std::fs::read(path).with_context(|| format!("read artefact {path}"))?;
        artefacts.push(ArtefactDigest {
            label: label.trim().to_string(),
            sha3_256: sha3_256_hex(&bytes),
        });
    }
    let total = match opts.opt("total") {
        Some(v) => v.parse().context("--total")?,
        None => participants.len(),
    };
    let threshold = match opts.opt("threshold") {
        Some(v) => v.parse().context("--threshold")?,
        None => 3,
    };
    let minutes = CeremonyMinutes {
        version: 1,
        ceremony_id: opts.get("ceremony-id")?.to_string(),
        kind: parse_kind(opts.get("kind")?)?,
        occurred_at: match opts.opt("occurred-at") {
            Some(v) => v.parse().context("--occurred-at")?,
            None => now_unix(),
        },
        location: opts.get("location")?.to_string(),
        trust_domain: opts.get("trust-domain")?.to_string(),
        old_root_kid: opts.opt("old-root-kid").map(str::to_string),
        new_root_kid: opts.opt("new-root-kid").map(str::to_string),
        threshold,
        total,
        participants,
        artefacts,
        notes: opts.opt("notes").unwrap_or("").to_string(),
    };
    let signed = SignedMinutes::new(minutes);
    emit(opts, &signed.to_json().map_err(|e| anyhow!("encode: {e}"))?)
}

fn cmd_minutes_sign(opts: &Opts) -> Result<()> {
    let path = opts.get("minutes")?;
    let bytes = std::fs::read(path).with_context(|| format!("read {path}"))?;
    let mut signed = SignedMinutes::from_json(&bytes).map_err(|e| anyhow!("parse: {e}"))?;
    let kid = opts.get("kid")?;
    let seed = resolve_seed(opts.get("seed")?)?;
    let (sk, _pk) = CompositeSecretKey::from_seed(&seed);
    signed.sign(kid, &sk).map_err(|e| anyhow!("sign: {e}"))?;
    eprintln!(
        "{kid} signed; {}/{} participants now present",
        signed.signed_count(),
        signed.minutes.participants.len()
    );
    let json = signed.to_json().map_err(|e| anyhow!("encode: {e}"))?;
    // Default to overwriting the minutes file in place unless --out is given.
    match opts.opt("out") {
        Some(_) => emit(opts, &json),
        None => std::fs::write(path, &json).with_context(|| format!("write {path}")),
    }
}

fn cmd_minutes_verify(opts: &Opts) -> Result<()> {
    let bytes = std::fs::read(opts.get("minutes")?).context("read minutes")?;
    let signed = SignedMinutes::from_json(&bytes).map_err(|e| anyhow!("parse: {e}"))?;
    signed
        .verify_all()
        .map_err(|e| anyhow!("verification failed: {e}"))?;
    println!(
        "OK  {}  all {} participant(s) signed",
        signed.minutes.ceremony_id,
        signed.minutes.participants.len()
    );
    Ok(())
}

fn cmd_destroy(opts: &Opts) -> Result<()> {
    let at = match opts.opt("at") {
        Some(v) => v.parse().context("--at")?,
        None => now_unix(),
    };
    let mut records = Vec::new();
    for v in opts.all("share") {
        let path = v.strip_prefix('@').unwrap_or(v);
        let record = destroy_media(path, at).map_err(|e| anyhow!("{path}: {e}"))?;
        eprintln!(
            "destroyed share {} ({}) at {path}: {} bytes zeroized, read-back verified",
            record.index, record.holder, record.bytes_zeroized
        );
        records.push(record);
    }
    if records.is_empty() {
        bail!("destroy needs at least one --share @file");
    }
    emit(
        opts,
        &serde_json::to_vec_pretty(&records).context("encode records")?,
    )
}

fn cmd_verify_destruction(opts: &Opts) -> Result<()> {
    let mut n = 0;
    for v in opts.all("share") {
        let path = v.strip_prefix('@').unwrap_or(v);
        ferro_ceremony::verify_destruction(path).map_err(|e| anyhow!("{path}: {e}"))?;
        n += 1;
    }
    if n == 0 {
        bail!("verify-destruction needs at least one --share @file");
    }
    println!("OK  {n} medium/media confirmed irrecoverable");
    Ok(())
}

include!("dry_run.rs");
