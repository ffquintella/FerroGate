// Full end-to-end ceremony dry-run, included into `main.rs`.
//
// `dry-run` exercises every step of an annual rotation against a scratch
// directory with five synthetic operators, leaving the artefacts on disk for
// inspection. It is the executable form of the F14 "staging dry-run" acceptance
// criterion and is what the CLI integration test drives.

struct DryRunOperator {
    name: String,
    role: String,
    kid: String,
    seed: [u8; 32],
    pubkey: CompositePublicKey,
}

fn random_seed() -> [u8; 32] {
    let mut s = [0u8; 32];
    OsRng.fill_bytes(&mut s);
    s
}

#[allow(clippy::too_many_lines, clippy::similar_names)]
fn cmd_dry_run(opts: &Opts) -> Result<()> {
    let work = opts.get("work-dir")?;
    let root = Path::new(work);
    std::fs::create_dir_all(root).with_context(|| format!("create {work}"))?;
    let old_dir = root.join("old-shares");
    let new_dir = root.join("new-shares");
    std::fs::create_dir_all(&old_dir).ok();
    std::fs::create_dir_all(&new_dir).ok();

    let now = match opts.opt("now") {
        Some(v) => v.parse().context("--now")?,
        None => now_unix(),
    };
    let threshold = 3usize;

    println!("== FerroGate root-key ceremony dry-run ==\nwork-dir: {work}\n");

    // ----- Operators (5 share holders / signers) --------------------------
    let roles = ["share-holder", "share-holder", "share-holder", "witness", "ceremony-lead"];
    let operators: Vec<DryRunOperator> = (1..=5)
        .map(|i| {
            let seed = random_seed();
            let (_sk, pubkey) = CompositeSecretKey::from_seed(&seed);
            DryRunOperator {
                name: format!("operator-{i}"),
                role: roles[i - 1].to_string(),
                kid: format!("op-{i}"),
                seed,
                pubkey,
            }
        })
        .collect();
    let holders: Vec<String> = operators.iter().map(|o| o.name.clone()).collect();
    println!("[1/8] {} operators provisioned (3-of-5 quorum)", operators.len());

    // ----- Roots ----------------------------------------------------------
    let old_seed = random_seed();
    let new_seed = random_seed();
    let old_kid = "root-2025";
    let new_kid = "root-2026";
    let (old_sk, old_pk) = CompositeSecretKey::from_seed(&old_seed);
    let (new_sk, new_pk) = CompositeSecretKey::from_seed(&new_seed);
    println!("[2/8] outgoing root {old_kid} and incoming root {new_kid} derived");

    // ----- Split both roots into sealed media -----------------------------
    let old_set = SealedShareSet::seal(old_kid, &old_seed, threshold, &holders, now - DEFAULT_WINDOW_SECS)
        .map_err(|e| anyhow!("seal old: {e}"))?;
    let new_set = SealedShareSet::seal(new_kid, &new_seed, threshold, &holders, now)
        .map_err(|e| anyhow!("seal new: {e}"))?;
    let old_paths = write_shares(&old_dir, &old_set.shares)?;
    write_shares(&new_dir, &new_set.shares)?;
    println!("[3/8] both roots Shamir-split 3-of-5 into sealed media");

    // ----- Cross-sign, both directions ------------------------------------
    let bundle = CrossSignBundle::create(
        &old_sk, old_kid, &old_pk, &new_sk, new_kid, &new_pk, now, DEFAULT_WINDOW_SECS,
    )
    .map_err(|e| anyhow!("cross-sign: {e}"))?;
    bundle.verify().map_err(|e| anyhow!("cross-sign verify: {e}"))?;
    let bundle_json = bundle.to_json().map_err(|e| anyhow!("encode bundle: {e}"))?;
    std::fs::write(root.join("cross-sign.json"), &bundle_json)?;
    println!("[4/8] cross-sign bundle validates in BOTH directions");

    // ----- JWKS: newer preferred ------------------------------------------
    let new_pk_b64 = resolve_pub_b64(&bundle.new_pub)?;
    let old_pk_b64 = resolve_pub_b64(&bundle.old_pub)?;
    let jwks = ferro_svid::JwkSet {
        keys: vec![
            ferro_svid::Jwk::from_public_key_at(new_kid, &new_pk_b64, bundle.window_start),
            ferro_svid::Jwk::from_public_key_at(old_kid, &old_pk_b64, bundle.window_start - 1),
        ],
        crl: None,
    };
    let preferred = jwks.preferred().ok_or_else(|| anyhow!("empty jwks"))?;
    if preferred.kid != new_kid {
        bail!("newer-preferred check failed: preferred {} != {new_kid}", preferred.kid);
    }
    std::fs::write(root.join("jwks.json"), serde_json::to_vec_pretty(&jwks)?)?;
    println!("[5/8] JWKS publishes both roots; preferred = {} (the newer)", preferred.kid);

    // ----- Reconstruct the new root from a 3-share subset -----------------
    let subset = &new_set.shares[..threshold];
    let recovered = SealedShareSet::combine(subset).map_err(|e| anyhow!("combine: {e}"))?;
    let (_rsk, rpk) = CompositeSecretKey::from_seed(&recovered);
    if rpk.to_concat_bytes() != new_pk.to_concat_bytes() {
        bail!("reconstructed new root does not match");
    }
    println!("[6/8] new root reconstructed from a 3-of-5 subset; pubkey matches");

    // ----- Minutes signed by ALL participants -----------------------------
    let participants: Vec<Participant> = operators
        .iter()
        .map(|o| Participant {
            name: o.name.clone(),
            role: o.role.clone(),
            kid: o.kid.clone(),
            pubkey: STANDARD.encode(o.pubkey.to_concat_bytes()),
        })
        .collect();
    let minutes = CeremonyMinutes {
        version: 1,
        ceremony_id: "dry-run-2026".to_string(),
        kind: CeremonyKind::Rotation,
        occurred_at: now,
        location: "staging Faraday room (dry-run)".to_string(),
        trust_domain: "ferrogate.staging".to_string(),
        old_root_kid: Some(old_kid.to_string()),
        new_root_kid: Some(new_kid.to_string()),
        threshold,
        total: operators.len(),
        participants,
        artefacts: vec![ArtefactDigest {
            label: "cross-sign-bundle".to_string(),
            sha3_256: sha3_256_hex(&bundle_json),
        }],
        notes: "Automated staging dry-run; no production key material.".to_string(),
    };
    let mut signed = SignedMinutes::new(minutes);
    for o in &operators {
        let (sk, _pk) = CompositeSecretKey::from_seed(&o.seed);
        signed.sign(&o.kid, &sk).map_err(|e| anyhow!("{} sign: {e}", o.kid))?;
    }
    signed.verify_all().map_err(|e| anyhow!("minutes verify: {e}"))?;
    std::fs::write(root.join("minutes.json"), signed.to_json().map_err(|e| anyhow!("{e}"))?)?;
    println!("[7/8] ceremony minutes signed by all {} participants (WORM-ready)", operators.len());

    // ----- End-of-window destruction of the OLD shares --------------------
    let mut records = Vec::new();
    for p in &old_paths {
        records.push(destroy_media(p, now + DEFAULT_WINDOW_SECS).map_err(|e| anyhow!("{e}"))?);
    }
    // Reconstruction of the old root must now fail (media is gone).
    let reload: Vec<_> = old_paths
        .iter()
        .map(|p| std::fs::read(p).map_err(|e| anyhow!("{e}")))
        .collect::<Result<_>>()?;
    let combine_after = reload
        .iter()
        .map(|b| SealedShare::from_json(b).and_then(|s| s.to_share()))
        .collect::<std::result::Result<Vec<_>, _>>();
    if combine_after.is_ok() {
        bail!("old shares still reconstruct after destruction");
    }
    std::fs::write(root.join("destruction.json"), serde_json::to_vec_pretty(&records)?)?;
    println!(
        "[8/8] all {} outgoing-root media zeroized; post-zeroization read-back verified",
        records.len()
    );

    println!("\n== dry-run complete: all F14 ceremony steps passed ==");
    println!("artefacts written under {work}/");
    Ok(())
}

fn write_shares(dir: &Path, shares: &[SealedShare]) -> Result<Vec<std::path::PathBuf>> {
    let mut paths = Vec::new();
    for share in shares {
        let path = dir.join(format!("share-{}.json", share.index));
        std::fs::write(&path, share.to_json().map_err(|e| anyhow!("encode: {e}"))?)
            .with_context(|| format!("write {}", path.display()))?;
        paths.push(path);
    }
    Ok(paths)
}
