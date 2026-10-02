//! `mia x509-svid` — inspect the sealed X.509-SVID this host is holding.
//!
//! The daemon seals its X.509-SVID (feature F17) under a key bound to this
//! machine: sealed by the TPM where there is one, wrapped to a macOS Secure
//! Enclave key on a Mac, and derived from the hardware fingerprint otherwise
//! (see [`crate::credstore`]). This command opens that store the same way the
//! daemon does and reports what is inside — which is also the practical
//! demonstration that the file is machine-bound: run it on any other host, or
//! after a boot-state change on a TPM host, and it fails.
//!
//! It prints the **certificate** and never the private key. The key exists so
//! this host can terminate mTLS with the credential; a copy on a terminal or in
//! a shell history would undo the point of sealing it. A workload that needs to
//! use the credential should be served it by the helper API, not by scraping
//! this output.
//!
//! Read-only and offline: no CMIS contact, no config, no signalling the daemon.

use anyhow::Context as _;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use std::fmt::Write as _;

const USAGE: &str = "usage: mia x509-svid [--pem] [--bundle-pem]";

/// What the caller asked to see.
#[derive(Default, Clone, Copy)]
struct Opts {
    /// Print the leaf certificate as PEM.
    pem: bool,
    /// Print the trust bundle as PEM.
    bundle_pem: bool,
}

/// Run the `mia x509-svid` subcommand. `args` is everything after `x509-svid`.
pub fn run(args: &[String]) -> anyhow::Result<()> {
    let Some(opts) = parse(args)? else {
        print_help();
        return Ok(());
    };

    let path = crate::credstore::store_path();
    // The fallback sealer needs the fingerprint; on a TPM host it goes unused.
    let fingerprint = ferro_machineid::collect_facts()
        .ok()
        .map(|f| f.fingerprint().as_bytes().to_vec());
    let now = i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .context("system clock is before the Unix epoch")?
            .as_secs(),
    )
    .unwrap_or(i64::MAX);

    let Some(result) = crate::credstore::with_sealer(fingerprint.as_deref(), |sealer| {
        crate::credstore::load(&path, sealer, now)
    }) else {
        anyhow::bail!(
            "this host has neither a usable TPM nor a hardware fingerprint, so no sealed \
             credential can exist here"
        );
    };

    let loaded = match result {
        Ok(Some(l)) => l,
        Ok(None) => {
            anyhow::bail!(
                "no sealed X.509-SVID at {} — the daemon writes one after a successful \
                 attestation",
                path.display()
            )
        }
        Err(e) => {
            return Err(anyhow::anyhow!(e)).context(format!(
                "opening {} (a store sealed on another host, or on this host before a boot-state \
             change, will not open here — that is the point)",
                path.display()
            ))
        }
    };

    if opts.pem {
        print!("{}", pem("CERTIFICATE", &loaded.credential.leaf_der));
    }
    if opts.bundle_pem {
        print!("{}", pem("CERTIFICATE", &loaded.credential.bundle_der));
    }
    if opts.pem || opts.bundle_pem {
        return Ok(());
    }

    let remaining = loaded.not_after - now;
    println!("spiffe-id:   {}", loaded.spiffe_id);
    println!(
        "sealed-with: {} (opens only on this machine)",
        loaded.backend
    );
    println!("store:       {}", path.display());
    println!(
        "not-after:   {} ({})",
        loaded.not_after,
        humanise(remaining)
    );
    println!(
        "leaf:        {} bytes DER",
        loaded.credential.leaf_der.len()
    );
    println!(
        "bundle:      {} bytes DER",
        loaded.credential.bundle_der.len()
    );
    println!("private-key: held, not printed");
    Ok(())
}

/// Render `remaining` seconds as a short human phrase.
fn humanise(remaining: i64) -> String {
    if remaining <= 0 {
        return "expired".to_string();
    }
    let (h, m) = (remaining / 3600, (remaining % 3600) / 60);
    if h > 0 {
        format!("expires in {h}h {m}m")
    } else {
        format!("expires in {m}m")
    }
}

/// Wrap DER as PEM with the conventional 64-character lines.
fn pem(label: &str, der: &[u8]) -> String {
    let b64 = STANDARD.encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(core::str::from_utf8(chunk).unwrap_or_default());
        out.push('\n');
    }
    let _ = writeln!(out, "-----END {label}-----");
    out
}

/// Parse flags. `Ok(None)` means `--help` was requested.
fn parse(args: &[String]) -> anyhow::Result<Option<Opts>> {
    let mut opts = Opts::default();
    for arg in args {
        match arg.as_str() {
            "-h" | "--help" => return Ok(None),
            "--pem" => opts.pem = true,
            "--bundle-pem" => opts.bundle_pem = true,
            other => anyhow::bail!("unknown option: {other}\n\n{USAGE}"),
        }
    }
    Ok(Some(opts))
}

fn print_help() {
    println!("{USAGE}");
    println!();
    println!("Inspect the X.509-SVID this host has sealed to disk. The store is bound to");
    println!("this machine — sealed by the TPM where there is one, wrapped to the Secure");
    println!("Enclave on a Mac, or derived from the hardware fingerprint — so it does not");
    println!("open anywhere else.");
    println!();
    println!("  --pem         print the leaf certificate as PEM");
    println!("  --bundle-pem  print the trust bundle as PEM");
    println!();
    println!("The private key is never printed.");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pem_wraps_at_64_columns_with_the_right_labels() {
        let der = vec![0xABu8; 100];
        let out = pem("CERTIFICATE", &der);
        let lines: Vec<&str> = out.lines().collect();

        assert_eq!(lines[0], "-----BEGIN CERTIFICATE-----");
        assert_eq!(lines[lines.len() - 1], "-----END CERTIFICATE-----");
        for line in &lines[1..lines.len() - 1] {
            assert!(line.len() <= 64, "body line too long: {}", line.len());
        }

        // And it decodes back to the original DER.
        let body: String = lines[1..lines.len() - 1].concat();
        assert_eq!(STANDARD.decode(body).unwrap(), der);
    }

    #[test]
    fn flags_parse_and_unknown_options_are_refused() {
        assert!(parse(&["--help".to_string()]).unwrap().is_none());
        let o = parse(&["--pem".to_string()]).unwrap().unwrap();
        assert!(o.pem && !o.bundle_pem);
        let o = parse(&["--bundle-pem".to_string()]).unwrap().unwrap();
        assert!(o.bundle_pem && !o.pem);
        assert!(parse(&["--key".to_string()]).is_err());
    }

    #[test]
    fn remaining_time_reads_sensibly() {
        assert_eq!(humanise(-1), "expired");
        assert_eq!(humanise(0), "expired");
        assert_eq!(humanise(90), "expires in 1m");
        assert_eq!(humanise(3700), "expires in 1h 1m");
    }
}
