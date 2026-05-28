//! File-backed RIM loader with hot reload (feature F10).
//!
//! [`RimLoader::try_reload`] reads a signed bundle from disk, verifies its
//! composite signature against [`TrustedKeys`], decodes it into a
//! [`RimGeneration`], and applies it to a shared [`RimStore`]. The apply is a
//! single write-lock swap so in-flight readers see either the old generation
//! set in full or the new in full — never a torn intermediate.
//!
//! Monotonic-version and validity-window enforcement live in
//! [`RimStore::apply`]; this module just plumbs file I/O.
//!
//! Production deployments run a small async watcher task in CMIS that polls
//! the bundle's mtime and calls `try_reload` whenever it changes; in tests we
//! call it directly. The S3-backed refresh path is sequenced in M5 (see
//! `docs/roadmap.md`).

use std::path::{Path, PathBuf};

use crate::rim::{ApplyError, ApplyOutcome, RimStore};
use crate::rim_bundle::{BundleError, SignedRimBundle, TrustedKeys};

/// What happened on a reload attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReloadOutcome {
    /// The on-disk bundle advanced the store; the new generation is now active.
    Applied(ApplyOutcome),
    /// The on-disk bundle's version is not strictly newer than the active one;
    /// nothing was changed. Returned both when the file hasn't moved and when
    /// the publisher re-issued at the same version.
    UpToDate {
        /// The version currently active in the store.
        version: u64,
    },
}

/// Failure modes for a reload.
#[derive(Debug, thiserror::Error)]
pub enum ReloadError {
    /// The bundle file could not be read.
    #[error("read {path}: {source}")]
    Io {
        /// Path that failed.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// The bundle failed to parse, decode, or pass signature verification.
    #[error("bundle: {0}")]
    Bundle(#[from] BundleError),
    /// The store rejected the bundle for non-monotonicity or an empty window.
    #[error("apply: {0}")]
    Apply(#[from] ApplyError),
}

/// A loader binding a file path, the publisher trust set, and the live store.
pub struct RimLoader {
    path: PathBuf,
    trust: TrustedKeys,
    store: RimStore,
}

impl RimLoader {
    /// Build a loader. The store handle should also be cloned into whatever
    /// [`crate::TpmQuoteVerifier`] performs lookups; they share state.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>, trust: TrustedKeys, store: RimStore) -> Self {
        Self {
            path: path.into(),
            trust,
            store,
        }
    }

    /// The bundle path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The shared store handle.
    #[must_use]
    pub fn store(&self) -> &RimStore {
        &self.store
    }

    /// Read, verify, and apply the bundle currently on disk.
    ///
    /// Returns [`ReloadOutcome::UpToDate`] (not an error) when the on-disk
    /// bundle's version is `<=` the active one — the caller's polling loop can
    /// then back off without escalating.
    pub fn try_reload(&self) -> Result<ReloadOutcome, ReloadError> {
        let bytes = std::fs::read(&self.path).map_err(|source| ReloadError::Io {
            path: self.path.clone(),
            source,
        })?;
        let signed = SignedRimBundle::from_json(&bytes)?;
        let bundle = signed.verify(&self.trust)?;
        let incoming_version = bundle.version;
        if incoming_version <= self.store.current_version() {
            return Ok(ReloadOutcome::UpToDate {
                version: self.store.current_version(),
            });
        }
        let generation = bundle.to_generation()?;
        let outcome = self.store.apply(generation)?;
        Ok(ReloadOutcome::Applied(outcome))
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use ferro_crypto::composite::CompositeSecretKey;

    use crate::rim_bundle::{RimBundle, SignedRimBundle};

    use super::*;

    fn write_signed(path: &Path, bundle: RimBundle, kid: &str, sk: &CompositeSecretKey) {
        let signed = SignedRimBundle::sign(bundle, kid, sk).unwrap();
        let mut f = std::fs::File::create(path).unwrap();
        f.write_all(&serde_json::to_vec(&signed).unwrap()).unwrap();
    }

    fn temp_path(tag: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        p.push(format!("ferrogate-rim-{tag}-{nanos}.json"));
        p
    }

    fn bundle(version: u64, digest: u8) -> RimBundle {
        RimBundle {
            version,
            policy_id: format!("fleet-{version}"),
            not_before: 0,
            not_after: 1_000_000,
            approved_digests_hex: vec![hex::encode([digest; 48])],
        }
    }

    #[test]
    fn reload_applies_then_reports_up_to_date() {
        let path = temp_path("apply");
        let (sk, pk) = CompositeSecretKey::generate().unwrap();
        write_signed(&path, bundle(1, 0xAA), "pub", &sk);

        let mut trust = TrustedKeys::new();
        trust.add("pub", pk);
        let store = RimStore::new();
        let loader = RimLoader::new(&path, trust, store.clone());

        match loader.try_reload().unwrap() {
            ReloadOutcome::Applied(o) => assert_eq!(o.version, 1),
            ReloadOutcome::UpToDate { version } => {
                panic!("expected Applied, got UpToDate {version}")
            }
        }
        assert_eq!(store.current_version(), 1);
        assert_eq!(store.lookup_at(&[0xAA; 48], 500).unwrap().0, "fleet-1");

        // Re-reading the same file is a no-op.
        match loader.try_reload().unwrap() {
            ReloadOutcome::UpToDate { version } => assert_eq!(version, 1),
            ReloadOutcome::Applied(o) => panic!("expected UpToDate, got Applied {o:?}"),
        }
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn reload_swaps_in_new_generation_atomically() {
        let path = temp_path("swap");
        let (sk, pk) = CompositeSecretKey::generate().unwrap();
        write_signed(&path, bundle(1, 0xAA), "pub", &sk);
        let mut trust = TrustedKeys::new();
        trust.add("pub", pk);
        let store = RimStore::new();
        let loader = RimLoader::new(&path, trust, store.clone());
        loader.try_reload().unwrap();

        // Publish a fresher bundle with a *different* digest.
        write_signed(&path, bundle(2, 0xBB), "pub", &sk);
        loader.try_reload().unwrap();
        // Newest gen approves 0xBB under fleet-2.
        assert_eq!(store.lookup_at(&[0xBB; 48], 500).unwrap().0, "fleet-2");
        // Older gen still approves 0xAA under fleet-1 (within retention).
        assert_eq!(store.lookup_at(&[0xAA; 48], 500).unwrap().0, "fleet-1");
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn reload_rejects_non_monotonic_version_on_disk() {
        let path = temp_path("nonmono");
        let (sk, pk) = CompositeSecretKey::generate().unwrap();
        write_signed(&path, bundle(5, 0xAA), "pub", &sk);
        let mut trust = TrustedKeys::new();
        trust.add("pub", pk);
        let store = RimStore::new();
        let loader = RimLoader::new(&path, trust, store.clone());
        loader.try_reload().unwrap();

        // A regression: lower version is silently treated as up-to-date,
        // never applied. (We don't escalate because operators often re-publish
        // at lower numbers during a rollback — the active version is the truth.)
        write_signed(&path, bundle(3, 0xBB), "pub", &sk);
        match loader.try_reload().unwrap() {
            ReloadOutcome::UpToDate { version } => assert_eq!(version, 5),
            ReloadOutcome::Applied(o) => panic!("expected UpToDate, got Applied {o:?}"),
        }
        // The rollback digest was never admitted.
        assert!(store.lookup_at(&[0xBB; 48], 500).is_none());
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn reload_with_unknown_publisher_is_refused() {
        let path = temp_path("badkid");
        let (sk, _pk) = CompositeSecretKey::generate().unwrap();
        write_signed(&path, bundle(1, 0xAA), "evil", &sk);
        let trust = TrustedKeys::new();
        let store = RimStore::new();
        let loader = RimLoader::new(&path, trust, store.clone());
        let err = loader.try_reload().unwrap_err();
        assert!(matches!(
            err,
            ReloadError::Bundle(BundleError::UnknownKid(_))
        ));
        assert_eq!(store.current_version(), 0);
        std::fs::remove_file(path).ok();
    }
}
